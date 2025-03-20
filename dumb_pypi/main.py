"""A simple read-only PyPI static index server generator.

To generate the registry, pass a list of packages using either --package-list
or --package-list-json.

Packages can be specified as:
1. Just filenames (combined with --packages-url to form full URLs)
2. Complete URLs to the packages (e.g., GitHub release URLs)
3. Git repository URLs (e.g., git+https://github.com/user/repo@version)

By default, the entire registry is rebuilt. If you want to do a rebuild of
changed packages only, you can pass --previous-package-list(-json) with the old
package list.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import inspect
import itertools
import json
import math
import os.path
import re
import sys
import tempfile
import urllib.parse
from collections.abc import Generator
from collections.abc import Iterator
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from typing import IO
from typing import NamedTuple

import jinja2
import packaging.utils
import packaging.version

CHANGELOG_ENTRIES_PER_PAGE = 5000
DIGIT_RE = re.compile("([0-9]+)", re.ASCII)
# Copied from distlib/wheel.py
WHEEL_FILENAME_RE = re.compile(
    r"""
(?P<nm>[^-]+)
-(?P<vn>\d+[^-]*)
(-(?P<bn>\d+[^-]*))?
-(?P<py>\w+\d+(\.\w+\d+)*)
-(?P<bi>\w+)
-(?P<ar>\w+(\.\w+)*)
\.whl$
""",
    re.IGNORECASE | re.VERBOSE,
)

# Pattern to match GitHub archive URLs
GITHUB_ARCHIVE_RE = re.compile(
    r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/archive/refs/tags/(?P<version>.+?)\.(tar\.gz|zip)"
)

# Pattern to match Git repository URLs
GIT_REPO_URL_RE = re.compile(
    r"git\+https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^@]+)(@(?P<version>.+))?"
)


def remove_extension(name: str) -> str:
    if name.endswith(("gz", "bz2")):
        name, _ = name.rsplit(".", 1)
    name, _ = name.rsplit(".", 1)
    return name


def get_filename_from_url(url: str) -> str:
    """Extract filename from a URL."""
    parsed_url = urllib.parse.urlparse(url)
    return os.path.basename(parsed_url.path)


def is_github_archive_url(url: str) -> bool:
    """Check if URL is a GitHub archive URL."""
    return bool(GITHUB_ARCHIVE_RE.match(url))


def is_git_repo_url(url: str) -> bool:
    """Check if URL is a Git repository URL."""
    return bool(GIT_REPO_URL_RE.match(url))


def extract_package_info_from_github_url(url: str) -> tuple[str, str | None]:
    """Extract the package name and version from a GitHub archive URL."""
    match = GITHUB_ARCHIVE_RE.match(url)
    if not match:
        raise ValueError(f"Not a GitHub archive URL: {url}")

    # For GitHub archives, we'll use the repository name as the package name
    repo_name = match.group("repo")
    version = match.group("version")

    # If version starts with 'v', strip it
    if version.startswith("v") and len(version) > 1 and version[1].isdigit():
        version = version[1:]

    return repo_name, version


def extract_package_info_from_git_url(url: str) -> tuple[str, str | None]:
    """Extract the package name and version from a Git repository URL."""
    match = GIT_REPO_URL_RE.match(url)
    if not match:
        raise ValueError(f"Not a Git repository URL: {url}")

    # For Git URLs, we'll use the repository name as the package name
    repo_name = match.group("repo")
    version = match.group("version")

    # If version starts with 'v', strip it
    if (
        version
        and version.startswith("v")
        and len(version) > 1
        and version[1].isdigit()
    ):
        version = version[1:]

    return repo_name, version


def create_dummy_filename_for_git(name: str, version: str | None) -> str:
    """Create a dummy filename for Git URLs to use in displays/sorting."""
    safe_version = version or "0.0.0"
    return f"{name}-{safe_version}.tar.gz"


def guess_name_version_from_filename(
    filename: str,
    url: str | None = None,
) -> tuple[str, str | None]:
    # Special case for GitHub archive URLs
    if url and is_github_archive_url(url):
        return extract_package_info_from_github_url(url)

    # Special case for Git repository URLs
    if url and is_git_repo_url(url):
        return extract_package_info_from_git_url(url)

    if filename.endswith(".whl"):
        # TODO: Switch to packaging.utils.parse_wheel_filename which enforces
        # PEP440 versions for wheels.
        m = WHEEL_FILENAME_RE.match(filename)
        if m is not None:
            return m.group("nm"), m.group("vn")
        else:
            raise ValueError(f"Invalid package name: {filename}")
    else:
        # These don't have a well-defined format like wheels do, so they are
        # sort of "best effort", with lots of tests to back them up.
        # The most important thing is to correctly parse the name.
        name = remove_extension(filename)
        version = None

        if "-" in name:
            if name.count("-") == 1:
                name, version = name.split("-")
            else:
                parts = name.split("-")
                for i in range(len(parts) - 1, 0, -1):
                    part = parts[i]
                    if "." in part and re.search("[0-9]", part):
                        name, version = "-".join(parts[0:i]), "-".join(parts[i:])

        # possible with poorly-named files
        if len(name) <= 0:
            raise ValueError(f"Invalid package name: {filename}")

        # impossible
        assert version is None or len(version) > 0, version

        return name, version


def _natural_key(s: str) -> tuple[int | str, ...]:
    return tuple(int(part) if part.isdigit() else part for part in DIGIT_RE.split(s))


class Package(NamedTuple):
    filename: str
    url: str | None  # New field for direct URL
    name: str
    version: str | None
    parsed_version: packaging.version.Version
    hash: str | None
    requires_dist: tuple[str, ...] | None
    requires_python: str | None
    core_metadata: str | None
    upload_timestamp: int | None
    uploaded_by: str | None
    yanked_reason: str | None

    def __lt__(self, other: tuple[Any, ...]) -> bool:
        assert isinstance(other, Package), type(other)
        return self.sort_key < other.sort_key

    @property
    def sort_key(
        self,
    ) -> tuple[str, packaging.version.Version, bool, tuple[str | int, ...], str]:
        """Sort key for a filename."""
        return (
            self.name,
            self.parsed_version,
            # sort wheels first
            not self.filename.endswith(".whl") if self.filename else True,
            # natural sort within
            _natural_key(self.filename) if self.filename else (),
            # all things equal, use filename
            self.filename if self.filename else "",
        )

    @property
    def formatted_upload_time(self) -> str:
        assert self.upload_timestamp is not None
        dt = datetime.utcfromtimestamp(self.upload_timestamp)
        return _format_datetime(dt)

    @property
    def info_string(self) -> str:
        # TODO: I'd like to remove this "info string" and instead format things
        # nicely for humans (e.g. in a table or something).
        #
        # This might mean changing the web interface to use different pages for
        # humans than the /simple/ ones it currently links to. (Even if pip can
        # parse links from a <table>, it might add significantly more bytes.)
        info = self.version or "unknown version"
        if self.upload_timestamp is not None:
            info += f", {self.formatted_upload_time}"
        if self.uploaded_by is not None:
            info += f", {self.uploaded_by}"
        if is_git_repo_url(self.url or ""):
            info += " (Git repository)"
        return info

    def get_url(self, base_url: str, *, include_hash: bool = True) -> str:
        # Use direct URL if provided, otherwise build from base_url and filename
        if self.url:
            url = self.url
        else:
            url = f"{base_url.rstrip('/')}/{self.filename}"

        # Add hash if needed
        hash_part = f"#{self.hash}" if self.hash and include_hash else ""
        return f"{url}{hash_part}"

    @property
    def display_filename(self) -> str:
        """Return a filename suitable for display."""
        if not self.filename:
            if is_git_repo_url(self.url or ''):
                # Create a proper filename for pip to parse
                return f"{self.name}-{self.version or '0.0.0'}.tar.gz"
        return self.filename

    @property
    def packagetype(self) -> str:
        if self.filename and self.filename.endswith(".whl"):
            return "bdist_wheel"
        elif self.filename and self.filename.endswith(".egg"):
            return "bdist_egg"
        elif is_git_repo_url(self.url or ""):
            return "git"
        else:
            return "sdist"

    def json_info(self, base_url: str) -> dict[str, Any]:
        ret: dict[str, Any] = {
            "filename": self.display_filename,
            "url": self.get_url(base_url, include_hash=False),
            "requires_python": self.requires_python,
            "packagetype": self.packagetype,
            "yanked": bool(self.yanked_reason),
            "yanked_reason": self.yanked_reason,
        }
        if self.upload_timestamp is not None:
            ret["upload_time"] = self.formatted_upload_time
        if self.hash is not None:
            algo, h = self.hash.split("=")
            ret["digests"] = {algo: h}
        return ret

    def input_json(self) -> dict[str, Any]:
        """A dict suitable for json lines."""
        return {
            k: getattr(self, k)
            for k in inspect.getfullargspec(self.create).kwonlyargs
            if getattr(self, k) is not None
        }

    @classmethod
    def create(
        cls,
        *,
        filename: str = "",
        url: str | None = None,
        name: str | None = None,  # Allow explicit name override
        version: str | None = None,  # Allow explicit version override
        hash: str | None = None,
        requires_dist: Sequence[str] | None = None,
        requires_python: str | None = None,
        upload_timestamp: int | None = None,
        uploaded_by: str | None = None,
        yanked_reason: str | None = None,
        core_metadata: str | None = None,
    ) -> Package:
        # DEBUG: Print input parameters
        print(
            f"DEBUG: Creating package with url={url}, name={name}, version={version}",
            file=sys.stderr,
        )

        # Handle Git repository URLs
        if url and is_git_repo_url(url):
            if name is None or version is None:
                auto_name, auto_version = extract_package_info_from_git_url(url)
                print(
                    f"DEBUG: Extracted from Git URL: name={auto_name}, version={auto_version}",
                    file=sys.stderr,
                )
                if name is None:
                    name = auto_name
                if version is None:
                    version = auto_version
            # For Git repositories, we don't have a real filename
            filename = ""

        # If URL is provided but filename is not, extract the filename from the URL
        elif url and not filename and not is_git_repo_url(url):
            filename = get_filename_from_url(url)

        # Check filename safety if it's provided
        if filename and (
            not re.match(r"[a-zA-Z0-9_\-\.\+]+$", filename) or ".." in filename
        ):
            raise ValueError(f"Unsafe package name: {filename}")

        # Allow override of name and version, or auto-detect from filename/URL
        if name is None or version is None:
            auto_name, auto_version = guess_name_version_from_filename(filename, url)
            if name is None:
                name = auto_name
            if version is None:
                version = auto_version

        # Parse version safely
        try:
            parsed_version = packaging.version.parse(version or "0")
        except packaging.version.InvalidVersion:
            # If we can't parse the version, use a dummy version
            print(
                f"Warning: Could not parse version '{version}' for package '{name}', using 0.0.0",
                file=sys.stderr,
            )
            parsed_version = packaging.version.parse("0.0.0")

        canonical_name = packaging.utils.canonicalize_name(name)

        # DEBUG: Print created package
        print(
            f"DEBUG: Created package: name={canonical_name}, version={version}",
            file=sys.stderr,
        )

        return cls(
            filename=filename,
            url=url,
            name=canonical_name,
            version=version,
            parsed_version=parsed_version,
            hash=hash,
            requires_dist=tuple(requires_dist) if requires_dist is not None else None,
            requires_python=requires_python,
            core_metadata=core_metadata,
            upload_timestamp=upload_timestamp,
            uploaded_by=uploaded_by,
            yanked_reason=yanked_reason,
        )


@contextlib.contextmanager
def atomic_write(path: str) -> Generator[IO[str]]:
    tmp = tempfile.mktemp(
        prefix="." + os.path.basename(path),
        dir=os.path.dirname(path),
    )
    try:
        with open(tmp, "w") as f:
            yield f
    except BaseException:
        os.remove(tmp)
        raise
    else:
        os.replace(tmp, path)


def _format_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


IMPORTANT_METADATA_FOR_INFO = frozenset(
    (
        "name",
        "version",
        "requires_dist",
        "requires_python",
    )
)


def _package_json(sorted_files: list[Package], base_url: str) -> dict[str, Any]:
    # https://warehouse.pypa.io/api-reference/json.html
    # note: the full api contains much more, we only output the info we have
    by_version: dict[str, list[Package]] = collections.defaultdict(list)
    for file in sorted_files:
        if file.version is not None:
            by_version[file.version].append(file)

    # Find a file from the latest release to use for "info". We don't want to
    # mix-and-match the metadata across releases since tools like Poetry rely
    # on this, but we do want to pick the file in the release with the most
    # populated metadata.
    latest_file = sorted_files[-1]
    if sorted_files[-1].version is not None:
        latest_file = max(
            by_version[sorted_files[-1].version],
            key=lambda f: sum(bool(getattr(f, v)) for v in IMPORTANT_METADATA_FOR_INFO),
        )

    return {
        "info": {
            "name": latest_file.name,
            "version": latest_file.version,
            "requires_dist": latest_file.requires_dist,
            "requires_python": latest_file.requires_python,
            "platform": "UNKNOWN",
            "summary": None,
            "yanked": bool(latest_file.yanked_reason),
            "yanked_reason": latest_file.yanked_reason,
        },
        "releases": {
            version: [file_.json_info(base_url) for file_ in files]
            for version, files in by_version.items()
        },
        "urls": [file_.json_info(base_url) for file_ in by_version[latest_file.version]]
        if latest_file and latest_file.version is not None
        else [],
    }


class Settings(NamedTuple):
    output_dir: str
    packages_url: str
    title: str
    logo: str
    logo_width: int
    generate_timestamp: bool
    disable_per_release_json: bool


def build_repo(
    packages: dict[str, set[Package]],
    previous_packages: dict[str, set[Package]] | None,
    settings: Settings,
) -> None:
    simple = os.path.join(settings.output_dir, "simple")
    pypi = os.path.join(settings.output_dir, "pypi")
    current_date = _format_datetime(datetime.utcnow())

    jinja_env = jinja2.Environment(
        loader=jinja2.PackageLoader("dumb_pypi", "templates"),
        autoescape=True,
    )
    jinja_env.globals["title"] = settings.title
    jinja_env.globals["packages_url"] = settings.packages_url
    jinja_env.globals["logo"] = settings.logo
    jinja_env.globals["logo_width"] = settings.logo_width
    jinja_env.globals["is_git_repo_url"] = is_git_repo_url  # Add function to templates

    # Short circuit if nothing changed at all.
    if packages == previous_packages:
        return

    # DEBUG: Print all packages
    for pkg_name, pkg_files in packages.items():
        print(f"DEBUG: Package {pkg_name} has {len(pkg_files)} files", file=sys.stderr)
        for pkg in pkg_files:
            print(
                f"  - {pkg.filename or 'no-filename'} URL: {pkg.url} Version: {pkg.version}",
                file=sys.stderr,
            )

    # Sorting package versions is actually pretty expensive, so we do it once
    # at the start.
    sorted_packages = {name: sorted(files) for name, files in packages.items()}

    # /simple/index.html
    # Rebuild if there are different package names.
    if previous_packages is None or set(packages) != set(previous_packages):
        os.makedirs(simple, exist_ok=True)
        with atomic_write(os.path.join(simple, "index.html")) as f:
            f.write(
                jinja_env.get_template("simple.html").render(
                    date=current_date,
                    generate_timestamp=settings.generate_timestamp,
                    package_names=sorted(sorted_packages),
                )
            )

    for package_name, sorted_files in sorted_packages.items():
        # Rebuild if the files are different for this package.
        if (
            previous_packages is None
            or package_name not in previous_packages
            or previous_packages[package_name] != packages[package_name]
        ):
            latest_version = sorted_files[-1].version

            # /simple/{package}/index.html
            simple_package_dir = os.path.join(simple, package_name)
            os.makedirs(simple_package_dir, exist_ok=True)
            with atomic_write(os.path.join(simple_package_dir, "index.html")) as f:
                f.write(
                    jinja_env.get_template("package.html").render(
                        date=current_date,
                        generate_timestamp=settings.generate_timestamp,
                        package_name=package_name,
                        files=sorted_files,
                        packages_url=settings.packages_url,
                        requirement=f"{package_name}=={latest_version}"
                        if latest_version
                        else package_name,
                    )
                )

            # /pypi/{package}/json
            pypi_package_dir = os.path.join(pypi, package_name)
            os.makedirs(pypi_package_dir, exist_ok=True)
            with atomic_write(os.path.join(pypi_package_dir, "json")) as f:
                json.dump(_package_json(sorted_files, settings.packages_url), f)

            # /pypi/{package}/{version}/json
            if not settings.disable_per_release_json:
                # TODO: Consider making this only generate JSON for the changed versions.
                version_to_files = collections.defaultdict(list)
                for file_ in sorted_files:
                    version_to_files[file_.version].append(file_)
                for version, files in version_to_files.items():
                    if version is None:
                        continue
                    version_dir = os.path.join(pypi_package_dir, version)
                    os.makedirs(version_dir, exist_ok=True)
                    with atomic_write(os.path.join(version_dir, "json")) as f:
                        json.dump(_package_json(files, settings.packages_url), f)

    # Create .nojekyll file to prevent GitHub Pages from processing with Jekyll
    with open(os.path.join(settings.output_dir, ".nojekyll"), "w") as f:
        pass

    # /changelog
    # Always rebuild (we would have short circuited already if nothing changed).
    changelog = os.path.join(settings.output_dir, "changelog")
    os.makedirs(changelog, exist_ok=True)
    files_newest_first = sorted(
        itertools.chain.from_iterable(packages.values()),
        key=lambda package: (-(package.upload_timestamp or 0), package),
    )
    page_count = math.ceil(len(files_newest_first) / CHANGELOG_ENTRIES_PER_PAGE)
    for page_idx, start_idx in enumerate(
        range(0, len(files_newest_first), CHANGELOG_ENTRIES_PER_PAGE)
    ):
        chunk = files_newest_first[start_idx : start_idx + CHANGELOG_ENTRIES_PER_PAGE]
        page_number = page_idx + 1
        with atomic_write(os.path.join(changelog, f"page{page_number}.html")) as f:
            pagination_first = "page1.html" if page_number != 1 else None
            pagination_last = (
                f"page{page_count}.html" if page_number != page_count else None
            )
            pagination_prev = (
                f"page{page_number - 1}.html" if page_number != 1 else None
            )
            pagination_next = (
                f"page{page_number + 1}.html" if page_number != page_count else None
            )
            f.write(
                jinja_env.get_template("changelog.html").render(
                    files_newest_first=chunk,
                    page_number=page_number,
                    page_count=page_count,
                    pagination_first=pagination_first,
                    pagination_last=pagination_last,
                    pagination_prev=pagination_prev,
                    pagination_next=pagination_next,
                )
            )

    # /index.html
    # Always rebuild (we would have short circuited already if nothing changed).
    with atomic_write(os.path.join(settings.output_dir, "index.html")) as f:
        f.write(
            jinja_env.get_template("index.html").render(
                packages=sorted(
                    (
                        package,
                        sorted_versions[-1].version,
                    )
                    for package, sorted_versions in sorted_packages.items()
                ),
            )
        )

    # /packages.json
    # Always rebuild (we would have short circuited already if nothing changed).
    with atomic_write(os.path.join(settings.output_dir, "packages.json")) as f:
        for package in itertools.chain.from_iterable(sorted_packages.values()):
            f.write(f"{json.dumps(package.input_json())}\n")


def _lines_from_path(path: str) -> list[str]:
    f = sys.stdin if path == "-" else open(path)
    return f.read().splitlines()


def _create_packages(
    package_infos: Iterator[dict[str, Any]],
) -> dict[str, set[Package]]:
    packages: dict[str, set[Package]] = collections.defaultdict(set)
    for package_info in package_infos:
        try:
            package = Package.create(**package_info)
        except ValueError as ex:
            # TODO: this should really be optional; i'd prefer it to fail hard
            print(f"{ex} (skipping package)", file=sys.stderr)
        else:
            packages[package.name].add(package)

    return packages


def package_list(path: str) -> dict[str, set[Package]]:
    """Parse a list of filenames or URLs."""
    package_infos = []

    for line in _lines_from_path(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        print(f"DEBUG: Processing line: {line}", file=sys.stderr)

        # Check if it's a Git repository URL
        if line.startswith("git+"):
            name, version = extract_package_info_from_git_url(line)
            print(
                f"DEBUG: Git URL detected: name={name}, version={version}",
                file=sys.stderr,
            )
            package_infos.append({"url": line, "name": name, "version": version})
        # Check if it's a regular URL
        elif line.startswith(("http://", "https://")):
            # Special handling for GitHub archive URLs
            if is_github_archive_url(line):
                name, version = extract_package_info_from_github_url(line)
                print(
                    f"DEBUG: GitHub archive URL detected: name={name}, version={version}",
                    file=sys.stderr,
                )
                package_infos.append({"url": line, "name": name, "version": version})
            else:
                package_infos.append({"url": line})
        else:
            package_infos.append({"filename": line})

    return _create_packages(iter(package_infos))


def package_list_json(path: str) -> dict[str, set[Package]]:
    return _create_packages(json.loads(line) for line in _lines_from_path(path))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    package_input_group = parser.add_mutually_exclusive_group(required=True)
    package_input_group.add_argument(
        "--package-list",
        help="path to a list of packages (one filename or URL per line)",
        type=package_list,
        dest="packages",
    )
    package_input_group.add_argument(
        "--package-list-json",
        help="path to a list of packages (one JSON object per line)",
        type=package_list_json,
        dest="packages",
    )

    previous_package_input_group = parser.add_mutually_exclusive_group(required=False)
    previous_package_input_group.add_argument(
        "--previous-package-list",
        help="path to the previous list of packages (for partial rebuilds)",
        type=package_list,
        dest="previous_packages",
    )
    previous_package_input_group.add_argument(
        "--previous-package-list-json",
        help="path to the previous list of packages (for partial rebuilds)",
        type=package_list_json,
        dest="previous_packages",
    )

    parser.add_argument(
        "--output-dir",
        help="path to output to",
        required=True,
    )
    parser.add_argument(
        "--packages-url",
        help="url to packages (used as base URL for packages without full URLs)",
    )
    parser.add_argument(
        "--title",
        help="site title (for web interface)",
        default="My Private PyPI",
    )
    parser.add_argument(
        "--logo",
        help="URL for logo to display (defaults to no logo)",
    )
    parser.add_argument(
        "--logo-width",
        type=int,
        help="width of logo to display",
        default=0,
    )
    parser.add_argument(
        "--no-generate-timestamp",
        action="store_false",
        dest="generate_timestamp",
        help=(
            "Don't template creation timestamp in outputs.  This option makes "
            "the output repeatable."
        ),
    )
    parser.add_argument(
        "--no-per-release-json",
        action="store_true",
        help=(
            "Disable per-release JSON API (/pypi/<package>/<version>/json).\n"
            "This may be useful for large repositories because this metadata can be "
            "a huge number of files for little benefit as almost no tools use it."
        ),
    )
    args = parser.parse_args(argv)

    # Make --packages-url optional but warn if missing and needed
    if not args.packages_url:
        # Check if any packages lack a direct URL
        any_non_url_packages = any(
            pkg for pkgs in args.packages.values() for pkg in pkgs if not pkg.url
        )
        if any_non_url_packages:
            print(
                "Warning: Some packages don't have direct URLs. Using empty base URL.",
                file=sys.stderr,
            )

    settings = Settings(
        output_dir=args.output_dir,
        packages_url=args.packages_url or "",
        title=args.title,
        logo=args.logo,
        logo_width=args.logo_width,
        generate_timestamp=args.generate_timestamp,
        disable_per_release_json=args.no_per_release_json,
    )
    build_repo(args.packages, args.previous_packages, settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
