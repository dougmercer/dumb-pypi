"""A simple read-only PyPI static index server generator for git repositories.

This script parses git repository URLs in the format:
git+https://github.com/username/repo@version#egg=package-name-version

It generates a PyPI-compatible simple API structure:
/simple/index.html - main index
/simple/{package}/index.html - per package indexes

Usage:
    python git_pypi_parser.py --package-urls-json package_urls.json --output-dir ./output --site-title "My Git PyPI"
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from typing import Any, Dict, List, NamedTuple, Optional, IO, Set
from urllib.parse import urlparse

import jinja2
import packaging.utils
import packaging.version

# Regex for git repository URLs
# Format: git+https://github.com/username/repo@version#egg=package-name[-version]
GIT_URL_RE = re.compile(r'''
    git\+(?P<url>https?://[^@]+)
    @(?P<version>[^#]+)
    \#egg=(?P<egg>[^-]+(?:-[^0-9][^-]*)*)
    (?:-(?P<egg_version>\d[^-]*))?$
''', re.VERBOSE)


class Package(NamedTuple):
    name: str
    version: str
    url: str
    upload_timestamp: Optional[int] = None
    
    @property
    def formatted_upload_time(self) -> str:
        if self.upload_timestamp is None:
            return "unknown upload time"
        dt = datetime.utcfromtimestamp(self.upload_timestamp)
        return _format_datetime(dt)
    
    @property
    def info_string(self) -> str:
        info = self.version or 'unknown version'
        if self.upload_timestamp is not None:
            info += f', {self.formatted_upload_time}'
        return info
    
    def json_info(self) -> Dict[str, Any]:
        ret: Dict[str, Any] = {
            'name': self.name,
            'version': self.version,
            'url': self.url,
        }
        if self.upload_timestamp is not None:
            ret['upload_time'] = self.formatted_upload_time
        return ret


@contextlib.contextmanager
def atomic_write(path: str) -> IO[str]:
    """Write a file atomically."""
    tmp = tempfile.mktemp(
        prefix='.' + os.path.basename(path),
        dir=os.path.dirname(path),
    )
    try:
        with open(tmp, 'w') as f:
            yield f
    except BaseException:
        os.remove(tmp)
        raise
    else:
        os.replace(tmp, path)


def _format_datetime(dt: datetime) -> str:
    """Format a datetime object to a string."""
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def parse_git_url(url: str) -> Optional[Package]:
    """Parse a git URL into package information.
    
    Handles formats like:
    git+https://github.com/username/repo@version#egg=package-name
    git+https://github.com/username/repo@version#egg=package-name-0.1.0
    """
    # First try the regex match
    match = GIT_URL_RE.match(url)
    if not match:
        print(f"Failed to parse URL with regex: {url}")
        # Fall back to a simpler parsing approach
        return fallback_parse_git_url(url)
    
    # Extract the package name from the egg part (without version)
    package_name = match.group('egg')
    # Use the version from the URL
    version = match.group('version')
    
    # Print for debugging
    print(f"Parsed URL: {url}")
    print(f"  - Package name: {package_name}")
    print(f"  - Version: {version}")
    
    canonical_name = packaging.utils.canonicalize_name(package_name)
    
    return Package(
        name=canonical_name,
        version=version,
        url=url,
        upload_timestamp=int(datetime.now().timestamp())
    )


def fallback_parse_git_url(url: str) -> Optional[Package]:
    """Fallback parser for git URLs if regex fails."""
    print(f"Using fallback parser for: {url}")
    
    # Basic structure check
    if not url.startswith('git+http') or '#egg=' not in url or '@' not in url:
        print(f"URL does not have the expected format: {url}")
        return None
    
    # Extract version from the part between @ and #
    at_pos = url.find('@')
    hash_pos = url.find('#')
    
    if at_pos == -1 or hash_pos == -1 or at_pos > hash_pos:
        print(f"Cannot extract version from URL: {url}")
        return None
    
    version = url[at_pos+1:hash_pos]
    
    # Extract egg part
    egg_part = url[url.find('#egg=')+5:]
    
    # Handle case where version is appended to egg
    package_name = egg_part
    if '-' in egg_part:
        # Try to identify if the last part is a version
        parts = egg_part.split('-')
        # If the last part starts with a digit, assume it's a version
        if parts[-1][0].isdigit():
            package_name = '-'.join(parts[:-1])
        else:
            package_name = egg_part
    
    print(f"Fallback parser result:")
    print(f"  - Package name: {package_name}")
    print(f"  - Version: {version}")
    
    return Package(
        name=packaging.utils.canonicalize_name(package_name),
        version=version,
        url=url,
        upload_timestamp=int(datetime.now().timestamp())
    )


class Settings(NamedTuple):
    output_dir: str
    title: str
    generate_timestamp: bool


def build_repo(
        packages: Dict[str, Set[Package]],
        settings: Settings,
) -> None:
    """Build a PyPI-compatible repository structure."""
    output_dir = settings.output_dir
    simple_dir = os.path.join(output_dir, 'simple')
    os.makedirs(simple_dir, exist_ok=True)
    
    current_date = _format_datetime(datetime.utcnow())

    # Setup Jinja environment - this is the key fix
    # Using FileSystemLoader with the correct path to templates
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir),
        autoescape=True,
    )
    jinja_env.globals['title'] = settings.title

    # Create main index.html
    with atomic_write(os.path.join(simple_dir, 'index.html')) as f:
        f.write(jinja_env.get_template('simple_index.md').render(
            date=current_date,
            generate_timestamp=settings.generate_timestamp,
            package_names=sorted(packages.keys()),
        ))

    # Create individual package directories and index files
    for package_name, package_set in sorted(packages.items()):
        sorted_packages = sorted(
            package_set, 
            key=lambda p: packaging.version.parse(p.version),
            reverse=True
        )
        
        # Create package directory
        package_dir = os.path.join(simple_dir, package_name)
        os.makedirs(package_dir, exist_ok=True)
        
        # Create package index.html
        with atomic_write(os.path.join(package_dir, 'index.html')) as f:
            f.write(jinja_env.get_template('package_index.md').render(
                date=current_date,
                generate_timestamp=settings.generate_timestamp,
                package_name=package_name,
                packages=sorted_packages,
                requirement=f'{package_name}=={sorted_packages[0].version}' if sorted_packages else package_name,
            ))

    # Write packages.json for API access
    with atomic_write(os.path.join(output_dir, 'packages.json')) as f:
        json_data = {
            name: [pkg.json_info() for pkg in sorted(
                pkgs, 
                key=lambda p: packaging.version.parse(p.version),
                reverse=True
            )]
            for name, pkgs in packages.items()
        }
        json.dump(json_data, f, indent=2)

    # Create root index.html
    with atomic_write(os.path.join(output_dir, 'index.html')) as f:
        f.write(jinja_env.get_template('root_index.md').render(
            date=current_date,
            generate_timestamp=settings.generate_timestamp,
            title=settings.title,
        ))

    with open(os.path.join(output_dir, ".nojekyll"), "w") as f:
        pass


def load_package_urls_json(path: str) -> Dict[str, Set[Package]]:
    """Load package URLs from a JSON file."""
    packages: Dict[str, Set[Package]] = collections.defaultdict(set)
    
    with open(path) as f:
        urls = json.load(f)
    
    for url in urls:
        package = parse_git_url(url)
        if package:
            packages[package.name].add(package)
    
    return packages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    
    parser.add_argument(
        '--package-urls-json',
        help='path to a JSON file containing a list of git repository URLs',
        required=True,
    )
    parser.add_argument(
        '--output-dir', 
        help='path to output directory', 
        required=True,
    )
    parser.add_argument(
        '--site-title',
        help='site title for the index', 
        default='Git PyPI Repository',
    )
    parser.add_argument(
        '--no-generate-timestamp',
        action='store_false', 
        dest='generate_timestamp',
        help="Don't include creation timestamp in outputs",
    )
    
    args = parser.parse_args()
    
    settings = Settings(
        output_dir=args.output_dir,
        title=args.site_title,
        generate_timestamp=args.generate_timestamp,
    )
    
    packages = load_package_urls_json(args.package_urls_json)
    build_repo(packages, settings)
    return 0


if __name__ == '__main__':
    sys.exit(main())
