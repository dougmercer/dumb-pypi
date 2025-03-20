#!/usr/bin/env python3
"""A simple read-only PyPI static index server generator.

Takes a list of direct URLs to wheel files on GitHub releases and generates a "dumb"
PyPI index that can be used with pip.

Usage:
    python simple_pypi_generator.py --url-list urls.txt --output-dir ./pypi-index
"""

import argparse
import os
import re
import sys
import contextlib
import tempfile
import urllib.parse
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, NamedTuple, IO, Generator, Optional

import jinja2
import packaging.utils
import packaging.version

# Wheel filename regex pattern
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


class Package(NamedTuple):
    """Represents a package with its URL and metadata."""
    
    name: str
    version: str
    filename: str
    url: str
    parsed_version: packaging.version.Version

    @property
    def info_string(self) -> str:
        """Returns a string with package version information."""
        return f"{self.version}"
    
    def get_url(self, base_url: str = "", *, include_hash: bool = False) -> str:
        """Returns the URL for the package."""
        return self.url


def get_filename_from_url(url: str) -> str:
    """Extract filename from a URL."""
    parsed_url = urllib.parse.urlparse(url)
    return os.path.basename(parsed_url.path)


def parse_wheel_filename(filename: str) -> tuple[str, str]:
    """Parse a wheel filename to extract package name and version."""
    m = WHEEL_FILENAME_RE.match(filename)
    if m is not None:
        return m.group("nm"), m.group("vn")
    else:
        raise ValueError(f"Invalid wheel filename: {filename}")


@contextlib.contextmanager
def atomic_write(path: str) -> Generator[IO[str], None, None]:
    """Write to a temporary file and atomically replace the target file."""
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


def format_datetime(dt: datetime) -> str:
    """Format a datetime object as a string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def build_package_index(
    url_list: List[str],
    output_dir: str,
    generate_timestamp: bool = True,
) -> None:
    """Build a PyPI index from a list of URLs."""
    # Create the output directories
    simple_dir = os.path.join(output_dir, "simple")
    os.makedirs(simple_dir, exist_ok=True)
    
    # Set up Jinja2 environment
    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader("."),
        autoescape=True,
    )
    
    # Parse the template provided in the question
    package_template = jinja_env.from_string("""<!doctype html>
<html>
    <head>
        <title>{{package_name}}</title>
    </head>
    <body>
        <h1>{{package_name}}</h1>
        <p>
            Latest version:
            <input
                type="text"
                value="{{requirement}}"
                id="requirement"
                style="font-family: monospace; width: {{requirement|length}}ch;"
                readonly="readonly"
            />
        </p>
        {% if generate_timestamp %}
            <p>Generated on {{date}}.</p>
        {% endif %}
        <ul>
            {% for file in files|reverse %}
                <li>
                    <a href="{{file.get_url()}}">{{file.filename}}</a>
                    ({{file.info_string}})
                </li>
            {% endfor %}
        </ul>

        <script>
            document.getElementById('requirement').onfocus = (e) => e.target.select();
        </script>
    </body>
</html>""")
    
    # Create a simple index template
    simple_index_template = jinja_env.from_string("""<!DOCTYPE html>
<html>
    <head>
        <title>Simple Index</title>
    </head>
    <body>
        <h1>Simple Package Index</h1>
        {% if generate_timestamp %}
            <p>Generated on {{date}}.</p>
        {% endif %}
        <ul>
            {% for package_name in package_names %}
                <li><a href="{{package_name}}/">{{package_name}}</a></li>
            {% endfor %}
        </ul>
    </body>
</html>""")
    
    # Process URLs
    packages: Dict[str, Set[Package]] = defaultdict(set)
    
    for url in url_list:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
            
        try:
            # Extract the filename from the URL
            filename = get_filename_from_url(url)
            
            # Only process wheel files
            if not filename.endswith('.whl'):
                continue
                
            # Extract package name and version from the filename
            name, version = parse_wheel_filename(filename)
            
            # Canonicalize package name
            canonical_name = packaging.utils.canonicalize_name(name)
            
            # Create a Package object
            package = Package(
                name=canonical_name,
                version=version,
                filename=filename,
                url=url,
                parsed_version=packaging.version.parse(version),
            )
            
            # Add the package to the collection
            packages[canonical_name].add(package)
            
        except ValueError as e:
            print(f"Error processing {url}: {e}", file=sys.stderr)
    
    # Current datetime for timestamp
    current_date = format_datetime(datetime.utcnow())
    
    # Generate the simple index
    with atomic_write(os.path.join(simple_dir, "index.html")) as f:
        f.write(simple_index_template.render(
            date=current_date,
            generate_timestamp=generate_timestamp,
            package_names=sorted(packages.keys()),
        ))
    
    # Generate package pages
    for package_name, package_files in packages.items():
        # Sort files by version
        sorted_files = sorted(
            package_files,
            key=lambda pkg: (pkg.parsed_version, pkg.filename)
        )
        
        # Create package directory
        package_dir = os.path.join(simple_dir, package_name)
        os.makedirs(package_dir, exist_ok=True)
        
        # Get the latest version for the requirement field
        latest_version = sorted_files[-1].version if sorted_files else ""
        requirement = f"{package_name}=={latest_version}" if latest_version else package_name
        
        # Write the package index
        with atomic_write(os.path.join(package_dir, "index.html")) as f:
            f.write(package_template.render(
                date=current_date,
                generate_timestamp=generate_timestamp,
                package_name=package_name,
                files=sorted_files,
                requirement=requirement,
            ))
    
    # Create .nojekyll file for GitHub Pages
    with open(os.path.join(output_dir, ".nojekyll"), "w") as f:
        pass


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--url-list",
        help="path to a text file with URLs (one per line)",
        required=True,
    )
    
    parser.add_argument(
        "--output-dir",
        help="directory where the index will be generated",
        required=True,
    )
    
    parser.add_argument(
        "--no-generate-timestamp",
        action="store_false",
        dest="generate_timestamp",
        help="Don't include generation timestamp in outputs",
    )
    
    args = parser.parse_args()
    
    # Read URLs from file
    with open(args.url_list) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    # Build the package index
    build_package_index(
        url_list=urls,
        output_dir=args.output_dir,
        generate_timestamp=args.generate_timestamp,
    )
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
