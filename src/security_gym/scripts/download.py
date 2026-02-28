"""Download security-gym datasets from GitHub Releases."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

GITHUB_REPO = "j-klawson/security-gym"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases"
DEFAULT_DATA_DIR = Path("data")


def _get_releases() -> list[dict]:
    """Fetch release metadata from GitHub API."""
    req = urllib.request.Request(GITHUB_API, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _download_file(url: str, dest: Path, name: str) -> None:
    """Download a file with progress reporting."""
    req = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        block_size = 1024 * 1024  # 1MB

        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(block_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    print(f"\r  {name}: {mb:.1f}/{total_mb:.1f} MB ({pct}%)", end="", flush=True)
                else:
                    mb = downloaded / (1024 * 1024)
                    print(f"\r  {name}: {mb:.1f} MB", end="", flush=True)
        print()


def list_datasets() -> None:
    """List available datasets from GitHub Releases."""
    try:
        releases = _get_releases()
    except urllib.error.URLError as e:
        print(f"Error fetching releases: {e}", file=sys.stderr)
        sys.exit(1)

    if not releases:
        print("No releases found.")
        return

    for release in releases:
        tag = release["tag_name"]
        name = release["name"] or tag
        assets = release.get("assets", [])
        db_assets = [a for a in assets if a["name"].endswith(".db")]
        if db_assets:
            print(f"\n{name} ({tag})")
            for asset in db_assets:
                size_mb = asset["size"] / (1024 * 1024)
                print(f"  {asset['name']}  ({size_mb:.1f} MB)")


def download(tag: str | None = None, data_dir: Path = DEFAULT_DATA_DIR) -> None:
    """Download dataset files from a GitHub Release."""
    try:
        releases = _get_releases()
    except urllib.error.URLError as e:
        print(f"Error fetching releases: {e}", file=sys.stderr)
        sys.exit(1)

    if not releases:
        print("No releases found.", file=sys.stderr)
        sys.exit(1)

    # Find the target release
    if tag:
        release = next((r for r in releases if r["tag_name"] == tag), None)
        if not release:
            available = ", ".join(r["tag_name"] for r in releases)
            print(f"Release '{tag}' not found. Available: {available}", file=sys.stderr)
            sys.exit(1)
    else:
        # Find the latest release that contains .db assets (skip code-only releases)
        release = next(
            (r for r in releases if any(a["name"].endswith(".db") for a in r.get("assets", []))),
            None,
        )
        if not release:
            print("No releases with dataset files found.", file=sys.stderr)
            sys.exit(1)

    tag = release["tag_name"]
    assets = release.get("assets", [])
    db_assets = [a for a in assets if a["name"].endswith(".db")]

    print(f"Downloading from release: {release['name'] or tag}")

    for asset in db_assets:
        dest = data_dir / asset["name"]
        if dest.exists():
            size_mb = dest.stat().st_size / (1024 * 1024)
            print(f"  {asset['name']}: already exists ({size_mb:.1f} MB), skipping")
            continue

        _download_file(asset["browser_download_url"], dest, asset["name"])

    print(f"\nDatasets saved to {data_dir}/")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="security-gym-download",
        description="Download security-gym datasets from GitHub Releases.",
    )
    sub = parser.add_subparsers(dest="command")

    # list
    sub.add_parser("list", help="List available datasets")

    # download
    dl = sub.add_parser("download", help="Download dataset files")
    dl.add_argument("--tag", help="Release tag (default: latest)")
    dl.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="Output directory")

    args = parser.parse_args()

    if args.command == "list":
        list_datasets()
    elif args.command == "download":
        download(tag=args.tag, data_dir=args.data_dir)
    else:
        # Default to download
        download()


if __name__ == "__main__":
    main()
