"""Build the standalone browser-only artifact used by GitHub Pages.

The generated files need no Python runtime; Python is only used here to prepare
relative project-site asset URLs and mark the client-side demo mode.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "frontend"


def build(output_dir: Path) -> Path:
    output = output_dir.resolve()
    if output == ROOT or output == SOURCE or SOURCE in output.parents:
        # A Pages artifact should never overwrite the repository root or frontend source.
        raise ValueError(f"Refusing to overwrite source directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    source_html = SOURCE / "index.html"
    if not source_html.is_file() or not (SOURCE / "src" / "main.js").is_file():
        raise FileNotFoundError("Frontend entry point is missing")
    html = source_html.read_text(encoding="utf-8")
    html = html.replace('<html lang="en">', '<html lang="en" data-static-demo="true">')
    html = html.replace('href="/src/', 'href="./src/').replace('src="/src/', 'src="./src/')
    (output / "index.html").write_text(html, encoding="utf-8")
    source_assets = SOURCE / "src"
    destination_assets = output / "src"
    if destination_assets.exists():
        shutil.rmtree(destination_assets)
    shutil.copytree(source_assets, destination_assets)
    (output / ".nojekyll").touch()
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Build SentinelFlow's GitHub Pages static demo.")
    parser.add_argument("--output", default=str(ROOT / "_site"), help="Output directory (default: repository _site/)")
    args = parser.parse_args()
    destination = build(Path(args.output))
    print(f"GitHub Pages browser demo built in: {destination}")


if __name__ == "__main__":
    main()
