"""
setup_hooks.py — Install git hooks for AegisFlow IDS
Run once after cloning: python setup_hooks.py

Installs:
  .git/hooks/pre-push → auto-deploys to GitHub Pages on push
"""

import os
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).parent
HOOKS_SRC = ROOT / "scripts" / "hooks"
HOOKS_DST = ROOT / ".git" / "hooks"

HOOK_CONTENT = r"""#!/bin/sh
# Auto-deploy to GitHub Pages on push
REMOTE="$1"
URL="$2"

if ! echo "$URL" | grep -q "github.com"; then exit 0; fi

CHANGED=$(git diff --name-only HEAD~1 HEAD 2>/dev/null | grep "^frontend/" | head -1)
if [ -z "$CHANGED" ]; then
  echo "[gh-pages] No frontend changes, skipping deploy."
  exit 0
fi

echo "[gh-pages] Deploying to GitHub Pages..."
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if command -v pwsh >/dev/null 2>&1; then
  pwsh -File "$ROOT_DIR/scripts/deploy-gh-pages.ps1"
else
  bash "$ROOT_DIR/scripts/deploy-gh-pages.sh"
fi
exit 0
"""


def install_hooks():
    if not HOOKS_DST.exists():
        print("Error: .git/hooks directory not found. Run from project root.")
        sys.exit(1)

    hook_path = HOOKS_DST / "pre-push"
    hook_path.write_text(HOOK_CONTENT)

    # Make executable on Unix
    current = stat.S_IMODE(hook_path.stat().st_mode)
    hook_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"✓ Installed pre-push hook → {hook_path}")
    print()
    print("Now every 'git push' with frontend changes will auto-deploy to:")
    print("  https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/")
    print()
    print("To skip the hook for a specific push: git push --no-verify")


if __name__ == "__main__":
    install_hooks()
