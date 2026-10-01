#!/bin/bash
# deploy-gh-pages.sh — Linux/macOS version of the deploy script
# Usage: bash scripts/deploy-gh-pages.sh

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND="$ROOT/frontend"
OUT_DIR="$FRONTEND/out"
REMOTE="https://github.com/rohitsingh83/Network-Intrusion-Detection-System-Simulation.git"
BRANCH="gh-pages"
LIVE_URL="https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   AegisFlow IDS — GitHub Pages Deployment Script    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Step 1: Build
echo "▶ Step 1/3: Building Next.js static export..."
cd "$FRONTEND"
GITHUB_PAGES=true NEXT_PUBLIC_STANDALONE=true NEXT_TELEMETRY_DISABLED=1 npm run build
echo "✓ Build successful"

# Step 2: .nojekyll
echo ""
echo "▶ Step 2/3: Preparing deploy artifacts..."
touch "$OUT_DIR/.nojekyll"
echo "✓ .nojekyll added"

# Step 3: Push to gh-pages
echo ""
echo "▶ Step 3/3: Deploying to $BRANCH branch..."
TMP=$(mktemp -d)
cp -r "$OUT_DIR/." "$TMP/"
cd "$TMP"
git init -b "$BRANCH"
git add -A
COMMIT_HASH=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
git commit -m "Deploy AegisFlow SOC Dashboard

Built: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Commit: $COMMIT_HASH"
git remote add origin "$REMOTE"
git push --force origin "$BRANCH"
cd "$ROOT"
rm -rf "$TMP"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              ✓ DEPLOYMENT COMPLETE!                  ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Live URL:                                           ║"
echo "║  $LIVE_URL  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
