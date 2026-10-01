#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploy AegisFlow SOC Dashboard to GitHub Pages.

.DESCRIPTION
    Builds the Next.js frontend with GitHub Pages settings and pushes
    the static export directly to the gh-pages branch.
    No special token scope required — works with the standard gh auth token.

.EXAMPLE
    .\scripts\deploy-gh-pages.ps1

.NOTES
    Run this from the project root after making frontend changes.
    The site will be live at:
    https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Config ────────────────────────────────────────────────────────────────────
$ROOT     = Split-Path $PSScriptRoot -Parent
$FRONTEND = Join-Path $ROOT "frontend"
$OUT_DIR  = Join-Path $FRONTEND "out"
$REMOTE   = "https://github.com/rohitsingh83/Network-Intrusion-Detection-System-Simulation.git"
$BRANCH   = "gh-pages"
$LIVE_URL = "https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   AegisFlow IDS — GitHub Pages Deployment Script    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Build ─────────────────────────────────────────────────────────────
Write-Host "▶ Step 1/3: Building Next.js static export..." -ForegroundColor Yellow
Set-Location $FRONTEND

$env:GITHUB_PAGES          = "true"
$env:NEXT_PUBLIC_STANDALONE = "true"
$env:NEXT_TELEMETRY_DISABLED = "1"

npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Build failed. Fix errors above and retry." -ForegroundColor Red
    exit 1
}

Write-Host "✓ Build successful → $OUT_DIR" -ForegroundColor Green

# ── Step 2: Add .nojekyll ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Step 2/3: Preparing deploy artifacts..." -ForegroundColor Yellow
New-Item -ItemType File -Path (Join-Path $OUT_DIR ".nojekyll") -Force | Out-Null
Write-Host "✓ .nojekyll added (ensures _next/ assets are served)" -ForegroundColor Green

# ── Step 3: Push to gh-pages ──────────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Step 3/3: Deploying to $BRANCH branch..." -ForegroundColor Yellow

$TMP = Join-Path $env:TEMP "aegisflow-deploy-$(Get-Random)"
New-Item -ItemType Directory -Path $TMP | Out-Null

try {
    Copy-Item "$OUT_DIR\*" $TMP -Recurse -Force

    Push-Location $TMP
    git init -b $BRANCH | Out-Null
    git add -A | Out-Null

    $commitMsg = "Deploy AegisFlow SOC Dashboard`n`nBuilt: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')`nCommit: $(git -C $ROOT rev-parse --short HEAD 2>$null)"
    git commit -m $commitMsg | Out-Null
    git remote add origin $REMOTE | Out-Null
    git push --force origin $BRANCH 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "✗ Push failed. Check your internet connection and git credentials." -ForegroundColor Red
        exit 1
    }
    Pop-Location
} finally {
    Remove-Item $TMP -Recurse -Force -ErrorAction SilentlyContinue
    Set-Location $ROOT
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              ✓ DEPLOYMENT COMPLETE!                  ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  Live URL:                                           ║" -ForegroundColor Green
Write-Host "║  $LIVE_URL  ║" -ForegroundColor Green
Write-Host "║                                                      ║" -ForegroundColor Green
Write-Host "║  Note: GitHub Pages may take 1-2 min to update.     ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
