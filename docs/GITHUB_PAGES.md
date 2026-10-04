# Publish the working website on `github.io`

This repository is configured to publish a **static, browser-only SentinelFlow demo** with GitHub Pages. The Pages version reuses the SOC interface and runs its own synthetic-flow engine in JavaScript. It does not need FastAPI, Python, SQLite, Render, or a third-party API to load and use the website.

## What works on GitHub Pages

- Dashboard, recent detections, time charts, severity/protocol breakdowns, flow explorer, and filters
- Eight synthetic scenario buttons plus normal and mixed replay
- The six adjustable signature thresholds, static-demo statistical scoring, risk/severity, and alert grouping
- Alert investigation detail, recommended review steps, incident status changes, and analyst notes
- Saved demo state per browser using localStorage, plus **Reset demo data** in the Replay lab

All behavior is represented as flow metadata in JavaScript. No packet is generated, no network target is contacted, and the browser demo makes no API calls. Every displayed address is from the RFC 5737 documentation ranges.

## Important static-hosting difference

GitHub Pages serves HTML/CSS/JavaScript files; it does not run this project's Python FastAPI server or SQLite database. The GitHub Pages site therefore stores flows, alerts, notes, and rule changes **only in that visitor's browser profile**. Visitors do not share state, and clearing browser site data clears that demo's changes. ML is disabled in the browser-only version; the optional ML model and measured evaluation remain available in the full Python project. The browser demo uses an explicit educational fallback baseline and labels this limitation in the UI. The full FastAPI/SQLite workflow remains runnable locally; `render.yaml` remains an optional backend-hosting setup if you later want a shared API.

## Publish it

### 1. Push this repository to GitHub

Create a repository named `Network-Intrusion-Detection-System-Simulation` under your own account, then push this project. If this folder is not yet a Git repository, run these commands from the project root, replacing `YOUR-USERNAME`:

```bash
git init -b main
git add .
git status --short
git commit -m "Build SentinelFlow GitHub Pages demo"
git remote add origin https://github.com/YOUR-USERNAME/Network-Intrusion-Detection-System-Simulation.git
git push -u origin main
```

If you already have a Git repository or remote, do not repeat `git init`/`git remote add`; commit and push the new files to the `main` branch instead. Confirm `.env`, database files, and `.joblib` model artifacts are not staged; `.gitignore` excludes these by default. See [`GITHUB_STRATEGY.md`](GITHUB_STRATEGY.md) for the full review/publish checklist.

### 2. Enable the GitHub Actions Pages source

In the GitHub repository, open **Settings → Pages → Build and deployment → Source** and select **GitHub Actions**. GitHub documents this publishing source and workflow pattern [here](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

This repository includes `.github/workflows/deploy-pages.yml`. It copies the frontend, changes root-relative asset paths to project-site-safe relative paths, marks the browser-only mode, uploads the site, and deploys it. The workflow runs on pushes to `main` or from **Actions → Deploy SentinelFlow to GitHub Pages → Run workflow**. If your default branch is not `main`, edit the workflow's branch name before pushing.

### 3. Open your site

For a project repository, the URL format is:

```text
https://YOUR-USERNAME.github.io/Network-Intrusion-Detection-System-Simulation/
```

Replace `YOUR-USERNAME` with the account that owns the repository. GitHub Pages describes project sites as living under `https://<owner>.github.io/<repositoryname>` [here](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages). Wait for the workflow to finish successfully, then open the URL. Initial publication can take a few minutes.

A personal root site such as `https://YOUR-USERNAME.github.io/` is a different GitHub Pages site and requires a repository named exactly `YOUR-USERNAME.github.io`; use the project URL above for this project repository.

## Test the Pages mode before pushing

With the regular app running, open `http://127.0.0.1:8000/?static-demo=1`. The query flag forces the same browser-only adapter used by GitHub Pages. Or serve `frontend/` as static files and open `/?static-demo=1`. Browser storage is origin-specific, so this local test's data is separate from the deployed site.

## If you need shared server-side state

GitHub Pages alone cannot host FastAPI/SQLite. Keep this browser-local portfolio website, and separately deploy the Python API (the repository includes an optional Render guide). Making the Pages UI use a remote API would require a configured backend URL, cross-origin policy, and write-key handling; do not put a private server secret in public frontend JavaScript. For a class portfolio site, the current isolated browser demo avoids those risks and works without a second service.
