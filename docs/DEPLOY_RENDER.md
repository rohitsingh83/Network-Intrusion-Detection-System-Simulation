# Deploy SentinelFlow to Render

This guide publishes the **synthetic-only SentinelFlow demo** as a public portfolio site. Render needs a Git repository connected to your account; the repository already includes `render.yaml`, which defines the Python web service, builds the optional Random Forest from the included synthetic CSV, configures the platform port and health check, enables demo seeding, and asks Render to generate a secret API key for write endpoints.

> **This is a learning/portfolio deployment, not a production IDS.** Keep the dataset synthetic. Do not ingest real organization telemetry, secrets, credentials, or private network details. Render's free web service uses ephemeral storage; demo flows, notes, and incident status can reset after a spin-down/redeploy. Free services also spin down when idle and may take about a minute to wake. Review Render's current [free-instance limitations](https://render.com/docs/free) before publishing.

## 1. Push the project to GitHub

If you have not published it yet, create a **new empty repository** on GitHub named `Network-Intrusion-Detection-System-Simulation`. Do not add a GitHub README/license there because this folder already has both. From this project folder, in a terminal:

```bash
git init -b main
git add .
git status --short
git commit -m "Build SentinelFlow synthetic IDS lab"
git remote add origin https://github.com/YOUR-USERNAME/Network-Intrusion-Detection-System-Simulation.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Review `git status` before pushing. The `.gitignore` excludes local databases, environment files, and the trained `.joblib` model. Full beginner-safe Git guidance is in [`GITHUB_STRATEGY.md`](GITHUB_STRATEGY.md).

## 2. Create the Render service from the Blueprint

1. Sign in to [Render](https://dashboard.render.com/) and connect your GitHub account.
2. Choose **New → Blueprint** (or the current Blueprint creation option), select the repository you just pushed, and let Render read the root `render.yaml`.
3. Review the service settings. The Blueprint selects the Free web plan, installs `requirements.txt`, trains Random Forest on the included synthetic CSV during build, starts `python run.py`, and checks `/health`.
4. Apply/create the Blueprint and wait for the build and deploy to finish. Render will show the assigned `onrender.com` URL in the service dashboard. Open `/` for the console or `/api/docs` for the API docs.
5. Verify the health endpoint: `https://YOUR-SERVICE.onrender.com/health`. It should report `status: ok` and `mode: synthetic-data-only`.

`run.py` binds to loopback by default during local development. The Blueprint sets `IDS_HOST=0.0.0.0`; `run.py` honors Render's `PORT` unless `IDS_PORT` is explicitly set.

## 3. Enable dashboard write actions

The Blueprint uses Render's `generateValue: true` for `IDS_API_KEY`, so the key is created in Render rather than committed to the repository. To enable safe replay, status changes, rule updates, and notes on the deployed dashboard:

1. In Render, open the service's **Environment** page and copy the generated `IDS_API_KEY` value.
2. Open your live SentinelFlow website and select **API key** in the top bar.
3. Paste the key into the prompt. The browser stores it locally for this site and sends it as `X-API-Key` to protected write APIs. Do this only on a device/browser profile you control; do not include the key in screenshots, source files, or chat.

GET endpoints remain public and return only the educational synthetic demo records. All writes require the generated key in this Blueprint.

## 4. Persistence choices

The included Blueprint intentionally uses the Free plan and SQLite's default local file. Render documents that Free web services do not support persistent disks, spin down after 15 minutes idle, and lose local-filesystem changes on spin-down. Thus investigation notes/status and replayed records are demo-only and may reset; the seeded synthetic baseline is recreated on a fresh database.

If you need the SQLite demo database to survive redeploys, Render's current persistent-disk support requires a compatible paid web service. Attach a disk mounted at `/opt/render/project/src/runtime-data` and add this service environment variable in Render:

```text
IDS_DB_PATH=/opt/render/project/src/runtime-data/ids.db
```

The project creates the parent directory automatically. Keep the mount separate from the tracked `data/` folder so the included synthetic CSV remains available. See Render's [persistent-disk documentation](https://render.com/docs/disks) for current costs and limitations. This single-file SQLite design is intended for one small demo instance, not horizontal scaling.

## What this setup does not do

- It does not deploy or enable packet capture, port scans, attack traffic, or automated blocking.
- It does not make the service production-ready. There is no user identity system, RBAC, enterprise audit pipeline, or production data-retention policy.
- It does not publish the repository on your behalf. You must connect your own GitHub/Render accounts in their dashboards; never send account passwords or API keys in chat.
