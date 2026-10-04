# NetGuard MVP

A local network visibility application with a plain HTML/CSS/JavaScript dashboard and a Python
FastAPI backend. AI explanations are optional, generated on demand by a local Ollama model; the
scanner's findings and risk scores remain deterministic.

## Run on Windows

Open PowerShell in this folder:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_local.py
```

Open <http://127.0.0.1:8000>. `run_local.py` starts the dashboard, API, and scan worker
together. Press **Ctrl+C** to stop them.

## MVP flow

1. Select target and TCP port presets, enter your own targets/ports, or combine both. The
   private subnet presets are examples; adjust them to your actual authorized subnet.
2. Confirm authorization, review the validated target and port scope, and approve the scan.
3. Watch progress and inspect discovered assets, open TCP services, deterministic findings,
   recommendations, and local scan history.

Only bounded TCP connection checks are used. Public targets are refused unless explicitly
allow-listed in the backend configuration. No credentials, exploit attempts, stealth, or device
changes are performed.

Scan data is stored in `backend/data/netguard.db`. The app serves its HTML, CSS, JavaScript,
and API from loopback. When a user explicitly requests an AI explanation, only that finding's
details are sent to the local Ollama endpoint; no hosted model or agent workflow is used.
Rule-based explanations work without Ollama.

To enable local AI explanations, install and start Ollama separately, make the desired model
available (for example, `ollama pull llama3.2:3b`), and configure `OLLAMA_BASE_URL`,
`OLLAMA_MODEL`, and optionally `OLLAMA_TIMEOUT_SECS` in `backend/.env`. The application only
accepts Ollama endpoints bound to this device and reports a clear error if the local service or
model is unavailable. No Python dependency is added for this feature.

## Useful endpoints

- `GET /health` — local service status
- `POST /scans/plan` — normalize a `ScanCreate` request or explicit plain-text scope
- `POST /scans/preview` — validate scope without creating a scan
- `POST /scans` — queue a scan after the user's approval
- `GET /scans` and `GET /scans/{id}/progress` — scan history and progress
- `GET /scans/{id}/pipeline` — evidence changes, ranked findings, and raw-evidence verification
- `POST /findings/{id}/explanation` — generate an on-demand explanation via local Ollama
- `GET /assets`, `GET /findings`, `GET /stats/overview` — dashboard data

Completed scans persist per-host TCP observations locally. The deterministic pipeline compares
them with previous scans, ranks findings by severity and asset risk, and verifies finding claims
against observed open ports.

The Python tests are in `backend/tests`. From `backend/`, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -c pytest.ini tests
```
