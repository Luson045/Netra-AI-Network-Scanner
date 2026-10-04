# NetGuard MVP

A local network visibility MVP with a plain HTML/CSS/JavaScript dashboard and a Python
FastAPI backend. It includes no AI calls or agent workflow.

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

1. Enter an authorized private/loopback IP or CIDR and a short port list.
2. Confirm authorization, review the validated target and port scope, and approve the scan.
3. Watch progress and inspect discovered assets, open TCP services, deterministic findings,
   recommendations, and local scan history.

Only bounded TCP connection checks are used. Public targets are refused unless explicitly
allow-listed in the backend configuration. No credentials, exploit attempts, stealth, or device
changes are performed.

Scan data is stored in `backend/data/netguard.db`. The app serves its HTML, CSS, JavaScript,
and API from loopback; it does not send scan data to a hosted service. The MVP does not use
hosted AI, local AI, or multi-agent analysis.

## Useful endpoints

- `GET /health` — local service status
- `POST /scans/preview` — validate scope without creating a scan
- `POST /scans` — queue a scan after the user's approval
- `GET /scans` and `GET /scans/{id}/progress` — scan history and progress
- `GET /assets`, `GET /findings`, `GET /stats/overview` — dashboard data

The Python tests are in `backend/tests`. From `backend/`, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -c pytest.ini tests
```
