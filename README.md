# Netra AI

A local network visibility application with a plain HTML/CSS/JavaScript dashboard and a Python
FastAPI backend. Quick Scan runs deterministic checks with built-in common TCP ports. Deep Scan
uses local Ollama agents to propose ports for the exact authorized target scope, then explain
scan history and prioritize measured findings. All scans use safe TCP connection checks.

## Run on Windows

Open PowerShell in this folder:

```powershell
cd backend
python -m venv .venv #only for the first time when you don't have an existing venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_local.py
```

Open <http://127.0.0.1:8000>. `run_local.py` starts the dashboard, API, and scan worker
together. Press **Ctrl+C** to stop them. Restart this process after updating the backend; an old
running process will not have the Deep Scan endpoints.

## Build the Windows desktop download

On Windows, run `build_windows.bat` from the project root. It creates
`NetraAI-Windows.zip` in the root directory. Publish that ZIP alongside the root website files
so its **Download for Windows** links work. The download contains `Setup.bat` and the packaged
application; users should extract the ZIP, run `Setup.bat`, then start Netra AI from the desktop
shortcut. The setup installs to the current user's Local AppData and does not require admin
rights or a separate Python installation.

The desktop build opens the dashboard at <http://127.0.0.1:8000>. Scan history is stored in
`%LOCALAPPDATA%\Netra AI\data`. Deep Scan AI features still require Ollama installed and running
locally, as described below.

## Scan workflow

1. Choose authorized target presets or enter the addresses to assess. Private subnet presets
   are examples; adjust them to your actual authorized subnet.
2. Confirm authorization and choose **Quick Scan** or **Deep Scan**. Quick Scan queues
   immediately with the built-in common ports, or accepts optional custom port numbers/ranges.
   Deep Scan ignores custom ports and asks the local planning agent for a focused port list.
   The planner considers the scanner device's OS and listening TCP services, plus known
   sensitive-service ports, shows its rationale and detected device context, and waits for
   your approval before queuing. If no findings are produced, Deep Scan skips AI analysis and
   reports “Everything is OK!”.
3. Follow progress. Deep Scan runs an analysis agent after discovery to summarize scan history,
   explain the priority of measured findings, and suggest evidence-based next steps. Scan history
   also lets you request a local AI explanation for each finding.

Only bounded TCP connection checks are used. Public targets are refused unless explicitly
allow-listed in the backend configuration. No credentials, exploit attempts, stealth, or device
changes are performed.

Scan data and Deep Scan agent results are stored in `backend/data/netguard.db`. The app serves
its HTML, CSS, JavaScript, and API from loopback. Deep Scan sends only the authorized target
scope and measured results to Ollama on this device; it never sends data to a hosted model.
Agent-selected ports are restricted to a built-in candidate list and are revalidated before the
scan is queued. The independent deterministic findings and raw-evidence checks remain available
alongside AI analysis.

Deep Scan and AI explanations require Ollama running on this device. Install Ollama, download a
model (for example, `ollama pull llama3.2:3b`), and configure `OLLAMA_BASE_URL`, `OLLAMA_MODEL`,
and optionally `OLLAMA_TIMEOUT_SECS` in `backend/.env`. Only loopback Ollama endpoints are
accepted. If the local model is unavailable or returns an invalid plan, the app reports an error
instead of silently substituting a port list.

## Useful endpoints

- `GET /health` — local service status
- `POST /scans/deep/plan` — generate a local-agent port proposal for user review
- `POST /scans/deep` — queue a revalidated, user-approved Deep Scan
- `POST /scans/{id}/deep-analysis` — generate or retrieve persisted agent analysis
- `POST /scans/plan` — normalize a `ScanCreate` request or explicit plain-text scope
- `POST /scans/preview` — validate scope without creating a scan
- `POST /scans` — queue a deterministic Quick Scan
- `DELETE /scans/{id}` and `DELETE /scans` — delete one scan or all completed history
- `GET /scans` and `GET /scans/{id}/progress` — scan history and progress
- `GET /scans/{id}/pipeline` — evidence changes, ranked findings, and raw-evidence verification
- `POST /findings/{id}/explanation` — generate an on-demand explanation via local Ollama
- `GET /assets`, `GET /findings`, `GET /stats/overview` — dashboard data

Completed scans persist per-host TCP observations locally. The deterministic pipeline compares
them with previous scans, ranks findings by severity and asset risk, and verifies finding claims
against observed open ports. Deep Scan agent summaries and port plans are saved with their scan
history. Deleting history removes its findings and rebuilds the visible asset/service inventory
from observations that remain when deleting a single scan. Deleting all history also clears all
current findings, assets, and services; active scans are retained, but their prior inventory is
cleared.

The Python tests are in `backend/tests`. From `backend/`, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -c pytest.ini tests
```
