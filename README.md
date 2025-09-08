# Red Team Recon Automation Toolkit

A lightweight OSINT and recon toolkit with a Flask backend and a modern, static frontend. It performs subdomain discovery, DNS/port scanning, tech fingerprinting, and optional enrichment via SpiderFoot. Exports include JSON/CSV/HTML and a server-side PDF powered by ReportLab.

## Features
- Subdomain discovery (crt.sh, light brute-force, Sublist3r)
- DNS resolution and port scanning (socket-based; nmap optional if available)
- Tech stack detection (BuiltWith or headers-based)
- OSINT: theHarvester, GitHub search, paste sites (when enabled)
- Optional SpiderFoot enhancement after initial results
- PDF export generated server-side: `POST /api/export/pdf`

## Project structure
```
.
├─ backend/
│  ├─ app.py               # Flask API server (entrypoint)
│  ├─ pdf_export.py        # ReportLab PDF generator
│  ├─ spiderfoot/          # Bundled SpiderFoot (used for enhancement)
│  ├─ theHarvester/        # Used via subprocess where available
│  ├─ outputs/             # Scan outputs (gitignored)
│  └─ .env                 # Secrets (gitignored) — use .env.example
├─ frontend/
│  ├─ index.html           # Modern UI
│  ├─ script.js            # Frontend app logic
│  └─ style.css            # Styling
├─ requirements.txt
└─ README.md
```

## Prerequisites
- Python 3.10+
- Git
- (Optional) nmap, dnstwist, theHarvester installed in PATH for richer results

## Setup (Windows PowerShell)
```powershell
python -m venv venv
venv\Scripts\Activate
pip install -r requirements.txt
# Create backend/.env from template and fill secrets
copy backend\.env.example backend\.env
```

## Environment variables (backend/.env)
- `RECON_ALLOWED_KEY`: optional simple key (currently not enforced in code)
- `SHODAN_API_KEY`: for IP enrichment via Shodan
- `GITHUB_TOKEN`: to increase GitHub Search API limits
- `CENSYS_ID`, `CENSYS_SECRET`: for Censys module
- `PORT`: Flask server port (default: 5000)

See `backend/.env.example` for a template.

## Run
- Backend (Flask):
  ```powershell
  python backend\app.py
  ```
  The server starts at `http://localhost:5000` (see `PORT`).

- Frontend:
  - Open `frontend/index.html` directly in your browser, or
  - Serve statically (optional):
    ```powershell
    # From the frontend directory
    python -m http.server 8080
    # Then browse http://localhost:8080
    ```

## Key API Endpoints
- `GET /api/health` — dependency and config status
- `POST /api/recon` — start a scan
  - Body JSON: `{ "target": "example.com", "reconType": "quick|normal|deep", "services": { ... } }`
  - Response: `{ "success": true, "data": { "job_id": "..." } }`
- `GET /api/status/<job_id>` — job status and results when finished
- `POST /api/stop/<job_id>` — request scan stop and return partial results later
- `POST /api/enhance/<job_id>` — run selective SpiderFoot modules using existing results
- `POST /api/export/pdf` — generate a PDF from results (uses `backend/pdf_export.py`)

## Security & ethics
- Only run against assets you own or are authorized to test.
- Keep secrets out of git. `.gitignore` excludes `.env` and `backend/outputs/`.
- Consider rotating any keys that were ever shared or displayed.

## Git: initialize and first commit
1) Initialize the repo and create the initial commit (from project root):
```powershell
git init
git add -A
git commit -m "chore: initial commit (gitignore, env template, README)"
```

2) Create a remote (replace with your repo URL) and push:
```powershell
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

## Notes
- SpiderFoot runs separately as an enhancement step after the main scan (see the UI button "Enhance with SpiderFoot").
- Some modules use subprocess fallbacks (e.g., `whois`, `dig`, `dnstwist`, `theHarvester`, `nmap`) if available in your PATH.
- PDF export is server-side using ReportLab to avoid browser limitations.
