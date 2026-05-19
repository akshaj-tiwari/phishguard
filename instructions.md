# PhishGuard — Complete Setup Guide

> **From zero to a fully running ML-powered phishing detector in your browser.**

This guide covers every step from scratch: getting API keys, installing dependencies, training the model, starting the backend, launching the dashboard, and loading the browser extension.

---

## What You're Setting Up

| Component | What it does |
|---|---|
| **ML model** (`ml/`) | Trains an XGBoost classifier on ~200k URLs. Saved to `backend/models/` |
| **Backend API** (`backend/`) | FastAPI server — exposes `/scan`, `/history`, `/stats`, `/report/{id}` |
| **Dashboard** (`dashboard/`) | React + Vite web app — analytics, scanner, scan history |
| **Extension** (`extension/`) | Chrome extension — scans the active tab and shows a risk popup |

---

## Prerequisites

Install these before doing anything else:

| Tool | Version | Download |
|---|---|---|
| **Python** | 3.10 or 3.11 | https://www.python.org/downloads/ |
| **Node.js** | 18 or higher | https://nodejs.org/ |
| **Git** | any | https://git-scm.com/ |
| **Chrome / Edge / Brave** | any recent | chromium-based browser |

> **Windows users**: run all commands in **PowerShell** or **Git Bash**. The commands below work on Windows, macOS, and Linux.

---

## Step 1 — Get Your API Keys

You need one free API key. A second one is optional.

### 1a. VirusTotal (required for CTI enrichment)

1. Go to **https://www.virustotal.com/gui/join-us** and create a free account.
2. After logging in, click your avatar (top-right) → **API key**.
3. Copy the key — it looks like: `abcd1234ef567890...` (64 hex characters).

> Free tier: **4 requests/minute, 500 requests/day**. Enough for local development.  
> If you skip this key the scanner still works — CTI enrichment is just skipped.

### 1b. PhishTank (optional — only needed to download extra phishing data)

1. Go to **https://phishtank.com/develop/index.php** and register.
2. Copy your API key from the developer page.

---

## Step 2 — Clone the Repository

```bash
git clone https://github.com/your-username/phishguard.git
cd phishguard
```

---

## Step 3 — Configure the Backend `.env` File

The backend reads API keys and database settings from a `.env` file. **This file must never be committed to Git.**

1. Copy the example file:

   **Windows (PowerShell):**
   ```powershell
   Copy-Item .env.example backend\.env
   ```

   **macOS / Linux:**
   ```bash
   cp .env.example backend/.env
   ```

2. Open `backend/.env` in any text editor and fill in your keys:

   ```env
   # backend/.env

   # VirusTotal — paste your key from Step 1a
   VIRUSTOTAL_API_KEY=paste_your_virustotal_key_here

   # PhishTank — paste your key from Step 1b (or leave as-is to skip)
   PHISHTANK_API_KEY=paste_your_phishtank_key_here

   # Database — leave this line commented out for local development.
   # SQLite is used automatically (no setup needed).
   # Uncomment and fill in only if you want PostgreSQL:
   # DATABASE_URL=postgresql://user:password@localhost:5432/phishguard
   ```

3. Save the file.

---

## Step 4 — Set Up the Python Environment

> Do this once. All backend and ML commands share the same virtual environment.

```bash
# From the project root — create a virtual environment
python -m venv .venv

# Activate it
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# Install all Python dependencies
pip install -r backend/requirements.txt
```

You should see `(.venv)` at the start of your terminal prompt — that means the environment is active.

> **Tip**: Every time you open a new terminal to run backend or ML commands, activate the venv again first.

---

## Step 5 — Train the ML Model

> **This step takes 10–20 minutes** depending on your CPU. You only need to do it once.  
> The datasets (ISCX URL 2016 + Tranco top-1M legit domains) are in `ml/data/`.

Make sure your venv is active, then run:

```bash
cd ml
python train.py
```

You'll see output like:
```
Loading ISCX: iscx_url_2016.csv
  ISCX phishing : 96,457
  ISCX benign   : 34,902
Loading Tranco: legit.csv
  Tranco domains: 1,000,000
Final dataset  — 200,000 URLs (100,000 each class)

Extracting features for 200,000 URLs...
Training XGBoost v2 (500 trees, deeper, regularised)...
This will take ~10-15 minutes on 160k URLs. Go get chai.
...
Accuracy : 96.84%   (target >= 95%)  ✓
```

When training finishes, two files are saved to `backend/models/`:
- `phishguard_v3.1.pkl` — the trained XGBoost pipeline
- `feature_names.pkl` — the 40-feature name list

Go back to the project root before continuing:

```bash
cd ..
```

---

## Step 6 — Start the Backend API

The backend is a **FastAPI** server. Keep this terminal open — it must stay running while you use the dashboard or extension.

```bash
# Make sure your venv is active
# From the project root:
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
✓ Database ready (SQLite dev): sqlite:///...phishguard_dev.db...
✓ Model loaded: .../backend/models/phishguard_v3.1.pkl (40 features)
✓ PhishGuard API ready
✓ Docs: http://localhost:8000/docs
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**Verify it works** — open your browser and visit:
- **http://localhost:8000/health** → should return `{"status":"ok","service":"PhishGuard API v1.0"}`
- **http://localhost:8000/docs** → interactive Swagger UI where you can test every endpoint

> Leave this terminal running. Open a **new terminal** for the next steps.

---

## Step 7 — Launch the React Dashboard

Open a **new terminal** (keep the backend terminal from Step 6 running):

```bash
# From the project root:
cd dashboard

# Install JavaScript dependencies (first time only)
npm install

# Start the dev server
npm run dev
```

You'll see:
```
  VITE v8.x.x  ready in 300ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.x.x:5173/
```

Open **http://localhost:5173** in your browser.

### What you should see

- **Sidebar** shows a green "Online" dot next to "Backend API" — this confirms the dashboard has successfully connected to the FastAPI server.
- **Overview tab** shows live stats (will be zeros until you scan some URLs).
- **URL Scanner tab** — paste any URL and click **Scan URL** to run a live ML + CTI analysis.

> If you see a red "Offline" dot, the backend from Step 6 is not running. Go back and check that terminal.

---

## Step 8 — Load the Browser Extension

1. Open Chrome (or Edge/Brave) and go to: **`chrome://extensions/`**

2. Turn on **Developer mode** (toggle in the top-right corner).

3. Click **Load unpacked**.

4. In the file picker, navigate to your `phishguard` folder and select the **`extension`** subfolder. Click **Select Folder**.

5. The **PhishGuard** extension appears in the list. Click the puzzle-piece icon in the browser toolbar and **pin** PhishGuard.

6. Browse to any website. Click the PhishGuard icon in the toolbar.

   - The popup calls `POST /scan` on the FastAPI backend.
   - You'll see a **risk score (0–100%)**, a verdict (Safe / Suspicious / Malicious), and a VirusTotal summary.
   - If the backend is not running, it falls back to a lightweight URL heuristic automatically.

> **High-risk alert**: If the extension detects a phishing page (risk ≥ 70%), Chrome will show a desktop notification.

---

## Running Summary — Three Terminals

Once everything is set up, your normal workflow is:

| Terminal | Command | Stays open? |
|---|---|---|
| Terminal 1 | `cd backend && uvicorn main:app --reload --port 8000` | ✅ Yes |
| Terminal 2 | `cd dashboard && npm run dev` | ✅ Yes |
| Terminal 3 | *(optional)* `cd ml && python train.py` | Only when retraining |

---

## Troubleshooting

### "Model not found" on backend startup
Run `python ml/train.py` first. The backend needs `backend/models/phishguard_v1.pkl`.

### Dashboard shows red "Offline" dot
The backend isn't running. Start it with `uvicorn main:app --reload --port 8000` from the `backend/` directory.

### Extension shows "Backend offline"
Same as above — start the backend. The extension falls back to heuristics automatically.

### `psycopg2` install error on Windows
You don't need PostgreSQL for local dev. SQLite is used by default. If the install fails, remove `psycopg2-binary` from `requirements.txt` temporarily and re-run `pip install -r requirements.txt`.

### VirusTotal returns `no_api_key`
Open `backend/.env` and make sure `VIRUSTOTAL_API_KEY=` has your actual key (no quotes, no spaces).

### Port 8000 or 5173 already in use
Change the port:
```bash
uvicorn main:app --reload --port 8001    # backend
# update dashboard/.env: VITE_API_BASE_URL=http://localhost:8001
npm run dev -- --port 5174               # dashboard
```

---

## Project Structure Reference

```
phishguard/
├── backend/
│   ├── main.py                  ← FastAPI entry point
│   ├── .env                     ← Your API keys (create from .env.example)
│   ├── requirements.txt         ← Python dependencies
│   ├── models/
│   │   ├── phishguard_v1.pkl    ← Trained model (generated by ml/train.py)
│   │   └── feature_names.pkl   ← Feature names (generated by ml/train.py)
│   ├── routers/
│   │   ├── scan.py              ← POST /scan, GET /history, GET /stats
│   │   └── report.py            ← GET /report/{id}
│   ├── services/
│   │   ├── feature_extractor.py ← 40-feature URL parser
│   │   ├── model_service.py     ← Loads model, runs predict()
│   │   ├── cti_service.py       ← VirusTotal + URLhaus
│   │   └── dns_service.py       ← DNS A-record lookup
│   └── db/
│       ├── database.py          ← SQLAlchemy + SQLite/Postgres setup
│       ├── schemas.py           ← Pydantic request/response models
│       └── crud.py              ← DB read/write helpers
│
├── ml/
│   ├── train.py                 ← Training pipeline (run this once)
│   └── data/
│       ├── iscx_url_2016.csv    ← Phishing dataset (ISCX 2016)
│       └── legit.csv            ← Tranco top-1M legitimate domains
│
├── dashboard/
│   ├── .env                     ← VITE_API_BASE_URL=http://localhost:8000
│   └── src/
│       ├── api.js               ← All backend fetch calls (change URL here)
│       └── components/
│           ├── DashboardOverview.jsx   ← Live stats from GET /stats
│           ├── ScanHistory.jsx         ← Live history from GET /history
│           ├── ScannerPanel.jsx        ← Calls POST /scan
│           ├── ThreatReportModal.jsx   ← Calls GET /report/{id}
│           └── SettingsPanel.jsx       ← Connection test + key instructions
│
├── extension/
│   ├── manifest.json            ← Chrome extension manifest v3
│   ├── background.js            ← Pre-scans every tab via POST /scan
│   ├── popup.js                 ← Calls POST /scan, shows result
│   ├── popup.html / popup.css   ← Extension popup UI
│   └── content.js               ← Page-level content script
│
├── .env.example                 ← Template — copy to backend/.env
└── instructions.md              ← This file
```
