# 🛡️ PhishGuard
**An ML-Powered Phishing URL Detection System with Cyber Threat Intelligence Integration**

**Developed by:** Akshaj Tiwari and Shafqat Jabbar

---

## 📖 Overview
Phishing attacks frequently bypass traditional static blacklists by utilizing newly registered domains. PhishGuard addresses this vulnerability by combining statistical Machine Learning classification with active Cyber Threat Intelligence. 

Designed to mirror real-world Security Operations Center (SOC) workflows, the system operates as a real-time Chrome browser extension. It analyzes visited URLs on the fly, decoding obfuscation, querying live threat feeds (like VirusTotal and URLhaus), performing passive DNS/WHOIS forensics, analyzing typosquatting and implementing other methods to identify the malicious URL. Results are synthesized into structured threat reports accessible via an analyst dashboard.

---

## 🎯 Goals
- **ML Pipeline:** Build & deploy an ML pipeline (≥95% accuracy on a balanced dataset, sub-500ms response time for browser integration).
- **Active Threat Intelligence:** Implement active threat intelligence including URL obfuscation decoding, live DNS/WHOIS lookups, and typosquatting detection.
- **End-to-End System:** Deliver a functional Chrome extension for real-time protection, coupled with a React-based web dashboard for security analysts (featuring scan history and exportable threat reports).

---

## 📦 Deliverables
1. **Serialized ML Model:** Trained classification model with documented evaluation metrics.
2. **REST API Backend:** Deployed FastAPI application orchestrating URL feature extraction, model inference, and live CTI (Cyber Threat Intelligence) lookups.
3. **Analyst Dashboard:** Web UI displaying scan history, risk distribution visuals, and downloadable structured IoC (Indicator of Compromise) reports.
4. **Project Report:** A brief report stating the architecture and the methods implemented.

---

## 🗄️ Dataset Resources
To train and evaluate our models, we utilize the following datasets and APIs:
- **PhishTank:** Verified, daily-updated phishing URLs.
- **URLhaus (API):** Live malicious URL database.
- **Tranco Top 1M:** Research-grade popular legitimate domains.
- **ISCX URL 2016:** Kaggle benchmark dataset.

---

## 🛠️ Tech Stack
**Machine Learning:**
- Python, scikit-learn, XGBoost, Pandas

**Backend API:**
- Python, FastAPI

**Threat Intelligence:**
- VirusTotal API, URLhaus API

**Forensics / Core:**
- `python-whois`, `dnspython`, `urllib`

**Frontend UI:**
- React, Tailwind CSS, Recharts

**Client Extension:**
- JavaScript, HTML/CSS
