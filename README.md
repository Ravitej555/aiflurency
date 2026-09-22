# 🛡️ ThreatLens AI — Autonomous Cyber Threat Intelligence & Forensic Operations Center

[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-ThreatLens_AI-00e5ff?style=for-the-badge&logo=google-chrome&logoColor=black)](https://ravitej555.github.io/threadlens-AI/landing.html)
[![SOC Console](https://img.shields.io/badge/🛰️_SOC_Console-Live_Preview-a855f7?style=for-the-badge&logo=target&logoColor=white)](https://ravitej555.github.io/threadlens-AI/index.html)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)

> 🚀 **Live Interactive Demo:**
> * 🌐 **Landing Page & Architecture:** [https://ravitej555.github.io/threadlens-AI/landing.html](https://ravitej555.github.io/threadlens-AI/landing.html)
> * 🛰️ **SOC Security Console:** [https://ravitej555.github.io/threadlens-AI/index.html](https://ravitej555.github.io/threadlens-AI/index.html)
> * 🚩 **FlyRank Checkpoint Report (Domain + Badge):** [Plant Your Flag: Domain + Badge Report](PLANT_YOUR_FLAG_REPORT.md)
> * 📋 **Previous Checkpoint Report (Hardening):** [Break Your Own Site Report](BREAK_YOUR_OWN_SITE_REPORT.md)
> * 🎓 **FlyRank Credential Verification:** [Verify Ravitej Manu (FR-GAIF-2026-RM)](https://internship.flyrank.ai/verify?id=FR-GAIF-2026-RM&first_name=Ravitej)

**ThreatLens AI** is an autonomous cybersecurity SOC (Security Operations Center) copilot and malware forensic analysis platform. Designed for incident responders, SOC analysts, and threat hunters, ThreatLens AI combines machine learning heuristics, byte-level Shannon Entropy calculations, and real-time generative AI intelligence to rapidly detect, classify, and mitigate cyber threats.

---

## 🎯 FlyRank AI Fluency: "Plant Your Flag" & "Break Your Own Site" Checkpoints
This repository contains the verified, production-ready deliverables for FlyRank AI Fluency:
- **Plant Your Flag: Domain + Badge (Week 7 / Week 9):** Custom domain routing, privacy-friendly visitor telemetry (`analytics.js`), launch hygiene (SVG favicon, 1200x630 `og-preview.png`), and official FlyRank Graduate Credential Badge installed in the footer. Documented in [PLANT_YOUR_FLAG_REPORT.md](PLANT_YOUR_FLAG_REPORT.md).
- **Break Your Own Site Audit:** Full edge-case matrix, fixed vs. known-limitations list, and triage documented in [BREAK_YOUR_OWN_SITE_REPORT.md](BREAK_YOUR_OWN_SITE_REPORT.md).

---

## 🌟 Key Capabilities

- **🛰️ Live Threat Intelligence Feed & Tactical Radar:**
  - Real-time telemetry monitoring attack classifications, source IPs, and target hosts.
  - Interactive 360° and thermal radar tracking active anomalous network activity.
  - Severity level filtering: *CRITICAL*, *HIGH*, *MEDIUM*, *LOW*, and *BENIGN*.

- **🔬 AI Payload & Binary Forensic Scanner:**
  - Analyzes files (`.exe`, `.dll`, `.pdf`, `.ps1`, `.zip`, `.js`) and suspicious URLs.
  - Calculates **Shannon Entropy (0–8)** to identify packed, obfuscated, or encrypted payloads.
  - Multi-feature weighted scoring (suspicious strings, PE header anomalies, byte distributions).
  - Decision tree heuristic classification with automated confidence scoring.

- **🤖 ThreatLens AI Copilot (Powered by Google Gemini):**
  - Streaming conversational interface for interactive threat analysis.
  - Generates comprehensive **SOC Incident Reports** (PDF export ready).
  - Translates IOCs and attack patterns into **MITRE ATT&CK** matrix mappings.
  - Provides actionable incident containment and mitigation playbooks (host isolation, firewall rules, PowerShell scripts).

- **📊 Trend Analysis & SOC Telemetry:**
  - Chart.js telemetry tracking attack vectors and severity distribution trends.
  - System health, memory, and threat throughput metrics.

---

## 🏗️ System Architecture

```text
               ┌────────────────────────────────────────────────────────┐
               │                     Analyst / Browser                  │
               └───────────┬────────────────────────────────┬───────────┘
                           │                                │
            (Port 8080)    ▼                                ▼    (Port 3000)
    ┌───────────────────────────────────┐        ┌───────────────────────┐
    │     ThreatLens Standalone UI      │        │ Next.js Enterprise UI │
    │     (HTML5 / CSS3 / Vanilla JS)   │        │ (React 18 / Tailwind) │
    └─────────────────┬─────────────────┘        └───────────┬───────────┘
                      │                                      │
                      ▼                                      ▼ (Port 8000)
    ┌────────────────────────────────────────────────────────────────────┐
    │                     FastAPI Application Server                     │
    │  • Shannon Entropy Engine       • Decision Tree Heuristics         │
    │  • Streaming Copilot Proxy      • Incident Playbook Generator      │
    └─────────────────┬──────────────────────────────────────┬───────────┘
                      │                                      │
                      ▼                                      ▼
       ┌───────────────────────────────┐      ┌───────────────────────────┐
       │     Google Gemini AI API      │      │ PostgreSQL / Docker Stack │
       │ (Gemini 2.5 Flash / Pro)      │      │ (Telemetry & Threat Data) │
       └───────────────────────────────┘      └───────────────────────────┘
```

---

## 🚀 Getting Started

### Option 1: Standalone Server (Quickest, Zero Configuration)

The standalone mode runs the self-contained FastAPI backend and modern SOC dashboard with zero build steps:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ravitej555/threadlens-AI.git
   cd threadlens-AI
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Add your GEMINI_API_KEY (optional, fallback offline analysis is built-in)
   ```

4. **Launch the platform:**
   ```bash
   python main.py
   ```

5. **Access the application:**
   - **SOC Dashboard:** [http://localhost:8080/](http://localhost:8080/)
   - **Landing Page:** [http://localhost:8080/landing](http://localhost:8080/landing)
   - **API Health:** [http://localhost:8080/health](http://localhost:8080/health)

---

### Option 2: Docker Compose

Run the entire containerized environment with a single command:

```bash
docker-compose -f docker-compose.standalone.yml up --build
```

For full-stack deployment with PostgreSQL and Next.js frontend:
```bash
docker-compose up --build
```

---

## 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status and version check |
| `POST` | `/api/copilot/chat` | Send prompt to AI Copilot (JSON response) |
| `POST` | `/api/copilot/chat/stream` | Real-time token streaming chat with Gemini |
| `POST` | `/api/copilot/analyze` | Perform static + ML forensic analysis on file metadata |
| `POST` | `/api/copilot/report` | Generate structured SOC incident response report |
| `POST` | `/api/copilot/summarize` | Generate threat feed intelligence summary |
| `POST` | `/api/copilot/explain` | Explain ML prediction and Shannon entropy metrics |

---

## ⚙️ Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port for the FastAPI server |
| `HOST` | `0.0.0.0` | Bind host address |
| `GEMINI_API_KEY` | `""` | Optional Google Gemini API key for live AI reasoning |
| `ENVIRONMENT` | `production` | Environment mode (`development` / `production`) |

---

## 🛡️ Responsible Disclosure & Security

This tool is designed strictly for defensive cybersecurity analysis, threat detection research, and Security Operations Center training. Do not use for unauthorized or malicious testing.
