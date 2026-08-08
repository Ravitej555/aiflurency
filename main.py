import os
import json
import re
import math
import time
import asyncio
from typing import List, Optional, Dict, Any
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Try importing requests for external Gemini API calls
import requests

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Load .env manually if dotenv not installed
ENV_FILE = BASE_DIR / ".env"
if ENV_FILE.exists():
    with open(ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Initialize FastAPI App
app = FastAPI(
    title="ThreatLens AI — Enterprise Cybersecurity SOC Copilot API",
    description="Backend API powering ThreatLens AI Copilot, Malware Forensic Analysis, and Incident Response Playbooks",
    version="2.5.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SYSTEM_PROMPT = """You are ThreatLens AI Copilot.

You are an expert SOC analyst, malware researcher, incident responder, DFIR specialist, threat intelligence analyst, and cybersecurity instructor.

Your responsibilities:
- Explain malware and cyber threats.
- Interpret scan reports and static/dynamic forensic indicators.
- Analyze uploaded files (SHA256, MD5, entropy, YARA rules, string indicators).
- Recommend actionable mitigation steps (containment, eradication, recovery, prevention).
- Generate structured SOC executive reports (Executive Summary, Malware Family, Risk, MITRE ATT&CK Mapping, IOCs, Conclusion).
- Explain AI predictions (Gini impurity, decision tree rules, feature attributions).
- Explain confidence scores and potential false positives.
- Map attack vectors to MITRE ATT&CK framework techniques.
- Assist security analysts in investigating threats.

Never provide offensive hacking or malware creation instructions.
Always answer professionally with clear markdown formatting, bold highlights, and syntax-highlighted code blocks."""

# ── PYDANTIC MODELS ─────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str # 'user' or 'assistant'
    content: str

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = []
    scan_context: Optional[Dict[str, Any]] = None

class FileMetadata(BaseModel):
    filename: str
    file_type: Optional[str] = "Binary Artifact"
    sha256: Optional[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5: Optional[str] = "d41d8cd98f00b204e9800998ecf8427e"
    file_size: Optional[int] = 0
    entropy: Optional[float] = 0.0
    strings_count: Optional[int] = 0
    yara_matches: Optional[List[str]] = []
    extracted_metadata: Optional[Dict[str, Any]] = {}
    prediction: str = "Benign"
    confidence: str = "95.0%"
    risk_level: str = "LOW"
    virustotal_result: Optional[str] = "Clean / 0 engines flagged"
    static_analysis: Optional[str] = "Normal PE header structure"

class ReportRequest(BaseModel):
    scan_data: FileMetadata
    custom_notes: Optional[str] = ""
    analyst_name: Optional[str] = "Lead SOC Analyst"

class SummarizeRequest(BaseModel):
    threats: List[Dict[str, Any]]

class ExplainRequest(BaseModel):
    prediction: Optional[str] = "Ransomware"
    confidence: Optional[str] = "98.4%"
    risk_level: Optional[str] = "CRITICAL"
    entropy: Optional[float] = 0.0
    strings_count: Optional[int] = 0
    filename: Optional[str] = ""

# ── HELPER FUNCTION FOR GEMINI API ──────────────────────────────
def query_gemini_api(prompt_text: str, scan_ctx: Dict[str, Any] = None, user_key: str = "", system_override: str = SYSTEM_PROMPT) -> str:
    key = user_key or os.getenv("GEMINI_API_KEY", "") or GEMINI_API_KEY
    if not key:
        return """⚠️ **GEMINI API KEY REQUIRED**

To receive real-time answers generated directly by **Google Gemini API** via the FastAPI backend:

1. Click the **⚙️ Settings** icon in the ThreatLens Copilot toolbar.
2. Paste your Google Gemini API key and click **Save Settings** (or update `GEMINI_API_KEY` in `.env`).

*Once saved, FastAPI will route 100% of your queries to Gemini API for live threat analysis.*"""

    ctx_prompt = ""
    if scan_ctx:
        ctx_prompt = f"\n[ATTACHED ARTIFACT CONTEXT: Filename={scan_ctx.get('filename','N/A')}, Prediction={scan_ctx.get('prediction','N/A')}, Confidence={scan_ctx.get('confidence','N/A')}, Entropy={scan_ctx.get('entropy','N/A')}, Hashes={scan_ctx.get('sha256','N/A')}]"

    full_text = f"{system_override}{ctx_prompt}\n\nUser Request: {prompt_text}"

    # Try models in order: gemini-2.5-flash -> gemini-1.5-flash
    models = ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"]
    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        payload = {
            "contents": [
                {
                    "parts": [{"text": full_text}]
                }
            ]
        }
        try:
            res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
            if res.status_code == 200:
                data = res.json()
                text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if text:
                    return text
            elif res.status_code == 400 or res.status_code == 403:
                err_msg = res.json().get("error", {}).get("message", "Invalid API Key")
                return f"❌ **GEMINI API ERROR ({res.status_code})**: {err_msg}. Please check your API key in Copilot ⚙️ Settings."
        except Exception as e:
            print(f"Gemini API model {model} error: {e}")

    return "⚠️ Failed to reach Gemini API. Please verify your internet connection and GEMINI_API_KEY."

    q = query.lower().strip()
    ctx_str = ""
    if scan_ctx:
        ctx_str = f" [Context Attached: {scan_ctx.get('filename','File')} | Prediction: {scan_ctx.get('prediction','Threat')} ({scan_ctx.get('confidence','98%')})]"

    # 1. SOC Report Request
    if "report" in q or "generate soc report" in q:
        fn = scan_ctx.get("filename", "Artifact_Sample.bin") if scan_ctx else "employee_payload.exe"
        pred = scan_ctx.get("prediction", "Ransomware.Win32.Entropy") if scan_ctx else "Ransomware.Win32.Entropy"
        risk = scan_ctx.get("risk_level", "CRITICAL") if scan_ctx else "CRITICAL"
        conf = scan_ctx.get("confidence", "98.4%") if scan_ctx else "98.4%"
        entropy = scan_ctx.get("entropy", 7.82) if scan_ctx else 7.82
        sha = scan_ctx.get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") if scan_ctx else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        return f"""### 🛡️ SOC EXECUTIVE THREAT INCIDENT REPORT
**Generated by ThreatLens AI Copilot** | *IST {time.strftime('%d %b %Y %I:%M:%S %p')}*

---

#### 1. Executive Summary
During automated endpoint telemetry monitoring, a high-severity security anomaly was identified on system artifact **`{fn}`**. Decision Tree forensic evaluation classified the file payload as **{pred}** with a Gini Confidence Score of **{conf}**. Immediate isolation procedures were initiated.

#### 2. Threat Analysis & Metadata
- **Artifact Filename:** `https://threatlens.internal/{fn}`
- **SHA-256 Hash:** `https://threatlens.internal/{sha[:32]}...`
- **Shannon Entropy:** `https://threatlens.internal/{entropy} / 8.00` *(High Entropy / Obfuscated)*
- **AI Prediction:** **{pred}**
- **Risk Level:** `<span style="color:#ef4444;font-weight:700;">{risk}</span>`
- **Gini Model Confidence:** **{conf}**

#### 3. MITRE ATT&CK Framework Mapping
- **T1059.001 (Command & Scripting Interpreter - PowerShell):** Execution of base64 obfuscated cradles.
- **T1486 (Data Encrypted for Impact):** High Shannon entropy indicating cryptographic payload sequence.
- **T1490 (Inhibit System Recovery):** Volume Shadow Copy deletion (`vssadmin delete shadows`).

#### 4. Indicators of Compromise (IOCs)
- **File Hashes:** `{sha}`
- **C2 IP Addresses:** `185.220.101.5:8080`, `198.51.100.16:443`
- **YARA Signature Matches:** `YARA_Ransomware_Entropy_High`, `YARA_PowerShell_Cradle_Detector`

#### 5. Recommended Action Plan & Containment
1. **Host Containment:** Execute network adapter isolation: `Disable-NetAdapter -Name "*"`
2. **Process Termination:** Force kill process tree: `taskkill /F /IM powershell.exe /T`
3. **Registry Clean:** Remove persistence keys from `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`
4. **Credential Reset:** Force password reset for compromised domain credentials.

---
*Status: Incident Logged & Remediation Active.*"""

    # 2. Mitigation Steps
    if "mitigat" in q or "remediat" in q or "contain" in q:
        return """### 🛡️ INCIDENT RESPONSE & MITIGATION PLAYBOOK

#### 1. Immediate Containment (First 5 Minutes)
- **Host Isolation:** Disconnect infected NIC or execute PowerShell adapter shutdown:
  ```powershell
  Disable-NetAdapter -Name "Ethernet0" -Confirm:$false
  ```
- **Network Rule:** Block remote command and control (C2) IP at the perimeter firewall:
  ```cmd
  netsh advfirewall firewall add rule name="SOC-C2-Block" dir=in action=block remoteip=185.220.101.5
  ```

#### 2. Eradication & Process Kill
- Force kill active malicious execution trees:
  ```cmd
  taskkill /F /IM powershell.exe /T
  taskkill /F /IM wscript.exe /T
  ```

#### 3. Recovery & Shadow Copy Protection
- Verify Shadow Copies remain intact:
  ```cmd
  vssadmin list shadows
  ```

#### 4. Long-Term Prevention
- Enforce AppLocker / Software Restriction Policies on `%APPDATA%` and `%TEMP%`.
- Enable PowerShell Constrained Language Mode (CLM) and Script Block Logging."""

    # 3. Explain AI Prediction & Confidence Score
    if "explain" in q or "predict" in q or "confidence" in q or "gini" in q:
        conf = scan_ctx.get("confidence", "98.4%") if scan_ctx else "98.4%"
        pred = scan_ctx.get("prediction", "Ransomware") if scan_ctx else "Ransomware"
        entropy = scan_ctx.get("entropy", 7.82) if scan_ctx else 7.82
        return f"""### 🔬 AI PREDICTION & GINI CONFIDENCE DECOMPOSITION

#### 1. Why was it classified as {pred}?
The ThreatLens AI Decision Tree model uses **Gini Impurity Optimization** across 48,000 baseline signatures to evaluate binary metrics:
- **Shannon Entropy ({entropy} / 8.0):** Standard code runs at 4.5–6.2. An entropy above **6.80** indicates cryptographic encryption or payload packing.
- **Suspicious Strings:** Detected signatures matching process injection API calls (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).
- **File Extension Risk:** High-risk executable format boost.

#### 2. Gini Confidence Metric ({conf})
- **Gini Impurity (0.0 = Pure Node):** The decision path reached a leaf node with near zero impurity, yielding **{conf}** mathematical probability of threat correlation.

#### 3. False Positive Assessment
- **Low Risk of False Positive:** High entropy + API string indicators strongly rule out standard compressed archives or benign installers."""

    # 4. Analyze Uploaded File
    if "analyze" in q or "file" in q or "scan" in q or "sha256" in q:
        fn = scan_ctx.get("filename", "suspect_payload.exe") if scan_ctx else "employee_report.pdf"
        return f"""### 🧪 AUTOMATED FORENSIC FILE DECOMPOSITION
**Target Artifact:** `{fn}`

- **File Entropy:** `https://threatlens.internal/7.82 / 8.00` *(High Randomness)*
- **SHA-256:** `https://threatlens.internal/8f3c4d1e2b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1`
- **MD5:** `https://threatlens.internal/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`
- **YARA Matches:** `[YARA_Ransomware_Entropy_High, YARA_PowerShell_Cradle_Detector]`
- **VirusTotal Telemetry:** `48 / 72 Security Vendors Flagged Malicious`

**Forensic Summary:**
The file exhibits severe obfuscation and memory allocation behaviors typical of zero-day ransomware or Trojan downloaders. Immediate quarantine is recommended."""

    # 5. Malware Family Breakdown
    if "malware" in q or "family" in q or "trojan" in q or "worm" in q:
        return """### 🦠 MALWARE CLASSIFICATION SPECTRUM

- **Ransomware:** Encrypts user files with AES/RSA and demands ransom (`.encrypted`, `.locked`). High Shannon entropy (>7.5).
- **Trojan:** Disguised as legitimate software; performs stealthy memory injection into `explorer.exe` or `svchost.exe`.
- **Worm:** Self-propagating network threat exploiting unpatched SMB (EternalBlue) or RCE vulnerabilities.
- **Rootkit:** Hooks OS kernel structures (`SSDT`) to hide malicious processes and registry keys from Task Manager."""

    # 6. Threat Summary
    if "summary" in q or "ioc" in q or "feed" in q:
        crit_count = sum(1 for t in (scan_ctx.get("threats", []) if scan_ctx else []) if t.get("severity") == "CRITICAL") or 2
        return f"""### 📊 SOC TELEMETRY & IOC SUMMARY

- **Total Monitored Artifacts:** `6 Active Telemetry Feeds`
- **Critical Risk Items:** `{crit_count} Items` (Requires Immediate Action)
- **Top Attack Vector:** `PowerShell Base64 Cradles & SMB Exploitation`
- **Primary C2 IPs Flagged:** `185.220.101.5`, `198.51.100.16`
- **Status:** All threat feeds synchronized with perimeter firewall."""

    # 7. Greetings / Platform Info
    if any(k in q for k in ["hi", "hello", "hey", "who are you", "what is threatlens"]):
        return """### 🤖 THREATLENS AI COPILOT ONLINE
Welcome! I am your autonomous **Cybersecurity SOC Assistant & DFIR Specialist**.

How I can assist you today:
- 🛡️ **Generate SOC Reports:** Type *"Generate SOC Report"* to build executive PDF reports.
- 🔬 **Analyze Uploaded Files:** Type *"Analyze uploaded file"* or click any scan item.
- 🛡️ **Mitigation Guidance:** Ask *"How to mitigate ransomware?"* for containment playbooks.
- 🧬 **Explain AI Predictions:** Ask *"Explain confidence score"* or *"Why is it malicious?"*."""

    # General Fallback Response
    clean_p = query.replace("<", "&lt;").replace(">", "&gt;")
    return f"""### 🤖 THREATLENS AI COPILOT
Analyzed query: *"{clean_p}"*{ctx_str}

As your SOC Security Assistant, I recommend the following defensive actions:
1. **Threat Inspection:** Upload suspicious binaries or URLs in the **File & Link AI Scanner** tab.
2. **SOC Report Generation:** Type *"Generate SOC Report"* to export a complete incident document.
3. **Mitigation Playbook:** Type *"Mitigation Steps"* for host isolation commands.

*Tip: You can also add your Gemini API Key in `.env` or settings for open-ended LLM reasoning.*"""

# ── API ENDPOINTS ───────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = BASE_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>ThreatLens AI Backend Running</h1>")

class KeyRequest(BaseModel):
    api_key: str

@app.post("/api/copilot/key")
async def save_copilot_key(req: KeyRequest):
    global GEMINI_API_KEY
    key = req.api_key.strip()
    os.environ["GEMINI_API_KEY"] = key
    GEMINI_API_KEY = key
    
    env_content = f"# ThreatLens AI Enterprise SOC Environment Configuration\nGEMINI_API_KEY={key}\nPORT=8080\nHOST=0.0.0.0\n"
    try:
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.write(env_content)
    except Exception as e:
        print(f"Error updating .env: {e}")
        
    return {"status": "success", "message": "Gemini API Key saved and active on FastAPI backend."}

@app.post("/api/copilot/chat")
async def copilot_chat(req: ChatRequest):
    scan_ctx = req.scan_context or {}
    response_text = query_gemini_api(req.message, scan_ctx=scan_ctx)
    return {
        "status": "success",
        "response": response_text,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

@app.post("/api/copilot/analyze")
async def copilot_analyze(meta: FileMetadata):
    scan_ctx = meta.model_dump()
    query = f"Analyze file {meta.filename} with SHA256 {meta.sha256}, Entropy {meta.entropy}, YARA matches {meta.yara_matches}, and prediction {meta.prediction}."
    response_text = query_gemini_api(query, scan_ctx=scan_ctx)
    return {
        "status": "success",
        "analysis": response_text,
        "file_metadata": scan_ctx
    }

@app.post("/api/copilot/report")
async def copilot_report(req: ReportRequest):
    scan_ctx = req.scan_data.model_dump()
    query = f"Generate a detailed SOC Executive Incident Report for target artifact {req.scan_data.filename} with prediction {req.scan_data.prediction} and Gini confidence {req.scan_data.confidence}."
    report_text = query_gemini_api(query, scan_ctx=scan_ctx)
    return {
        "status": "success",
        "report_markdown": report_text,
        "filename": f"SOC_Report_{req.scan_data.filename}.pdf"
    }

@app.post("/api/copilot/summarize")
async def copilot_summarize(req: SummarizeRequest):
    scan_ctx = {"threats": req.threats}
    query = f"Summarize the active threat intelligence feed ({len(req.threats)} items) and highlight top critical IOCs and targeted host IP addresses."
    summary_text = query_gemini_api(query, scan_ctx=scan_ctx)
    return {
        "status": "success",
        "summary": summary_text
    }

@app.post("/api/copilot/explain")
async def copilot_explain(req: ExplainRequest):
    scan_ctx = req.model_dump()
    query = f"Explain why the model predicted {req.prediction} with {req.confidence} confidence. Decompose Shannon Entropy, decision tree Gini impurity rules, and potential false positive scenarios."
    explain_text = query_gemini_api(query, scan_ctx=scan_ctx)
    return {
        "status": "success",
        "explanation": explain_text
    }

# Legacy fallback endpoint compatibility
@app.post("/api/chat")
async def legacy_chat(req: Dict[str, Any]):
    prompt = req.get("prompt", "")
    response_text = generate_threatlens_copilot_response(prompt)
    return {"response": response_text}

# Mount static directory for CSS/JS
app.mount("/", StaticFiles(directory=str(BASE_DIR)), name="static")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
