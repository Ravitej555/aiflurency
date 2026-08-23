
# 1. FRONTEND — React / Vanilla JS

## 📁 File Location
```text
frontend/src/App.jsx  (or app.js)
```
```javascript
const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch("http://localhost:8080/scan-file", {
    method: "POST",
    body: formData
});
```

### Simple example:

```text
User selects:
virus.txt / payload.exe
        ↓
     Frontend
        ↓
 POST /scan-file
        ↓
     FastAPI
```

---

# 2. FRONTEND → BACKEND CONNECTION


```javascript
"http://localhost:8080/scan-file"
```

```text
Browser / Port 8080 → Frontend UI
Port 8080           → FastAPI backend (/scan-file, /api/copilot/chat)
```


---

# 3. BACKEND — FastAPI

Now move to:

## 📁 File Location
```text
backend/main.py  (or app/main.py)
```

Find your FastAPI application:

```python
from fastapi import FastAPI

app = FastAPI(
    title="ThreatLens AI — Malware Analysis Platform",
    version="2.5.0"
)
```

---

# 4. The `/scan-file` API Endpoint

Stay in `main.py` and find:

```python
@app.post("/scan-file")
async def scan_file(file: UploadFile = File(...)):
```

```text
Frontend
   │
   │ POST /scan-file
   ▼
FastAPI
   │
   ▼
Read uploaded file bytes
```

---

# 5. File Hashing

```python
import hashlib

md5_hash = hashlib.md5(file_bytes).hexdigest()
sha256_hash = hashlib.sha256(file_bytes).hexdigest()
```

---
# 6. Suspicious Indicator & String Detection

```python
suspicious_indicators = [
    "http://",
    "https://",
    "powershell",
    "Invoke-WebRequest",
    "VirtualAlloc"
]

for indicator in suspicious_indicators:
    if indicator in content:
        score += 20
```

### Simple example:

```text
File contains:
powershell
http://malicious-c2.com

        ↓

Indicator found → Risk score increases
```

---

# 7. Risk Score Calculation

```python
def calculate_risk_score(content):
    score = 0
    for indicator in suspicious_indicators:
        if indicator in content:
            score += 20
    return min(score, 100)
```

```text
0–39   → Low Risk
40–69  → Suspicious
70–100 → High Risk
```

# 8. MACHINE LEARNING MODEL — Decision Tree

```python
from sklearn.tree import DecisionTreeClassifier

model = DecisionTreeClassifier()
```

Then show your features:

```python
X = df[
    [
        "file_size",
        "suspicious_strings",
        "hash_entropy"
    ]
]
```
---

# 9. Training the Model

```python
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

model.fit(X_train, y_train)
```
---

# 10. Prediction

```python
prediction = model.predict(test_features)
```

### Example:

```text
Input:
File size = 450 KB
Suspicious strings = 3
Shannon Entropy = 7.82

        ↓

Decision Tree

        ↓

Prediction:
Ransomware
```

---

# 11. Confidence Score

```python
proba = model.predict_proba(test_features)
confidence = max(proba[0]) * 100
```

### Example:

```text
Classification: Ransomware
Confidence: 92.4%
```

---

# 12. Recommended Action

```python
if confidence >= 80:
    action = "Escalate to Security Analyst / Quarantined"
elif confidence >= 50:
    action = "Needs Review by Analyst"
else:
    action = "Likely Safe"
```

### Example:

```text
92% confidence
      ↓
High Risk
      ↓
Escalate to Security Analyst / Quarantined
```

---

# 13. Result comes back to Frontend

```javascript
const data = await response.json();
setResult(data);
```

### Complete flow recap:

```text
UPLOAD
   ↓
Frontend UI
   ↓
POST /scan-file
   ↓
FastAPI Backend
   ↓
Hash + Indicators + Entropy
   ↓
Feature Extraction
   ↓
Decision Tree Classifier
   ↓
Classification + Confidence
   ↓
Recommended Action
   ↓
JSON Response
   ↓
Frontend UI
```

---

# 17. NOW DEMONSTRATE IT LIVE

This is where your explanation becomes interactive.

Go back to your website: `http://localhost:8080` (or `http://localhost:5173`)

### 🎤 Say:

> *"Now I'll demonstrate the complete flow."*

### Step 1: Upload File
Select your test file:
> *"First, I select a file."*

### Step 2: Click Analyze
Click **Analyze Artifact**:
> *"The frontend now sends this file to my FastAPI backend."*

### Step 3: Show the Results
Point at the screen:
* **Classification** (`Ransomware.Win32.Entropy`)
* **Confidence** (`99.4%`)
* **Risk Level** (`CRITICAL`)
* **Recommended Action** (`Quarantined / Isolate Host`)

> *"The backend analyzes the file, the machine learning model makes the classification, and the result is returned to the frontend."*

---

# 18. Docker — VERY SIMPLE EXPLANATION

Open your project tree and show:

```text
Dockerfile
docker-compose.yml
```

### Backend Dockerfile (`Dockerfile`)
> *"This Dockerfile packages my FastAPI backend together with its Python dependencies."*

### Docker Compose (`docker-compose.yml`)
> *"Instead of starting the services separately, Docker Compose allows me to start the entire platform together with one command: `docker-compose up --build`."*

---

# 19. Final Architecture

End with this:

```text
                 USER
                   │
                   ▼
              Frontend UI
            localhost:8080
                   │
                   │ POST /scan-file
                   ▼
           FastAPI Backend
            localhost:8080
                   │
          ┌────────┴────────┐
          ▼                 ▼
    File Analysis       ML Model
    Hash + Entropy   Decision Tree
          │                 │
          └────────┬────────┘
                   ▼
       Classification + Risk
          + Confidence
          + Recommendation
                   │
                   ▼
              Frontend UI
```

### 🎤 Final Conclusion:

> *"So, my project combines frontend development, backend APIs, file analysis, machine learning, and Docker into one complete malware analysis platform. The main goal is to provide a simple interface for performing an initial automated analysis of suspicious files."*

---

# ⭐ The Easiest Way to Remember Your Explanation

Don't memorize 50 lines of code. Remember these **8 steps**:

```text
1. USER
   ↓
2. UPLOAD FILE
   ↓
3. FRONTEND UI
   ↓
4. FASTAPI BACKEND
   ↓
5. FILE ANALYSIS (Hashes + Entropy)
   ↓
6. ML MODEL (Decision Tree)
   ↓
7. RESULT & PLAYBOOK
   ↓
8. DOCKER DEPLOYMENT
```

And for every section use the simple formula:

$$\text{WHAT} \longrightarrow \text{WHY} \longrightarrow \text{HOW} \longrightarrow \text{SHOW CODE} \longrightarrow \text{SHOW UI}$$

For example:
* **What?** *"This is my `/scan-file` API."*
* **Why?** *"It receives the file from the frontend."*
* **How?** *"The frontend sends the file using a POST request."*
* **Code:** `main.py`
* **UI:** Upload $\rightarrow$ Analyze $\rightarrow$ Result.
