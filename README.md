
---

# 🔐 SentinelAI: Multi-Domain Security System

**SentinelAI** is a machine-learning based cybersecurity detection platform designed to identify and classify threats across **web applications**, **network ids**, and **Android systems**.
The project focuses on backend security intelligence, realistic detection pipelines, and centralized alert logging—similar to enterprise IDS/WAF systems.

---

## 📌 Table of Contents

* Project Overview
* Key Capabilities
* System Architecture
* Detection Modules
* Machine Learning Pipeline
* Backend API Design
* Execution & Outputs
* Alert Logging System
* Installation & Setup
* Running the System
* API Usage Examples
* Screenshots Walkthrough
* Project Status
* Future Enhancements
* Contact & Support
* License & Acknowledgments

---

## 1️⃣ Project Overview

**SentinelAI** is a centralized security intelligence system that detects cyber threats using **trained machine learning models** rather than static rule-based signatures.

Unlike traditional IDS/WAF systems, SentinelAI:

* Learns attack patterns from real datasets
* Detects previously unseen attack variations
* Operates via API-driven inference
* Logs alerts silently and centrally

🎯 **Goal:**
Build a realistic, extensible, backend-focused cybersecurity detection system suitable for real-world integration.

---

## 2️⃣ Key Capabilities

| Domain               | Threats Detected                                      |
| -------------------- | ----------------------------------------------------- |
| **Web Applications** | SQL Injection, XSS, Command Injection, Path Traversal |
| **Network Traffic**  | Brute Force, Abnormal Flows, Intrusion Patterns       |
| **Android Apps**     | Malware, Permission Abuse                             |

---

## 3️⃣ System Architecture

```text
Incoming Data
   ↓
Preprocessing
   ↓
Feature Engineering
   ↓
Machine Learning Models
   ↓
Threat Classification
   ↓
Central Alert Logger
   ↓
JSON API Response
```

SentinelAI is intentionally designed **without dependency on a UI**, making it suitable for backend security integrations such as WAFs, SOC tools, and monitoring pipelines.

---

## 4️⃣ Detection Modules

---

### 🔹 Web Application Attack Detection

**Purpose**
Detect malicious user inputs submitted through:

* Login forms
* Search boxes
* URL parameters
* API request bodies

**Technique**

* Natural Language Processing (NLP)
* TF-IDF vectorization (max 5,000 features)
* Logistic Regression classifier

**Example Payloads**

```text
<script>alert(1)</script>
' OR 1=1 --
../../etc/passwd
```

📷 **Screenshots**

**Payload Input**
![Web Payload Input](https://github.com/user-attachments/assets/54df837c-8323-4cc3-9875-ba1b67991063)

**Detection Result**
![Web Detection Output](https://github.com/user-attachments/assets/064bfa0f-7d22-4f12-b32a-e7a006cb6831)

---

### 🔹 Network Intrusion Detection System (IDS)

**Purpose**
Detect malicious network behavior using **flow-based statistics**, not packet content.

**Dataset**

* CIC-IDS2018 (1M+ network flow records)

**Features**

* Flow duration
* Packet count
* Byte rates
* Protocol statistics

**Model**

* Random Forest Classifier

📷 **Screenshots**

**Network Traffic Analysis**
![Network Analysis](https://github.com/user-attachments/assets/b7309b17-1295-4326-b7cf-a2625ded5420)

**Intrusion Detected**
![Intrusion Detected](https://github.com/user-attachments/assets/984f8f61-3be2-4bb3-b972-69e6b1798666)

---

### 🔹 Android Malware Detection

**Purpose**
Classify Android applications as **BENIGN** or **MALWARE** based on permission abuse.

**Features**

* Binary permission vectors
* Sensitive permission combinations

**Model**

* Random Forest Classifier

📷 **Screenshot**

**Android Malware Detection Output**
![Android Malware Output](https://github.com/user-attachments/assets/901e5b38-1fef-450c-be29-410de387a354)


---

## 5️⃣ Machine Learning Pipeline

| Stage               | Description                   |
| ------------------- | ----------------------------- |
| Data Cleaning       | Missing values, normalization |
| Feature Engineering | TF-IDF / numeric vectors      |
| Model Training      | Domain-specific ML models     |
| Evaluation          | Accuracy, precision, recall   |
| Serialization       | `.pkl` files using Joblib     |

---

## 6️⃣ Backend API Design

SentinelAI uses **FastAPI** to expose lightweight, high-performance inference endpoints.

The API is designed to accept **arbitrary user input** (text, payloads, feature vectors)
and dynamically analyze it for **malicious patterns**, similar to real-world WAF and IDS systems.

Any input submitted to the API is:

* Validated
* Preprocessed
* Passed through trained ML models
* Classified as BENIGN or MALICIOUS
* Logged centrally if malicious

| Endpoint               | Description                                   |
| ---------------------- | --------------------------------------------- |
| `POST /detect/web`     | Inspect any user-supplied payload for attacks |
| `POST /detect/network` | Analyze network flow statistics               |
| `POST /detect/android` | Detect Android malware via permissions        |
| `GET /alerts`          | Retrieve logged security alerts               |

## 7️⃣ Execution & Outputs

Each detection request returns:

* Threat classification
* Confidence score
* Severity level
* Recommendation

Example output:

```json
{
  "threat_detected": true,
  "threat_type": "XSS",
  "confidence": 0.99,
  "severity": "high",
  "recommendation": "Block request and log event"
}
```

---

## 8️⃣ Alert Logging System

All detected threats are logged centrally.

**Log Location**

```text
backend/alerts/alerts.log
```


---

## 9️⃣ Installation & Setup

### Requirements

* Python 3.8+
* 4 GB RAM minimum
* Linux / Windows / macOS

### Setup

```bash
git clone https://github.com/Anjalita/SentinelAI-Multi-Domain-Security-System.git
cd SentinelAI-Multi-Domain-Security-System
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows
pip install -r backend/requirements.txt
```

---

## 🔟 Running the System

```bash
cd backend
python api.py
```

Server:

```text
http://127.0.0.1:8000
```

API Documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 1️⃣1️⃣ Screenshots Walkthrough

| File                 | Description                |
| -------------------- | -------------------------- |
| `web_payload.png`    | Web payload input          |
| `web_payload_op.png` | Web attack classification  |
| `web_and_alert.png`  | Alert logging              |
| `network.png`        | Network traffic analysis   |
| `netwrok_op.png`     | Network intrusion detected |
| `android_op.png`     | Android malware detection  |
| `api.png`            | FastAPI server             |

---

## 1️⃣2️⃣ Project Status

### ✅ Completed

* Dataset preprocessing
* ML model training
* Backend API
* Central alert logging

### ⏳ Optional / Future

* Live packet capture (tcpdump / Wireshark)
* APK static analysis
* Dashboard UI
* Cloud deployment

---

## 1️⃣3️⃣ Future Enhancements

* Real-time packet ingestion
* Advanced anomaly detection
* SIEM integration
* Role-based access control
* Containerized deployment (Docker)

---

## 1️⃣4️⃣ Contact & Support

If you face any issues, have questions, or want to contribute:

**Anjalita Fernandes**
GitHub: [https://github.com/Anjalita](https://github.com/Anjalita)


---

## 1️⃣5️⃣ License & Acknowledgments

**License**

* MIT License

---

### 🧠 Final Note

SentinelAI demonstrates **end-to-end security system engineering**, prioritizing correctness, architecture, and realism over UI complexity.

---
