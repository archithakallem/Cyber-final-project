# 🔐 Cyber Risk Assessment & Threat Intelligence Platform

A unified cybersecurity analysis system that combines **network scanning, threat intelligence, contextual enrichment, scoring, and visualization** into a single interactive dashboard.

---

## 📘 Overview

CyberScan is designed to analyze digital targets such as:

- 🌐 Domain
- 🖥️ IP Address
- 🔗 URL
- 🧾 File Hash

The platform integrates multiple security resources and transforms raw scan data into **structured risk insights**, making it easier to understand exposure, threats, and overall security posture.

---

## 🎯 Objectives

- Build a **centralized security analysis platform**
- Support multiple target types with automatic detection
- Integrate **network scanning + threat intelligence**
- Provide **risk scoring and interpretation**
- Enable **multi-target comparison**
- Maintain scan history
- Trigger **automated email alerts** for high-risk findings

---

## ⚙️ Tech Stack

### 🔹 Backend
- **FastAPI** → API layer for scanning & processing  
- **Python** → core logic implementation  
- **Uvicorn** → ASGI server  

### 🔹 Frontend
- **Streamlit** → interactive dashboard UI  
- **Plotly** → advanced interactive charts  
- **Pandas** → data processing  

### 🔹 Database
- **SQLite** → stores scan history  

### 🔹 Security Tools & APIs
- **Nmap (python-nmap)** → network scanning (open ports)  
- **VirusTotal API** → threat intelligence  
- **WHOIS** → ownership and domain context  
- **SSL Validation** → secure communication check  

---

## 🧠 System Architecture
User Input (UI)
↓
Streamlit Frontend
↓
FastAPI Backend
↓
Scanner Modules
(Nmap + VirusTotal + WHOIS + SSL)
↓
Data Processing Layer
↓
Scoring Engine
↓
SQLite Database
↓
Visualization + Alerts


---

## 🔍 Core Features

### 🔹 1. Multi-Target Scanning
- Accepts **comma-separated targets**
- Example:
scanme.nmap.org, example.com, 8.8.8.8
- Each target is scanned independently
- Results are compared in dashboards

---

### 🔹 2. Target Type Detection

Automatically detects:
- Domain
- IP
- URL
- File Hash

Ensures correct scanning strategy for each type.

---

### 🔹 3. Scanner Module

#### 🌐 Nmap
- Detects open ports
- Measures exposure

#### 🛡 VirusTotal
- Detects malicious signals
- Provides threat intelligence

#### 🧾 WHOIS
- Provides ownership & registration info

#### 🔐 SSL Check
- Validates secure connection

---

### 🔹 4. Scoring Engine

CyberScan converts raw data into meaningful scores:

- **Exposure Score** → based on open ports  
- **Threat Score** → based on malicious detections  
- **Context Score** → based on configuration  
- **Risk Score** → final combined score  

---

### 🔹 5. Interactive Dashboards

| Page | Description |
|------|------------|
| Summary | Overall metrics & quick report |
| Analysis | Detailed findings |
| Visuals | Charts & comparisons |
| History | Past scans & trends |
| Recommendations | Actionable insights |
| Risk Map | Severity visualization |
| System Info | Architecture & working |

---

### 🔹 6. Visualizations

- 📊 Bar charts  
- 🥧 Pie charts  
- 🍩 Donut charts  
- 📈 Line charts  
- 🔥 Heatmaps  
- 🌐 Sunburst charts  
- 🎯 Scatter/bubble charts  

---

### 🔹 7. Multi-Target Comparison

- Compare:
- Risk
- Exposure
- Threat
- Open ports
- Identify highest-risk target instantly

---

### 🔹 8. History Tracking

- Stored in SQLite
- Tracks:
- Target
- Timestamp
- Scores
- Enables trend analysis

---

### 🔹 9. Email Alert System

Triggered when:
- Malicious detections > 0  
- OR Risk score > 70  

📧 Sends:
- Target
- Risk score
- Findings

⚠️ Note: Email delivery depends on SMTP configuration.

---

## 🔄 Workflow

1. User inputs target
2. System detects target type
3. Scanner modules run
4. Data is processed
5. Scores are calculated
6. Data stored in database
7. Dashboards display results
8. Email alert triggered (if required)

---

## 🚀 Installation & Setup

### 1. Clone Repository
```bash
git clone https://github.com/archithakallem/Cyber-final-project.git
cd Cyber-final-project

2. Create Virtual Environment
python -m venv venv
venv\Scripts\activate

3. Install Dependencies
pip install -r requirements.txt
4. Install Nmap

Download and install from:
https://nmap.org/download.html

▶️ Run Application
Start Backend
uvicorn app.main:app --reload
Start Frontend
streamlit run ui/app.py
📊 Example Targets
scanme.nmap.org
example.com
8.8.8.8
eicar.org
⚠️ Limitations
Depends on external APIs (VirusTotal)
Basic scoring model
Limited deep vulnerability detection
🔮 Future Enhancements
AI-based threat analysis
PDF report generation
Real-time monitoring
Advanced vulnerability scanning
Geo-based risk mapping
🔐 Disclaimer

This tool is for educational purposes only.
Do not scan systems without proper authorization.

👩‍💻 Author

Kallem Architha Reddy
Cyber Risk Assessment & Threat Intelligence Platform

