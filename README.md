# CyberScan

CyberScan is a security analysis dashboard that combines a FastAPI backend with a Streamlit frontend to scan a target, enrich the result with external intelligence, calculate a risk score, store scan history, and optionally send alert emails.

## Features

- FastAPI-based scan API
- Streamlit dashboard with Home, Summary, Analysis, Visuals, History, Recommendations, Risk Map, and System Info pages
- Nmap-based open-port discovery
- VirusTotal enrichment for threat intelligence
- Structured scoring for exposure, threat, context, and overall risk
- SQLite history tracking
- Optional email alerts when malicious detections are found or overall risk is high

## Tech Stack

### Backend
- FastAPI
- Uvicorn
- Python
- SQLite

### Frontend
- Streamlit
- Plotly
- Pandas

### Scanning / Intelligence
- python-nmap
- requests
- VirusTotal API

## Project Structure

```text
cyberscan_project/
├── app/
│   ├── main.py
│   ├── routes.py
│   ├── scanner.py
│   ├── processor.py
│   ├── scoring.py
│   └── database.py
├── pages/
│   ├── 1_Summary.py
│   ├── 2_Analysis.py
│   ├── 3_Visuals.py
│   ├── 4_History.py
│   ├── 5_Recommendations.py
│   ├── 6_Risk_Map.py
│   └── 7_System_Info.py
├── utils/
│   └── email_sender.py
├── app.py
├── ui_utils.py
├── requirements.txt
└── README.md
```

## How It Works

1. The user enters a target, backend URL, VirusTotal API key, and optional alert email in the Streamlit control center.
2. The Streamlit UI calls the FastAPI `/scan/{target}` endpoint.
3. The backend runs Nmap to discover open ports for network targets.
4. The backend queries VirusTotal to enrich the target with threat intelligence.
5. The processor normalizes the raw output into a structured format.
6. The scoring layer calculates:
   - Exposure score
   - Threat score
   - Context score
   - Overall risk score
7. The result is saved into SQLite for history tracking.
8. If the result qualifies for alerting, an email report can be sent automatically.

## Supported Targets

Current project flow is designed for:
- Domain
- IP address
- URL
- File hash

> Note: Full behavior depends on how your active `scanner.py` and `routes.py` are wired in your local project.

## API Endpoints

### Run a scan
```http
GET /scan/{target}?api_key=YOUR_VT_KEY&email=optional@example.com
```

### Get target history
```http
GET /history/{target}
```

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/archithakallem/Cyber-final-project
cd cyberscan_project
```

### 2. Create and activate virtual environment
#### Windows
```bash
python -m venv venv
venv\Scripts\activate
```

#### macOS / Linux
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Nmap on your machine
CyberScan uses the Nmap binary through `python-nmap`, so Nmap must also be installed and available in your system path.

- Windows: install Nmap from the official installer
- macOS: `brew install nmap`
- Ubuntu/Debian: `sudo apt install nmap`

## Run the Application

### Start backend
```bash
uvicorn app.main:app --reload
```

### Start frontend
```bash
streamlit run app.py
```

## Email Alerting

Email alerts are sent only when:
- malicious detections are present, or
- the overall risk score is greater than 70

and an email address is provided from the UI.

Configure your sender credentials in your email utility or environment before using this feature.

## Database

Scan history is stored in SQLite. The database includes:
- target
- timestamp
- exposure
- threat
- context
- risk

## Example Targets

- `scanme.nmap.org`
- `example.com`
- `8.8.8.8`

## Future Enhancements

- WHOIS enrichment
- SSL/TLS validation
- Better target normalization
- File upload analysis
- PDF/HTML export reports
- Stronger scoring model

## Disclaimer

Use CyberScan only on systems, domains, IPs, or assets that you own or are explicitly authorized to test.

## License

Add your preferred license here.
