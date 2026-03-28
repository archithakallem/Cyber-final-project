🔐 Risk Analysis System (CyberScan)

A web-based cybersecurity tool that analyzes URLs using the VirusTotal API, calculates risk scores, visualizes results, and automatically sends email reports.

🚀 Features :
-> URL scanning using VirusTotal API
-> Interactive data visualization (Bar, Line, Area charts)
-> Risk scoring system (Safe / Suspicious / Malicious)
-> Automated HTML email reporting after scan
-> Real-time dashboard built with Streamlit
-> Secure API key input via sidebar

🛠️ Technologies Used :
Python
Streamlit
Pandas
Requests
smtplib (Email sending)
MIME (HTML email formatting)
Base64 (URL encoding)

📦 Installation & Setup  :

1️⃣ Clone the repository
git clone https://github.com/archithakallem/riskanalysis.git
cd riskanalysis

2️⃣ Install dependencies
pip install streamlit pandas requests

3️⃣ Get VirusTotal API Key
Sign up at: https://www.virustotal.com
Copy your API key

4️⃣ Setup Email (Important)  : To enable email alerts:
Go to your Google Account → Security
Enable 2-Step Verification
Generate an App Password
Replace in code:
sender = "your_email@gmail.com"
receiver = "your_email@gmail.com"
password = "your_app_password"

▶️ How to Run :
streamlit run app.py

🧪 How to Use :
Enter a URL in the sidebar
Enter your VirusTotal API key
Click Analyze URL
View:
-> Risk score
-> Verdict (Safe / Suspicious / Malicious)
-> Visualization charts
Email report is automatically sent after analysis

📊 Output Example :
Detection statistics (malicious, harmless, suspicious, etc.)
Risk score (%)
Interactive charts
HTML email report with:
-> Target URL
-> Scan time
-> Detection table
-> Recommendation

⚠️ Notes :
Email is sent automatically after each scan
Use App Password, not your Gmail password
Avoid scanning unauthorized or unsafe URLs
