HAIL- THE IDS is a real-time Intrusion Detection System designed to detect, log, and explain network threats using a combination of rule-based detection, honeypot deception, and LLM-powered threat explanation. Built for security enthusiasts and researchers, this IDS provides deep visibility into malicious behaviors targeting your infrastructure

🧠 Key Features 📡 Real-Time Threat Detection: Monitors live network traffic and flags suspicious activities.

🪤 Honeypot Integration: Logs attacker behavior via low-interaction honeypots (e.g., Cowrie/Dionaea).

🧾 Rule-Based Detection Engine: Detects attacks like Port Scans, Brute Force, DDoS, ARP Spoofing, DNS Tunneling, etc.

🤖 LLM-Powered Threat Analysis: Uses a local Large Language Model (e.g., Mistral via Ollama) to generate human-friendly summaries of threats.

📊 Professional Dashboard: Streamlit-based UI displaying live traffic, alerts, visualizations, and explanations.

🔍 Threat Explanation Mode: Toggle between detection mode and analysis mode to explore threat details deeply.

📁 Modular Design: Easily extendable for new rules, logs, and UI components.

🚀 How It Works

1.Live Traffic Monitoring Monitors network logs or packet captures in real time.

2.Rule-Based Detection Custom rules analyze logs for known intrusion patterns (e.g., repeated login attempts, large packet floods, DNS tunneling).

3.Honeypot Deception Logs attacker activity through Cowrie (SSH/Telnet) or Dionaea (SMB, HTTP, FTP) for deeper threat profiling.

4.LLM Threat Explanation When a threat is detected, a local LLM (e.g., Mistral) generates a simplified explanation of the threat’s nature, origin, and possible intent.

5.Interactive UI Streamlit app shows:

📈 Real-time traffic table

⚠️ Threat alerts

📋 Threat summaries

📊 Traffic and threat visualizations

🧪 DETECTED THREAT TYPES

Port Scan

Brute Force Login

ARP Spoofing

DNS Tunneling

ICMP/UDP/HTTP Flood

C2 Beaconing Patterns

Unauthorized Access to Honeypots

Custom Threat Rules (Extensible)

🔧INSTALLATION AND SETUP

Clone the repository bash Copy Edit git clone https://github.com/Tauseefmalikk/HAIL-THE-IDS.git cd HAIL-THE-IDS

Create virtual environment & install dependencies bash Copy Edit python -m venv .venv source .venv/bin/activate # or .venv\Scripts\activate on Windows pip install -r requirements.txt

Start Honeypots (Optional) Start Cowrie or Dionaea and configure them to log to honeypot_logs/.

Start the Streamlit Dashboard bash Copy Edit streamlit run dashboard/main.py

About
HAIL- THE IDS is a real-time Intrusion Detection System designed to detect, log, and explain network threats using a combination of rule-based detection, honeypot deception, and LLM-powered threat explanation. Built for security enthusiasts and researchers, this IDS provides deep visibility into malicious behaviors targeting your infrastructure

Resources
 Readme
 Activity
Stars
 0 stars
Watchers
 0 watching
Forks
 0 forks
Releases
No releases published
Create a new release
Packages
No packages published
Publish your first package
Footer
© 2025 GitH
