# 🛡️ HAIL-THE-IDS: Real-Time Intrusion Detection System

**HAIL-THE-IDS** is a real-time Intrusion Detection System built for modern cybersecurity monitoring. It combines **rule-based threat detection**, **honeypot deception**, and **LLM-powered threat explanation** to deliver actionable insights with a professional dashboard interface.

Designed for security enthusiasts, researchers, and institutions, HAIL offers deep visibility into malicious behaviors targeting your network infrastructure.

---

## 🧠 Key Features

- **📡 Real-Time Threat Detection**  
  Monitors live network traffic and flags suspicious activity instantly.

- **🪤 Honeypot Integration**  
  Captures attacker behavior using Cowrie or Dionaea honeypots.

- **🧾 Rule-Based Detection Engine**  
  Detects well-known threats like Port Scans, Brute Force attacks, DDoS, and more using logical rules.

- **🤖 LLM-Powered Threat Analysis**  
  Uses a local LLM (e.g., [Mistral](https://mistral.ai) via [Ollama](https://ollama.com)) to generate human-readable threat summaries.

- **📊 Professional Dashboard**  
  Streamlit-based real-time UI showing alerts, traffic, honeypot logs, and visual analytics.

- **🔍 Threat Explanation Mode**  
  Toggle between detection and explanation modes to explore threat details and intent.

- **📁 Modular Design**  
  Easily extensible with new detection rules, custom visualizations, and data sources.

---

## 🚀 How It Works

### 1. Live Traffic Monitoring  
Continuously monitors network traffic logs or real-time packet captures.

### 2. Rule-Based Detection  
Uses a set of predefined rules to detect:
- Login brute force attempts
- Port scanning
- DNS tunneling
- DDoS indicators
- Suspicious large packets
- Unauthorized honeypot access

### 3. Honeypot Deception  
Low-interaction honeypots like **Cowrie** (SSH/Telnet) and **Dionaea** (SMB/HTTP/FTP) capture attacker behavior for deeper insights.

### 4. LLM Threat Explanation  
Once a threat is detected, the system queries a local LLM (e.g., Mistral) to:
- Describe the threat
- Identify the attack’s purpose
- Suggest mitigation insights

### 5. Interactive Dashboard  
Built with Streamlit, the UI includes:
- 📈 Live network traffic table  
- ⚠️ Real-time threat alerts  
- 🧾 Natural-language threat summaries  
- 📊 Visual analytics (charts, timelines, etc.)

---

## 🧪 Detected Threat Types

- ✅ Port Scan  
- ✅ Brute Force Login  
- ✅ ARP Spoofing  
- ✅ DNS Tunneling  
- ✅ ICMP / UDP / HTTP Flood  
- ✅ Command & Control Beaconing  
- ✅ Unauthorized Honeypot Access  
- ✅ Custom Rules (Add Your Own)

---

## 🔧 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Tauseefmalikk/HAIL-THE-IDS.git
cd HAIL-THE-IDS
