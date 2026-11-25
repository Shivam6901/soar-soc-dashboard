# SOAR Network Defense Center

**Course:** UCS503 — Software Engineering (5th Semester, B.E. CSE)  
**Group:** 3C62 — Thapar Institute of Engineering and Technology, Patiala  
**Team Members:**
- **Shivam Batra** (`1024030845`)
- **Emaan Dhillon** (`1024030851`)

A modular **Security Orchestration, Automation, and Response (SOAR)** & SOC Telemetry Dashboard built in Python with Streamlit, Scapy, Plotly, Windows Defender Firewall / Linux `iptables`, Nmap (+ pure-Python TCP fallback), and Google Gemini AI triage.

---

## Key Features
- **Live Network Monitor:** Multi-adapter Scapy `AsyncSniffer` (`Wi-Fi + Loopback`) with thread-safe bounded buffering (`deque(maxlen=2500)`), automatic port `8501` exclusion, and Python-enforced port filtering.
- **Forensic PCAP Analysis:** Upload and inspect `.pcap` / `.pcapng` captures frame-by-frame with Hex & ASCII decoding.
- **Sustained Volumetric Detection:** 1-second packet resampling with a 2-second rolling sustained rate threshold (PPS) to prevent single-second false positives.
- **Automated Firewall Containment:** Cross-platform inbound blocking via Windows Defender Firewall (`netsh advfirewall`) or Linux `iptables`, protected by loopback and host self-IP guards.
- **Active Recon & AI Incident Triage:** Nmap host scanning (with a built-in 18-port Python TCP connect fallback) paired with 3-bullet Gemini AI / rule-based SOC summaries.
- **Client Traffic Load Simulator:** Built-in `/demo` HTTP/TCP load controller (`target_server.py`) and two-laptop hotspot CLI harness (`attacker.py`) for safe classroom evaluation.

---

## Project Structure
```text
├── streamlit_app.py       # Main SOC Command Center UI & detection orchestration
├── capture.py             # Thread-safe Scapy capture, port filter, & PCAP generator
├── firewall.py            # Windows netsh / Linux iptables containment & safety guards
├── recon.py               # Nmap runner, 18-port TCP fallback, & Gemini AI triage
├── charts.py              # Local timezone alignment & multi-curve Plotly timeline
├── target_server.py       # Threaded HTTP/1.1 demo target + /demo load controller
├── attacker.py            # Standalone Python CLI load generator for 2-laptop tests
├── generate_pcap.py       # Helper to generate synthetic test_traffic.pcap
├── tests/test_soar.py     # 8 automated unit & Streamlit AppTest integration tests
├── report/                # Final Software Engineering report (HTML, Markdown, PDF)
├── requirements.txt       # Python dependencies
└── DEMO_GUIDE.md          # Step-by-step live demo instructions
```

---

## Setup & Running Locally (Windows)

1. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
   *(Requires [Npcap](https://npcap.com/) on Windows for live Wi-Fi packet capture; optional [Nmap](https://nmap.org/download.html) for full OS/service scans.)*

2. Open **two PowerShell windows as Administrator**:
   - **Terminal 1 (Target Server & Load Simulator):**
     ```powershell
     python target_server.py
     ```
   - **Terminal 2 (SOAR Dashboard):**
     ```powershell
     streamlit run streamlit_app.py
     ```

3. Run the automated test suite:
   ```powershell
   python tests/test_soar.py
   ```
