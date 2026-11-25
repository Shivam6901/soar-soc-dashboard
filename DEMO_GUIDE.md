# Live Demo Guide (iPhone + 1 Laptop OR 2 Laptops)

This setup lets you show a **real, live DDoS attack and automatic Windows Firewall block** using your **iPhone's Personal Hotspot**—completely disconnected from Thapar's `EACCESS` Wi-Fi.

---

## One-Time Setup on Your Laptop

1. Open PowerShell in this folder and install the Python libraries:
   ```powershell
   cd C:\Users\LENOVO\.gemini\antigravity\scratch\soar-soc-dashboard
   pip install -r requirements.txt
   ```
2. **Npcap** is already installed on your PC (`C:\Windows\System32\Npcap`).
3. *(Optional)* Install **Nmap for Windows** (https://nmap.org/download.html) only if you want to click **Initiate Active Scan** during the demo.

---

## Option A: 1 Laptop + Your iPhone (No Apps Needed on iPhone!)

1. Turn on **Personal Hotspot** on your iPhone and connect your laptop to it (disconnect from `EACCESS`).
2. Open **two PowerShell windows as Administrator** on your laptop (Right-click Start -> *Terminal (Admin)*):
   - **Admin Terminal 1 (Target Server):**
     ```powershell
     cd C:\Users\LENOVO\.gemini\antigravity\scratch\soar-soc-dashboard
     python target_server.py
     ```
     It prints a URL like: `Open on iPhone Safari: http://172.20.10.2:8080/demo`
     *(If Windows Firewall asks to allow Python, click **Allow**.)*
   - **Admin Terminal 2 (SOAR Dashboard):**
     ```powershell
     cd C:\Users\LENOVO\.gemini\antigravity\scratch\soar-soc-dashboard
     streamlit run streamlit_app.py
     ```
3. In the dashboard sidebar on your laptop:
   - **Traffic Source**: `Live Network Monitor`
   - **Network Adapter**: Pick your **Wi-Fi** adapter (showing your `172.20.10.x` IP)
   - **Capture Filter**: Keep `tcp port 8080`
   - **Attack Threshold (Packets / Sec)**: Set to `50` (triggers cleanly from iPhone Safari)
   - **Response Policy**: `Active Containment (Auto-Drop Attacker)`
   - Click **▶ Start Live Monitoring**
4. On your **iPhone**, open **Safari** and go to `http://<Laptop-IP>:8080/demo` (the exact link printed in Terminal 1):
   - Tap **1. Start Normal Traffic** -> Dashboard stays **Green (`NETWORK HEALTHY`)**.
   - Adjust the **Flood Intensity** slider if needed and tap **2. Start Continuous Flood Attack** -> Runs continuously until you tap **Stop** or the **Windows Firewall** blocks your iPhone (`BLOCKED BY FIREWALL (Auto-Stopped)`).
5. After the demo, click **Flush Active Firewall Rules** in the sidebar to unblock your iPhone.

> **Quick tip before class:** Test opening `http://<Laptop-IP>:8080/demo` on iPhone Safari once before going to Ma'am. If your iPhone's hotspot blocks the iPhone itself from opening the laptop's IP, use **Option B** below (connect Laptop 2 to your iPhone hotspot).

---

## Option B: 2 Laptops on Your iPhone Hotspot

If you bring a second laptop (or a friend's laptop):
1. Connect **both laptops** to your iPhone's Personal Hotspot.
2. Copy just `attacker.py` to Laptop 2 (needs only Python, no `pip install`).
3. Run `target_server.py` and `streamlit run streamlit_app.py` as Admin on Laptop 1, click **Start Acquisition**.
4. On Laptop 2, run:
   ```powershell
   python attacker.py <Laptop-1-IP>
   ```
5. Click **Flush Active Firewall Rules** in the sidebar after the demo.
