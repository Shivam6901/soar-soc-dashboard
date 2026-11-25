"""Target server for Laptop 1 with a web-based Client Traffic Load Simulator (/demo)."""

import http.server
import socket
import socketserver
import threading
import time

PORT = 8080
_COUNT_LOCK = threading.Lock()
_REQUEST_COUNT = 0
_RECENT_CLIENTS = set()

DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Client Traffic Load Simulator</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      background: #060911;
      color: #f8fafc;
      margin: 0;
      padding: 18px;
      text-align: center;
    }
    .card {
      max-width: 430px;
      margin: 14px auto;
      background: #0c1322;
      border: 1px solid #2b3f63;
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 12px 28px rgba(0, 0, 0, 0.4);
    }
    h2 { margin: 0 0 6px 0; color: #38bdf8; font-size: 20px; }
    p { color: #94a3b8; font-size: 13.5px; margin: 0 0 16px 0; }
    .slider-box {
      background: #090f1c;
      border: 1px solid #1b2840;
      border-radius: 10px;
      padding: 12px 14px;
      margin-bottom: 14px;
      text-align: left;
    }
    .slider-label {
      display: flex;
      justify-content: space-between;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    input[type="range"] { width: 100%; accent-color: #f43f5e; }
    button {
      width: 100%;
      padding: 14px;
      margin: 7px 0;
      border: none;
      border-radius: 10px;
      font-size: 15.5px;
      font-weight: 700;
      cursor: pointer;
    }
    .btn-normal { background: #10b981; color: #04120c; }
    .btn-attack { background: #f43f5e; color: #ffffff; }
    .btn-stop { background: #334155; color: #f8fafc; }
    .stats {
      margin-top: 16px;
      padding: 14px;
      background: #050912;
      border: 1px solid #1b2840;
      border-radius: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13.5px;
      text-align: left;
      line-height: 1.75;
    }
    .ok { color: #34d399; font-weight: 700; }
    .bad { color: #fb7185; font-weight: 700; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Client Traffic Load Simulator</h2>
    <p>Runs continuously until you tap <b>Stop</b> or the <b>Windows Firewall blocks this client</b>.</p>

    <div class="slider-box">
      <div class="slider-label">
        <span>Flood Intensity (Workers)</span>
        <span id="intensityVal">12</span>
      </div>
      <input id="intensity" type="range" min="2" max="25" value="12"
             oninput="document.getElementById('intensityVal').textContent = this.value" />
    </div>

    <button class="btn-normal" onclick="startMode('normal')">1. Start Normal Traffic (1 req/s)</button>
    <button class="btn-attack" onclick="startMode('attack')">2. Start Continuous Flood Attack</button>
    <button class="btn-stop" onclick="stopTraffic('Stopped manually')">Stop</button>

    <div class="stats">
      <div>Mode           : <span id="mode">IDLE</span></div>
      <div>Live Rate      : <span id="rps">0</span> req/s</div>
      <div>Accepted (OK)  : <span id="ok" class="ok">0</span></div>
      <div>Blocked / Fail : <span id="fail" class="bad">0</span></div>
      <div>Status         : <span id="status">Ready</span></div>
    </div>
  </div>

  <script>
    let running = false;
    let runId = 0;
    let okCount = 0;
    let failCount = 0;
    let recentOk = 0;
    let consecutiveFails = 0;
    let currentModeLabel = "IDLE";

    setInterval(() => {
      document.getElementById("rps").textContent = running ? recentOk : 0;
      recentOk = 0;
    }, 1000);

    function updateUI(modeText, statusText) {
      document.getElementById("mode").textContent = modeText;
      document.getElementById("ok").textContent = okCount;
      document.getElementById("fail").textContent = failCount;
      document.getElementById("status").textContent = statusText;
    }

    async function sendOne(myRunId) {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 2500);
      try {
        const res = await fetch("/ping?t=" + Date.now() + Math.random(), {
          cache: "no-store",
          signal: controller.signal
        });
        if (!running || myRunId !== runId) return;
        if (res.ok) {
          okCount++;
          recentOk++;
          consecutiveFails = 0;
          updateUI(currentModeLabel, "TRAFFIC ACCEPTED");
        } else {
          failCount++;
          consecutiveFails++;
          updateUI(currentModeLabel, "ERROR " + res.status);
        }
      } catch (e) {
        if (!running || myRunId !== runId) return;
        failCount++;
        consecutiveFails++;
        if (consecutiveFails >= 6) {
          updateUI(currentModeLabel, "BLOCKED BY FIREWALL (No Reply)");
        } else {
          updateUI(currentModeLabel, "Sending... (Waiting on response)");
        }
      } finally {
        clearTimeout(t);
      }
    }

    async function workerLoop(myRunId, delayMs) {
      while (running && myRunId === runId) {
        await sendOne(myRunId);
        if (delayMs > 0 && running && myRunId === runId) {
          await new Promise((r) => setTimeout(r, delayMs));
        }
      }
    }

    function stopTraffic(reason) {
      runId++;
      running = false;
      currentModeLabel = "STOPPED";
      updateUI("STOPPED", reason || "Stopped");
    }

    function startMode(kind) {
      runId++;
      const myRunId = runId;
      okCount = 0;
      failCount = 0;
      recentOk = 0;
      consecutiveFails = 0;
      running = true;

      if (kind === "normal") {
        currentModeLabel = "NORMAL";
        updateUI("NORMAL", "Sending normal traffic (1 req/s)...");
        workerLoop(myRunId, 1000);
      } else {
        const workers = parseInt(document.getElementById("intensity").value, 10) || 16;
        currentModeLabel = "FLOOD (" + workers + "x)";
        updateUI(currentModeLabel, "Flooding continuously...");
        for (let i = 0; i < workers; i++) {
          workerLoop(myRunId, 0);
        }
      }
    }
  </script>
</body>
</html>
"""


class DemoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        global _REQUEST_COUNT
        try:
            if self.path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            if self.path.startswith("/demo") or self.path == "/":
                body = DEMO_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return

            with _COUNT_LOCK:
                _REQUEST_COUNT += 1
                _RECENT_CLIENTS.add(self.client_address[0])
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # Force a fresh TCP connection per request so browser bursts generate clear PPS spikes
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            # Browser closed/aborted socket before reading response (normal during bursts/stops)
            return

    def log_message(self, format, *args):
        return


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, request, client_address):
        # Suppress noisy socket abort tracebacks when client cancels requests
        return


def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def rate_printer() -> None:
    global _REQUEST_COUNT, _RECENT_CLIENTS
    while True:
        time.sleep(1.0)
        with _COUNT_LOCK:
            count = _REQUEST_COUNT
            clients = sorted(_RECENT_CLIENTS)
            _REQUEST_COUNT = 0
            _RECENT_CLIENTS.clear()
        if count > 0:
            print(f"[TARGET SERVER] Last 1s: {count} req(s) from {', '.join(clients)}")


def main() -> None:
    lan_ip = get_lan_ip()
    print("=" * 64)
    print("  SOAR DEMO TARGET SERVER (Run on Victim Host)")
    print(f"  Host IP (Hotspot/LAN)    : {lan_ip}")
    print(f"  Client Load Simulator URL: http://{lan_ip}:{PORT}/demo")
    print(f"  Listening on 0.0.0.0:{PORT}")
    print("  Press Ctrl+C to stop.")
    print("=" * 64)

    threading.Thread(target=rate_printer, daemon=True).start()
    server = ThreadedHTTPServer(("0.0.0.0", PORT), DemoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nTarget server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
