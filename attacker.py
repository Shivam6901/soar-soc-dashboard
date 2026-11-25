"""Safe 2-laptop hotspot demo traffic generator (run on Laptop 2).

Uses only Python's standard library (no extra pip install needed on Laptop 2).
Phase 1 sends slow normal requests so the dashboard stays green.
Phase 2 sends a controlled burst (>130 PPS) until Laptop 1's Windows Firewall drops it.
"""

import argparse
import socket
import threading
import time

PORT = 8080


def send_one_request(target_ip: str, port: int, timeout: float = 0.8) -> bool:
    """Open a short TCP connection and send a minimal HTTP GET. Returns True if accepted."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target_ip, port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: demo\r\nConnection: close\r\n\r\n")
        s.recv(64)
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_phase(name: str, target_ip: str, port: int, duration_sec: int, workers: int, delay_sec: float) -> None:
    print(f"\n--- {name} ({duration_sec}s) ---")
    stop_at = time.time() + duration_sec
    lock = threading.Lock()
    stats = {"ok": 0, "blocked": 0}

    def worker() -> None:
        while time.time() < stop_at:
            accepted = send_one_request(target_ip, port)
            with lock:
                if accepted:
                    stats["ok"] += 1
                else:
                    stats["blocked"] += 1
            if delay_sec > 0:
                time.sleep(delay_sec)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()

    while time.time() < stop_at:
        time.sleep(1.0)
        with lock:
            ok, blocked = stats["ok"], stats["blocked"]
            stats["ok"] = 0
            stats["blocked"] = 0
        status = "FIREWALL BLOCKING / TIMED OUT" if blocked > ok and blocked > 5 else "TRAFFIC ACCEPTED"
        print(f"  [1s] Sent OK: {ok:4d} | Blocked/Failed: {blocked:4d}  --> {status}")

    for t in threads:
        t.join(timeout=1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe hotspot demo traffic generator for Laptop 2")
    parser.add_argument("target_ip", nargs="?", help="IP address of Laptop 1 on the hotspot")
    parser.add_argument("--port", type=int, default=PORT, help="Target port (default: 8080)")
    parser.add_argument("--normal-sec", type=int, default=8, help="Seconds of normal traffic")
    parser.add_argument("--attack-sec", type=int, default=20, help="Seconds of burst traffic")
    args = parser.parse_args()

    target_ip = args.target_ip or input("Enter Laptop 1's Hotspot IP address: ").strip()
    if not target_ip:
        print("No target IP entered. Exiting.")
        return

    print(f"Target: {target_ip}:{args.port}")
    run_phase("PHASE 1: NORMAL USER TRAFFIC (~5 req/s)", target_ip, args.port, args.normal_sec, workers=1, delay_sec=0.2)
    run_phase("PHASE 2: CONTROLLED FLOOD BURST (>200 req/s)", target_ip, args.port, args.attack_sec, workers=25, delay_sec=0.0)
    print("\nDemo sequence finished.")


if __name__ == "__main__":
    main()
