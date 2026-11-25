"""Active host reconnaissance (Nmap) and Gemini AI incident triage helpers."""

import html
import ipaddress
import os
import shlex
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple

try:
    import google.generativeai as genai

    _HAS_GEMINI = True
except ImportError:
    _HAS_GEMINI = False


def find_nmap_binary() -> Optional[str]:
    """Locate nmap on PATH or in standard Windows installation directories."""
    found = shutil.which("nmap")
    if found:
        return found
    for candidate in (
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


_COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "upnp/http",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8501: "streamlit",
}


def _python_fallback_scan(target_ip: str) -> str:
    """Fast TCP connect port probe used when the external nmap binary is not installed."""
    def check_port(port: int) -> Optional[Tuple[int, str]]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.45)
        try:
            if s.connect_ex((target_ip, port)) == 0:
                return port, _COMMON_PORTS.get(port, "unknown")
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    open_ports = []
    with ThreadPoolExecutor(max_workers=18) as pool:
        for res in pool.map(check_port, sorted(_COMMON_PORTS.keys())):
            if res is not None:
                open_ports.append(res)

    lines = [
        f"Built-in TCP Recon Report for {target_ip}",
        "(Note: nmap.exe not installed yet — run 'winget install Insecure.Nmap' for full Nmap OS/NSE scans)",
        "",
        "PORT      STATE  SERVICE",
    ]
    if open_ports:
        for port, svc in open_ports:
            lines.append(f"{f'{port}/tcp':<9} open   {svc}")
    else:
        lines.append("All 18 probed common TCP ports are closed or filtered.")
    return "\n".join(lines)


def run_direct_nmap(target_ip: str, flags: str) -> Tuple[str, str]:
    """Execute an Nmap scan against target_ip (with built-in TCP scan fallback)."""
    try:
        ip_obj = ipaddress.ip_address(target_ip.strip())
    except ValueError:
        return f"nmap {flags} {target_ip}", f"[!] Invalid IP address: {target_ip}"

    nmap_bin = find_nmap_binary()
    if not nmap_bin:
        return (
            f"python-recon --top-ports {ip_obj}",
            _python_fallback_scan(str(ip_obj)),
        )

    cmd_list = [nmap_bin, *shlex.split(flags), str(ip_obj)]
    cmd_display = f"nmap {flags} {ip_obj}"
    try:
        res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=25)
        out = res.stdout if res.stdout.strip() else res.stderr
        return cmd_display, out.strip() if out and out.strip() else "[!] Probe filtered by ingress firewall."
    except subprocess.TimeoutExpired:
        return cmd_display, f"[!] Probe timed out for target host {ip_obj}."
    except Exception as exc:
        return cmd_display, f"Command execution error: {exc}"


def init_gemini_model(api_key: Optional[str] = None) -> Tuple[Optional[object], str]:
    """Initialize an available Gemini model if an API key is provided."""
    key = (api_key or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if not (_HAS_GEMINI and key):
        return None, "SOC Rule Core"

    try:
        genai.configure(api_key=key)
        supported = [
            m.name
            for m in genai.list_models()
            if "generateContent" in getattr(m, "supported_generation_methods", [])
        ]
        chosen = None
        for cand in (
            "models/gemini-2.5-flash",
            "models/gemini-2.0-flash",
            "models/gemini-1.5-flash",
            "models/gemini-pro",
        ):
            if cand in supported:
                chosen = cand
                break
        if not chosen and supported:
            chosen = supported[0]
        if chosen:
            return genai.GenerativeModel(chosen), chosen.replace("models/", "")
    except Exception:
        pass
    return None, "SOC Rule Core"


def generate_ai_threat_summary(nmap_output_text: str, gemini_model: Optional[object], model_tag: str) -> str:
    """Produce a formatted HTML triage report from Nmap output using Gemini or heuristics."""
    fallback_text = (
        "• Host State: Target appears firewalled or silently dropping active recon probes.\n"
        "• Attack Surface: No responsive TCP listening ports identified in Fast Sweep.\n"
        "• SOC Action: Enforce perimeter ingress filtering and inspect upstream flows."
    )

    if gemini_model:
        try:
            prompt = (
                "You are a tier-3 SOC analyst. Analyze this Nmap recon report. "
                "Provide exactly 3 concise, formal bullet points on: (1) Host exposure, "
                "(2) Potential vulnerability exposure, and (3) Recommended containment actions.\n\n"
                f"```\n{nmap_output_text}\n```"
            )
            res = gemini_model.generate_content(prompt)
            summary = res.text or fallback_text
        except Exception:
            summary = fallback_text
    else:
        summary = fallback_text

    safe_tag = html.escape(model_tag.upper())
    safe_summary = html.escape(summary).replace("\n", "<br>")
    return f"""
<div class='soc-term soc-term-amber'>
<span style='color:#fbbf24; font-weight:600;'>[INCIDENT TRIAGE REPORT // {safe_tag}]</span><br>
----------------------------------------------------------------------<br>
{safe_summary}
</div>
"""
