"""Cross-platform firewall containment helpers for the SOAR dashboard."""

import ctypes
import ipaddress
import os
import platform
import re
import subprocess
from typing import List, Tuple

RULE_PREFIX = "SOAR_BLOCK_"


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    """Return True if the current process has elevated privileges."""
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def validate_blockable_ip(ip_str: str, protected_ips: List[str] | None = None) -> Tuple[bool, str]:
    """Validate an IP address and guard against blocking loopback or host IPs."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address: {ip_str}"

    if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
        return False, f"Refusing to block special/loopback IP: {ip_str}"

    if protected_ips and str(ip_obj) in protected_ips:
        return False, f"Refusing to block local host IP: {ip_str}"

    return True, str(ip_obj)


def enforce_firewall_drop(ip_address: str, protected_ips: List[str] | None = None) -> Tuple[bool, str]:
    """Block inbound traffic from ip_address using Windows Firewall or Linux iptables."""
    ok, clean_ip_or_err = validate_blockable_ip(ip_address, protected_ips)
    if not ok:
        return False, f"[GUARD] {clean_ip_or_err}"

    clean_ip = clean_ip_or_err

    if is_windows():
        rule_name = f"{RULE_PREFIX}{clean_ip}"
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={clean_ip}",
            "profile=any",
            "enable=yes",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return True, f"[WINDOWS FIREWALL] Inbound block rule '{rule_name}' active."
            err_msg = (res.stderr or res.stdout or "Access denied").strip()
            return False, f"[ERROR] Windows Firewall failed (run terminal as Admin): {err_msg}"
        except Exception as exc:
            return False, f"[ERROR] Windows Firewall exception: {exc}"

    # Linux fallback (iptables)
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return True, f"[KERNEL] Drop rule appended to INPUT chain for {clean_ip}."
    except Exception as exc:
        return False, f"[ERROR] Kernel insertion failed: {exc}"


def flush_soar_firewall_rules(tracked_ips: List[str] | None = None) -> Tuple[bool, str]:
    """Remove SOAR-created firewall rules without touching unrelated system rules."""
    if is_windows():
        rule_names = set()
        if tracked_ips:
            for ip in tracked_ips:
                rule_names.add(f"{RULE_PREFIX}{ip}")

        try:
            show_res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if show_res.returncode == 0 and show_res.stdout:
                for match in re.findall(r"Rule Name:\s*(SOAR_BLOCK_[^\r\n]+)", show_res.stdout):
                    rule_names.add(match.strip())
        except Exception:
            pass

        if not rule_names:
            return True, "No active SOAR Windows Firewall rules found."

        errors = []
        removed = 0
        for name in sorted(rule_names):
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0:
                removed += 1
            else:
                msg = (res.stderr or res.stdout or "").strip()
                if "No rules match" not in msg:
                    errors.append(f"{name}: {msg}")

        if errors:
            return False, f"Removed {removed} rule(s); errors (run as Admin): {'; '.join(errors)}"
        return True, f"Removed {removed} SOAR Windows Firewall rule(s)."

    # Linux fallback
    try:
        if tracked_ips:
            for ip in tracked_ips:
                subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    timeout=10,
                )
            return True, f"Removed SOAR iptables rules for {len(tracked_ips)} IP(s)."
        subprocess.run(["sudo", "iptables", "-F"], capture_output=True, check=True, timeout=10)
        return True, "Flushed Linux iptables INPUT rules."
    except Exception as exc:
        return False, f"Flush error: {exc}"
