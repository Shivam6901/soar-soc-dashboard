"""Packet capture, thread-safe buffering, interface discovery, and simulation helpers."""

import collections
import datetime
import random
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from scapy.all import AsyncSniffer, Ether, ICMP, IP, TCP, UDP, conf, get_if_addr, get_if_list, wrpcap

# Thread-safe buffer shared between Scapy's background sniffer thread and Streamlit UI
_BUFFER_LOCK = threading.Lock()
_PACKET_BUFFER: collections.deque = collections.deque(maxlen=2500)
_ALLOWED_PORT: Optional[int] = None


def push_packet_row(row: Dict) -> None:
    with _BUFFER_LOCK:
        _PACKET_BUFFER.append(row)


def drain_packet_buffer() -> List[Dict]:
    items: List[Dict] = []
    with _BUFFER_LOCK:
        while _PACKET_BUFFER:
            items.append(_PACKET_BUFFER.popleft())
    return items


def clear_packet_buffer() -> None:
    with _BUFFER_LOCK:
        _PACKET_BUFFER.clear()


def get_local_host_ips() -> List[str]:
    """Return non-loopback IPv4 addresses bound to this machine."""
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ips)


def list_capture_interfaces() -> List[Tuple[str, str]]:
    """Return list of (interface_id, human_label) pairs for UI selection."""
    choices: List[Tuple[str, str]] = []
    seen = set()

    # Try Windows/Scapy rich interface list first
    try:
        for iface in conf.ifaces.values():
            dev_name = getattr(iface, "network_name", None) or getattr(iface, "name", None)
            if not dev_name or dev_name in seen:
                continue
            seen.add(dev_name)
            desc = getattr(iface, "description", "") or getattr(iface, "name", dev_name)
            ip = getattr(iface, "ip", "") or ""
            label = f"{desc} ({ip})" if ip and ip != "0.0.0.0" else desc
            choices.append((dev_name, label))
    except Exception:
        pass

    if not choices:
        for name in get_if_list():
            if name in seen:
                continue
            seen.add(name)
            try:
                ip = get_if_addr(name)
            except Exception:
                ip = ""
            label = f"{name} ({ip})" if ip and ip != "0.0.0.0" else name
            choices.append((name, label))

    # Put interfaces with an active IPv4 first
    def sort_key(item: Tuple[str, str]) -> Tuple[int, str]:
        _, lbl = item
        has_lan_ip = "(192.168." in lbl or "(10." in lbl or "(172." in lbl
        is_wifi = "wi-fi" in lbl.lower() or "wireless" in lbl.lower() or "wlan" in lbl.lower()
        if is_wifi and has_lan_ip:
            return (0, lbl)
        if has_lan_ip:
            return (1, lbl)
        if "loopback" in lbl.lower() or "(127." in lbl:
            return (2, lbl)
        return (3, lbl)

    choices.sort(key=sort_key)
    return [("AUTO_ALL", "Auto (All Active: Wi-Fi + Loopback)")] + choices


def parse_packet_data(pkt, light_mode: bool = False) -> Optional[Dict]:
    """Extract normalized telemetry fields from a Scapy packet."""
    t = float(pkt.time)
    src = pkt[IP].src if pkt.haslayer(IP) else (pkt[Ether].src if pkt.haslayer(Ether) else "Unknown")
    dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[Ether].dst if pkt.haslayer(Ether) else "Unknown")
    ttl = pkt[IP].ttl if pkt.haslayer(IP) else "N/A"
    proto, sport, dport = "Other", 0, 0

    if pkt.haslayer(TCP):
        proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    # Never capture Streamlit's own UI traffic during live capture
    if light_mode:
        if sport == 8501 or dport == 8501:
            return None
        if _ALLOWED_PORT is not None and sport != _ALLOWED_PORT and dport != _ALLOWED_PORT:
            return None

    raw_bytes = bytes(pkt)[:32]
    summary = (
        f"{proto} {src}:{sport} -> {dst}:{dport}"
        if light_mode
        else pkt.summary()
    )
    return {
        "Packet ID": 0,
        "Timestamp": t,
        "Time": datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3],
        "Source IP": src,
        "Source Port": sport,
        "Destination IP": dst,
        "Destination Port": dport,
        "Protocol": proto,
        "Length": len(pkt),
        "TTL": ttl,
        "Hex": " ".join(f"{b:02x}" for b in raw_bytes),
        "Ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes),
        "Summary": summary,
        "Location": "Private Subnet"
        if src.startswith(("192.168.", "10.", "172.", "127."))
        else "Public Node",
    }


def _scapy_async_callback(pkt) -> None:
    try:
        row = parse_packet_data(pkt, light_mode=True)
        if row:
            push_packet_row(row)
    except Exception:
        pass


def _extract_filter_port(bpf_filter: str) -> Optional[int]:
    tokens = bpf_filter.strip().split()
    for idx, tok in enumerate(tokens):
        if tok.lower() == "port" and idx + 1 < len(tokens) and tokens[idx + 1].isdigit():
            return int(tokens[idx + 1])
    return None


def _start_single_sniffer(iface: Optional[str], bpf_filter: str) -> Tuple[Optional[AsyncSniffer], Optional[str]]:
    kwargs = {"prn": _scapy_async_callback, "store": False}
    if iface:
        kwargs["iface"] = iface
    if bpf_filter.strip():
        kwargs["filter"] = bpf_filter.strip()

    try:
        sniffer = AsyncSniffer(**kwargs)
        sniffer.start()
        return sniffer, None
    except Exception as exc:
        if "filter" in kwargs:
            try:
                kwargs.pop("filter")
                sniffer = AsyncSniffer(**kwargs)
                sniffer.start()
                return sniffer, f"BPF filter ignored ({exc}); using Python port filter."
            except Exception as exc2:
                return None, str(exc2)
        return None, str(exc)


def start_real_capture(iface: Optional[str] = None, bpf_filter: str = "") -> Tuple[Optional[List[AsyncSniffer]], Optional[str]]:
    """Start Scapy AsyncSniffer(s) on the chosen adapter (or all active Wi-Fi/Loopback)."""
    global _ALLOWED_PORT
    _ALLOWED_PORT = _extract_filter_port(bpf_filter)

    if iface == "AUTO_ALL" or not iface:
        all_ifaces = [
            (dev, lbl)
            for dev, lbl in list_capture_interfaces()
            if dev != "AUTO_ALL"
            and any(tag in lbl for tag in ("(192.168.", "(10.", "(172.", "(127.", "loopback", "Loopback", "Wi-Fi", "Wireless"))
        ]
        if not all_ifaces:
            all_ifaces = [(dev, lbl) for dev, lbl in list_capture_interfaces() if dev != "AUTO_ALL"][:2]

        sniffers: List[AsyncSniffer] = []
        last_err = None
        for dev, _ in all_ifaces[:3]:
            s, err = _start_single_sniffer(dev, bpf_filter)
            if s is not None:
                sniffers.append(s)
            elif err:
                last_err = err
        if sniffers:
            return sniffers, None
        return None, last_err or "No capture interface could be started."

    s, err = _start_single_sniffer(iface, bpf_filter)
    return ([s], err) if s is not None else (None, err)


def stop_real_capture(sniffers) -> None:
    if not sniffers:
        return
    items = sniffers if isinstance(sniffers, list) else [sniffers]
    for sniffer in items:
        try:
            sniffer.stop()
        except Exception:
            pass


def simulated_traffic_tick(elapsed_time: float) -> None:
    """Push simulated normal background traffic and an attack burst after 4 seconds."""
    t = time.time()
    for _ in range(random.randint(15, 25)):
        src = f"192.168.1.{random.choice([10, 16, 79, 131, 157, 182, 195, 215])}"
        sport = random.randint(1024, 65535)
        proto = "TCP" if random.random() < 0.75 else "UDP"
        dport = random.choice([80, 443, 53, 22])
        push_packet_row(
            {
                "Packet ID": 0,
                "Timestamp": t + random.uniform(0, 0.4),
                "Time": datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3],
                "Source IP": src,
                "Source Port": sport,
                "Destination IP": "10.0.0.1",
                "Destination Port": dport,
                "Protocol": proto,
                "Length": random.randint(64, 1200),
                "TTL": 64,
                "Hex": "45 00 00 3c 1a ...",
                "Ascii": "E..<..",
                "Summary": f"{proto} {src}:{sport} -> 10.0.0.1:{dport}",
                "Location": "Private Subnet",
            }
        )

    if elapsed_time > 4.0:
        for _ in range(random.randint(140, 190)):
            sport = random.randint(1024, 65535)
            push_packet_row(
                {
                    "Packet ID": 0,
                    "Timestamp": t + random.uniform(0, 0.4),
                    "Time": datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3],
                    "Source IP": "192.168.1.105",
                    "Source Port": sport,
                    "Destination IP": "10.0.0.1",
                    "Destination Port": 80,
                    "Protocol": "TCP",
                    "Length": 64,
                    "TTL": 64,
                    "Hex": "45 00 00 28 00 01 00 00 40 06 7c b2 c0 a8 01 69 0a 00 00 01",
                    "Ascii": "E..(...@..|...i....",
                    "Summary": f"TCP 192.168.1.105:{sport} -> 10.0.0.1:80 [SYN]",
                    "Location": "Private Subnet",
                }
            )


def generate_benchmark_pcap(
    filename: str = "test_traffic.pcap",
    num_normal_packets: int = 1000,
    num_ddos_packets: int = 5000,
    attacker_ip: str = "192.168.1.105",
    victim_ip: str = "10.0.0.1",
    ddos_duration_seconds: int = 5,
) -> str:
    """Create a synthetic benchmark PCAP with normal traffic + a volumetric burst."""
    packets = []
    start_time = time.time()

    for _ in range(num_normal_packets):
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = f"10.0.0.{random.randint(2, 254)}"
        sport = random.randint(1024, 65535)
        dport = random.randint(80, 443)
        layer4 = (
            TCP(sport=sport, dport=dport)
            if random.random() < 0.7
            else UDP(sport=sport, dport=dport)
        )
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src=src_ip, dst=dst_ip)
            / layer4
        )
        pkt.time = start_time + random.uniform(0, ddos_duration_seconds + 10)
        packets.append(pkt)

    for _ in range(num_ddos_packets):
        ddos_pkt_time = start_time + random.uniform(2, 2 + ddos_duration_seconds)
        sport = random.randint(1024, 65535)
        layer4 = (
            TCP(sport=sport, dport=80, flags="S")
            if random.random() < 0.6
            else UDP(sport=sport, dport=80)
        )
        pkt = (
            Ether(src="00:11:22:33:44:66", dst="66:77:88:99:aa:bb")
            / IP(src=attacker_ip, dst=victim_ip)
            / layer4
        )
        pkt.time = ddos_pkt_time
        packets.append(pkt)

    packets.sort(key=lambda x: x.time)
    wrpcap(filename, packets)
    return filename
