"""SOC Command Center & SOAR Telemetry Dashboard (Windows/Linux local edition)."""

import datetime
import html
import os
import tempfile
import time

import pandas as pd
import streamlit as st
from scapy.all import PcapReader

from capture import (
    clear_packet_buffer,
    drain_packet_buffer,
    get_local_host_ips,
    list_capture_interfaces,
    parse_packet_data,
    start_real_capture,
    stop_real_capture,
)
from charts import build_incident_timeline_chart, to_local_naive_dt
from firewall import (
    enforce_firewall_drop,
    flush_soar_firewall_rules,
    is_admin,
    is_windows,
)
from recon import (
    find_nmap_binary,
    generate_ai_threat_summary,
    init_gemini_model,
    run_direct_nmap,
)

# --- Page Setup ---
st.set_page_config(
    layout="wide",
    page_title="SOAR Shield // Live Network Defense",
    page_icon="🛡️",
)

# --- Refined Modern SOC Styling ---
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap');

    :root {
        --bg-base: #060911;
        --bg-card: #0c1322;
        --bg-elevated: #111b2e;
        --border-subtle: #1b2840;
        --border-accent: #2b3f63;
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
        --accent-blue: #38bdf8;
        --accent-indigo: #818cf8;
        --accent-crimson: #f43f5e;
        --accent-emerald: #10b981;
        --accent-amber: #fbbf24;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif !important;
        background-color: var(--bg-base) !important;
        color: var(--text-main) !important;
    }
    .stApp { background-color: var(--bg-base); }

    @keyframes pulseGlow {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.65); }
        70% { box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    @keyframes pulseRed {
        0% { box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.75); }
        70% { box-shadow: 0 0 0 8px rgba(244, 63, 94, 0); }
        100% { box-shadow: 0 0 0 0 rgba(244, 63, 94, 0); }
    }

    .soc-hero {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 16px;
        padding: 16px 22px;
        margin-bottom: 16px;
        background: linear-gradient(120deg, #0d1628 0%, #09101d 60%, #11172b 100%);
        border: 1px solid var(--border-accent);
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
    }
    .soc-title {
        font-size: 20px;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: var(--text-main);
        margin-bottom: 4px;
    }
    .soc-subtitle {
        font-size: 13px;
        color: var(--text-muted);
    }
    .soc-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11.5px;
        padding: 7px 14px;
        border-radius: 999px;
        font-weight: 700;
        letter-spacing: 0.04em;
        white-space: nowrap;
    }
    .dot-green {
        width: 8px; height: 8px; border-radius: 50%;
        background: #34d399;
        animation: pulseGlow 1.8s infinite;
    }
    .dot-red {
        width: 8px; height: 8px; border-radius: 50%;
        background: #fb7185;
        animation: pulseRed 1.3s infinite;
    }
    .badge-live {
        background: rgba(16, 185, 129, 0.14);
        border: 1px solid rgba(16, 185, 129, 0.45);
        color: #34d399;
    }
    .badge-alert {
        background: rgba(244, 63, 94, 0.16);
        border: 1px solid rgba(244, 63, 94, 0.55);
        color: #fda4af;
    }
    .badge-blocked {
        background: rgba(56, 189, 248, 0.14);
        border: 1px solid rgba(56, 189, 248, 0.5);
        color: #7dd3fc;
    }

    .story-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        margin: 12px 0 18px 0;
    }
    .story-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 12px 14px;
    }
    .story-card.active-green { border-color: rgba(16, 185, 129, 0.45); background: rgba(16, 185, 129, 0.06); }
    .story-card.active-red { border-color: rgba(244, 63, 94, 0.5); background: rgba(244, 63, 94, 0.08); }
    .story-card.active-blue { border-color: rgba(56, 189, 248, 0.45); background: rgba(56, 189, 248, 0.06); }
    .story-step {
        font-family: 'JetBrains Mono', monospace;
        font-size: 10.5px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-muted);
        margin-bottom: 4px;
    }
    .story-val {
        font-size: 14px;
        font-weight: 700;
        color: var(--text-main);
    }
    .story-desc {
        font-size: 12px;
        color: var(--text-muted);
        margin-top: 3px;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, #0e1628 0%, #090f1c 100%);
        border: 1px solid var(--border-subtle);
        border-top: 2px solid var(--accent-blue);
        border-radius: 10px;
        padding: 14px 16px;
        box-shadow: 0 6px 16px rgba(0, 0, 0, 0.25);
    }
    div[data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        color: var(--text-main) !important;
        font-size: 22px !important;
        font-weight: 700 !important;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 12px !important;
        font-weight: 600 !important;
        color: var(--text-muted) !important;
    }

    .section-title {
        font-size: 15px;
        font-weight: 700;
        color: var(--text-main);
        margin: 18px 0 2px 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .section-caption {
        font-size: 12.5px;
        color: var(--text-muted);
        margin-bottom: 10px;
    }

    .soc-term {
        background-color: #050912;
        border: 1px solid var(--border-accent);
        border-left: 3px solid var(--accent-blue);
        border-radius: 8px;
        padding: 12px 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #e2e8f0;
        line-height: 1.55;
        white-space: pre-wrap;
        word-break: break-word;
    }
    .soc-term-amber {
        border-left-color: var(--accent-amber);
        background: #070b14;
    }

    .banner-red {
        background: linear-gradient(90deg, rgba(244, 63, 94, 0.16) 0%, rgba(244, 63, 94, 0.04) 100%);
        border: 1px solid rgba(244, 63, 94, 0.45);
        color: #fda4af;
        font-size: 13px;
        font-weight: 600;
        padding: 12px 16px;
        border-radius: 10px;
        margin: 8px 0 14px 0;
    }
    .banner-green {
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.14) 0%, rgba(16, 185, 129, 0.03) 100%);
        border: 1px solid rgba(16, 185, 129, 0.4);
        color: #6ee7b7;
        font-size: 13px;
        font-weight: 600;
        padding: 12px 16px;
        border-radius: 10px;
        margin: 8px 0 14px 0;
    }

    .stButton>button {
        background: linear-gradient(180deg, #182742 0%, #0f182a 100%) !important;
        color: var(--text-main) !important;
        border: 1px solid var(--border-accent) !important;
        border-radius: 8px !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        padding: 9px 16px !important;
        transition: all 0.2s ease;
    }
    .stButton>button:hover {
        border-color: var(--accent-blue) !important;
        box-shadow: 0 0 14px rgba(56, 189, 248, 0.22) !important;
        color: #ffffff !important;
    }

    section[data-testid="stSidebar"] {
        background-color: #070b14 !important;
        border-right: 1px solid var(--border-subtle) !important;
    }
    .stDataFrame {
        border: 1px solid var(--border-subtle) !important;
        border-radius: 8px;
    }
</style>
""",
    unsafe_allow_html=True,
)


# --- Session State Initialization ---
defaults = {
    "live_records": [],
    "is_capturing": False,
    "nmap_output": None,
    "mitigation_log": [],
    "capture_start_time": None,
    "uploaded_df": None,
    "uploaded_file_sig": None,
    "async_sniffer": None,
    "capture_warning": None,
    "gemini_api_key_input": "",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if "gemini_model" not in st.session_state:
    model, tag = init_gemini_model()
    st.session_state.gemini_model = model
    st.session_state.model_tag = tag

@st.cache_data(ttl=15, show_spinner=False)
def cached_local_host_ips() -> list[str]:
    return get_local_host_ips()


@st.cache_data(ttl=15, show_spinner=False)
def cached_capture_interfaces():
    return list_capture_interfaces()


@st.cache_data(ttl=60, show_spinner=False)
def cached_nmap_installed() -> bool:
    return find_nmap_binary() is not None


local_host_ips = cached_local_host_ips()
admin_ok = is_admin()
nmap_installed = cached_nmap_installed()

# --- Sidebar Controls ---
st.sidebar.markdown("### 1. Traffic Source")
mode = st.sidebar.radio(
    "Choose how packets enter the dashboard:",
    [
        "Live Network Monitor",
        "Analyze PCAP File",
    ],
)

selected_iface = None
bpf_filter = ""
if mode == "Live Network Monitor":
    ifaces = cached_capture_interfaces()
    if ifaces:
        iface_map = {}
        iface_labels = []
        for idx, (dev_name, lbl) in enumerate(ifaces):
            unique_lbl = lbl if lbl not in iface_map else f"{lbl} [{idx}]"
            iface_map[unique_lbl] = dev_name
            iface_labels.append(unique_lbl)
        chosen_lbl = st.sidebar.selectbox("Network Adapter", iface_labels)
        selected_iface = iface_map.get(chosen_lbl)
    bpf_filter = st.sidebar.text_input(
        "Capture Filter (Optional)",
        value="tcp port 8080",
        help="Focuses live capture on demo port 8080. Clear to capture all traffic.",
    )
elif st.session_state.is_capturing:
    st.session_state.is_capturing = False
    stop_real_capture(st.session_state.async_sniffer)
    st.session_state.async_sniffer = None

st.sidebar.markdown("### 2. Detection & Auto-Defense")
ddos_threshold = st.sidebar.slider("Attack Threshold (Packets / Sec)", 20, 500, 35, 5)
defense_mode = st.sidebar.radio(
    "Response Policy",
    [
        "Active Containment (Auto-Drop Attacker)",
        "Monitor Mode (Audit Only)",
    ],
)

uploaded_file = None
if mode == "Analyze PCAP File":
    uploaded_file = st.sidebar.file_uploader("Upload PCAP capture", type=["pcap", "pcapng"])

with st.sidebar.expander("AI Triage Settings (Optional)", expanded=False):
    api_key_in = st.text_input(
        "Google Gemini API Key",
        value=st.session_state.gemini_api_key_input,
        type="password",
        placeholder="Paste key or set GOOGLE_API_KEY",
    )
    if api_key_in != st.session_state.gemini_api_key_input:
        st.session_state.gemini_api_key_input = api_key_in
        model, tag = init_gemini_model(api_key_in)
        st.session_state.gemini_model = model
        st.session_state.model_tag = tag
    st.caption(f"Engine: `{st.session_state.model_tag}`")

st.sidebar.markdown("---")
st.sidebar.markdown("### 3. System Status & Cleanup")
if local_host_ips:
    st.sidebar.caption(f"Laptop IP: `{', '.join(local_host_ips)}`")
else:
    st.sidebar.caption("Laptop IP: Not connected")

if is_windows():
    if admin_ok:
        st.sidebar.success("Admin Mode: Ready for Live Capture & Firewall")
    else:
        st.sidebar.warning("Open terminal as Administrator for live firewall blocking.")
st.sidebar.caption(f"Nmap Scanner: {'Installed' if nmap_installed else 'Not installed (optional)'}")

if st.sidebar.button("Flush Active Firewall Rules", use_container_width=True):
    tracked = [entry["Attacking IP"] for entry in st.session_state.mitigation_log]
    ok, msg = flush_soar_firewall_rules(tracked)
    if ok:
        st.session_state.mitigation_log = []
        st.sidebar.success(msg)
    else:
        st.sidebar.error(msg)

# Drain Thread-Safe Packet Buffer
new_packets = drain_packet_buffer()
if new_packets:
    base_id = len(st.session_state.live_records)
    for idx, pkt_data in enumerate(new_packets, start=1):
        pkt_data["Packet ID"] = base_id + idx
        st.session_state.live_records.append(pkt_data)

if len(st.session_state.live_records) > 2500:
    st.session_state.live_records = st.session_state.live_records[-2000:]

# --- Capture Controls ---
if mode != "Analyze PCAP File":
    c1, c2 = st.columns([1.4, 1.0])
    with c1:
        if not st.session_state.is_capturing:
            if st.button("▶ Start Live Monitoring", use_container_width=True):
                st.session_state.is_capturing = True
                st.session_state.capture_start_time = time.time()
                st.session_state.capture_warning = None
                sniffer, err = start_real_capture(selected_iface, bpf_filter)
                st.session_state.async_sniffer = sniffer
                if sniffer is None:
                    st.session_state.is_capturing = False
                    st.session_state.capture_warning = (
                        f"Could not start live packet sniffer: {err}. "
                        "Make sure Npcap is installed and PowerShell is running as Administrator."
                    )
                elif err:
                    st.session_state.capture_warning = err
                st.rerun()
        else:
            if st.button("⏸ Pause Capture", use_container_width=True):
                st.session_state.is_capturing = False
                stop_real_capture(st.session_state.async_sniffer)
                st.session_state.async_sniffer = None
                st.rerun()
    with c2:
        if st.button("🗑 Reset Data", use_container_width=True):
            clear_packet_buffer()
            st.session_state.live_records = []
            st.session_state.mitigation_log = []
            st.session_state.nmap_output = None
            st.session_state.capture_warning = None
            st.rerun()

    if st.session_state.capture_warning:
        st.warning(st.session_state.capture_warning)

    raw_df = pd.DataFrame(st.session_state.live_records)

else:
    if uploaded_file is not None:
        file_sig = (uploaded_file.name, uploaded_file.size)
        if st.session_state.uploaded_file_sig != file_sig:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(uploaded_file.getbuffer())
                tmp_path = tmp.name
            rows = []
            try:
                with PcapReader(tmp_path) as reader:
                    for idx, pkt in enumerate(reader):
                        r = parse_packet_data(pkt)
                        if r:
                            r["Packet ID"] = idx + 1
                            rows.append(r)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            st.session_state.uploaded_df = pd.DataFrame(rows)
            st.session_state.uploaded_file_sig = file_sig
            st.sidebar.success(f"Loaded {len(rows):,} packets from PCAP")
        raw_df = st.session_state.uploaded_df
    else:
        st.session_state.uploaded_df = None
        st.session_state.uploaded_file_sig = None
        raw_df = pd.DataFrame()

# ==============================================================================
# MAIN DASHBOARD
# ==============================================================================
if not raw_df.empty:
    raw_df["Timestamp_dt"] = to_local_naive_dt(raw_df["Timestamp"])
    raw_df["Second_Bucket"] = raw_df["Timestamp_dt"].dt.floor("1s")

    packet_rates = (
        raw_df.set_index("Timestamp_dt").resample("1s").size().rename("Packet Rate").reset_index()
    )
    # Require sustained 2-second rate above threshold so normal page loads don't false-trigger
    sustained_rate = (
        packet_rates["Packet Rate"].rolling(window=2, min_periods=2).mean()
        if len(packet_rates) >= 2
        else pd.Series([0] * len(packet_rates), index=packet_rates.index)
    )
    attack_windows = packet_rates[sustained_rate > ddos_threshold]
    is_attack = not attack_windows.empty

    # Top Talkers summary (aligned with 2-second sustained detection)
    per_sec_ip = raw_df.groupby(["Source IP", "Second_Bucket"]).size()
    sustained_ip = (
        per_sec_ip.groupby(level=0)
        .apply(lambda s: s.rolling(window=2, min_periods=2).mean().max() if len(s) >= 2 else 0)
        .fillna(0)
        .astype(int)
    )
    peak_ip = per_sec_ip.groupby(level=0).max()
    top_sources = raw_df["Source IP"].value_counts().reset_index()
    top_sources.columns = ["Source IP", "Packets"]
    top_sources["Peak PPS"] = top_sources["Source IP"].map(peak_ip).fillna(0).astype(int)
    top_sources["Sustained PPS"] = top_sources["Source IP"].map(sustained_ip).fillna(0).astype(int)
    top_sources["Risk Level"] = top_sources["Sustained PPS"].apply(
        lambda pps: "CRITICAL"
        if pps > ddos_threshold
        else ("SUSPICIOUS" if pps >= max(10, int(ddos_threshold * 0.6)) else "NORMAL")
    )

    # Identify attacker inside the attack window (never pick our own host IP)
    protected_ips = set(local_host_ips) | {"127.0.0.1", "0.0.0.0", "Unknown"}
    top_attacker_ip = None
    if is_attack:
        attack_secs = set(attack_windows["Timestamp_dt"])
        window_df = raw_df[raw_df["Second_Bucket"].isin(attack_secs)]
        candidates = window_df[~window_df["Source IP"].isin(protected_ips)]["Source IP"].value_counts()
        if not candidates.empty:
            top_attacker_ip = candidates.index[0]
    if not top_attacker_ip:
        ext_sources = top_sources[~top_sources["Source IP"].isin(protected_ips)]
        if not ext_sources.empty:
            top_attacker_ip = ext_sources.iloc[0]["Source IP"]
        elif not top_sources.empty:
            top_attacker_ip = top_sources.iloc[0]["Source IP"]

    # Automated Containment Action
    if is_attack and "Active" in defense_mode and top_attacker_ip:
        already_logged = any(
            entry["Attacking IP"] == top_attacker_ip for entry in st.session_state.mitigation_log
        )
        if not already_logged:
            ok, kernel_log_msg = enforce_firewall_drop(
                top_attacker_ip, protected_ips=list(protected_ips)
            )
            action_label = (
                "Windows Firewall Block" if is_windows() else "iptables DROP"
            )
            st.session_state.mitigation_log.append(
                {
                    "Attacking IP": top_attacker_ip,
                    "Peak Rate": f"{int(packet_rates['Packet Rate'].max())} PPS",
                    "Detection Time": datetime.datetime.now().strftime("%H:%M:%S"),
                    "Detection Epoch": time.time(),
                    "Success": ok,
                    "Action Taken": action_label if ok else "BLOCK FAILED",
                    "Status Details": kernel_log_msg,
                }
            )

    current_pps = int(packet_rates.iloc[-1]["Packet Rate"]) if not packet_rates.empty else 0
    peak_pps = int(packet_rates["Packet Rate"].max()) if not packet_rates.empty else 0
    active_rule_count = sum(1 for e in st.session_state.mitigation_log if e.get("Success", False))
    blocked_active = active_rule_count > 0

    # Compute per-second rate series for the primary attacker
    attacker_series = None
    if top_attacker_ip:
        att_df = raw_df[raw_df["Source IP"] == top_attacker_ip]
        if not att_df.empty:
            attacker_series = att_df.set_index("Timestamp_dt").resample("1s").size()

    # Hero Header + Narrative Summary
    if blocked_active:
        badge_html = '<div class="soc-badge badge-blocked"><span class="dot-green"></span>THREAT CONTAINED</div>'
        hero_summary = (
            f"Volumetric spike from <b>{html.escape(str(top_attacker_ip))}</b> reached "
            f"<b>{peak_pps} PPS</b> and was automatically blocked by the firewall."
        )
    elif is_attack:
        badge_html = '<div class="soc-badge badge-alert"><span class="dot-red"></span>ATTACK DETECTED</div>'
        hero_summary = (
            f"Traffic exceeded the <b>{ddos_threshold} PPS</b> limit (peaked at <b>{peak_pps} PPS</b>). "
            f"Primary source: <b>{html.escape(str(top_attacker_ip))}</b>."
        )
    else:
        badge_html = '<div class="soc-badge badge-live"><span class="dot-green"></span>NETWORK HEALTHY</div>'
        hero_summary = (
            f"Live monitoring active. Traffic is operating smoothly below the "
            f"<b>{ddos_threshold} PPS</b> alert limit."
        )

    st.markdown(
        f"""
    <div class="soc-hero">
        <div>
            <div class="soc-title">SOAR Network Defense Center</div>
            <div class="soc-subtitle">{hero_summary}</div>
        </div>
        {badge_html}
    </div>
    """,
        unsafe_allow_html=True,
    )

    # 3-Step Incident Story Strip
    step1_cls = "active-blue" if st.session_state.is_capturing or mode == "Analyze PCAP File" else ""
    step2_cls = "active-red" if is_attack else "active-green"
    step3_cls = "active-green" if blocked_active else ("active-red" if is_attack else "")

    step1_text = "Capturing Live Packets" if st.session_state.is_capturing else ("Forensic PCAP Loaded" if mode == "Analyze PCAP File" else "Capture Paused")
    step2_text = f"Flood Detected ({peak_pps} PPS)" if is_attack else "Normal Traffic Flow"
    step3_text = (
        f"Blocked {st.session_state.mitigation_log[-1]['Attacking IP']}"
        if blocked_active
        else ("Audit Mode (No Auto-Block)" if "Monitor" in defense_mode else "Standing By")
    )

    st.markdown(
        f"""
    <div class="story-grid">
        <div class="story-card {step1_cls}">
            <div class="story-step">Step 1 · Telemetry</div>
            <div class="story-val">{html.escape(step1_text)}</div>
            <div class="story-desc">{len(raw_df):,} packets from {raw_df['Source IP'].nunique():,} node(s)</div>
        </div>
        <div class="story-card {step2_cls}">
            <div class="story-step">Step 2 · Detection</div>
            <div class="story-val">{html.escape(step2_text)}</div>
            <div class="story-desc">Current: {current_pps} PPS · Limit: {ddos_threshold} PPS</div>
        </div>
        <div class="story-card {step3_cls}">
            <div class="story-step">Step 3 · Auto-Response</div>
            <div class="story-val">{html.escape(step3_text)}</div>
            <div class="story-desc">{html.escape(defense_mode)}</div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # KPI Metric Strip
    m1, m2, m3, m4 = st.columns(4)
    m1.metric(
        "Current Speed",
        f"{current_pps} PPS",
        delta=f"Peak: {peak_pps} PPS",
        delta_color="inverse" if current_pps > ddos_threshold else "normal",
    )
    m2.metric("Packets Captured", f"{len(raw_df):,}", delta=f"{raw_df['Source IP'].nunique():,} source IPs")
    m3.metric("Primary Node", str(top_attacker_ip or "None"))
    m4.metric("Firewall Rules Active", f"{active_rule_count}")

    # Incident Timeline Chart
    st.markdown("<div class='section-title'>📈 Traffic & Incident Timeline</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='section-caption'>"
        "Smooth curves compare <b>Total Traffic</b>, the <b>Top Source IP</b>, and the <b>Baseline Trend</b>. "
        "Shaded red zones show when traffic breached the limit, and green markers show when the firewall blocked the attacker."
        "</div>",
        unsafe_allow_html=True,
    )
    fig = build_incident_timeline_chart(
        packet_rates=packet_rates,
        attacker_rates=attacker_series,
        top_attacker_ip=top_attacker_ip,
        ddos_threshold=ddos_threshold,
        mitigation_log=st.session_state.mitigation_log,
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    # Operations Split
    col_left, col_right = st.columns([1.15, 1])

    with col_left:
        st.markdown("<div class='section-title'>🌐 Top Traffic Sources</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-caption'>Devices sending the highest volume of packets to your laptop.</div>",
            unsafe_allow_html=True,
        )
        st.dataframe(top_sources.head(8), use_container_width=True, height=220, hide_index=True)

        st.markdown("<div class='section-title'>🛡️ Automated Firewall Audit Log</div>", unsafe_allow_html=True)
        if st.session_state.mitigation_log:
            display_log = [
                {k: v for k, v in entry.items() if k not in {"Detection Epoch", "Success"}}
                for entry in st.session_state.mitigation_log
            ]
            st.dataframe(pd.DataFrame(display_log), use_container_width=True, height=140, hide_index=True)
        else:
            st.markdown(
                "<div class='soc-term' style='color:#94a3b8;'>No IPs blocked yet. Firewall activates automatically if traffic exceeds the threshold in Active Containment mode.</div>",
                unsafe_allow_html=True,
            )

    with col_right:
        st.markdown("<div class='section-title'>🔍 Host Recon & AI Incident Report</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='section-caption'>Scan a suspicious IP with Nmap and generate a 3-point SOC summary.</div>",
            unsafe_allow_html=True,
        )

        sorted_ips = [ip for ip in top_sources["Source IP"].tolist() if ip not in {"0.0.0.0", "Unknown"}]
        selected_ip = st.selectbox("Select Target IP:", sorted_ips) if sorted_ips else None

        recon_profile = st.radio(
            "Scan Depth:",
            ["Quick Port Scan (-Pn -F -T4)", "Deep Service & OS (-Pn -sV -O --host-timeout 10s -T4)"],
            horizontal=True,
        )
        flags = "-Pn -F -T4" if "Quick" in recon_profile else "-Pn -sV -O --host-timeout 10s -T4"

        if selected_ip:
            if st.button("Initiate Active Scan", use_container_width=True):
                with st.spinner(f"Scanning {selected_ip}..."):
                    cmd, out = run_direct_nmap(selected_ip, flags)
                    st.session_state.nmap_output = (cmd, out)

        if st.session_state.nmap_output:
            cmd, out = st.session_state.nmap_output
            safe_cmd = html.escape(cmd)
            safe_out = html.escape(out).replace("\n", "<br>")
            st.markdown(
                f"""
            <div class="soc-term">
            <span style="color:#38bdf8;">$ {safe_cmd}</span><br>
            ----------------------------------------------------------------------<br>
            {safe_out}
            </div>
            """,
                unsafe_allow_html=True,
            )
            st.markdown(
                generate_ai_threat_summary(
                    out,
                    st.session_state.gemini_model,
                    st.session_state.model_tag,
                ),
                unsafe_allow_html=True,
            )

    # Dissector Stream
    st.markdown("<div class='section-title'>📦 Live Packet Inspector</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='section-caption'>Latest 100 captured network frames (newest at the top).</div>",
        unsafe_allow_html=True,
    )
    disp_cols = ["Packet ID", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Summary"]
    st.dataframe(raw_df[disp_cols].tail(100).iloc[::-1], use_container_width=True, height=210, hide_index=True)

    with st.expander("Inspect Individual Frame (Hex & ASCII Decode)", expanded=False):
        max_pkt_id = int(raw_df["Packet ID"].max())
        min_pkt_id = int(raw_df["Packet ID"].min())
        p_inspect = st.number_input(
            "Enter Packet ID:",
            min_value=min_pkt_id,
            max_value=max_pkt_id,
            value=max_pkt_id,
        )
        inspect_row = raw_df[raw_df["Packet ID"] == p_inspect]
        if not inspect_row.empty:
            p = inspect_row.iloc[0]
            pl, pr = st.columns(2)
            with pl:
                st.markdown(
                    f"""
                <div class="soc-term">
                <b>[FRAME #{int(p['Packet ID'])} DETAILS]</b><br>
                Time      : {html.escape(str(p['Time']))}<br>
                Protocol  : {html.escape(str(p['Protocol']))} (Port {int(p['Source Port'])} -&gt; {int(p['Destination Port'])})<br>
                From IP   : {html.escape(str(p['Source IP']))} ({html.escape(str(p['Location']))})<br>
                To IP     : {html.escape(str(p['Destination IP']))}<br>
                Size/TTL  : {int(p['Length'])} Bytes / TTL {html.escape(str(p['TTL']))}
                </div>
                """,
                    unsafe_allow_html=True,
                )
            with pr:
                st.markdown(
                    f"""
                <div class="soc-term soc-term-amber">
                <b>[HEX DUMP]</b><br>{html.escape(str(p['Hex']))}<br><br>
                <b>[ASCII DECODE]</b><br>{html.escape(str(p['Ascii']))}
                </div>
                """,
                    unsafe_allow_html=True,
                )

else:
    st.markdown(
        """
    <div class="soc-hero">
        <div>
            <div class="soc-title">SOAR Network Defense Center</div>
            <div class="soc-subtitle">Ready to capture live packets, detect volumetric floods, and automatically block attackers.</div>
        </div>
        <div class="soc-badge badge-live"><span class="dot-green"></span>STANDBY</div>
    </div>
    """,
        unsafe_allow_html=True,
    )
    if mode == "Analyze PCAP File":
        st.info("Forensic Engine Ready. Upload a `.pcap` or `.pcapng` file using the left sidebar.")
    else:
        st.info("Click **▶ Start Live Monitoring** above to start capturing traffic and plotting the live timeline.")

# Live loop refresh while acquisition is running
if st.session_state.is_capturing:
    time.sleep(1.0)
    st.rerun()
