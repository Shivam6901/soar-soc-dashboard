"""Automated unit and integration test suite for the SOAR Network Defense Center."""

import os
import sys
import time
import unittest

import pandas as pd
from scapy.all import Ether, IP, TCP
from streamlit.testing.v1 import AppTest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import capture
import charts
import firewall
import recon
import target_server


class TestSOARComponents(unittest.TestCase):
    def test_tc01_firewall_ip_validation_and_self_guard(self):
        self.assertFalse(firewall.validate_blockable_ip("127.0.0.1")[0])
        self.assertFalse(firewall.validate_blockable_ip("0.0.0.0")[0])
        self.assertFalse(firewall.validate_blockable_ip("not-an-ip")[0])
        self.assertFalse(firewall.validate_blockable_ip("172.16.211.73", ["172.16.211.73"])[0])
        ok, clean = firewall.validate_blockable_ip("172.20.10.1", ["172.20.10.2"])
        self.assertTrue(ok)
        self.assertEqual(clean, "172.20.10.1")

    def test_tc02_capture_buffer_cap_and_port_filtering(self):
        self.assertEqual(capture._PACKET_BUFFER.maxlen, 2500)
        capture._ALLOWED_PORT = 8080
        try:
            eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            p_ui = eth / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=51000, dport=8501)
            p_other = eth / IP(src="192.168.1.5", dst="10.0.0.1") / TCP(sport=51000, dport=80)
            p_demo = eth / IP(src="172.20.10.1", dst="172.20.10.2") / TCP(sport=51000, dport=8080)
            self.assertIsNone(capture.parse_packet_data(p_ui, light_mode=True))
            self.assertIsNone(capture.parse_packet_data(p_other, light_mode=True))
            self.assertIsNotNone(capture.parse_packet_data(p_other, light_mode=False))
            row = capture.parse_packet_data(p_demo, light_mode=True)
            self.assertIsNotNone(row)
            self.assertEqual(row["Destination Port"], 8080)
        finally:
            capture._ALLOWED_PORT = None

    def test_tc03_interface_discovery_auto_first(self):
        ifaces = capture.list_capture_interfaces()
        self.assertGreaterEqual(len(ifaces), 1)
        self.assertEqual(ifaces[0][0], "AUTO_ALL")

    def test_tc04_benchmark_pcap_generation_and_readback(self):
        tmp_pcap = os.path.join(PROJECT_DIR, "tests", "_tmp_bench.pcap")
        try:
            capture.generate_benchmark_pcap(tmp_pcap, num_normal_packets=50, num_ddos_packets=150)
            self.assertTrue(os.path.exists(tmp_pcap))
            self.assertGreater(os.path.getsize(tmp_pcap), 1000)
        finally:
            if os.path.exists(tmp_pcap):
                os.remove(tmp_pcap)

    def test_tc05_timeline_chart_and_local_tz_markers(self):
        now = time.time()
        dt = charts.to_local_naive_dt(pd.Series([now - 4, now - 3, now - 2, now - 1, now]))
        pr = pd.DataFrame({"Timestamp_dt": dt, "Packet Rate": [12, 18, 95, 180, 15]})
        att = pd.Series([8, 10, 90, 175, 0], index=dt)
        fig = charts.build_incident_timeline_chart(
            pr,
            att,
            "172.20.10.1",
            35,
            [{"Attacking IP": "172.20.10.1", "Detection Epoch": now - 1, "Success": True}],
        )
        self.assertEqual(len(fig.data), 4)
        self.assertGreaterEqual(len(fig.layout.shapes), 3)
        self.assertGreaterEqual(len(fig.layout.annotations), 2)

    def test_tc06_recon_fallback_and_ai_summary(self):
        cmd, out = recon.run_direct_nmap("127.0.0.1", "-Pn -F -T4")
        self.assertIn("127.0.0.1", cmd)
        self.assertTrue(len(out) > 20)
        html_report = recon.generate_ai_threat_summary("<script>alert(1)</script>", None, "SOC Rule Core")
        self.assertIn("INCIDENT TRIAGE REPORT", html_report)
        self.assertNotIn("<script>", html_report)

    def test_tc07_client_load_simulator_html_and_backlog(self):
        self.assertEqual(target_server.ThreadedHTTPServer.request_queue_size, 128)
        self.assertIn("Client Traffic Load Simulator", target_server.DEMO_HTML)
        self.assertNotIn("iPhone", target_server.DEMO_HTML)

    def test_tc08_streamlit_dashboard_integration(self):
        capture.clear_packet_buffer()
        old_cwd = os.getcwd()
        os.chdir(PROJECT_DIR)
        try:
            at = AppTest.from_file("streamlit_app.py")
            at.run(timeout=15)
            self.assertFalse(at.exception)
            capture.simulated_traffic_tick(0.5)
            capture.simulated_traffic_tick(5.5)
            at.radio[1].set_value("Monitor Mode (Audit Only)")
            at.run(timeout=15)
            self.assertFalse(at.exception)
            self.assertEqual(len(at.metric), 4)
            self.assertEqual(len(at.dataframe), 2)
        finally:
            capture.clear_packet_buffer()
            os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
