"""Helper script to generate a sample test_traffic.pcap for offline PCAP testing."""

from capture import generate_benchmark_pcap

if __name__ == "__main__":
    out = generate_benchmark_pcap("test_traffic.pcap")
    print(f"Created benchmark PCAP: {out}")
