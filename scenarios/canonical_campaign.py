"""Deterministic canonical campaign event generator.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 24, testing.md section 19.

Produces the 7 canonical beats in deterministic chronological order:
1. T+00:00   reconnaissance / scan
2. T+00:30   beaconing (C2)
3. T+01:30   DGA burst
4. T+02:30   DNS tunnel
5. T+03:30   exfiltration
6. T+04:30   suspicious TLS/QUIC session
7. T+05:30   volumetric DDoS/flood
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent


def generate_canonical_campaign_events(
    start_time: float = 1773280000.0,
    ddos_packets_per_window: int = 6000,
) -> list[NormalizedEvent]:
    """Generate the deterministic sequence of normalized events comprising the canonical campaign."""
    events: list[NormalizedEvent] = []
    cap_pcap = CapabilityState(InputMode.PCAP_REPLAY)

    # --------------------------------------------------------------------------
    # Beat 1: Reconnaissance / Vertical Port Scan (T+00:00 to T+00:15)
    # --------------------------------------------------------------------------
    scan_src = "192.168.1.100"
    scan_dst = "10.0.0.50"
    t_scan = start_time
    for p in range(1, 106):
        events.append(
            NormalizedEvent.from_flow(
                observed_time=t_scan + p * 0.05,
                input_mode=InputMode.PCAP_REPLAY,
                capability=cap_pcap,
                src_ip=scan_src,
                dst_ip=scan_dst,
                src_port=40000 + p,
                dst_port=p,
                protocol="TCP",
                tcp_flags="S",
                packets=1,
                bytes=60,
            )
        )

    # --------------------------------------------------------------------------
    # Beat 2: Botnet C2 Periodic Beaconing (T+00:30 to T+01:20)
    # --------------------------------------------------------------------------
    c2_src = "10.0.0.22"
    c2_dst = "198.51.100.44"
    c2_port = 8443
    t_c2 = start_time + 30.0
    intervals = [5.01, 4.99, 5.00, 5.02, 4.98, 5.01, 5.00, 4.99, 5.00, 5.01]
    curr_t = t_c2
    for interval in intervals:
        curr_t += interval
        events.append(
            NormalizedEvent.from_flow(
                observed_time=curr_t,
                input_mode=InputMode.PCAP_REPLAY,
                capability=cap_pcap,
                src_ip=c2_src,
                dst_ip=c2_dst,
                src_port=49152,
                dst_port=c2_port,
                protocol="TCP",
                tcp_flags="PA",
                packets=1,
                bytes=120,
            )
        )

    # --------------------------------------------------------------------------
    # Beat 3: DGA Query Burst (T+01:30 to T+02:00)
    # --------------------------------------------------------------------------
    dga_src = "10.0.0.45"
    t_dga = start_time + 90.0
    dga_domains = [
        "xzkjqwyfp7931.org",
        "qwrtyzxvbm992.net",
        "bdfhjlnprtxz12.com",
        "zxvcbmnlkjhg88.info",
        "mnbvcxzasdfg77.ru",
        "lkjhgfdsamnb55.com",
        "plokmijnuhby66.cc",
        "zaqxswcdevfr44.biz",
    ]
    for i, domain in enumerate(dga_domains):
        events.append(
            NormalizedEvent.from_flow(
                observed_time=t_dga + i * 1.5,
                input_mode=InputMode.PCAP_REPLAY,
                capability=cap_pcap,
                src_ip=dga_src,
                dst_ip="1.1.1.1",
                src_port=53000 + i,
                dst_port=53,
                protocol="UDP",
                dns={"qname": domain, "qtype": "A", "nxdomain": True, "rcode": 3},
                packets=1,
                bytes=78,
            )
        )

    # --------------------------------------------------------------------------
    # Beat 4: DNS Tunnelling (T+02:30 to T+03:10)
    # --------------------------------------------------------------------------
    tunnel_src = "10.0.0.60"
    t_tunnel = start_time + 150.0
    for i in range(8):
        qname = f"chunk{i:02d}.a89bf234cde780ffff.tunnel.exfil-corp.attacker.org"
        events.append(
            NormalizedEvent.from_flow(
                observed_time=t_tunnel + i * 2.0,
                input_mode=InputMode.PCAP_REPLAY,
                capability=cap_pcap,
                src_ip=tunnel_src,
                dst_ip="8.8.8.8",
                src_port=53100 + i,
                dst_port=53,
                protocol="UDP",
                dns={"qname": qname, "qtype": "TXT", "nxdomain": False, "rcode": 0},
                packets=1,
                bytes=160,
            )
        )

    # --------------------------------------------------------------------------
    # Beat 5: Data Exfiltration (T+03:30 to T+04:10)
    # --------------------------------------------------------------------------
    exfil_src = "10.0.0.15"
    exfil_dst = "203.0.113.88"
    t_exfil = start_time + 210.0
    for i in range(5):
        events.append(
            NormalizedEvent.from_flow(
                observed_time=t_exfil + i * 3.0,
                input_mode=InputMode.PCAP_REPLAY,
                capability=cap_pcap,
                src_ip=exfil_src,
                dst_ip=exfil_dst,
                src_port=55000 + i,
                dst_port=443,
                protocol="TCP",
                flow_summary={
                    "bytes_toclient": 10_000,
                    "bytes_toserver": 3_000_000,
                    "pkts_toclient": 20,
                    "pkts_toserver": 2000,
                },
                direction="outbound",
                packets=2020,
                bytes=3_010_000,
            )
        )

    # --------------------------------------------------------------------------
    # Beat 6: Suspicious Encrypted Session / TLS (T+04:30 to T+05:00)
    # --------------------------------------------------------------------------
    tls_src = "10.0.0.75"
    tls_dst = "198.51.100.99"
    t_tls = start_time + 270.0
    events.append(
        NormalizedEvent.from_flow(
            observed_time=t_tls,
            input_mode=InputMode.PCAP_REPLAY,
            capability=cap_pcap,
            src_ip=tls_src,
            dst_ip=tls_dst,
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            tls={
                "ja3": "6734f37431670b3ab4292b8faea04307",
                "ja3s": "ec74a5c5110605f9f8eac84b7252e1fb",
                "ja4": "t13d1516h2_8daaf6152771_02711d04b684",
                "sni": "unknown-cdn-edge.net",
            },
            shape={
                "packet_size_first_n": [240, 1420, 180, 520, 1420],
                "direction_first_n": ["c2s", "s2c", "c2s", "c2s", "s2c"],
            },
            packets=5,
            bytes=3800,
        )
    )

    # --------------------------------------------------------------------------
    # Beat 7: Volumetric DDoS / SYN Flood (T+05:30 to T+06:00)
    # --------------------------------------------------------------------------
    ddos_target = "10.0.0.5"
    ddos_port = 80
    t_ddos = start_time + 330.0

    # Emit two consecutive tumbling windows (1.0s each) with high packet counts to satisfy hysteresis
    for w_idx in range(2):
        w_start = t_ddos + w_idx * 1.0
        # Intersperse packets across 1.0s
        step = 0.95 / ddos_packets_per_window
        for p_idx in range(ddos_packets_per_window):
            # Spoofed sources
            src_ip = f"198.51.100.{(p_idx % 200) + 1}"
            events.append(
                NormalizedEvent.from_flow(
                    observed_time=w_start + p_idx * step,
                    input_mode=InputMode.PCAP_REPLAY,
                    capability=cap_pcap,
                    src_ip=src_ip,
                    dst_ip=ddos_target,
                    src_port=10000 + (p_idx % 50000),
                    dst_port=ddos_port,
                    protocol="TCP",
                    tcp_flags="S",
                    packets=1,
                    bytes=60,
                )
            )

    # Ensure chronological order
    events.sort(key=lambda e: float(e.observed_time if isinstance(e.observed_time, (int, float)) else e.observed_time.timestamp()))
    return events
