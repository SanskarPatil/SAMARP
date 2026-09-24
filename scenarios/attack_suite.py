"""Labelled SYNTHETIC attack suite for evaluation (PS-compliance task 5).

Generates several instances per PS class a-f, including deliberately weak or
borderline variants, so recall is measured on more than one example and
detector limits become visible.  Every instance carries ground truth:

    AttackLabel(attack_id, ps_letter, ps_class, variant, key_ips, t_start, t_end)

``key_ips`` are the addresses an analyst would use to attribute an alert to
the attack (attacker source and, where meaningful, the victim / C2 server).
Traffic shapes emulate the PS-named tools (hping3 SYN/UDP flood, dnscat2 /
iodine TXT/NULL/CNAME tunnels, DGArchive-style families, a sandboxed C2
beacon) - no tool was run; this is Python emulation, labelled as such.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from random import Random

from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent
from models.dga_dataset import _extended_dga_label

PS_CLASSES = {
    "a": "Volumetric DDoS / flooding",
    "b": "Botnet C2 beaconing",
    "c": "DGA / DNS tunnelling",
    "d": "Malware in encrypted sessions",
    "e": "Port scanning / reconnaissance",
    "f": "Data exfiltration",
}
LETTER_OF = {name: letter for letter, name in PS_CLASSES.items()}


@dataclass(frozen=True)
class AttackLabel:
    attack_id: str
    ps_letter: str
    variant: str
    key_ips: frozenset[str]
    t_start: float
    t_end: float
    expected_hard: bool = False           # a variant we expect current detectors to miss
    n_events: int = 0

    @property
    def ps_class(self) -> str:
        return PS_CLASSES[self.ps_letter]


@dataclass
class _Builder:
    rng: Random
    cap: CapabilityState = field(default_factory=lambda: CapabilityState(InputMode.PCAP_REPLAY))
    events: list = field(default_factory=list)

    def flow(self, t, src, dst, sport, dport, proto, **kw):
        ev = NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=self.cap, src_ip=src, dst_ip=dst,
                                       src_port=sport, dst_port=dport, protocol=proto, **kw)
        self.events.append(ev)
        return ev


def _ddos(b: _Builder, t, victim, pps, sources, seconds, proto="TCP", port=80):
    rng = b.rng
    srcs = [f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(sources)]
    n = int(pps * seconds)
    for i in range(n):
        b.flow(t + i / pps, srcs[i % sources], victim, rng.randint(1024, 65535), port, proto,
               tcp_flags="S" if proto == "TCP" else None, packets=1, bytes=60 if proto == "TCP" else 512, direction="inbound")
    return t + seconds


def _beacon(b: _Builder, t, src, dst, period, jitter, count, port=443):
    for _ in range(count):
        b.flow(t, src, dst, 49152, port, "TCP", tcp_flags="PA", packets=2, bytes=b.rng.randint(180, 260), direction="outbound")
        t += period * (1 + b.rng.uniform(-jitter, jitter))
    return t


def _dga(b: _Builder, t, src, family, count, nx_rate, spacing=1.2):
    for i in range(count):
        nx = b.rng.random() < nx_rate
        qname = f"{_extended_dga_label(b.rng, family, i)}.{b.rng.choice(('com', 'net', 'info', 'xyz', 'top'))}"
        b.flow(t, src, "1.1.1.1", 53000 + i, 53, "UDP", dns={"qname": qname, "qtype": "A", "nxdomain": nx, "rcode": 3 if nx else 0},
               packets=2, bytes=90, direction="outbound")
        t += spacing
    return t


def _tunnel(b: _Builder, t, src, domain, qtype, label_len, count, spacing):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(count):
        chunk = "".join(b.rng.choice(alphabet) for _ in range(label_len))
        b.flow(t, src, "8.8.8.8", 53200 + i % 100, 53, "UDP", dns={"qname": f"{chunk}.{i:03d}.{domain}", "qtype": qtype, "nxdomain": False, "rcode": 0},
               packets=2, bytes=label_len + 120, direction="outbound")
        t += spacing
    return t


def _tls(b: _Builder, t, src, dst, ja3, sni, sessions, port=443, sizes=None, spacing=20.0):
    for _ in range(sessions):
        shape = {"packet_size_first_n": sizes or [240, 1420, 180, 520, 1420], "direction_first_n": ["c2s", "s2c", "c2s", "c2s", "s2c"]}
        tls = {"ja3": ja3, "ja3s": "ec74a5c5110605f9f8eac84b7252e1fb", "ja4": "t13d1516h2_8daaf6152771_02711d04b684"}
        if sni:
            tls["sni"] = sni
        b.flow(t, src, dst, b.rng.randint(49152, 65535), port, "TCP", tls=tls, shape=shape, packets=5, bytes=sum(shape["packet_size_first_n"]),
               direction="outbound")
        t += spacing
    return t


def _scan(b: _Builder, t, src, targets, ports, rate):
    i = 0
    for host in targets:
        for port in ports:
            b.flow(t + i / rate, src, host, 40000 + i % 20000, port, "TCP", tcp_flags="S", packets=1, bytes=60, direction="outbound")
            i += 1
    return t + i / rate


def _exfil(b: _Builder, t, src, dst, total_bytes, records, spacing):
    per = total_bytes // records
    for _ in range(records):
        b.flow(t, src, dst, 55000, 443, "TCP", packets=per // 1200, bytes=per, direction="outbound",
               flow_summary={"bytes_toserver": per, "bytes_toclient": 4_000, "pkts_toserver": per // 1200, "pkts_toclient": 8})
        t += spacing
    return t


def generate_attack_suite(seed: int = 11, start_time: float = 1773280000.0, first_offset: float = 300.0, gap: float = 210.0) -> tuple[list[NormalizedEvent], list[AttackLabel]]:
    """30 labelled attack instances, spaced ``gap`` seconds apart (stream time)."""
    rng = Random(seed)
    b = _Builder(rng)
    labels: list[AttackLabel] = []
    t = start_time + first_offset
    n = [0]

    def attacker():
        n[0] += 1
        return f"10.0.9.{n[0]}"

    def record(letter, variant, key_ips, t0, t1, hard=False, count_before=0):
        labels.append(AttackLabel(f"{letter}{sum(1 for l in labels if l.ps_letter == letter) + 1}", letter, variant, frozenset(key_ips), t0, t1, hard,
                                  len(b.events) - count_before))

    plan = [
        ("a", "SYN flood 6k pps, 200 spoofed src, 3 s", lambda s, t: ({"10.0.1.250"}, _ddos(b, t, "10.0.1.250", 6000, 200, 3)), False),
        ("a", "SYN flood 12k pps, 500 spoofed src, 3 s", lambda s, t: ({"10.0.1.251"}, _ddos(b, t, "10.0.1.251", 12000, 500, 3)), False),
        ("a", "UDP flood 8k pps to :53, 3 s", lambda s, t: ({"10.0.1.252"}, _ddos(b, t, "10.0.1.252", 8000, 300, 3, "UDP", 53)), False),
        ("a", "SYN flood 3k pps, 50 src, 4 s (below min_pps)", lambda s, t: ({"10.0.1.253"}, _ddos(b, t, "10.0.1.253", 3000, 50, 4)), True),
        ("a", "low-rate SYN 800 pps, 20 src, 5 s", lambda s, t: ({"10.0.1.254"}, _ddos(b, t, "10.0.1.254", 800, 20, 5)), True),
        ("b", "beacon 5 s, 1 % jitter", lambda s, t: ({s, "203.0.113.10"}, _beacon(b, t, s, "203.0.113.10", 5, 0.01, 12)), False),
        ("b", "beacon 20 s, 5 % jitter", lambda s, t: ({s, "203.0.113.11"}, _beacon(b, t, s, "203.0.113.11", 20, 0.05, 12)), False),
        ("b", "beacon 30 s, 10 % jitter", lambda s, t: ({s, "203.0.113.12"}, _beacon(b, t, s, "203.0.113.12", 30, 0.10, 12)), False),
        ("b", "beacon 30 s, 30 % jitter", lambda s, t: ({s, "203.0.113.13"}, _beacon(b, t, s, "203.0.113.13", 30, 0.30, 12)), True),
        ("b", "beacon 90 s, 5 % jitter (long period)", lambda s, t: ({s, "203.0.113.14"}, _beacon(b, t, s, "203.0.113.14", 90, 0.05, 10)), True),
        ("c", "DGA numeric_seed, 12 q, 90 % NXDOMAIN", lambda s, t: ({s}, _dga(b, t, s, "numeric_seed", 12, 0.9)), False),
        ("c", "DGA base32, 12 q, 90 % NXDOMAIN", lambda s, t: ({s}, _dga(b, t, s, "base32", 12, 0.9)), False),
        ("c", "DGA dictcat (word-based), 12 q, 60 % NXDOMAIN", lambda s, t: ({s}, _dga(b, t, s, "dictcat", 12, 0.6)), True),
        ("c", "DNS tunnel TXT, 60-char labels, 30 q @1/s", lambda s, t: ({s}, _tunnel(b, t, s, "tun.evil-ops.example", "TXT", 60, 30, 1.0)), False),
        ("c", "DNS tunnel CNAME, 40-char labels, 20 q @0.2/s", lambda s, t: ({s}, _tunnel(b, t, s, "cdn-sync.example", "CNAME", 40, 20, 5.0)), True),
        ("d", "known-bad JA3 (CobaltStrike list), SNI present", lambda s, t: ({s, "203.0.113.20"}, _tls(b, t, s, "203.0.113.20", "72a589da586844d7f0818ce684948eea", "cdn-a.example", 3)), False),
        ("d", "no SNI, direct IP, port 4443", lambda s, t: ({s, "203.0.113.21"}, _tls(b, t, s, "203.0.113.21", "e7d705a3286e19ea42f587b344ee6865", None, 3, port=4443)), False),
        ("d", "novel JA3 + JA4, SNI present, 1 session (canonical beat 6 shape)", lambda s, t: ({s, "203.0.113.22"}, _tls(b, t, s, "203.0.113.22", "6734f37431670b3ab4292b8faea04307", "unknown-cdn-edge.net", 1)), True),
        ("d", "novel JA3, SNI present, 4 sessions", lambda s, t: ({s, "203.0.113.23"}, _tls(b, t, s, "203.0.113.23", "1d095e68489d3c535297cd8dffb06cb9", "static-img.example", 4)), True),
        ("d", "fixed-size small-packet shape, 6 sessions", lambda s, t: ({s, "203.0.113.24"}, _tls(b, t, s, "203.0.113.24", "3b5074b1b5d032e5620f69f9f700ff0e", "api.example", 6, sizes=[310] * 5, spacing=15.0)), False),
        ("e", "vertical scan 150 ports @50/s", lambda s, t: ({s, "10.0.4.20"}, _scan(b, t, s, ["10.0.4.20"], range(1, 151), 50)), False),
        ("e", "horizontal sweep :445 on 80 hosts @40/s", lambda s, t: ({s}, _scan(b, t, s, [f"10.0.2.{i}" for i in range(1, 81)], [445], 40)), False),
        ("e", "hybrid 20 hosts x 10 ports @30/s", lambda s, t: ({s}, _scan(b, t, s, [f"10.0.3.{i}" for i in range(1, 21)], [22, 23, 80, 135, 139, 443, 445, 3389, 5900, 8080], 30)), False),
        ("e", "slow vertical scan 120 ports @0.2/s", lambda s, t: ({s, "10.0.4.21"}, _scan(b, t, s, ["10.0.4.21"], range(1, 121), 0.2)), True),
        ("e", "small scan 40 ports @20/s", lambda s, t: ({s, "10.0.4.22"}, _scan(b, t, s, ["10.0.4.22"], range(20, 60), 20)), True),
        ("f", "exfil 5 MB in 5 records", lambda s, t: ({s, "203.0.113.30"}, _exfil(b, t, s, "203.0.113.30", 5_000_000, 5, 3.0)), False),
        ("f", "exfil 20 MB in 10 records", lambda s, t: ({s, "203.0.113.31"}, _exfil(b, t, s, "203.0.113.31", 20_000_000, 10, 3.0)), False),
        ("f", "exfil 60 MB in 20 records", lambda s, t: ({s, "203.0.113.32"}, _exfil(b, t, s, "203.0.113.32", 60_000_000, 20, 5.0)), False),
        ("f", "slow exfil 3 MB over 30 min", lambda s, t: ({s, "203.0.113.33"}, _exfil(b, t, s, "203.0.113.33", 3_000_000, 30, 60.0)), True),
        ("f", "exfil 400 KB in 4 records", lambda s, t: ({s, "203.0.113.34"}, _exfil(b, t, s, "203.0.113.34", 400_000, 4, 5.0)), False),
    ]
    for letter, variant, build, hard in plan:
        src = attacker()
        before = len(b.events)
        key_ips, t_end = build(src, t)
        record(letter, variant, key_ips | ({src} if letter != "a" else set()), t, max(t_end, t), hard, before)
        t += gap
    b.events.sort(key=lambda e: float(e.observed_time))
    return b.events, labels
