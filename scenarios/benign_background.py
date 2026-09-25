"""Deterministic SYNTHETIC benign background traffic (PS-compliance task 5).

Every figure computed on this stream must be labelled "synthetic benign
replay".  It emulates, as normalized flow events, what an office enclave
sends across a tap: web/TLS sessions, their DNS lookups, periodic system
traffic (NTP, update checks, telemetry heart-beats) and a few legitimate bulk
transfers (cloud backup uploads, large downloads).  Several of these are
deliberate hard negatives for our own detectors:

* telemetry heart-beats every 30 s     -> periodic like C2 beaconing
* cloud-backup uploads                 -> asymmetric outbound volume like exfiltration
* CDN hash / UUID sub-domains          -> random-looking names like DGA
* _dmarc / SPF TXT lookups             -> TXT records like DNS tunnelling
* large downloads                      -> packet bursts like volumetric floods
* internal resolver cache refresh      -> many port-53 servers answering one host fast,
                                          like DNS reflection (but every answer was asked for)

``load_background(source)`` accepts ``"synthetic"`` or a path to a classic
pcap file; a pcap is replayed through the existing header-only
ingest/replay.py path, so a real capture can be plugged in without code
changes (it is then labelled by the caller, not by this module).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Iterable

from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent
from models.dga_dataset import _benign_hostname

CLIENT_NET = "10.0.1."            # 50 office hosts 10.0.1.10 .. 10.0.1.59
RESOLVERS = ("1.1.1.1", "8.8.8.8")
NTP_SERVER = "192.0.2.123"
UPDATE_SERVER = "192.0.2.80"
TELEMETRY_SERVER = "192.0.2.90"
BACKUP_SERVER = "192.0.2.200"
MIRROR_SERVER = "192.0.2.201"
# Common browser / OS TLS client fingerprints (values are illustrative, fixed per "client family").
BENIGN_JA3 = ("cd08e31494f9531f560d64c695473da9", "773906b0efdefa24a7f2b8eb6985bf37", "9e10692f1b7f78228b2d4e424db3a98c", "579ccef312d18482fc42e2b822ca2430")
BENIGN_JA4 = ("t13d1516h2_8daaf6152771_b0da82dd1658", "t13d1517h2_8daaf6152771_b1ff8ab2d16f", "t13d1715h2_5b57614c22b0_3d5424432f57", "t13d1516h2_acb858a92679_c2f7e8a0e5a1")
BENIGN_JA3S = ("15af977ce25de452b96affa2addb1036", "eb1d94daa7e0344597e756a1fb6e7054")


@dataclass(frozen=True)
class BackgroundConfig:
    seed: int = 7
    duration_s: float = 7200.0
    hosts: int = 50
    web_sessions_per_host_per_min: float = 3.0
    telemetry_hosts: int = 5          # hosts with a 30 s heart-beat
    backup_hosts: int = 3             # hosts running a cloud backup upload
    download_hosts: int = 4           # hosts pulling a large file
    resolver_refresh: bool = True     # internal recursive resolver with bursty cache refresh
    start_time: float = 1773280000.0


def _cap() -> CapabilityState:
    return CapabilityState(InputMode.PCAP_REPLAY)


def _server_ip(rng: Random) -> str:
    # 198.18.0.0/15 is reserved for benchmarking - used here so benign servers
    # never collide with the documentation ranges the attack generators use.
    return f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def generate_benign_background(cfg: BackgroundConfig = BackgroundConfig()) -> list[NormalizedEvent]:
    rng = Random(cfg.seed)
    cap = _cap()
    t0, t_end = cfg.start_time, cfg.start_time + cfg.duration_s
    hosts = [f"{CLIENT_NET}{10 + i}" for i in range(cfg.hosts)]
    servers = [_server_ip(rng) for _ in range(400)]
    names = {srv: _benign_hostname(rng) for srv in servers}
    events: list[NormalizedEvent] = []

    def flow(t, src, dst, sport, dport, proto, out_b, in_b, **extra):
        packets = max(1, (out_b + in_b) // 1200)
        return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=cap, src_ip=src, dst_ip=dst,
                                         src_port=sport, dst_port=dport, protocol=proto, packets=packets, bytes=out_b + in_b,
                                         direction="outbound",
                                         flow_summary={"bytes_toserver": out_b, "bytes_toclient": in_b,
                                                       "pkts_toserver": max(1, out_b // 1200), "pkts_toclient": max(1, in_b // 1200)},
                                         **extra)

    def dns(t, src, qname, qtype="A", nx=False):
        return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=cap, src_ip=src,
                                         dst_ip=rng.choice(RESOLVERS), src_port=rng.randint(40000, 60000), dst_port=53, protocol="UDP",
                                         packets=2, bytes=rng.randint(90, 260), direction="outbound",
                                         dns={"qname": qname, "qtype": qtype, "nxdomain": nx, "rcode": 3 if nx else 0})

    for h_idx, host in enumerate(hosts):
        family = h_idx % len(BENIGN_JA3)
        # --- web / TLS sessions with their DNS lookups (Poisson arrivals) ---
        t = t0 + rng.uniform(0, 30)
        rate = cfg.web_sessions_per_host_per_min / 60.0
        while t < t_end:
            srv = rng.choice(servers)
            name = names[srv]
            qtype = rng.choices(("A", "AAAA", "HTTPS", "CNAME", "TXT", "MX"), weights=(62, 22, 8, 4, 2, 2))[0]
            if qtype == "TXT":
                name = f"_dmarc.{name.split('.', 1)[-1]}" if rng.random() < 0.5 else name
            typo = rng.random() < 0.02
            events.append(dns(t, host, name if not typo else _benign_hostname(rng).replace(".", "x", 1), qtype, nx=typo))
            if not typo:
                size_in = int(rng.lognormvariate(11.5, 1.3))          # median ~100 KB, long tail
                size_out = int(rng.uniform(800, 25_000))
                sizes = [rng.choice((517, 583, 1460)), 1460, rng.randint(200, 1460), 1460, rng.randint(80, 1460)]
                events.append(flow(t + rng.uniform(0.02, 0.2), host, srv, rng.randint(49152, 65535), 443, "TCP", size_out, size_in,
                                   tls={"ja3": BENIGN_JA3[family], "ja3s": rng.choice(BENIGN_JA3S), "ja4": BENIGN_JA4[family], "sni": name},
                                   shape={"packet_size_first_n": sizes, "direction_first_n": ["c2s", "s2c", "s2c", "c2s", "s2c"]}))
            t += rng.expovariate(rate)
        # --- NTP every 64 s (strictly periodic, UDP/123) ---
        t = t0 + rng.uniform(0, 64)
        while t < t_end:
            events.append(flow(t, host, NTP_SERVER, 123, 123, "UDP", 76, 76))
            t += 64.0 + rng.uniform(-0.05, 0.05)
        # --- update check every 300 s +- 5 s (TLS) ---
        t = t0 + rng.uniform(0, 300)
        while t < t_end:
            events.append(flow(t, host, UPDATE_SERVER, rng.randint(49152, 65535), 443, "TCP", 1800, 4200,
                               tls={"ja3": BENIGN_JA3[family], "ja3s": BENIGN_JA3S[0], "ja4": BENIGN_JA4[family], "sni": "update.systems.example"}))
            t += 300.0 + rng.uniform(-5, 5)

    # --- telemetry heart-beat every 30 s (hard negative for C2) ---
    for host in rng.sample(hosts, cfg.telemetry_hosts):
        t = t0 + rng.uniform(0, 30)
        while t < t_end:
            events.append(flow(t, host, TELEMETRY_SERVER, 50000, 443, "TCP", 640, 380,
                               tls={"ja3": BENIGN_JA3[0], "ja3s": BENIGN_JA3S[1], "ja4": BENIGN_JA4[0], "sni": "telemetry.vendor.example"}))
            t += 30.0 + rng.uniform(-0.5, 0.5)
    # --- cloud backup uploads: ~150 MB over ~12 min in 10 s flow records (hard negative for exfil) ---
    for host in rng.sample(hosts, cfg.backup_hosts):
        t = t0 + rng.uniform(600, t_end - t0 - 900)
        for _ in range(72):
            events.append(flow(t, host, BACKUP_SERVER, 51000, 443, "TCP", 2_100_000, 9_000,
                               tls={"ja3": BENIGN_JA3[1], "ja3s": BENIGN_JA3S[0], "ja4": BENIGN_JA4[1], "sni": "backup.cloud.example"}))
            t += 10.0
    # --- large downloads: ~400 MB in 5 s records (hard negative for volumetric) ---
    for host in rng.sample(hosts, cfg.download_hosts):
        t = t0 + rng.uniform(300, t_end - t0 - 600)
        for _ in range(40):
            events.append(flow(t, host, MIRROR_SERVER, 52000, 443, "TCP", 30_000, 10_000_000,
                               tls={"ja3": BENIGN_JA3[2], "ja3s": BENIGN_JA3S[1], "ja4": BENIGN_JA4[2], "sni": "mirror.downloads.example"}))
            t += 5.0

    # --- internal recursive resolver (hard negative for UDP reflection) ---
    # Separate RNG so the events above stay identical to earlier runs.
    if cfg.resolver_refresh:
        events.extend(_resolver_traffic(cfg, cap))

    events.sort(key=lambda e: float(e.observed_time))
    return events


INTERNAL_RESOLVER = "10.0.1.2"


def _resolver_traffic(cfg: BackgroundConfig, cap: CapabilityState) -> list[NormalizedEvent]:
    """Per-packet query/response pairs: a slow trickle plus a 3,000-query burst every 30 min."""
    rng = Random(cfg.seed + 5000)
    authorities = [f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(150)]
    out: list[NormalizedEvent] = []

    def pair(t, auth):
        sport = rng.randint(1024, 65535)
        out.append(NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=cap, src_ip=INTERNAL_RESOLVER,
                                             dst_ip=auth, src_port=sport, dst_port=53, protocol="UDP", packets=1,
                                             bytes=rng.randint(70, 110), direction="outbound"))
        out.append(NormalizedEvent.from_flow(observed_time=t + rng.uniform(0.004, 0.04), input_mode=InputMode.PCAP_REPLAY, capability=cap,
                                             src_ip=auth, dst_ip=INTERNAL_RESOLVER, src_port=53, dst_port=sport, protocol="UDP", packets=1,
                                             bytes=rng.randint(200, 1400), direction="inbound"))

    t0, t_end = cfg.start_time, cfg.start_time + cfg.duration_s
    t = t0 + rng.uniform(0, 2)
    while t < t_end:                               # ~0.5 queries/s steady
        pair(t, rng.choice(authorities))
        t += rng.expovariate(0.5)
    t = t0 + rng.uniform(60, 600)
    while t < t_end:                               # cache refresh: 3,000 queries in 1 s (above the 2,000 pps gate)
        for i in range(3000):
            pair(t + i / 3000, authorities[i % len(authorities)])
        t += 1800.0
    return out


def load_background(source: str | Path = "synthetic", cfg: BackgroundConfig = BackgroundConfig(),
                    address_plan=None) -> tuple[list[NormalizedEvent], str]:
    """Return (events, provenance label).

    ``source="synthetic"`` -> generated stream, label "synthetic benign replay".
    ``source=<path to .pcap>`` -> header-only replay of that capture through
    ingest/replay.py, label "pcap:<file name>" (treated as benign background).
    """
    if str(source) == "synthetic":
        return generate_benign_background(cfg), "synthetic benign replay"
    from ingest.replay import replay_to_events

    path = Path(source)
    events, _stats = replay_to_events(path, address_plan=address_plan)
    return events, f"pcap:{path.name}"


def iter_hosts(cfg: BackgroundConfig = BackgroundConfig()) -> Iterable[str]:
    return (f"{CLIENT_NET}{10 + i}" for i in range(cfg.hosts))
