"""UDP reflection/amplification and spoofed-source flood evidence."""
from __future__ import annotations
from typing import Any, Mapping
from features.stateless import shannon_entropy
from .common import DetectionOutcome, make_alert, unavailable
AMPLIFIER_PORTS = {53, 123, 389, 1900, 11211}
def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("dst_ip", "amplifier_port", "packets_per_second", "sources")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    port, sources, pps = int(window["amplifier_port"]), list(window["sources"]), float(window["packets_per_second"])
    fan_in = len(set(sources))
    if not (port in AMPLIFIER_PORTS and fan_in >= 10 and pps >= 5000): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="reflection", threat_class="UDP reflection/amplification", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="aggregate", dedup_components={"dst_ip": window["dst_ip"], "amplifier_port": port}, score=float(fan_in), evidence={"interpretation": "High-rate UDP fan-in from an amplification service is observable; reserved-source share excludes declared lab prefixes.", "packets_per_second": pps, "amplifier_port": port, "fan_in": fan_in, "source_entropy": shannon_entropy(sources), "reserved_source_share": float(window.get("reserved_source_share_external", 0.0))}, threshold={"fan_in_min": 10, "min_pps": 5000, "amplifier_ports": sorted(AMPLIFIER_PORTS)})


# ---------------------------------------------------------------------------
# Streaming detector (wired into DetectionPipeline).
# ---------------------------------------------------------------------------
from collections import OrderedDict, deque  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from ingest.identity import canonical as _canonical, identifier as _identifier  # noqa: E402

PS_CLASS = "Volumetric DDoS / flooding"
DETECTOR_NAME = "reflection"

DEFAULT_WINDOW_S = 5.0            # sliding window, 1 s buckets
DEFAULT_MIN_FAN_IN = 10           # distinct amplifiers answering one victim
DEFAULT_MIN_PPS = 2000.0          # reflected packets per second, OR
DEFAULT_MIN_BPS = 20_000_000.0    # reflected bits per second (large amplified responses)
DEFAULT_MIN_UNSOLICITED = 0.8     # share of responses from amplifiers the victim never queried
DEFAULT_REQUEST_MEMORY_S = 30.0   # how long a victim's own query to an amplifier counts as "solicited"
DEFAULT_MAX_TRACKED = 1024


def _amplifier_ports() -> tuple[int, ...]:
    try:
        from ingest.address_plan import AddressPlan

        ports = AddressPlan.load().amplifier_ports
        return tuple(int(p) for p in ports) or tuple(sorted(AMPLIFIER_PORTS))
    except Exception:  # pragma: no cover - plan file missing
        return tuple(sorted(AMPLIFIER_PORTS))


def _ts(ev) -> float:
    t = ev.observed_time
    return float(t.timestamp()) if isinstance(t, datetime) else float(t)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


class _VictimState:
    __slots__ = ("buckets", "first_seen", "last_seen", "flow_ids")

    def __init__(self, now: float) -> None:
        # deque of [second, packets, bytes, {amplifier: solicited?}]
        self.buckets: deque = deque()
        self.first_seen = now
        self.last_seen = now
        self.flow_ids: list[str] = []


class ReflectionDetector:
    """UDP reflection / amplification: many amplifiers answering one victim it never asked.

    Header and flow metadata only (source port, sizes, counts, direction). An
    amplifier response is a UDP packet FROM a declared amplification service
    port (config/address_plan.yaml amplifier_ports) TO the victim. It is
    "unsolicited" when the victim sent no query to that amplifier on that port
    within request_memory_s - the defining property of reflection, and the
    one that separates it from a busy recursive resolver.

    On a one-way tap that never shows the victim's own queries every response
    looks unsolicited; the rate and fan-in gates still apply, and the evidence
    says so.
    """

    def __init__(
        self,
        window_s: float = DEFAULT_WINDOW_S,
        min_fan_in: int = DEFAULT_MIN_FAN_IN,
        min_pps: float = DEFAULT_MIN_PPS,
        min_bps: float = DEFAULT_MIN_BPS,
        min_unsolicited_share: float = DEFAULT_MIN_UNSOLICITED,
        request_memory_s: float = DEFAULT_REQUEST_MEMORY_S,
        amplifier_ports: tuple[int, ...] | None = None,
        max_tracked: int = DEFAULT_MAX_TRACKED,
    ) -> None:
        self.window_s = window_s
        self.min_fan_in = min_fan_in
        self.min_pps = min_pps
        self.min_bps = min_bps
        self.min_unsolicited_share = min_unsolicited_share
        self.request_memory_s = request_memory_s
        self.amplifier_ports = frozenset(amplifier_ports or _amplifier_ports())
        self.max_tracked = max_tracked
        self._victims: OrderedDict[tuple[str, int], _VictimState] = OrderedDict()
        self._requests: OrderedDict[tuple[str, str, int], float] = OrderedDict()   # (host, amplifier, port) -> last query
        self._alerted: dict[tuple[str, int], float] = {}

    # -- bookkeeping --------------------------------------------------------
    def _note_request(self, host: str, amplifier: str, port: int, now: float) -> None:
        key = (host, amplifier, port)
        self._requests.pop(key, None)
        self._requests[key] = now
        while len(self._requests) > self.max_tracked * 16:
            self._requests.popitem(last=False)

    def _solicited(self, victim: str, amplifier: str, port: int, now: float) -> bool:
        t = self._requests.get((victim, amplifier, port))
        return t is not None and now - t <= self.request_memory_s

    # -- main entry ---------------------------------------------------------
    def evaluate_event(self, ev) -> dict[str, Any] | None:
        if str(ev.protocol).upper() != "UDP" or not ev.src_ip or not ev.dst_ip:
            return None
        now = _ts(ev)
        sport, dport = ev.src_port, ev.dst_port
        if ev.direction == "inbound" or ev.direction is None:
            if sport not in self.amplifier_ports:
                return None
            # A bidirectional record whose client is the victim is a solicited exchange.
            fs = ev.flow_summary or {}
            if ("bytes_toserver" in fs or "bytes_toclient" in fs) and dport in self.amplifier_ports:
                return None
        else:
            # Outbound query from an internal host to an amplification service: remember it.
            if dport in self.amplifier_ports:
                self._note_request(ev.src_ip, ev.dst_ip, int(dport), now)
            return None

        key = (ev.dst_ip, int(sport))
        state = self._victims.pop(key, None) or _VictimState(now)
        self._victims[key] = state
        while len(self._victims) > self.max_tracked:
            self._victims.popitem(last=False)

        second = int(now)
        if not state.buckets or state.buckets[-1][0] != second:
            state.buckets.append([second, 0, 0, {}])
        bucket = state.buckets[-1]
        bucket[1] += int(ev.packets if ev.packets is not None else 1)
        bucket[2] += int(ev.bytes or 0)
        if ev.src_ip not in bucket[3] and len(bucket[3]) < 4096:
            bucket[3][ev.src_ip] = self._solicited(ev.dst_ip, ev.src_ip, int(sport), now)
        while state.buckets and state.buckets[0][0] <= second - self.window_s:
            state.buckets.popleft()
        state.last_seen = now
        if ev.flow_id and len(state.flow_ids) < 16 and ev.flow_id not in state.flow_ids:
            state.flow_ids.append(ev.flow_id)
        return self._check(key, state, now, ev)

    def _check(self, key, state: _VictimState, now: float, ev) -> dict[str, Any] | None:
        last = self._alerted.get(key)
        if last is not None and now - last < 300.0:
            return None
        span = max(1.0, state.buckets[-1][0] - state.buckets[0][0] + 1.0)
        packets = sum(b[1] for b in state.buckets)
        bytes_ = sum(b[2] for b in state.buckets)
        amplifiers: dict[str, bool] = {}
        for b in state.buckets:
            for ip, solicited in b[3].items():
                amplifiers[ip] = amplifiers.get(ip, False) or solicited
        fan_in = len(amplifiers)
        pps, bps = packets / span, bytes_ * 8.0 / span
        unsolicited = sum(1 for s in amplifiers.values() if not s) / fan_in if fan_in else 0.0
        if fan_in < self.min_fan_in or unsolicited < self.min_unsolicited_share:
            return None
        if pps < self.min_pps and bps < self.min_bps:
            return None

        self._alerted[key] = now
        victim, port = key
        dedup = [PS_CLASS, victim, port]
        mean_size = bytes_ / packets if packets else 0.0
        # 0.5 at the gate, rising to 1.0 at 5x the rate gate.
        ratio = max(pps / self.min_pps, bps / self.min_bps)
        score = 0.5 + 0.5 * min(1.0, max(0.0, (ratio - 1.0) / 4.0))
        from alerts.confidence import apply_confidence

        mode = ev.input_mode.value if hasattr(ev.input_mode, "value") else str(ev.input_mode or "pcap_replay")
        return apply_confidence({
            "schema_version": "1.3",
            "timestamp": _iso(now),
            "flow_id": _identifier(dedup),
            "flow_ref_type": "aggregate",
            "ps_class": PS_CLASS,
            "threat_class": "udp_reflection",
            "detector": DETECTOR_NAME,
            "confidence": None,
            "score": round(min(1.0, max(0.0, score)), 3),
            "score_type": "anomaly_score",
            "calibrated": False,
            "evidence": {
                "interpretation": (
                    f"UDP reflection/amplification toward {victim}: {fan_in} distinct amplifiers answering from port {port} "
                    f"at {pps:,.0f} pps / {bps / 1e6:,.1f} Mbps (mean {mean_size:,.0f} B per packet); "
                    f"{unsolicited:.0%} of amplifiers were never queried by {victim}. Header metadata only."
                ),
                "target_ip": victim,
                "amplifier_port": port,
                "fan_in": fan_in,
                "packet_rate_pps": round(pps, 1),
                "bit_rate_bps": round(bps, 1),
                "mean_packet_bytes": round(mean_size, 1),
                "unsolicited_share": round(unsolicited, 3),
                "sample_amplifiers": sorted(amplifiers)[:10],
                "window_s": self.window_s,
            },
            "incident_id": _identifier(dedup),
            "dedup_key": _canonical(dedup),
            "capability": {"detector_state": "OBSERVABLE", "input_mode": mode, "missing_evidence": []},
            "status": "NEW",
            "severity": "CRITICAL" if pps >= 5 * self.min_pps or bps >= 5 * self.min_bps else "HIGH",
            "first_observed": _iso(state.buckets[0][0]),
            "last_observed": _iso(now),
            "event_count": packets,
            "contributing_flow_ids": state.flow_ids[:16],
            "window": {"start": _iso(state.buckets[0][0]), "end": _iso(now), "duration_s": round(span, 3)},
            "threshold": {"min_fan_in": self.min_fan_in, "min_pps": self.min_pps, "min_bps": self.min_bps,
                          "min_unsolicited_share": self.min_unsolicited_share, "amplifier_ports": sorted(self.amplifier_ports)},
            "recommendation": f"ADVISORY: {victim} is receiving unsolicited amplified UDP from port {port}. Ask upstream to rate-limit or filter source port {port} toward {victim}.",
        })
