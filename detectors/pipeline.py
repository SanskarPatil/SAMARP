"""Detection pipeline coordinating feature extraction and Tier-0/Tier-1 detectors.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 6.3, 7B, 11, 24.
Contract: schemas/alert.schema.json, schemas/normalized_event.schema.json.

Flow:
NormalizedEvent -> RollingWindowAggregator (ddos) & Stateless Detectors -> Raw Alerts.
"""

from __future__ import annotations

import time
from typing import Any

from detectors.c2 import C2Detector
from detectors.ddos import DDoSDetector
from detectors.dga import DGADetector
from detectors.dns import DNSTunnelDetector
from detectors.exfil import ExfilDetector
from detectors.scan import ScanDetector
from detectors.tls_quic import TLSQuicDetector
from features.rolling import TumblingWindowAggregator
from ingest.normalized_event import NormalizedEvent


class DetectionPipeline:
    """Unified detector coordinator evaluating normalized network events."""

    def __init__(
        self,
        window_duration_s: float = 1.0,
        watermark_delay_s: float = 0.3,
        enable_ddos: bool = True,
        enable_scan: bool = True,
        enable_c2: bool = True,
        enable_dga: bool = True,
        enable_dns: bool = True,
        enable_exfil: bool = True,
        enable_tls_quic: bool = True,
    ) -> None:
        self.rolling_aggregator = TumblingWindowAggregator(
            window_duration_s=window_duration_s,
            watermark_delay_s=watermark_delay_s,
        )

        # Instantiate detectors
        self.ddos = DDoSDetector() if enable_ddos else None
        self.scan = ScanDetector() if enable_scan else None
        self.c2 = C2Detector() if enable_c2 else None
        self.dga = DGADetector() if enable_dga else None
        self.dns_tunnel = DNSTunnelDetector() if enable_dns else None
        self.exfil = ExfilDetector() if enable_exfil else None
        self.tls_quic = TLSQuicDetector() if enable_tls_quic else None

    @staticmethod
    def _stamp_latency(alerts: list[dict[str, Any]], ingest_perf_ns: int) -> list[dict[str, Any]]:
        """latency_ms = wall time from the triggering event entering the pipeline to the alert leaving it.

        Measured with time.perf_counter_ns(), never estimated.  api/state.py
        extends it to cover deduplication, scoring and hash-chain signing when
        the same ingest timestamp is passed to AppState.ingest_alert().
        """
        now = time.perf_counter_ns()
        for alert in alerts:
            alert["latency_ms"] = round((now - ingest_perf_ns) / 1e6, 4)
        return alerts

    def process_event(self, event: NormalizedEvent, ingest_perf_ns: int | None = None) -> list[dict[str, Any]]:
        """Process a single NormalizedEvent through all active detectors and window aggregators.

        ``ingest_perf_ns`` is the time.perf_counter_ns() value at which the event
        was received; it defaults to "now" (the moment this call starts).

        Returns:
            List of emitted raw alert dictionaries matching schemas/alert.schema.json.
        """
        ingest_perf_ns = ingest_perf_ns if ingest_perf_ns is not None else time.perf_counter_ns()
        emitted_alerts: list[dict[str, Any]] = []

        # 1. Stateless and session-level detectors
        if self.scan is not None:
            alert = self.scan.evaluate_event(event)
            if alert is not None:
                emitted_alerts.append(alert)

        if self.c2 is not None:
            alert = self.c2.evaluate_event(event)
            if alert is not None:
                emitted_alerts.append(alert)

        if self.dga is not None:
            alert = self.dga.evaluate_event(event)
            if alert is not None:
                emitted_alerts.append(alert)

        if self.dns_tunnel is not None:
            alert = self.dns_tunnel.evaluate_event(event)
            if alert is not None:
                emitted_alerts.append(alert)

        if self.exfil is not None:
            alert = self.exfil.evaluate_event(event)
            if alert is not None:
                emitted_alerts.append(alert)

        if self.tls_quic is not None:
            alert = self.tls_quic.evaluate_event(event)
            if alert is not None:
                emitted_alerts.append(alert)

        # 2. Tumbling window aggregator and volumetric DDoS detector
        if self.ddos is not None:
            completed_windows = self.rolling_aggregator.add_event(event)
            for window in completed_windows:
                ddos_alerts = self.ddos.evaluate_window(window)
                emitted_alerts.extend(ddos_alerts)

        return self._stamp_latency(emitted_alerts, ingest_perf_ns)

    def flush(self, ingest_perf_ns: int | None = None) -> list[dict[str, Any]]:
        """Flush any remaining closed windows from the rolling aggregator."""
        ingest_perf_ns = ingest_perf_ns if ingest_perf_ns is not None else time.perf_counter_ns()
        emitted_alerts: list[dict[str, Any]] = []
        if self.ddos is not None:
            remaining_windows = self.rolling_aggregator.flush()
            for window in remaining_windows:
                ddos_alerts = self.ddos.evaluate_window(window)
                emitted_alerts.extend(ddos_alerts)
        return self._stamp_latency(emitted_alerts, ingest_perf_ns)
