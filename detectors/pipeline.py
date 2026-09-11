"""Detection pipeline coordinating feature extraction and Tier-0/Tier-1 detectors.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 6.3, 7B, 11, 24.
Contract: schemas/alert.schema.json, schemas/normalized_event.schema.json.

Flow:
NormalizedEvent -> RollingWindowAggregator (ddos) & Stateless Detectors -> Raw Alerts.
"""

from __future__ import annotations

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

    def process_event(self, event: NormalizedEvent) -> list[dict[str, Any]]:
        """Process a single NormalizedEvent through all active detectors and window aggregators.

        Returns:
            List of emitted raw alert dictionaries matching schemas/alert.schema.json.
        """
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

        return emitted_alerts

    def flush(self) -> list[dict[str, Any]]:
        """Flush any remaining closed windows from the rolling aggregator."""
        emitted_alerts: list[dict[str, Any]] = []
        if self.ddos is not None:
            remaining_windows = self.rolling_aggregator.flush()
            for window in remaining_windows:
                ddos_alerts = self.ddos.evaluate_window(window)
                emitted_alerts.extend(ddos_alerts)
        return emitted_alerts
