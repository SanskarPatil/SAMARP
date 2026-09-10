"""Deterministic unit coverage for P2 passive feature extraction."""

from __future__ import annotations

import copy
import unittest

from features.extractor import dns_window_features, feature_record, interarrival_features, ordered_feature_vector
from features.feature_order import FEATURE_COUNT, FEATURE_ORDER
from features.stateless import coefficient_of_variation, median_absolute_deviation, robust_z_score, shannon_entropy


EVENT = {
    "schema_version": 1,
    "observed_time": "2026-09-10T00:00:00Z",
    "input_mode": "pcap_replay",
    "capability": {"input_mode": "pcap_replay", "dns_names": "OBSERVABLE"},
    "dns": {"qname": "a9f3k2.example.test", "qtype": "TXT", "nxdomain": True},
    "shape": {
        "packet_size_first_n": [60, 120, 240],
        "direction_first_n": ["outbound", "inbound", "outbound"],
        "iat_median": 0.2,
        "iat_p95": 0.4,
        "iat_cv": 0.5,
        "upstream_packet_ratio": 2 / 3,
        "downstream_packet_ratio": 1 / 3,
    },
}


class FeaturePrimitiveTests(unittest.TestCase):
    def test_entropy_and_robust_statistics_are_deterministic(self) -> None:
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0)
        self.assertEqual(median_absolute_deviation([1, 1, 1]), 0.0)
        self.assertGreater(robust_z_score(100, [1, 1, 1]), 0.0)
        self.assertEqual(coefficient_of_variation([2, 2, 2]), 0.0)

    def test_interarrival_statistics(self) -> None:
        self.assertEqual(
            interarrival_features([0.0, 1.0, 3.0]),
            {"iat_median": 1.5, "iat_p95": 1.95, "iat_cv": 1 / 3},
        )


class FeatureExtractionTests(unittest.TestCase):
    def test_dns_qtype_distribution_includes_required_zero_shares(self) -> None:
        features = dns_window_features([EVENT])
        self.assertEqual(features["qtype_distribution"]["TXT"], 1.0)
        self.assertEqual(features["qtype_distribution"]["NULL"], 0.0)
        self.assertEqual(features["qtype_distribution"]["CNAME"], 0.0)
        self.assertEqual(features["qtype_entropy"], 0.0)

    def test_feature_extraction_is_pure_and_deterministic(self) -> None:
        source = copy.deepcopy(EVENT)
        first = feature_record(source)
        second = feature_record(source)
        self.assertEqual(first, second)
        self.assertEqual(source, EVENT)
        self.assertEqual(first["length"], 6.0)
        self.assertEqual(first["packet_size_first_n"], [60, 120, 240])

    def test_vector_uses_the_frozen_order(self) -> None:
        vector = ordered_feature_vector(feature_record(EVENT))
        self.assertEqual(len(vector), FEATURE_COUNT)
        self.assertEqual(FEATURE_ORDER[0], "length")
        self.assertEqual(vector[0], 6.0)
        self.assertEqual(vector[FEATURE_ORDER.index("packet_size_first_n")], 140.0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
