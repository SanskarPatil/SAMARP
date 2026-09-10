"""Tests for deterministic corpus generation and leakage-safe DGA splits."""

from __future__ import annotations

import unittest

from intel.baseline import generate_baseline_snapshot
from models.dga_dataset import build_dga_corpus, default_holdout_definition, split_holdouts


class DGAGroundTruthTests(unittest.TestCase):
    def test_corpus_is_seed_deterministic_and_contains_hard_negatives(self) -> None:
        first = build_dga_corpus()
        self.assertEqual(first, build_dga_corpus())
        self.assertTrue(any(example.label == 0 and "a1b2c3d4" in example.qname for example in first))
        self.assertEqual({example.family for example in first if example.label}, {"numeric_seed", "hexflux", "wordmix"})

    def test_holdouts_have_no_domain_leakage(self) -> None:
        partitions = split_holdouts(build_dga_corpus())
        domains = {name: {item.canonical_domain for item in items} for name, items in partitions.items()}
        for left_name, left_domains in domains.items():
            for right_name, right_domains in domains.items():
                if left_name != right_name:
                    self.assertFalse(left_domains & right_domains)
        definition = default_holdout_definition()
        self.assertTrue(all(item.family in definition.families for item in partitions["family"]))
        self.assertTrue(all(item.entity in definition.entities for item in partitions["entity"]))

    def test_baseline_snapshot_is_deterministic_and_immutable_by_default(self) -> None:
        events = [{"packets_per_second": 100.0, "outbound_byte_ratio": 1.0, "unique_destination_ports": 5.0}, {"packets_per_second": 110.0, "outbound_byte_ratio": 1.1, "unique_destination_ports": 7.0}, {"packets_per_second": 90.0, "outbound_byte_ratio": 0.9, "unique_destination_ports": 3.0}]
        snapshot = generate_baseline_snapshot(events)
        self.assertEqual(snapshot, generate_baseline_snapshot(events))
        self.assertFalse(snapshot["adaptive_updates"])
        self.assertEqual(snapshot["metrics"]["packets_per_second"]["median"], 100.0)


if __name__ == "__main__":
    unittest.main()
