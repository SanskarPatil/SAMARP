"""Jury-review evidence tools: real-PCAP evaluation harness, C2 jitter sweep, threshold sweep."""

import json
from random import Random

import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "ingest"))

from evaluate_pcap import evaluate_capture, load_labels  # noqa: E402
from pcap_builder import PcapWriter, ethernet, ipv4, tcp  # noqa: E402
from sweep_c2_jitter import beacon_detected  # noqa: E402
from sweep_thresholds import _grid  # noqa: E402

from ingest.address_plan import AddressPlan  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
T0 = 1790400000.0


def _scan_pcap(path):
    w = PcapWriter()
    for i in range(150):                                   # vertical scan, 150 ports, SYN only
        w.add(ethernet(ipv4("192.168.56.10", "192.168.56.20", 6, tcp(40000 + i, 1 + i, flags=0x02))), T0 + i * 0.02)
    for i in range(40):                                    # a little unrelated traffic afterwards
        w.add(ethernet(ipv4("192.168.56.30", "192.168.56.40", 6, tcp(50000, 443, flags=0x10))), T0 + 10 + i)
    return w.write(path)


def test_labels_are_validated(tmp_path):
    good = tmp_path / "l.json"
    good.write_text(json.dumps([{"ps_letter": "e", "key_ips": ["192.168.56.10"], "t_start": T0, "t_end": T0 + 5, "variant": "nmap -p 1-150"}]))
    labels = load_labels(good)
    assert labels[0].ps_letter == "e" and "192.168.56.10" in labels[0].key_ips
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps([{"ps_letter": "z", "key_ips": ["1.2.3.4"], "t_start": T0, "t_end": T0 + 1}]))
    with pytest.raises(ValueError):
        load_labels(bad)


def test_real_pcap_scan_is_detected_end_to_end(tmp_path):
    pcap = _scan_pcap(tmp_path / "lab.pcap")
    labels = load_labels_from([{"attack_id": "e1", "ps_letter": "e", "key_ips": ["192.168.56.10"], "t_start": T0, "t_end": T0 + 3, "variant": "vertical 150"}], tmp_path)
    plan = AddressPlan.load(ROOT / "config" / "address_plan_home.example.yaml")
    res = evaluate_capture(pcap, labels, plan)
    assert res["events"] == 190
    assert res["scored"]["per_class"]["e"]["detected"] == 1
    assert res["alerts_by_detector"].get("scan", 0) >= 1


def load_labels_from(rows, tmp_path):
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(rows))
    return load_labels(p)


def test_home_plan_sets_direction():
    plan = AddressPlan.load(ROOT / "config" / "address_plan_home.example.yaml")
    assert plan.direction("192.168.1.20", "142.250.1.1") == "outbound"
    assert plan.direction("142.250.1.1", "192.168.1.20") == "inbound"


def test_c2_jitter_extremes():
    rng = Random(1)
    assert beacon_detected(30.0, 0.0, rng, 12)
    assert sum(beacon_detected(30.0, 0.6, rng, 12) for _ in range(20)) <= 4


def test_threshold_grid_builds_every_detector():
    for det, letter, param, shipped, values, make in _grid():
        assert shipped in values, (det, param)
        assert make(shipped) is not None
