"""Harness sanity: benign replay, labelled attack suite, attribution and scoring."""

from scenarios.attack_suite import PS_CLASSES, generate_attack_suite
from scenarios.benign_background import BackgroundConfig, generate_benign_background, load_background
from scenarios.evaluation import attribute, run_stream, score

CFG = BackgroundConfig(seed=3, duration_s=600, hosts=8)


def test_background_is_deterministic_and_payload_free():
    a = generate_benign_background(CFG)
    b = generate_benign_background(CFG)
    assert len(a) == len(b) > 100
    assert [e.observed_time for e in a[:50]] == [e.observed_time for e in b[:50]]
    for ev in a[:200]:
        assert not hasattr(ev, "payload")


def test_load_background_labels_provenance():
    events, provenance = load_background("synthetic", CFG)
    assert events and provenance == "synthetic benign replay"


def test_attack_suite_covers_every_ps_class():
    events, labels = generate_attack_suite(seed=11, start_time=1773280000)
    assert events and len(labels) == 33
    for letter in PS_CLASSES:
        expected = 8 if letter == "a" else 5          # class a adds 3 UDP reflection attacks
        assert sum(1 for l in labels if l.ps_letter == letter) == expected
    attacker_ips = {ip for l in labels for ip in l.key_ips}
    assert not attacker_ips & {f"10.0.1.{i}" for i in range(10, 60)}, "attack IPs must not collide with benign hosts"


def test_attribution_needs_shared_ip_and_time_overlap():
    _events, labels = generate_attack_suite(seed=11, start_time=1773280000)
    lab = labels[0]
    ip = sorted(lab.key_ips)[0]
    hit = {"dedup_key": f"x|{ip}", "evidence": {}, "detector": "ddos", "ps_class": lab.ps_class,
           "first_observed": lab.t_start, "timestamp": lab.t_start + 1}
    far = dict(hit, first_observed=lab.t_end + 10_000, timestamp=lab.t_end + 10_001)
    other_ip = dict(hit, dedup_key="x|203.0.113.250")
    assert attribute(hit, labels) is lab
    assert attribute(far, labels) is None
    assert attribute(other_ip, labels) is None


def test_score_reports_all_fields_per_class():
    bg = generate_benign_background(CFG)
    start = min(float(e.observed_time) for e in bg)
    attacks, labels = generate_attack_suite(seed=11, start_time=start)
    run = run_stream(sorted(bg + attacks, key=lambda e: float(e.observed_time)), labels, "test", 600)
    out = score([run], [labels])
    for letter, row in out["per_class"].items():
        for key in ("attacks", "detected", "missed", "precision", "recall", "false_alerts", "false_incidents_per_hour", "overlap_alerts"):
            assert key in row, (letter, key)
        assert row["detected"] + row["missed"] == row["attacks"]
