"""Task 8: word-level hold-out, artifact without pickle, no feature-name warning, detector shadow/on modes."""

import re
import warnings

import pytest

import models.dga_model as dm
from detectors.dga import DGADetector
from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent
from models.dga_dataset import build_vocab_holdout_corpus, load_real_benign, registered_domain, vocabulary_split

CAP = CapabilityState(InputMode.PCAP_REPLAY)


def _sld(qname: str) -> str:
    return registered_domain(qname).split(".")[0]


def test_heldout_words_never_build_an_in_vocabulary_name():
    train, heldout = vocabulary_split()
    assert heldout and not set(train) & set(heldout)
    only = lambda words: re.compile(r"^(?:" + "|".join(sorted(map(re.escape, words), key=len, reverse=True)) + r")+\d*$")
    corpus = build_vocab_holdout_corpus(benign_in_vocab=300, benign_oov=150, per_family=20)
    for e in corpus:
        if e.family == "benign":
            assert only(train).match(_sld(e.qname)), e.qname
        elif e.family == "benign_oov":
            assert only(heldout).match(_sld(e.qname)), e.qname


def test_real_benign_loader_reads_tranco_csv(tmp_path):
    p = tmp_path / "top-1m.csv"
    p.write_text("1,google.com\n2,facebook.com\n3,google.com\nbad-line\n4,qq.com\n", encoding="utf-8")
    examples, prov = load_real_benign(p, top=10)
    assert [e.qname for e in examples] == ["google.com", "facebook.com", "qq.com"]
    assert all(e.label == 0 and e.family == "benign_real" for e in examples)
    assert prov["label"] == "real" and len(prov["sha256"]) == 64


def _small_model(factory=None):
    corpus = build_vocab_holdout_corpus(benign_in_vocab=240, benign_oov=10, per_family=40)
    return dm.train_lightgbm([e for e in corpus if e.family != "benign_oov"], factory)


def _hgb():
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(max_iter=30, random_state=1)


def test_predict_many_matches_predict_probability():
    model = _small_model(_hgb)
    names = ["api.github.com", "x7k2q9zr0v4mplw8.xyz", "shop.greenriver.in"]
    assert dm.predict_many(model, names) == pytest.approx([model.predict_probability(n) for n in names])


def test_lightgbm_no_feature_name_warning_and_artifact_roundtrip(tmp_path):
    pytest.importorskip("lightgbm")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        model = _small_model()
        before = dm.predict_many(model, ["api.github.com", "x7k2q9zr0v4mplw8.xyz"])
    assert not [w for w in caught if "feature name" in str(w.message).lower()], [str(w.message) for w in caught]
    paths = model.save_artifact(tmp_path, {"note": "test"})
    assert not list(tmp_path.glob("*.pkl")), "artifact must not be a pickle"
    loaded = dm.CalibratedDGAModel.load_artifact(tmp_path)
    assert loaded.feature_names == dm.DGA_MODEL_FEATURES
    assert dm.predict_many(loaded, ["api.github.com", "x7k2q9zr0v4mplw8.xyz"]) == pytest.approx(before, abs=1e-9)
    assert paths["booster"].endswith(dm.BOOSTER_FILE)


def test_load_default_model_is_none_without_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(dm, "ARTIFACT_DIR", tmp_path)
    assert dm.load_default_model() is None


class _FakeModel:
    version = "fake-1"

    def __init__(self, p):
        self.p = p

    def predict_probability(self, qname):
        return self.p


def _dga_burst(det, n=8, nx=True):
    out = None
    for i in range(n):
        ev = NormalizedEvent.from_flow(observed_time=1773280000.0 + i, input_mode=InputMode.PCAP_REPLAY, capability=CAP,
                                       src_ip="10.0.9.40", dst_ip="1.1.1.1", src_port=53000 + i, dst_port=53, protocol="UDP",
                                       dns={"qname": f"q{i}x7k2q9zr0v4mplw8jd.xyz", "qtype": "A", "nxdomain": nx}, packets=2, bytes=90)
        out = det.evaluate_event(ev) or out
    return out


def test_shadow_mode_records_model_but_rules_decide():
    rules_only = _dga_burst(DGADetector(model_mode="off"))
    shadow = _dga_burst(DGADetector(model=_FakeModel(0.01), model_mode="shadow"))
    assert (rules_only is None) == (shadow is None)
    if shadow is not None:
        assert shadow["evidence"]["model"]["mode"].startswith("shadow")
        assert shadow["score_type"] == "rule_score"


def test_on_mode_model_decides_and_is_platt_calibrated():
    hit = _dga_burst(DGADetector(model=_FakeModel(0.93), model_mode="on"))
    assert hit is not None and hit["score_type"] == "model_probability"
    assert hit["calibrated_on"] == "platt_dga" and hit["confidence"] == pytest.approx(0.93)
    assert hit["model_version"] == "fake-1"
    assert _dga_burst(DGADetector(model=_FakeModel(0.05), model_mode="on")) is None


def test_bad_model_mode_rejected():
    with pytest.raises(ValueError):
        DGADetector(model_mode="maybe")
