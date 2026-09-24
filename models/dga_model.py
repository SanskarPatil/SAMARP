"""The project's only trained model: calibrated LightGBM DGA classifier."""

from __future__ import annotations

import json
from dataclasses import dataclass
from math import exp
from pathlib import Path
from typing import Iterable, Mapping

from typing import Any, Callable

from features.extractor import domain_features
from features.feature_order import FEATURE_ORDER
from .dga_dataset import DomainExample


MODEL_VERSION = "dga-lightgbm-0.3.0"

# Per-domain lexical model inputs, taken IN FROZEN ORDER from FEATURE_ORDER.
# ``nxdomain_rate`` is deliberately excluded: it is a response-level, per-source
# observation that a single qname does not carry.  v0.1.0 filled it from the
# training label (0.1 benign / 0.7 DGA) - label leakage.  NXDOMAIN evidence is
# still used, from observed responses, by the burst rule in detectors/dga.py.
LEXICAL_FEATURES = ("length", "entropy", "digit_ratio", "vowel_ratio", "label_count", "lm_bigram", "lm_trigram")
DGA_MODEL_FEATURES = tuple(name for name in FEATURE_ORDER if name in LEXICAL_FEATURES)
assert "nxdomain_rate" not in DGA_MODEL_FEATURES


def build_language_model(domains: Iterable[str]) -> dict[str, float]:
    """Build an offline benign n-gram background model with a fixed floor."""
    counts: dict[str, int] = {}
    total = 0
    for domain in domains:
        label = domain.lower().split(".")[0]
        for size in (2, 3):
            for index in range(max(0, len(label) - size + 1)):
                gram = label[index : index + size]
                counts[gram] = counts.get(gram, 0) + 1
                total += 1
    return {**{gram: count / max(total, 1) for gram, count in counts.items()}, "__floor__": -12.0}


def model_vector(qname: str, language_model: Mapping[str, float]) -> tuple[float, ...]:
    """Feature vector computed from the observable query name ONLY (no label, no response)."""
    record = domain_features(qname, language_model=language_model)
    return tuple(float(record[name]) for name in DGA_MODEL_FEATURES)


def _record(example: DomainExample, language_model: Mapping[str, float]) -> tuple[float, ...]:
    return model_vector(example.qname, language_model)


def _sigmoid(value: float) -> float:
    value = max(min(value, 500.0), -500.0)
    return 1.0 / (1.0 + exp(-value))


@dataclass
class CalibratedDGAModel:
    classifier: Any
    language_model: dict[str, float]
    platt_slope: float
    platt_intercept: float
    version: str = MODEL_VERSION
    feature_names: tuple[str, ...] = DGA_MODEL_FEATURES

    def predict_probability(self, qname: str) -> float:
        raw_probability = _raw_probability(self.classifier, [model_vector(qname, self.language_model)])[0]
        logit = __import__("math").log(max(raw_probability, 1e-9) / max(1.0 - raw_probability, 1e-9))
        return _sigmoid(self.platt_slope * logit + self.platt_intercept)

    # -- artifact: LightGBM text booster + JSON metadata (no pickle) ----------
    def save_artifact(self, directory: Path, extra_meta: Mapping[str, Any] | None = None) -> dict[str, str]:
        """Write <dir>/dga_lightgbm.txt (booster) and <dir>/dga_model_meta.json.

        Plain text and JSON only: loading never executes code from the
        artifact (a pickle would).  Requires a fitted LGBMClassifier.
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        booster = getattr(self.classifier, "booster_", None)
        if booster is None:
            raise TypeError("save_artifact needs a fitted LightGBM classifier (booster_)")
        booster_path = directory / BOOSTER_FILE
        booster.save_model(str(booster_path))
        meta = {"model_version": self.version, "feature_names": list(self.feature_names),
                "platt_slope": self.platt_slope, "platt_intercept": self.platt_intercept,
                "language_model": self.language_model, **dict(extra_meta or {})}
        meta_path = directory / META_FILE
        meta_path.write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return {"booster": str(booster_path), "meta": str(meta_path)}

    @classmethod
    def load_artifact(cls, directory: Path) -> "CalibratedDGAModel":
        import lightgbm

        directory = Path(directory)
        meta = json.loads((directory / META_FILE).read_text(encoding="utf-8"))
        if tuple(meta["feature_names"]) != DGA_MODEL_FEATURES:
            raise ValueError(f"artifact features {meta['feature_names']} != code features {list(DGA_MODEL_FEATURES)}")
        booster = lightgbm.Booster(model_file=str(directory / BOOSTER_FILE))
        return cls(booster, dict(meta["language_model"]), float(meta["platt_slope"]), float(meta["platt_intercept"]),
                   version=str(meta["model_version"]))


ARTIFACT_DIR = Path(__file__).resolve().parent / "artifact"
BOOSTER_FILE = "dga_lightgbm.txt"
META_FILE = "dga_model_meta.json"


def _raw_probability(classifier: Any, rows: list[tuple[float, ...]]) -> list[float]:
    """P(DGA) from a fitted sklearn-style classifier or a raw lightgbm.Booster.

    Rows go in as a plain float array WITHOUT column names, matching how the
    model is fitted - so LightGBM never warns about feature names.
    """
    import numpy as np

    matrix = np.asarray(rows, dtype=float)
    if hasattr(classifier, "predict_proba"):
        return [float(p) for p in classifier.predict_proba(matrix)[:, 1]]
    return [float(p) for p in classifier.predict(matrix)]      # Booster, binary objective -> probability


def _default_classifier() -> Any:
    from lightgbm import LGBMClassifier  # imported lazily so the module loads without lightgbm

    return LGBMClassifier(n_estimators=120, learning_rate=0.08, num_leaves=15, min_child_samples=5, random_state=26145, n_jobs=1, verbosity=-1)


def train_lightgbm(examples: Iterable[DomainExample], classifier_factory: Callable[[], Any] | None = None) -> CalibratedDGAModel:
    from scipy.optimize import minimize

    from .dga_dataset import registered_domain

    examples = tuple(examples)
    by_label = {label: [example for example in examples if example.label == label] for label in (0, 1)}
    calibration = [example for label in (0, 1) for example in by_label[label][::4]]
    calibration_domains = {example.canonical_domain for example in calibration}
    fitting = [example for example in examples if example.canonical_domain not in calibration_domains]
    if len({example.label for example in fitting}) != 2 or len({example.label for example in calibration}) != 2:
        raise ValueError("training and calibration partitions both require benign and DGA examples")
    # The benign n-gram language model is built from FITTING benign names only.
    # Fitting rows get OUT-OF-FOLD language-model scores (5 folds by registered
    # domain) so a benign name never scores against a model that contains its
    # own n-grams; calibration and test rows are scored against the full model,
    # exactly as at inference time.
    fitting_benign = [example for example in fitting if example.label == 0]
    language_model = build_language_model(example.qname for example in fitting_benign)
    fold_of = {example.qname: int(__import__("hashlib").sha256(registered_domain(example.qname).encode()).hexdigest()[:8], 16) % 5 for example in fitting_benign}
    fold_models = {fold: build_language_model(e.qname for e in fitting_benign if fold_of[e.qname] != fold) for fold in range(5)}
    fitting_rows = [_record(example, fold_models[fold_of[example.qname]] if example.label == 0 else language_model) for example in fitting]
    classifier = (classifier_factory or _default_classifier)()
    # Fitted on an unnamed float array and always queried the same way (see
    # _raw_probability): mixing named fit / unnamed predict is what produced
    # LightGBM's "X does not have valid feature names" warning. Names are kept
    # in CalibratedDGAModel.feature_names and in the artifact metadata.
    import numpy as np

    classifier.fit(np.asarray(fitting_rows, dtype=float), [example.label for example in fitting])
    raw = _raw_probability(classifier, [_record(example, language_model) for example in calibration])
    targets = [example.label for example in calibration]
    logits = [__import__("math").log(max(probability, 1e-9) / max(1.0 - probability, 1e-9)) for probability in raw]
    result = minimize(lambda params: sum(-(target * __import__("math").log(max(_sigmoid(params[0] * value + params[1]), 1e-12)) + (1 - target) * __import__("math").log(max(1 - _sigmoid(params[0] * value + params[1]), 1e-12))) for value, target in zip(logits, targets)), x0=(1.0, 0.0), method="BFGS")
    slope, intercept = (float(result.x[0]), float(result.x[1])) if result.success else (1.0, 0.0)
    return CalibratedDGAModel(classifier, language_model, slope, intercept)


def per_class_report(labels: list[int], predictions: list[int]) -> dict[str, dict[str, float | int]]:
    """Precision / recall / F1 / support for both classes (benign=0, dga=1)."""
    out: dict[str, dict[str, float | int]] = {}
    for name, positive in (("benign", 0), ("dga", 1)):
        tp = sum(1 for y, p in zip(labels, predictions) if y == positive and p == positive)
        fp = sum(1 for y, p in zip(labels, predictions) if y != positive and p == positive)
        fn = sum(1 for y, p in zip(labels, predictions) if y == positive and p != positive)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        out[name] = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "support": tp + fn, "tp": tp, "fp": fp, "fn": fn}
    return out


def evaluate_model(model: CalibratedDGAModel, examples: Iterable[DomainExample], threshold: float = 0.5) -> dict[str, object]:
    """Evaluate from the query name alone - the label is used ONLY as ground truth."""
    from sklearn.metrics import brier_score_loss, roc_auc_score

    examples = tuple(examples)
    labels = [example.label for example in examples]
    probabilities = predict_many(model, [example.qname for example in examples])
    predictions = [int(probability >= threshold) for probability in probabilities]
    report: dict[str, object] = {"count": len(examples), "threshold": threshold, "per_class": per_class_report(labels, predictions), "brier_score": round(float(brier_score_loss(labels, probabilities)), 4) if len(set(labels)) == 2 else None, "roc_auc": round(float(roc_auc_score(labels, probabilities)), 4) if len(set(labels)) == 2 else None}
    bins = [{"lower": lower / 5, "upper": (lower + 1) / 5, "count": 0, "mean_probability": 0.0, "observed_rate": 0.0} for lower in range(5)]
    for probability, label in zip(probabilities, labels):
        bin_item = bins[min(4, int(probability * 5))]
        bin_item["count"] += 1
        bin_item["mean_probability"] += probability
        bin_item["observed_rate"] += label
    for bin_item in bins:
        if bin_item["count"]:
            bin_item["mean_probability"] /= bin_item["count"]
            bin_item["observed_rate"] /= bin_item["count"]
    report["reliability"] = bins
    return report


def predict_many(model: CalibratedDGAModel, qnames: list[str]) -> list[float]:
    """Vectorised predict_probability (same numbers, one model call)."""
    if not qnames:
        return []
    if not isinstance(model, CalibratedDGAModel):          # any other scorer: one name per call, name only
        return [float(model.predict_probability(q)) for q in qnames]
    import math

    raw = _raw_probability(model.classifier, [model_vector(q, model.language_model) for q in qnames])
    return [_sigmoid(model.platt_slope * math.log(max(p, 1e-9) / max(1.0 - p, 1e-9)) + model.platt_intercept) for p in raw]


def load_default_model() -> CalibratedDGAModel | None:
    """The saved artifact, or None when it is absent or lightgbm is not installed (rule fallback)."""
    if not (ARTIFACT_DIR / BOOSTER_FILE).is_file() or not (ARTIFACT_DIR / META_FILE).is_file():
        return None
    try:
        return CalibratedDGAModel.load_artifact(ARTIFACT_DIR)
    except ImportError:
        return None
