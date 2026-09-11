"""The project's only trained model: calibrated LightGBM DGA classifier."""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from math import exp
from pathlib import Path
from typing import Iterable, Mapping

from lightgbm import LGBMClassifier
from scipy.optimize import minimize
from sklearn.metrics import brier_score_loss, f1_score, precision_score, recall_score, roc_auc_score

from features.extractor import domain_features, ordered_feature_vector
from features.feature_order import FEATURE_ORDER
from .dga_dataset import DomainExample


MODEL_VERSION = "dga-lightgbm-0.1.0"


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


def _record(example: DomainExample, language_model: Mapping[str, float]) -> tuple[float, ...]:
    # NXDOMAIN is recorded observation context in the synthetic corpus, not a
    # label copied into inference.  Benign/positive rates model the fixture.
    rate = 0.1 if example.label == 0 else 0.7
    return ordered_feature_vector(domain_features(example.qname, nxdomain_rate=rate, language_model=language_model))


def _sigmoid(value: float) -> float:
    value = max(min(value, 500.0), -500.0)
    return 1.0 / (1.0 + exp(-value))


@dataclass
class CalibratedDGAModel:
    classifier: LGBMClassifier
    language_model: dict[str, float]
    platt_slope: float
    platt_intercept: float
    version: str = MODEL_VERSION

    def predict_probability(self, qname: str, nxdomain_rate: float = 0.0) -> float:
        record = domain_features(qname, nxdomain_rate=nxdomain_rate, language_model=self.language_model)
        raw_probability = float(self.classifier.predict_proba([ordered_feature_vector(record)])[0][1])
        logit = __import__("math").log(max(raw_probability, 1e-9) / max(1.0 - raw_probability, 1e-9))
        return _sigmoid(self.platt_slope * logit + self.platt_intercept)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            pickle.dump(self, handle)

    @classmethod
    def load(cls, path: Path) -> "CalibratedDGAModel":
        with path.open("rb") as handle:
            model = pickle.load(handle)
        if not isinstance(model, cls):
            raise TypeError("artifact is not a CalibratedDGAModel")
        return model


def train_lightgbm(examples: Iterable[DomainExample]) -> CalibratedDGAModel:
    examples = tuple(examples)
    benign_domains = [example.qname for example in examples if example.label == 0]
    language_model = build_language_model(benign_domains)
    by_label = {label: [example for example in examples if example.label == label] for label in (0, 1)}
    calibration = [example for label in (0, 1) for example in by_label[label][::4]]
    calibration_domains = {example.canonical_domain for example in calibration}
    fitting = [example for example in examples if example.canonical_domain not in calibration_domains]
    if len({example.label for example in fitting}) != 2 or len({example.label for example in calibration}) != 2:
        raise ValueError("training and calibration partitions both require benign and DGA examples")
    classifier = LGBMClassifier(n_estimators=40, learning_rate=0.08, num_leaves=7, min_child_samples=2, random_state=26145, n_jobs=1, verbosity=-1)
    classifier.fit([_record(example, language_model) for example in fitting], [example.label for example in fitting], feature_name=list(FEATURE_ORDER))
    raw = [float(classifier.predict_proba([_record(example, language_model)])[0][1]) for example in calibration]
    targets = [example.label for example in calibration]
    logits = [__import__("math").log(max(probability, 1e-9) / max(1.0 - probability, 1e-9)) for probability in raw]
    result = minimize(lambda params: sum(-(target * __import__("math").log(max(_sigmoid(params[0] * value + params[1]), 1e-12)) + (1 - target) * __import__("math").log(max(1 - _sigmoid(params[0] * value + params[1]), 1e-12))) for value, target in zip(logits, targets)), x0=(1.0, 0.0), method="BFGS")
    slope, intercept = (float(result.x[0]), float(result.x[1])) if result.success else (1.0, 0.0)
    return CalibratedDGAModel(classifier, language_model, slope, intercept)


def evaluate_model(model: CalibratedDGAModel, examples: Iterable[DomainExample]) -> dict[str, object]:
    examples = tuple(examples)
    labels = [example.label for example in examples]
    probabilities = [model.predict_probability(example.qname, 0.1 if example.label == 0 else 0.7) for example in examples]
    predictions = [int(probability >= 0.5) for probability in probabilities]
    report: dict[str, object] = {"count": len(examples), "precision": precision_score(labels, predictions, zero_division=0), "recall": recall_score(labels, predictions, zero_division=0), "f1": f1_score(labels, predictions, zero_division=0), "brier_score": brier_score_loss(labels, probabilities), "roc_auc": roc_auc_score(labels, probabilities) if len(set(labels)) == 2 else None}
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
