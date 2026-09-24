"""Guards against label leakage in the DGA model (PS-compliance task 1)."""

from __future__ import annotations

import inspect

import pytest

from features.feature_order import FEATURE_ORDER
from models import dga_model
from models.dga_dataset import (
    EXTENDED_DGA_FAMILIES,
    build_extended_dga_corpus,
    family_holdout_splits,
    grouped_train_validation_split,
    registered_domain,
)
from models.dga_model import DGA_MODEL_FEATURES, model_vector


def test_model_features_exclude_response_level_nxdomain_and_follow_frozen_order():
    assert "nxdomain_rate" not in DGA_MODEL_FEATURES
    positions = [FEATURE_ORDER.index(name) for name in DGA_MODEL_FEATURES]
    assert positions == sorted(positions)


def test_feature_vector_is_a_function_of_the_query_name_only():
    params = list(inspect.signature(model_vector).parameters)
    assert params == ["qname", "language_model"]
    assert "label" not in inspect.getsource(dga_model._record)
    predict_params = list(inspect.signature(dga_model.CalibratedDGAModel.predict_probability).parameters)
    assert predict_params == ["self", "qname"]


def test_evaluation_never_passes_the_label_into_inference():
    calls: list[tuple] = []

    class _Spy:
        def predict_probability(self, *args, **kwargs):
            calls.append((args, kwargs))
            return 0.9

    corpus = build_extended_dga_corpus(benign_count=40, per_family=8)
    pytest.importorskip("sklearn")
    dga_model.evaluate_model(_Spy(), corpus)
    assert calls and all(len(args) == 1 and not kwargs for args, kwargs in calls)


def test_grouped_split_has_no_registered_domain_on_both_sides_and_covers_every_family():
    split = grouped_train_validation_split(build_extended_dga_corpus())
    train_domains = {registered_domain(e.qname) for e in split["train"]}
    validation_domains = {registered_domain(e.qname) for e in split["validation"]}
    assert not train_domains & validation_domains
    for part in split.values():
        assert {e.family for e in part if e.label} == set(EXTENDED_DGA_FAMILIES)


def test_family_holdout_tests_only_on_an_unseen_family():
    corpus = build_extended_dga_corpus()
    folds = family_holdout_splits(corpus)
    assert [family for family, _, _ in folds] == list(EXTENDED_DGA_FAMILIES)
    for family, train, test in folds:
        assert {e.family for e in test if e.label} == {family}
        assert family not in {e.family for e in train}
        assert not {registered_domain(e.qname) for e in train} & {registered_domain(e.qname) for e in test}
        assert any(e.label == 0 for e in test)


def test_extended_corpus_is_deterministic():
    assert build_extended_dga_corpus(benign_count=60, per_family=10) == build_extended_dga_corpus(benign_count=60, per_family=10)


def test_training_runs_without_label_derived_features():
    pytest.importorskip("scipy")
    sklearn_linear = pytest.importorskip("sklearn.linear_model")
    corpus = build_extended_dga_corpus(benign_count=120, per_family=24)
    model = dga_model.train_lightgbm(corpus, lambda: sklearn_linear.LogisticRegression(max_iter=500))
    assert model.feature_names == DGA_MODEL_FEATURES
    for example in corpus[:10]:
        assert 0.0 <= model.predict_probability(example.qname) <= 1.0
