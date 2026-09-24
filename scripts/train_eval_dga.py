"""Leakage-free training + evaluation of the DGA LightGBM model (PS task 1).

Usage (from the project root):
    python scripts/train_eval_dga.py                  # evaluate only, LightGBM
    python scripts/train_eval_dga.py --save-model     # also train on the full corpus and save artifact (task 8)

Writes benchmarks/dga_eval_<UTC timestamp>.json and .md, containing the
machine spec and the exact command.  Every metric comes from this run.

Evaluation protocol
  1. grouped validation: ~30 % of registered domains held out (no domain on both sides)
  2. leave-one-family-out: for each of 5 DGA families, train WITHOUT it and test on it
     (plus a disjoint benign bucket) - the honest "unseen family" number
  3. the running rules-fallback detector is scored on the same test sets as a baseline
Features come from the query name only; labels are used only as ground truth.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from machine_spec import machine_spec, spec_markdown  # noqa: E402
from models.dga_dataset import build_extended_dga_corpus, family_holdout_splits, grouped_train_validation_split  # noqa: E402
from models.dga_model import DGA_MODEL_FEATURES, MODEL_VERSION, evaluate_model, per_class_report, train_lightgbm  # noqa: E402


def _classifier_factory(name: str):
    if name == "lightgbm":
        return None  # default in train_lightgbm
    if name == "sklearn-hgb":  # development fallback when lightgbm is not installed; never reported as LightGBM
        from sklearn.ensemble import HistGradientBoostingClassifier

        return lambda: HistGradientBoostingClassifier(max_iter=120, learning_rate=0.08, random_state=26145)
    raise SystemExit(f"unknown classifier {name}")


def _rule_baseline(examples, threshold: float) -> dict:
    from detectors.dga import DGADetector

    detector = DGADetector()
    labels = [e.label for e in examples]
    preds = [int(detector.score_domain(e.qname)[0] >= threshold and not detector.is_allowlisted(e.qname)) for e in examples]
    return {"threshold": threshold, "per_class": per_class_report(labels, preds)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--classifier", default="lightgbm", choices=("lightgbm", "sklearn-hgb"))
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    parser.add_argument("--save-model", action="store_true", help="train on the full corpus and write models/artifact/")
    args = parser.parse_args()
    factory = _classifier_factory(args.classifier)

    corpus = build_extended_dga_corpus()
    result: dict = {
        "machine": machine_spec(),
        "model_version": MODEL_VERSION,
        "classifier": args.classifier,
        "features": list(DGA_MODEL_FEATURES),
        "leakage_note": "nxdomain_rate removed from the per-domain model; features computed from qname only",
        "data": {"source": "synthetic: models/dga_dataset.build_extended_dga_corpus (seed 26145)",
                 "total": len(corpus), "benign": sum(1 for e in corpus if e.label == 0), "dga": sum(1 for e in corpus if e.label == 1),
                 "families": sorted({e.family for e in corpus if e.label})},
    }

    split = grouped_train_validation_split(corpus)
    model = train_lightgbm(split["train"], factory)
    result["grouped_validation"] = {
        "train_size": len(split["train"]), "validation_size": len(split["validation"]),
        "model": evaluate_model(model, split["validation"]),
        "rules_fallback_0.85": _rule_baseline(split["validation"], 0.85),
        "rules_fallback_0.70": _rule_baseline(split["validation"], 0.70),
    }
    importances = getattr(model.classifier, "feature_importances_", None)
    if importances is not None:
        result["grouped_validation"]["feature_importance"] = {name: int(value) for name, value in zip(DGA_MODEL_FEATURES, importances)}

    folds = []
    for family, train, test in family_holdout_splits(corpus):
        fold_model = train_lightgbm(train, factory)
        folds.append({"held_out_family": family, "train_size": len(train), "test_size": len(test),
                      "test_dga": sum(e.label for e in test), "model": evaluate_model(fold_model, test),
                      "rules_fallback_0.70": _rule_baseline(test, 0.70)})
    result["leave_one_family_out"] = folds

    if args.save_model:
        full = train_lightgbm(corpus, factory)
        artifact = ROOT / "models" / "artifact" / "dga_lightgbm.pkl"
        full.save(artifact)
        result["saved_artifact"] = str(artifact.relative_to(ROOT))

    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out / f"dga_eval_{stamp}.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    def row(name, rep):
        b, d = rep["per_class"]["benign"], rep["per_class"]["dga"]
        return f"| {name} | {b['precision']:.3f} | {b['recall']:.3f} | {b['f1']:.3f} | {d['precision']:.3f} | {d['recall']:.3f} | {d['f1']:.3f} |"

    gv = result["grouped_validation"]
    lines = [f"# DGA model evaluation ({stamp})", "", f"Classifier: **{args.classifier}**, model `{MODEL_VERSION}`. Data: {result['data']['source']} "
             f"({result['data']['benign']} benign, {result['data']['dga']} DGA). **Synthetic corpus - not real traffic.**", "",
             "## Machine", "| key | value |", "|---|---|", spec_markdown(result["machine"]), "",
             f"## Grouped validation (train {gv['train_size']}, validation {gv['validation_size']})", "",
             "| Detector | Benign P | Benign R | Benign F1 | DGA P | DGA R | DGA F1 |", "|---|---|---|---|---|---|---|",
             row("LightGBM (calibrated, thr 0.5)" if args.classifier == "lightgbm" else f"{args.classifier} (thr 0.5)", gv["model"]),
             row("rules-fallback thr 0.85", gv["rules_fallback_0.85"]), row("rules-fallback thr 0.70", gv["rules_fallback_0.70"]),
             f"\nModel ROC-AUC {gv['model']['roc_auc']}, Brier {gv['model']['brier_score']}. Feature importance: {gv.get('feature_importance', 'n/a')}.", "",
             "> Caveat: validation benign names come from the same synthetic generator vocabulary as training, so grouped-validation "
             "scores measure fit to our generator, not real-world accuracy. The leave-one-family-out rows are the meaningful generalisation test.", "",
             "## Leave-one-family-out (family never seen in training)", "",
             "| Held-out family | n DGA | Model DGA P | Model DGA R | Model DGA F1 | Model benign F1 | Rules(0.70) DGA R |", "|---|---|---|---|---|---|---|"]
    for f in folds:
        d, b, r = f["model"]["per_class"]["dga"], f["model"]["per_class"]["benign"], f["rules_fallback_0.70"]["per_class"]["dga"]
        lines.append(f"| {f['held_out_family']} | {f['test_dga']} | {d['precision']:.3f} | {d['recall']:.3f} | {d['f1']:.3f} | {b['f1']:.3f} | {r['recall']:.3f} |")
    (out / f"dga_eval_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
