"""Leakage-free training + evaluation of the DGA LightGBM model (PS tasks 1 and 8).

Usage (from the project root, venv active):
    python scripts/train_eval_dga.py                                   # evaluate, LightGBM
    python scripts/train_eval_dga.py --save-model                      # + save models/artifact/
    python scripts/train_eval_dga.py --real-benign intel\\tranco\\top-1m.csv   # + REAL benign test set
    python scripts/train_eval_dga.py --save-model --real-benign intel\\tranco\\top-1m.csv --train-real --real-top 30000
        # REAL benign also used for TRAINING: hash-split by domain, train half / disjoint test half

Writes benchmarks/dga_eval_<UTC>.json and .md with machine spec and command.

Evaluation protocol (features come from the query name only; labels are ground truth only)
  1. Word-level hold-out: ~30 % of benign vocabulary words never appear in training.
     Benign names built only from those words form the OUT-OF-VOCABULARY (OOV) set.
  2. Grouped validation on in-vocabulary data: no registered domain on both sides.
  3. OOV benign false-positive rate, and OOV benign + validation DGA mixed set.
  4. Leave-one-family-out: each of 5 DGA families unseen in training.
  5. Optional REAL benign list (Tranco CSV "rank,domain" or one domain per line):
     false-positive rate only, labelled "real". Absent -> reported as not available.
  6. The running rules-fallback detector is scored on the same sets.
With --save-model the deployed artifact is refit on ALL synthetic data; the
hold-out numbers above estimate how it generalises. Text booster + JSON, no pickle.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from machine_spec import machine_spec, spec_markdown  # noqa: E402
from models.dga_dataset import (build_vocab_holdout_corpus, family_holdout_splits, grouped_train_validation_split,  # noqa: E402
                                load_real_benign, vocabulary_split)
from models.dga_model import (ARTIFACT_DIR, DGA_MODEL_FEATURES, MODEL_VERSION, evaluate_model, per_class_report,  # noqa: E402
                              predict_many, train_lightgbm)


def _classifier_factory(name: str):
    if name == "lightgbm":
        return None  # default in train_lightgbm
    if name == "sklearn-hgb":  # development stand-in when lightgbm is not installed; never reported as LightGBM
        from sklearn.ensemble import HistGradientBoostingClassifier

        return lambda: HistGradientBoostingClassifier(max_iter=120, learning_rate=0.08, random_state=26145)
    raise SystemExit(f"unknown classifier {name}")


def _rule_preds(examples, threshold: float) -> list[int]:
    from detectors.dga import DGADetector

    detector = DGADetector()
    return [int(detector.score_domain(e.qname)[0] >= threshold and not detector.is_allowlisted(e.qname)) for e in examples]


def _rule_baseline(examples, threshold: float) -> dict:
    return {"threshold": threshold, "per_class": per_class_report([e.label for e in examples], _rule_preds(examples, threshold))}


def _benign_only(model, examples, threshold: float) -> dict:
    """False-positive view of a benign-only set (no DGA in it, so precision is undefined)."""
    probs = predict_many(model, [e.qname for e in examples])
    fp = [e.qname for e, p in zip(examples, probs) if p >= threshold]
    rules = {thr: sum(_rule_preds(examples, thr)) for thr in (0.85, 0.70)}
    n = len(examples)
    return {"n": n, "model_threshold": threshold, "model_false_positives": len(fp), "model_fpr": round(len(fp) / n, 4) if n else None,
            "model_mean_probability": round(statistics.fmean(probs), 4) if probs else None,
            "model_p95_probability": round(sorted(probs)[int(0.95 * (n - 1))], 4) if probs else None,
            "rules_fpr_0.85": round(rules[0.85] / n, 4) if n else None, "rules_fpr_0.70": round(rules[0.70] / n, 4) if n else None,
            "example_false_positives": fp[:10]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--classifier", default="lightgbm", choices=("lightgbm", "sklearn-hgb"))
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    parser.add_argument("--save-model", action="store_true", help="refit on all synthetic data and write models/artifact/")
    parser.add_argument("--real-benign", default=None, help="Tranco CSV (rank,domain) or one domain per line; evaluated as REAL benign")
    parser.add_argument("--real-top", type=int, default=10_000)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--train-real", action="store_true",
                        help="also TRAIN on real benign: hash-split the list by domain into a train half and a disjoint test half")
    parser.add_argument("--real-train-max", type=int, default=6000, help="cap on real benign training names (keeps class balance)")
    args = parser.parse_args()
    factory = _classifier_factory(args.classifier)
    thr = args.threshold

    corpus = build_vocab_holdout_corpus()
    in_vocab = tuple(e for e in corpus if e.family != "benign_oov")
    oov = tuple(e for e in corpus if e.family == "benign_oov")
    train_words, heldout_words = vocabulary_split()
    result: dict = {
        "machine": machine_spec(), "model_version": MODEL_VERSION, "classifier": args.classifier, "features": list(DGA_MODEL_FEATURES),
        "leakage_note": "nxdomain_rate removed; features from qname only; held-out benign WORDS never appear in training",
        "data": {"source": "synthetic: models/dga_dataset.build_vocab_holdout_corpus (seed 26145)",
                 "benign_in_vocab": sum(1 for e in in_vocab if e.label == 0), "benign_oov": len(oov),
                 "dga": sum(1 for e in corpus if e.label == 1), "families": sorted({e.family for e in corpus if e.label}),
                 "train_words": len(train_words), "heldout_words": list(heldout_words)},
    }

    real, provenance, real_train, real_test = [], None, [], []
    if args.real_benign:
        from models.dga_dataset import _bucket

        real, provenance = load_real_benign(args.real_benign, args.real_top)
        if args.train_real:
            # Deterministic, domain-disjoint halves: a domain is in exactly one half.
            real_train = [e for e in real if _bucket(f"real:{e.qname}", 2) == 0][: args.real_train_max]
            real_test = [e for e in real if _bucket(f"real:{e.qname}", 2) == 1]
            assert not {e.qname for e in real_train} & {e.qname for e in real_test}
        else:
            real_test = real
    elif args.train_real:
        raise SystemExit("--train-real needs --real-benign PATH")
    result["data"]["benign_training_sources"] = ["synthetic in-vocabulary"] + (["REAL (Tranco train half)"] if real_train else [])
    result["data"]["real_train"] = len(real_train)
    result["data"]["real_test"] = len(real_test)

    split = grouped_train_validation_split(in_vocab)
    model = train_lightgbm(list(split["train"]) + real_train, factory)
    val_dga = [e for e in split["validation"] if e.label == 1]
    result["grouped_validation_in_vocab"] = {
        "train_size": len(split["train"]), "validation_size": len(split["validation"]),
        "model": evaluate_model(model, split["validation"], thr),
        "rules_fallback_0.85": _rule_baseline(split["validation"], 0.85), "rules_fallback_0.70": _rule_baseline(split["validation"], 0.70),
    }
    importances = getattr(model.classifier, "feature_importances_", None)
    if importances is not None:
        result["grouped_validation_in_vocab"]["feature_importance"] = {n: int(v) for n, v in zip(DGA_MODEL_FEATURES, importances)}
    result["benign_only"] = {"in_vocab_validation": _benign_only(model, [e for e in split["validation"] if e.label == 0], thr),
                             "oov_heldout_words": _benign_only(model, oov, thr)}
    mixed = list(oov) + val_dga
    result["oov_mixed"] = {"description": "OOV benign + grouped-validation DGA", "model": evaluate_model(model, mixed, thr),
                           "rules_fallback_0.85": _rule_baseline(mixed, 0.85), "rules_fallback_0.70": _rule_baseline(mixed, 0.70)}

    if args.real_benign:
        result["real_benign"] = {"available": True, "provenance": provenance, "used_for_training": bool(real_train),
                                 "evaluated_on": "disjoint test half (hash split by domain)" if real_train else "whole list",
                                 **_benign_only(model, real_test, thr),
                                 "note": "rules fallback allowlists ~30 top domains, which favours it on the head of a popularity list"}
    else:
        result["real_benign"] = {"available": False, "reason": "no real benign list supplied (--real-benign); intel/tranco_sample.txt has 5 domains, too few to report"}

    folds = []
    for family, train, test in family_holdout_splits(in_vocab):
        fold_model = train_lightgbm(list(train) + real_train, factory)
        folds.append({"held_out_family": family, "train_size": len(train), "test_size": len(test), "test_dga": sum(e.label for e in test),
                      "model": evaluate_model(fold_model, test, thr), "rules_fallback_0.70": _rule_baseline(test, 0.70),
                      "oov_benign": _benign_only(fold_model, oov, thr),
                      **({"real_benign_test": _benign_only(fold_model, real_test, thr)} if real_test else {})})
    result["leave_one_family_out"] = folds

    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out / f"dga_eval_{stamp}.json"

    if args.save_model:
        if args.classifier != "lightgbm":
            raise SystemExit("--save-model writes a LightGBM artifact; run with --classifier lightgbm")
        full = train_lightgbm(list(corpus) + real_train, factory)
        paths = full.save_artifact(ARTIFACT_DIR, {"trained_on": result["data"], "trained_at_utc": result["machine"]["captured_at_utc"],
                                                  "metrics_file": f"benchmarks/{json_path.name}", "threshold": thr,
                                                  "note": "refit on ALL synthetic data after evaluation; see metrics_file for hold-out estimates"})
        import hashlib

        result["saved_artifact"] = {k: {"path": str(Path(v).relative_to(ROOT)).replace("\\", "/"),
                                        "sha256": hashlib.sha256(Path(v).read_bytes()).hexdigest(), "bytes": Path(v).stat().st_size}
                                    for k, v in paths.items()}
        result["saved_artifact"]["git"] = "models/artifact/ is .gitignored by project policy (vendored into the offline bundle); hashes above identify it"

    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.save_model:
        (ARTIFACT_DIR / "dga_metrics.json").write_text(json.dumps({k: result[k] for k in result if k != "machine"} | {"machine": result["machine"]}, indent=2), encoding="utf-8")

    def row(name, rep):
        b, d = rep["per_class"]["benign"], rep["per_class"]["dga"]
        return f"| {name} | {b['precision']:.3f} | {b['recall']:.3f} | {b['f1']:.3f} | {d['precision']:.3f} | {d['recall']:.3f} | {d['f1']:.3f} |"

    def fp_row(name, r):
        if not r.get("n"):
            return f"| {name} | - | - | - | - | - |"
        return f"| {name} | {r['n']} | {r['model_fpr']:.4f} ({r['model_false_positives']}) | {r['rules_fpr_0.85']:.4f} | {r['rules_fpr_0.70']:.4f} | {r['model_mean_probability']:.3f} |"

    label = "LightGBM (calibrated, thr %.2f)" % thr if args.classifier == "lightgbm" else f"{args.classifier} STAND-IN (thr {thr:.2f})"
    gv, om, rb = result["grouped_validation_in_vocab"], result["oov_mixed"], result["real_benign"]
    lines = [f"# DGA model evaluation ({stamp})", "",
             f"Classifier: **{args.classifier}**, model `{MODEL_VERSION}`. Data: {result['data']['source']} "
             f"({result['data']['benign_in_vocab']} in-vocabulary benign, {len(oov)} out-of-vocabulary benign, {result['data']['dga']} DGA). "
             f"**Synthetic corpus - not real traffic**, except the rows labelled *real*.", "",
             (f"**Benign training data includes REAL domains**: {len(real_train)} from the Tranco list (train half); every *real* number below is on the "
              f"other {len(real_test)} domains, which were never trained on." if real_train else "Benign training data: synthetic only."), "",
             f"Held-out benign words ({len(heldout_words)} of {len(train_words) + len(heldout_words)}, never in training): {', '.join(heldout_words)}.", "",
             "## Machine", "| key | value |", "|---|---|", spec_markdown(result["machine"]), "",
             f"## 1. Grouped validation, in-vocabulary (train {gv['train_size']}, validation {gv['validation_size']})", "",
             "| Detector | Benign P | Benign R | Benign F1 | DGA P | DGA R | DGA F1 |", "|---|---|---|---|---|---|---|",
             row(label, gv["model"]), row("rules-fallback thr 0.85", gv["rules_fallback_0.85"]), row("rules-fallback thr 0.70", gv["rules_fallback_0.70"]),
             f"\nModel ROC-AUC {gv['model']['roc_auc']}, Brier {gv['model']['brier_score']}. Feature importance: {gv.get('feature_importance', 'n/a')}.", "",
             "## 2. Benign false-positive rate: in-vocabulary vs out-of-vocabulary vs real", "",
             "| Benign set | n | Model FPR (count) | Rules FPR 0.85 | Rules FPR 0.70 | Model mean P(DGA) |", "|---|---|---|---|---|---|",
             fp_row("in-vocabulary (validation, synthetic)", result["benign_only"]["in_vocab_validation"]),
             fp_row("out-of-vocabulary (held-out words, synthetic)", result["benign_only"]["oov_heldout_words"]),
             fp_row(f"**real** ({rb['provenance']['file']}, {rb['evaluated_on']})", rb) if rb["available"] else f"| **real** | not available: {rb['reason']} | | | | |",
             "", f"OOV false positives (up to 10): {', '.join(result['benign_only']['oov_heldout_words']['example_false_positives']) or 'none'}.", "",
             "## 3. Out-of-vocabulary mixed set (OOV benign + validation DGA)", "",
             "| Detector | Benign P | Benign R | Benign F1 | DGA P | DGA R | DGA F1 |", "|---|---|---|---|---|---|---|",
             row(label, om["model"]), row("rules-fallback thr 0.85", om["rules_fallback_0.85"]), row("rules-fallback thr 0.70", om["rules_fallback_0.70"]),
             f"\nModel ROC-AUC {om['model']['roc_auc']}, Brier {om['model']['brier_score']}.", "",
             "## 4. Leave-one-family-out (family never seen in training)", "",
             "| Held-out family | n DGA | Model DGA P | Model DGA R | Model DGA F1 | Model benign F1 | Rules(0.70) DGA R |", "|---|---|---|---|---|---|---|"]
    for f in folds:
        d, b, r = f["model"]["per_class"]["dga"], f["model"]["per_class"]["benign"], f["rules_fallback_0.70"]["per_class"]["dga"]
        lines.append(f"| {f['held_out_family']} | {f['test_dga']} | {d['precision']:.3f} | {d['recall']:.3f} | {d['f1']:.3f} | {b['f1']:.3f} | {r['recall']:.3f} |")
    lines += ["", "Same folds, out-of-vocabulary benign false-positive rate of each fold model:", "",
              "| Held-out family | OOV benign n | Model FPR (count) |", "|---|---|---|"]
    if real_test:
        lines[-2:] = ["| Held-out family | OOV benign n | Model FPR (count) | Real benign n | Model real FPR (count) |", "|---|---|---|---|---|"]
        lines += [f"| {f['held_out_family']} | {f['oov_benign']['n']} | {f['oov_benign']['model_fpr']:.4f} ({f['oov_benign']['model_false_positives']}) | "
                  f"{f['real_benign_test']['n']} | {f['real_benign_test']['model_fpr']:.4f} ({f['real_benign_test']['model_false_positives']}) |" for f in folds]
    else:
        lines += [f"| {f['held_out_family']} | {f['oov_benign']['n']} | {f['oov_benign']['model_fpr']:.4f} ({f['oov_benign']['model_false_positives']}) |" for f in folds]
    lines += ["", "> Caveats: all rows except *real* use our synthetic generators. The attack suite in scripts/evaluate.py draws DGA names from the same",
              "> five families, so the live-pipeline DGA recall with the model is an in-family number; section 4 is the unseen-family estimate."]
    if args.save_model:
        lines += ["", f"Saved artifact (refit on all synthetic data{' + real train half' if real_train else ''}): {result['saved_artifact']}"]
    (out / f"dga_eval_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
