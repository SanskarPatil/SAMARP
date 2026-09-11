"""Build the vendored deterministic DGA artifact and evaluation report."""
from __future__ import annotations
import json
from pathlib import Path
from .dga_dataset import build_dga_corpus, split_holdouts
from .dga_model import evaluate_model, train_lightgbm

ROOT = Path(__file__).resolve().parents[1]
def main() -> None:
    partitions = split_holdouts(build_dga_corpus())
    model = train_lightgbm(partitions["train"])
    model.save(ROOT / "models" / "artifact" / "dga_lightgbm.pkl")
    report = {name: evaluate_model(model, examples) for name, examples in partitions.items() if examples}
    (ROOT / "models" / "evaluation.json").write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
if __name__ == "__main__": main()
