"""Superseded by scripts/train_eval_dga.py (task 8).

The v0.1 script trained on the 96-domain corpus and pickled the model. The
current pipeline evaluates with grouped, word-level and family hold-outs and
saves a text booster + JSON (no pickle). This entry point forwards to it.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "train_eval_dga.py"
    sys.argv = [str(script), "--save-model"]
    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    main()
