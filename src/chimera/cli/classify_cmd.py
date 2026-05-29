"""chimera.cli — classify cmd commands."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



# ----------------------------------------------------------------------
# classify — EMBER 2024 malware probability (optional [ml] extra)
# ----------------------------------------------------------------------


@main.command("classify")
@click.argument("path", type=click.Path(exists=True))
@click.option("--model", "model_path", type=click.Path(exists=True), default=None,
              help="Path to a LightGBM .txt model (default: bundled / "
                   "$CHIMERA_EMBER_MODEL).")
@click.option("--threshold", type=float, default=0.5,
              help="Probability threshold for the malicious label.")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]),
              default="text")
def classify(path: str, model_path: str | None, threshold: float, fmt: str):
    """Score a PE with EMBER 2024 (optional [ml] extra).

    Requires `lightgbm`, `lief`, and (ideally) the upstream `ember` pkg.
    Without them, the command prints a clear "not configured" message
    rather than crashing.
    """
    import json as _json
    from chimera.detection_engineering.ember_classify import EmberClassifier

    clf = EmberClassifier(
        model_path=Path(model_path) if model_path else None,
        threshold=threshold,
    )
    if not clf.is_available():
        raise click.ClickException(
            "EMBER classifier unavailable. Install with "
            "`pip install \"chimera[ml]\"` (lightgbm + lief), and set "
            "CHIMERA_EMBER_MODEL or drop a model at "
            "src/chimera/detection_engineering/data/ember/model.txt."
        )
    verdict = clf.classify(path)
    if verdict is None:
        raise click.ClickException(
            "EMBER could not score this binary — model file missing or "
            "feature extraction failed (is this a valid PE?)."
        )
    label = "MALICIOUS" if verdict.malicious_probability >= threshold else "BENIGN"
    if fmt == "json":
        click.echo(_json.dumps({
            "label": label,
            "probability": verdict.malicious_probability,
            "threshold": threshold,
            "model": verdict.model_path,
        }, indent=2))
        return
    click.echo(f"[chimera] EMBER 2024: {label}  "
               f"p_malicious={verdict.malicious_probability:.4f}  "
               f"(threshold={threshold})")
