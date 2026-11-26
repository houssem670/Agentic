"""Compare les règles CAN, IsolationForest et leur combinaison sur plusieurs graines."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean, pstdev
from typing import Sequence

from scripts.evaluate_rules import (
    ATTACK_LABELS,
    ATTACK_WINDOWS,
    SIMULATION_DURATION,
    ConfusionMetrics,
    TrafficWindow,
    calculate_metrics,
    evaluate_windows,
    split_windows,
)
from tools.anomaly_detector.ml_detector import MLAnomalyDetector
from tools.traffic_simulator.simulator import TrafficSimulator


DEFAULT_SEEDS = (42, 43, 44, 45, 46)
METHODS = (
    ("rules", "Règles seules"),
    ("ml", "ML seul"),
    ("combined", "Règles + ML"),
)
METRIC_FIELDS = (
    ("precision", "Précision"),
    ("recall", "Recall"),
    ("f1", "F1"),
    ("false_positive_rate", "Taux de faux positifs"),
)


@dataclass(frozen=True)
class SeedEvaluation:
    """Métriques globales et par attaque pour une graine de test."""

    seed: int
    metrics: dict[str, ConfusionMetrics]
    attack_recalls: dict[str, dict[str, float | None]]


def parse_seeds(value: str) -> tuple[int, ...]:
    """Convertit une liste séparée par des virgules en graines uniques."""
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        raise argparse.ArgumentTypeError("Fournissez des graines séparées par des virgules.")
    try:
        seeds = tuple(int(part) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Chaque graine doit être un entier.") from exc
    if len(set(seeds)) != len(seeds):
        raise argparse.ArgumentTypeError("Les graines doivent être uniques.")
    return seeds


def mean_and_std(values: Sequence[float | None]) -> tuple[float | None, float | None]:
    """Calcule la moyenne et l'écart-type de population."""
    available = [value for value in values if value is not None]
    if not available:
        return None, None
    return fmean(available), pstdev(available)


def evaluate_seed(
    detector: MLAnomalyDetector, seed: int
) -> SeedEvaluation:
    """Évalue les trois méthodes sur un scénario régénéré."""
    records = TrafficSimulator(
        duration=SIMULATION_DURATION,
        seed=seed,
        attack_windows=ATTACK_WINDOWS,
    ).generate(ATTACK_LABELS)
    windows = split_windows(records, duration=SIMULATION_DURATION, window_seconds=1.0)
    rule_results = evaluate_windows(windows)
    test_records = [record for window in windows for record in window.records]
    ml_by_window = {
        prediction.window_index: prediction.is_anomaly
        for prediction in detector.predict(test_records)
    }

    rule_predictions = [result.predicted_attack for result in rule_results]
    ml_predictions = [
        ml_by_window.get(int(window.start), False) for window in windows
    ]
    combined_predictions = [
        rules or ml for rules, ml in zip(rule_predictions, ml_predictions)
    ]
    predictions = {
        "rules": rule_predictions,
        "ml": ml_predictions,
        "combined": combined_predictions,
    }
    truth = [window.is_attack for window in windows]
    metrics = {
        method: calculate_metrics(truth, predicted)
        for method, predicted in predictions.items()
    }

    attack_recalls: dict[str, dict[str, float | None]] = {}
    for attack in ATTACK_LABELS:
        indices = [
            index
            for index, window in enumerate(windows)
            if window.attack_type == attack
        ]
        attack_recalls[attack] = {
            method: (
                sum(predicted[index] for index in indices) / len(indices)
                if indices
                else None
            )
            for method, predicted in predictions.items()
        }
    return SeedEvaluation(seed, metrics, attack_recalls)


def _format_metric(value: float | None) -> str:
    return f"{value:.3f}" if value is not None else "N/D"


def _format_summary(values: Sequence[float | None]) -> str:
    mean, standard_deviation = mean_and_std(values)
    if mean is None or standard_deviation is None:
        return "N/D"
    return f"{mean:.3f} ± {standard_deviation:.3f}"


def build_report(evaluations: Sequence[SeedEvaluation]) -> str:
    """Construit les tableaux par graine et les résumés multi-graines."""
    seeds = ", ".join(str(result.seed) for result in evaluations)
    lines = [
        "# Comparaison des règles et du détecteur ML",
        "",
        "Entraînement commun : 300 s de trafic normal, graine 7. "
        f"Graines de test : {seeds}.",
        "Les écarts-types présentés sont ceux de population ; IsolationForest "
        "est entraîné séparément par CAN ID sur les seules trames normales.",
        "",
        "## Moyenne ± écart-type par détecteur",
        "",
        "| Détecteur | Précision | Recall | F1 | Taux de faux positifs |",
        "|---|---:|---:|---:|---:|",
    ]
    for method, name in METHODS:
        metric_cells = [
            _format_summary(
                [getattr(result.metrics[method], field) for result in evaluations]
            )
            for field, _ in METRIC_FIELDS
        ]
        lines.append(f"| {name} | {' | '.join(metric_cells)} |")

    lines.extend(
        [
            "",
            "## Métriques par graine",
            "",
            "| Graine | Détecteur | Précision | Recall | F1 | Faux positifs |",
            "|---:|---|---:|---:|---:|---:|",
        ]
    )
    for result in evaluations:
        for method, name in METHODS:
            metrics = result.metrics[method]
            lines.append(
                f"| {result.seed} | {name} | {_format_metric(metrics.precision)} | "
                f"{_format_metric(metrics.recall)} | {_format_metric(metrics.f1)} | "
                f"{_format_metric(metrics.false_positive_rate)} |"
            )

    lines.extend(
        [
            "",
            "## Recall par type d'attaque (moyenne ± écart-type)",
            "",
            "| Type | Détecteur | Recall |",
            "|---|---|---:|",
        ]
    )
    for attack in ATTACK_LABELS:
        for method, name in METHODS:
            lines.append(
                f"| {attack} | {name} | "
                f"{_format_summary([result.attack_recalls[attack][method] for result in evaluations])} |"
            )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> None:
    """Entraîne une fois le modèle puis compare les graines demandées."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seeds",
        type=parse_seeds,
        default=DEFAULT_SEEDS,
        metavar="N1,N2,...",
        help="graines de test séparées par des virgules",
    )
    args = parser.parse_args(argv)

    training_records = TrafficSimulator(duration=300.0, seed=7).generate(attacks=())
    detector = MLAnomalyDetector(
        window_seconds=1.0,
        contamination=0.001,
        random_state=42,
    ).fit(training_records)
    evaluations = [evaluate_seed(detector, seed) for seed in args.seeds]
    report = build_report(evaluations)

    output = Path("reports/evaluation_comparison.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(report)
    print(f"Rapport écrit dans {output}.")


if __name__ == "__main__":
    main()
