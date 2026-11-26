"""Évalue hors ligne les règles de fréquence et de rejeu CAN."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import can

from tools.anomaly_detector.anomaly_detector import detect_frequency_anomaly
from tools.anomaly_detector.replay_detector import detect_replay_attack
from tools.traffic_simulator.simulator import (
    ATTACK_LABELS,
    CanRecord,
    TrafficSimulator,
)

SIMULATION_DURATION = 180.0
ATTACK_WINDOWS = {
    "flooding": (60.0, 70.0),
    "replay": (90.0, 100.0),
    "spoofing": (120.0, 130.0),
    "fuzzing": (150.0, 160.0),
}


@dataclass(frozen=True)
class TrafficWindow:
    """Une fenêtre temporelle et sa vérité terrain."""

    start: float
    end: float
    records: tuple[CanRecord, ...]
    attack_type: str | None

    @property
    def is_attack(self) -> bool:
        """Indique si la fenêtre contient au moins une trame d'attaque."""
        return self.attack_type is not None


@dataclass(frozen=True)
class WindowResult:
    """Résultat des deux règles pour une fenêtre."""

    window: TrafficWindow
    frequency_triggered: bool
    replay_triggered: bool
    frequency_can_ids: tuple[int, ...]
    replay_can_id: str | None

    @property
    def predicted_attack(self) -> bool:
        """Combine les alertes des deux règles."""
        return self.frequency_triggered or self.replay_triggered


@dataclass(frozen=True)
class ConfusionMetrics:
    """Matrice de confusion et métriques binaires."""

    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None


def split_windows(
    records: Sequence[CanRecord],
    duration: float,
    window_seconds: float = 1.0,
) -> list[TrafficWindow]:
    """Découpe les trames et attribue le type d'attaque majoritaire."""
    if not math.isfinite(duration) or duration <= 0:
        raise ValueError("La durée doit être finie et strictement positive.")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("La fenêtre doit être finie et strictement positive.")

    count = math.ceil(duration / window_seconds)
    buckets: list[list[CanRecord]] = [[] for _ in range(count)]
    for record in records:
        if not math.isfinite(record.timestamp) or not 0 <= record.timestamp < duration:
            raise ValueError("Chaque trame doit être dans l'intervalle de simulation.")
        buckets[int(record.timestamp // window_seconds)].append(record)

    windows: list[TrafficWindow] = []
    for index, bucket in enumerate(buckets):
        attack_counts = Counter(
            record.label for record in bucket if record.label != "normal"
        )
        attack_type = (
            min(attack_counts, key=lambda label: (-attack_counts[label], label))
            if attack_counts
            else None
        )
        start = index * window_seconds
        windows.append(
            TrafficWindow(
                start=start,
                end=min(start + window_seconds, duration),
                records=tuple(bucket),
                attack_type=attack_type,
            )
        )
    return windows


def calculate_metrics(
    truth: Sequence[bool], predictions: Sequence[bool]
) -> ConfusionMetrics:
    """Calcule les métriques binaires sans dépendance externe."""
    if len(truth) != len(predictions):
        raise ValueError("Vérité terrain et prédictions doivent avoir la même taille.")

    true_positive = sum(actual and predicted for actual, predicted in zip(truth, predictions))
    false_positive = sum(not actual and predicted for actual, predicted in zip(truth, predictions))
    true_negative = sum(not actual and not predicted for actual, predicted in zip(truth, predictions))
    false_negative = sum(actual and not predicted for actual, predicted in zip(truth, predictions))

    precision = _optional_ratio(true_positive, true_positive + false_positive)
    recall = _optional_ratio(true_positive, true_positive + false_negative)
    f1 = _optional_ratio(
        2 * true_positive,
        2 * true_positive + false_positive + false_negative,
    )
    false_positive_rate = _optional_ratio(
        false_positive, false_positive + true_negative
    )
    return ConfusionMetrics(
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
    )


def evaluate_windows(windows: Sequence[TrafficWindow]) -> list[WindowResult]:
    """Applique les deux règles existantes à chaque fenêtre."""
    results: list[WindowResult] = []
    for window in windows:
        counts = Counter(record.can_id for record in window.records)
        frequency_can_ids = tuple(
            sorted(
                can_id
                for can_id, count in counts.items()
                if detect_frequency_anomaly(
                    can_id=hex(can_id),
                    count=count,
                    window_seconds=1.0,
                    threshold=100.0,
                ).anomaly
            )
        )
        messages = [
            can.Message(
                timestamp=record.timestamp,
                arbitration_id=record.can_id,
                data=record.data,
                is_extended_id=record.can_id > 0x7FF,
            )
            for record in window.records
        ]
        replay_event = detect_replay_attack(messages)
        results.append(
            WindowResult(
                window=window,
                frequency_triggered=bool(frequency_can_ids),
                replay_triggered=replay_event is not None,
                frequency_can_ids=frequency_can_ids,
                replay_can_id=replay_event.can_id if replay_event is not None else None,
            )
        )
    return results


def generate_evaluation_windows() -> list[TrafficWindow]:
    """Génère le scénario fixe avec des périodes normales et attaquées."""
    records = TrafficSimulator(
        duration=SIMULATION_DURATION,
        seed=42,
        attack_windows=ATTACK_WINDOWS,
    ).generate(ATTACK_LABELS)
    return split_windows(records, duration=SIMULATION_DURATION, window_seconds=1.0)


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _optional_ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _format_metric(value: float | None) -> str:
    return f"{value:.3f}" if value is not None else "N/D"


def _build_report(results: Sequence[WindowResult]) -> str:
    """Construit le rapport Markdown global et par type d'attaque."""
    truth = [result.window.is_attack for result in results]
    predictions = [result.predicted_attack for result in results]
    metrics = calculate_metrics(truth, predictions)
    normal_windows = sum(not result.window.is_attack for result in results)
    attack_counts = Counter(
        result.window.attack_type
        for result in results
        if result.window.attack_type is not None
    )

    lines = [
        "# Évaluation des règles CAN",
        "",
        "Trafic synthétique hors ligne : 180 s, graine 42, fenêtres de 1 s.",
        "Une alerte combinée est positive si la fréquence **ou** le rejeu déclenche.",
        "",
        "## Répartition des fenêtres",
        "",
        "| Catégorie | Nombre de fenêtres |",
        "|---|---:|",
        f"| Normales | {normal_windows} |",
        f"| Attaques (total) | {sum(attack_counts.values())} |",
    ]

    for attack in ATTACK_LABELS:
        lines.append(f"| {attack} | {attack_counts[attack]} |")

    if results and normal_windows / len(results) < 0.5:
        lines.extend(
            [
                "",
                "> **Avertissement :** moins de 50 % des fenêtres sont normales ; "
                "le taux de faux positifs peut être peu représentatif.",
            ]
        )

    lines.extend(
        [
        "",
        "## Métriques globales",
        "",
        "| Précision | Recall | F1 | Taux de faux positifs |",
        "|---:|---:|---:|---:|",
        (
            f"| {_format_metric(metrics.precision)} | {_format_metric(metrics.recall)} | "
            f"{_format_metric(metrics.f1)} | {_format_metric(metrics.false_positive_rate)} |"
        ),
        "",
        "## Matrice de confusion",
        "",
        "| Vérité terrain | Prédit attaque | Prédit normal |",
        "|---|---:|---:|",
        f"| Attaque | {metrics.true_positive} | {metrics.false_negative} |",
        f"| Normal | {metrics.false_positive} | {metrics.true_negative} |",
        "",
        "## Recall et règles déclenchées par type",
        "",
        "| Type d'attaque | Fenêtres | Fréquence seule | Replay seul | Les deux | Non détectée | Recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    )

    for attack in ATTACK_LABELS:
        actual = [
            result
            for result in results
            if result.window.attack_type == attack
        ]
        detected = sum(result.predicted_attack for result in actual)
        recall = _ratio(detected, len(actual))
        frequency_only = sum(
            result.frequency_triggered and not result.replay_triggered
            for result in actual
        )
        replay_only = sum(
            result.replay_triggered and not result.frequency_triggered
            for result in actual
        )
        both = sum(
            result.frequency_triggered and result.replay_triggered
            for result in actual
        )
        missed = sum(not result.predicted_attack for result in actual)
        lines.append(
            f"| {attack} | {len(actual)} | {frequency_only} | {replay_only} | "
            f"{both} | {missed} | {recall:.3f} |"
        )

    lines.extend(
        [
            "",
            "### CAN IDs à l'origine des déclenchements",
            "",
            "| Type d'attaque | IDs fréquence | ID(s) répétition/rejeu |",
            "|---|---|---|",
        ]
    )
    for attack in ATTACK_LABELS:
        actual = [
            result
            for result in results
            if result.window.attack_type == attack
        ]
        frequency_ids = sorted(
            {
                can_id
                for result in actual
                for can_id in result.frequency_can_ids
            }
        )
        replay_ids = sorted(
            {
                result.replay_can_id
                for result in actual
                if result.replay_can_id is not None
            }
        )
        frequency_text = ", ".join(f"0x{can_id:03X}" for can_id in frequency_ids) or "—"
        replay_text = ", ".join(replay_ids) or "—"
        lines.append(f"| {attack} | {frequency_text} | {replay_text} |")

    frequency_count = sum(result.frequency_triggered for result in results)
    replay_count = sum(result.replay_triggered for result in results)
    lines.extend(
        [
            "",
            "## Déclenchements par règle",
            "",
            "| Règle | Fenêtres déclenchées |",
            "|---|---:|",
            f"| Fréquence (seuil strictement supérieur à 100 msg/s) | {frequency_count} |",
            f"| Rejeu (au moins 5 trames identiques en 100 ms) | {replay_count} |",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    """Génère le jeu fixe et écrit le rapport d'évaluation."""
    windows = generate_evaluation_windows()
    results = evaluate_windows(windows)
    report = _build_report(results)

    output = Path("reports/evaluation_rules.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nRapport écrit dans {output}.")


if __name__ == "__main__":
    main()
