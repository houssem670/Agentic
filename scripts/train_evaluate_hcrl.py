"""Train the existing Isolation Forest on HCRL normal traffic and evaluate it."""

from __future__ import annotations

import argparse
import csv
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import joblib

from scripts.evaluate_rules import ConfusionMetrics, calculate_metrics
from tools.anomaly_detector.ml_detector import (
    FEATURE_NAMES,
    MLAnomalyDetector,
    WindowFeatures,
    extract_features,
)
from tools.traffic_simulator.simulator import CanRecord


WINDOW_SECONDS = 1.0
TRAIN_FRACTION = 0.70
CONTAMINATION = 0.001
N_ESTIMATORS = 100
RANDOM_STATE = 42
PREDICTION_BATCH_WINDOWS = 256
DEFAULT_DATA_DIR = Path("datasets/hcrl")
DEFAULT_MODEL_PATH = Path("models/hcrl_ml_detector.joblib")
DEFAULT_REPORT_PATH = Path("reports/hcrl_ml_evaluation.md")
HCRL_DATASET_URL = "https://ocslab.hksecurity.net/Datasets/car-hacking-dataset"
ATTACK_FILES = (
    ("DoS", "DoS_dataset.csv"),
    ("Fuzzy", "Fuzzy_dataset.csv"),
    ("Gear spoofing", "gear_dataset.csv"),
    ("RPM spoofing", "RPM_dataset.csv"),
)

_NORMAL_LINE = re.compile(
    r"^Timestamp:\s*(?P<timestamp>\S+)\s+ID:\s*"
    r"(?P<can_id>[0-9a-fA-F]+)\s+(?P<marker>\S+)\s+DLC:\s*"
    r"(?P<dlc>\d+)\s+(?P<data>.*)$"
)
_INCOMPLETE_TIMESTAMP_LINE = re.compile(
    r"^Timestamp:\s*\d+(?:\.\d+)?\s*$"
)
_HEX_BYTE = re.compile(r"^[0-9a-fA-F]{2}$")


@dataclass
class CaptureStats:
    record_count: int = 0
    skipped_incomplete_final_lines: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    timestamp_regressions: int = 0
    equal_timestamps: int = 0
    gaps_over_one_second: int = 0
    max_gap_seconds: float = 0.0

    @property
    def duration_seconds(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    def observe_timestamp(self, timestamp: float, source: Path, line: int) -> None:
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError(f"{source}:{line}: timestamp must be finite and non-negative")
        if self.last_timestamp is not None:
            if timestamp < self.last_timestamp:
                self.timestamp_regressions += 1
                raise ValueError(f"{source}:{line}: timestamps are not ordered")
            delta = timestamp - self.last_timestamp
            if delta == 0:
                self.equal_timestamps += 1
            elif delta > 1.0:
                self.gaps_over_one_second += 1
                self.max_gap_seconds = max(self.max_gap_seconds, delta)
        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp
        self.record_count += 1


@dataclass
class CaptureEvaluation:
    name: str
    stats: CaptureStats
    tested_records: int
    known_id_records: int
    unseen_id_records: int
    known_normal_records: int
    known_attack_records: int
    unseen_normal_records: int
    unseen_attack_records: int
    known_windows: int
    known_attack_windows: int
    unseen_windows: int
    unseen_only_windows: int
    unseen_ids: frozenset[int]
    metrics: ConfusionMetrics
    tested_windows: int
    unseen_metrics: ConfusionMetrics
    per_id_evaluations: dict[int, PerIdEvaluation]


@dataclass(frozen=True)
class FeatureFalsePositiveDiagnostic:
    top_three_count: int
    zero_variance_changes: int
    normalized_deviation_mean: float | None
    normalized_deviation_samples: int


@dataclass(frozen=True)
class PerIdEvaluation:
    windows: int
    attack_windows: int
    metrics: ConfusionMetrics
    false_positive_features: dict[str, FeatureFalsePositiveDiagnostic]


@dataclass
class TrainingRun:
    training_record_count: int
    training_feature_count: int
    training_time_windows: int
    training_windows_by_id: dict[int, int]
    training_cutoff_seconds: float
    normal_stats: CaptureStats
    evaluations: list[CaptureEvaluation]
    model_path: Path
    report_path: Path
    calibration_status: str


def _validated_frame(
    timestamp_token: str,
    can_id_token: str,
    dlc_token: str,
    payload_tokens: Sequence[str],
    source: Path,
    line: int,
) -> tuple[float, int, int, bytes]:
    try:
        timestamp = float(timestamp_token)
    except ValueError as exc:
        raise ValueError(f"{source}:{line}: invalid timestamp") from exc
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError(f"{source}:{line}: timestamp must be finite and non-negative")

    if not 1 <= len(can_id_token) <= 4 or not re.fullmatch(
        r"[0-9a-fA-F]+", can_id_token
    ):
        raise ValueError(f"{source}:{line}: invalid standard CAN ID")
    can_id = int(can_id_token, 16)
    if can_id > 0x7FF:
        raise ValueError(f"{source}:{line}: CAN ID is outside the 11-bit range")

    try:
        dlc = int(dlc_token, 10)
    except ValueError as exc:
        raise ValueError(f"{source}:{line}: invalid DLC") from exc
    if not 0 <= dlc <= 8:
        raise ValueError(f"{source}:{line}: DLC must be in the range 0..8")
    if len(payload_tokens) != dlc or any(
        not _HEX_BYTE.fullmatch(token) for token in payload_tokens
    ):
        raise ValueError(f"{source}:{line}: payload bytes do not match DLC")

    return timestamp, can_id, dlc, bytes(int(token, 16) for token in payload_tokens)


def _iter_normal_records(
    path: Path, stats: CaptureStats
) -> Iterator[CanRecord]:
    origin: float | None = None
    with path.open("r", encoding="utf-8", newline="") as file:
        for line_number, line in enumerate(file, 1):
            text = line.rstrip("\r\n")
            if not text.strip():
                raise ValueError(f"{path}:{line_number}: blank lines are not valid records")

            match = _NORMAL_LINE.fullmatch(text)
            if match is None:
                is_unterminated = not line.endswith(("\n", "\r"))
                if is_unterminated and _INCOMPLETE_TIMESTAMP_LINE.fullmatch(text.strip()):
                    stats.skipped_incomplete_final_lines += 1
                    continue
                raise ValueError(f"{path}:{line_number}: malformed normal-run record")

            if match.group("marker") != "000":
                raise ValueError(f"{path}:{line_number}: unexpected field before DLC")
            payload = match.group("data").split()
            timestamp, can_id, dlc, data = _validated_frame(
                match.group("timestamp"),
                match.group("can_id"),
                match.group("dlc"),
                payload,
                path,
                line_number,
            )
            stats.observe_timestamp(timestamp, path, line_number)
            if origin is None:
                origin = timestamp
            yield CanRecord(
                timestamp=timestamp - origin,
                can_id=can_id,
                dlc=dlc,
                data=data,
                label="normal",
            )


def _iter_attack_records(
    path: Path,
    attack_name: str,
    stats: CaptureStats,
) -> Iterator[CanRecord]:
    origin: float | None = None
    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.reader(file, strict=True)
        try:
            for row in reader:
                line_number = reader.line_num
                fields = [field.strip() for field in row]
                if len(fields) < 4:
                    raise ValueError(f"{path}:{line_number}: too few CSV fields")
                label_flag = fields[-1]
                if label_flag not in {"R", "T"}:
                    raise ValueError(f"{path}:{line_number}: expected R or T label")

                timestamp, can_id, dlc, data = _validated_frame(
                    fields[0],
                    fields[1],
                    fields[2],
                    fields[3:-1],
                    path,
                    line_number,
                )
                stats.observe_timestamp(timestamp, path, line_number)
                if origin is None:
                    origin = timestamp
                yield CanRecord(
                    timestamp=timestamp - origin,
                    can_id=can_id,
                    dlc=dlc,
                    data=data,
                    label="normal" if label_flag == "R" else attack_name,
                )
        except csv.Error as exc:
            raise ValueError(f"{path}:{reader.line_num}: invalid CSV record") from exc


def _iter_windows(
    records: Iterable[CanRecord],
) -> Iterator[tuple[int, list[CanRecord]]]:
    current_index: int | None = None
    current_records: list[CanRecord] = []
    for record in records:
        window_index = int(record.timestamp // WINDOW_SECONDS)
        if current_index is not None and window_index < current_index:
            raise ValueError("Records must be timestamp-ordered within each capture")
        if current_index is not None and window_index != current_index:
            yield current_index, current_records
            current_records = []
        current_index = window_index
        current_records.append(record)
    if current_index is not None:
        yield current_index, current_records


def _score_capture(
    name: str,
    records: Iterable[CanRecord],
    stats: CaptureStats,
    detector: MLAnomalyDetector,
    known_ids: frozenset[int],
    minimum_window_index: int = 0,
) -> CaptureEvaluation:
    truth: list[bool] = []
    predictions: list[bool] = []
    unseen_truth: list[bool] = []
    unseen_predictions: list[bool] = []
    feature_batch: list[WindowFeatures] = []
    truth_by_window: dict[int, bool] = {}
    truth_by_id_by_window: dict[int, dict[int, bool]] = {}
    features_by_window: dict[int, list[WindowFeatures]] = {}
    counts: Counter[str] = Counter()
    unseen_ids: set[int] = set()
    per_id_truth: dict[int, list[bool]] = {}
    per_id_predictions: dict[int, list[bool]] = {}
    per_id_attack_windows: Counter[int] = Counter()
    feature_top_three_counts: dict[int, Counter[str]] = {}
    feature_zero_variance_changes: dict[int, Counter[str]] = {}
    feature_normalized_deviation_sums: dict[int, Counter[str]] = {}
    feature_normalized_deviation_samples: dict[int, Counter[str]] = {}

    def flush_prediction_batch() -> None:
        if not truth_by_window:
            return
        window_predictions = detector.predict_features(feature_batch)
        predicted_by_window = {
            prediction.window_index: prediction
            for prediction in window_predictions
        }
        if predicted_by_window.keys() != truth_by_window.keys():
            raise RuntimeError("Detector output does not match the scored windows")
        for window_index in sorted(truth_by_window):
            prediction = predicted_by_window[window_index]
            truth.append(truth_by_window[window_index])
            predictions.append(prediction.is_anomaly)

            for sample in features_by_window[window_index]:
                can_id = sample.can_id
                sample_truth = truth_by_id_by_window[window_index][can_id]
                sample_prediction = can_id in prediction.anomalous_can_ids
                per_id_truth.setdefault(can_id, []).append(sample_truth)
                per_id_predictions.setdefault(can_id, []).append(sample_prediction)
                per_id_attack_windows[can_id] += sample_truth
                if sample_prediction and not sample_truth:
                    deviations = detector.feature_deviations(sample, can_id)
                    top_three = feature_top_three_counts.setdefault(
                        can_id, Counter()
                    )
                    zero_variance = feature_zero_variance_changes.setdefault(
                        can_id, Counter()
                    )
                    deviation_sums = feature_normalized_deviation_sums.setdefault(
                        can_id, Counter()
                    )
                    deviation_samples = (
                        feature_normalized_deviation_samples.setdefault(
                            can_id, Counter()
                        )
                    )
                    top_three.update(item.name for item in deviations[:3])
                    for item in deviations:
                        if item.outside_zero_variance_baseline:
                            zero_variance[item.name] += 1
                        elif (
                            item.normalized_deviation is not None
                            and math.isfinite(item.normalized_deviation)
                        ):
                            deviation_sums[item.name] += item.normalized_deviation
                            deviation_samples[item.name] += 1
        feature_batch.clear()
        truth_by_window.clear()
        truth_by_id_by_window.clear()
        features_by_window.clear()

    for window_index, window_records in _iter_windows(records):
        if window_index < minimum_window_index:
            continue

        unseen_records = [
            record for record in window_records if record.can_id not in known_ids
        ]
        unseen_truth.append(
            any(record.label != "normal" for record in unseen_records)
        )
        unseen_predictions.append(bool(unseen_records))
        counts["tested_windows"] += 1

        known_records = [
            record for record in window_records if record.can_id in known_ids
        ]
        counts["tested_records"] += len(window_records)
        counts["known_id_records"] += len(known_records)
        counts["unseen_id_records"] += len(unseen_records)
        counts["known_normal_records"] += sum(
            record.label == "normal" for record in known_records
        )
        counts["known_attack_records"] += sum(
            record.label != "normal" for record in known_records
        )
        counts["unseen_normal_records"] += sum(
            record.label == "normal" for record in unseen_records
        )
        counts["unseen_attack_records"] += sum(
            record.label != "normal" for record in unseen_records
        )

        if unseen_records:
            counts["unseen_windows"] += 1
            unseen_ids.update(record.can_id for record in unseen_records)
        if not known_records:
            if unseen_records:
                counts["unseen_only_windows"] += 1
            continue

        known_attack = any(record.label != "normal" for record in known_records)
        features = extract_features(known_records, window_seconds=WINDOW_SECONDS)
        if not features or any(
            sample.window_index != window_index for sample in features
        ):
            raise RuntimeError("Feature extraction did not preserve the scored window")
        feature_batch.extend(features)
        features_by_window[window_index] = features
        truth_by_window[window_index] = known_attack
        records_by_id: dict[int, list[CanRecord]] = {}
        for record in known_records:
            records_by_id.setdefault(record.can_id, []).append(record)
        truth_by_id_by_window[window_index] = {
            can_id: any(record.label != "normal" for record in id_records)
            for can_id, id_records in records_by_id.items()
        }
        counts["known_windows"] += 1
        counts["known_attack_windows"] += known_attack
        if len(truth_by_window) >= PREDICTION_BATCH_WINDOWS:
            flush_prediction_batch()

    flush_prediction_batch()

    per_id_evaluations: dict[int, PerIdEvaluation] = {}
    for can_id, id_truth in per_id_truth.items():
        feature_diagnostics: dict[str, FeatureFalsePositiveDiagnostic] = {}
        top_three = feature_top_three_counts.get(can_id, Counter())
        zero_variance = feature_zero_variance_changes.get(can_id, Counter())
        deviation_sums = feature_normalized_deviation_sums.get(can_id, Counter())
        deviation_samples = feature_normalized_deviation_samples.get(
            can_id, Counter()
        )
        if can_id in feature_top_three_counts:
            feature_diagnostics = {
                name: FeatureFalsePositiveDiagnostic(
                    top_three_count=top_three[name],
                    zero_variance_changes=zero_variance[name],
                    normalized_deviation_mean=(
                        deviation_sums[name] / deviation_samples[name]
                        if deviation_samples[name]
                        else None
                    ),
                    normalized_deviation_samples=deviation_samples[name],
                )
                for name in FEATURE_NAMES
            }
        per_id_evaluations[can_id] = PerIdEvaluation(
            windows=len(id_truth),
            attack_windows=per_id_attack_windows[can_id],
            metrics=calculate_metrics(id_truth, per_id_predictions[can_id]),
            false_positive_features=feature_diagnostics,
        )

    return CaptureEvaluation(
        name=name,
        stats=stats,
        tested_records=counts["tested_records"],
        known_id_records=counts["known_id_records"],
        unseen_id_records=counts["unseen_id_records"],
        known_normal_records=counts["known_normal_records"],
        known_attack_records=counts["known_attack_records"],
        unseen_normal_records=counts["unseen_normal_records"],
        unseen_attack_records=counts["unseen_attack_records"],
        known_windows=counts["known_windows"],
        known_attack_windows=counts["known_attack_windows"],
        unseen_windows=counts["unseen_windows"],
        unseen_only_windows=counts["unseen_only_windows"],
        unseen_ids=frozenset(unseen_ids),
        metrics=calculate_metrics(truth, predictions),
        tested_windows=counts["tested_windows"],
        unseen_metrics=calculate_metrics(unseen_truth, unseen_predictions),
        per_id_evaluations=per_id_evaluations,
    )


def _format_metric(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def build_report(run: TrainingRun) -> str:
    windows_by_id = list(run.training_windows_by_id.values())
    min_windows = min(windows_by_id)
    max_windows = max(windows_by_id)
    dos_result = next(
        (result for result in run.evaluations if result.name == "DoS"), None
    )
    dos_unseen_ids = (
        ", ".join(f"{can_id:#05x}" for can_id in sorted(dos_result.unseen_ids))
        if dos_result is not None and dos_result.unseen_ids
        else "none"
    )
    window_count_text = (
        f"{min_windows} windows per ID"
        if min_windows == max_windows
        else f"{min_windows}-{max_windows} windows per ID"
    )
    if dos_result is None:
        dos_limitation = "- DoS evaluation was not present in the input captures."
    else:
        recall_note = (
            " Known-ID recall is `N/A` because there are no known-ID positive frames."
            if dos_result.known_attack_records == 0
            else ""
        )
        dos_limitation = (
            f"- DoS `T` frames: {dos_result.known_attack_records:,} on trained IDs "
            f"and {dos_result.unseen_attack_records:,} on unseen IDs "
            f"({dos_unseen_ids}).{recall_note} Unseen-ID traffic is counted above "
            "but is evaluated separately from the Isolation Forest."
        )
    lines = [
        "# HCRL Isolation Forest Training and Evaluation",
        "",
        f"Official label definition: `R` is a normal message and `T` is an injected "
        f"message ([HCRL dataset page]({HCRL_DATASET_URL})).",
        "",
        "## Training configuration",
        "",
        "- Detector: the existing per-CAN-ID Isolation Forest implementation.",
        f"- Window size: {WINDOW_SECONDS:g} second; existing 21-feature extractor.",
        f"- Training source: `normal_run_data.txt`; chronological first "
        f"{TRAIN_FRACTION:.0%} of valid capture duration.",
        f"- Training cutoff: relative second {run.training_cutoff_seconds:.0f}; "
        f"{run.training_time_windows} distinct one-second time windows and "
        f"{run.training_record_count:,} normal frames.",
        f"- Feature samples: {run.training_feature_count:,} CAN-ID/window vectors; "
        f"{len(run.training_windows_by_id)} trained CAN IDs; "
        f"{window_count_text}.",
        f"- Isolation Forest: {N_ESTIMATORS} trees per ID, contamination "
        f"{CONTAMINATION}, random state {RANDOM_STATE}; scoring is batched over "
        f"at most {PREDICTION_BATCH_WINDOWS} time windows.",
        f"- Threshold calibration: `{run.calibration_status}`. The independent "
        "normal-data calibration interface is available but was not activated; "
        "the existing contamination-based threshold is retained.",
        "- Labels are not part of the feature vectors. Only normal traffic before "
        "the chronological cutoff was passed to fitting.",
        f"- The one incomplete, unterminated final normal-file fragment was skipped; "
        f"{run.normal_stats.skipped_incomplete_final_lines} such line(s) recorded.",
        f"- Saved model: `{run.model_path.as_posix()}`.",
        "",
        "## Window-level results",
        "",
        "Metrics are calculated only for windows containing at least one CAN ID "
        "seen during normal-only training. A scored window is positive if it contains "
        "a `T` frame for a trained ID. Unseen-ID frames are excluded even in mixed "
        "windows; unseen-ID-only windows are excluded from the confusion matrices.",
        "",
        "| Capture | Scored windows | Known attack windows | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in run.evaluations:
        metrics = result.metrics
        lines.append(
            f"| {result.name} | {result.known_windows:,} | "
            f"{result.known_attack_windows:,} | "
            f"{_format_metric(metrics.precision)} | "
            f"{_format_metric(metrics.recall)} | "
            f"{_format_metric(metrics.f1)} | "
            f"{_format_metric(metrics.false_positive_rate)} | "
            f"{metrics.true_positive:,} | {metrics.false_positive:,} | "
            f"{metrics.true_negative:,} | {metrics.false_negative:,} |"
        )

    lines.extend(
        [
            "",
            "## Known-ID metrics by CAN ID",
            "",
            "Each row scores the per-ID one-second feature samples independently. "
            "These rows supplement, and do not replace, the existing capture-level "
            "window metrics above.",
            "",
            "| Capture | CAN ID | ID windows | Attack windows | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for result in run.evaluations:
        for can_id, evaluation in sorted(result.per_id_evaluations.items()):
            metrics = evaluation.metrics
            lines.append(
                f"| {result.name} | 0x{can_id:03X} | {evaluation.windows:,} | "
                f"{evaluation.attack_windows:,} | "
                f"{_format_metric(metrics.precision)} | "
                f"{_format_metric(metrics.recall)} | "
                f"{_format_metric(metrics.f1)} | "
                f"{_format_metric(metrics.false_positive_rate)} | "
                f"{metrics.true_positive:,} | {metrics.false_positive:,} | "
                f"{metrics.true_negative:,} | {metrics.false_negative:,} |"
            )

    lines.extend(
        [
            "",
            "## False-positive feature diagnostics",
            "",
            "Diagnostics are computed for per-ID false-positive windows. For each "
            "feature, `Top-3` counts how often it was among the three largest "
            "deviations from that ID's training-normal median/standard deviation. "
            "A zero-variance change is counted separately and is not assigned an "
            "artificially large normalized score. These are descriptive deviations, "
            "not causal Isolation Forest feature attributions.",
            "",
            "| Capture | CAN ID | ID false-positive windows | Feature | Top-3 count | Zero-variance changes | Mean normalized deviation (samples) |",
            "|---|---:|---:|---|---:|---:|---:|",
        ]
    )
    feature_rows = 0
    for result in run.evaluations:
        for can_id, evaluation in sorted(result.per_id_evaluations.items()):
            if not evaluation.false_positive_features:
                continue
            for name in FEATURE_NAMES:
                diagnostic = evaluation.false_positive_features[name]
                mean_text = (
                    "N/A"
                    if diagnostic.normalized_deviation_mean is None
                    else f"{diagnostic.normalized_deviation_mean:.3f} "
                    f"({diagnostic.normalized_deviation_samples:,})"
                )
                lines.append(
                    f"| {result.name} | 0x{can_id:03X} | "
                    f"{evaluation.metrics.false_positive:,} | {name} | "
                    f"{diagnostic.top_three_count:,} | "
                    f"{diagnostic.zero_variance_changes:,} | {mean_text} |"
                )
                feature_rows += 1
    if feature_rows == 0:
        lines.append("| No per-ID false positives | — | 0 | — | 0 | 0 | N/A |")

    lines.extend(
        [
            "",
            "## Unseen-ID novelty status (separate from ML)",
            "",
            "The novelty policy marks a window when it contains an ID absent from "
            "normal-only training. It is not an Isolation Forest prediction and "
            "does not by itself establish an attack. Metrics below compare this "
            "status with unseen-ID `T` labels over all occupied capture windows; "
            "they are separate from the known-ID forest metrics.",
            "",
            "| Capture | Occupied windows | Unseen-T windows | Novelty alerts | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for result in run.evaluations:
        metrics = result.unseen_metrics
        lines.append(
            f"| {result.name} | {result.tested_windows:,} | "
            f"{metrics.true_positive + metrics.false_negative:,} | "
            f"{metrics.true_positive + metrics.false_positive:,} | "
            f"{_format_metric(metrics.precision)} | "
            f"{_format_metric(metrics.recall)} | "
            f"{_format_metric(metrics.f1)} | "
            f"{_format_metric(metrics.false_positive_rate)} | "
            f"{metrics.true_positive:,} | {metrics.false_positive:,} | "
            f"{metrics.true_negative:,} | {metrics.false_negative:,} |"
        )

    lines.extend(
        [
            "",
            "## Known-ID and unseen-ID coverage",
            "",
            "| Capture | Tested frames | Known-ID frames (R/T) | Unseen-ID frames (R/T) | Unseen IDs | Unseen-containing windows | Unseen-only windows |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for result in run.evaluations:
        lines.append(
            f"| {result.name} | {result.tested_records:,} | "
            f"{result.known_id_records:,} "
            f"({result.known_normal_records:,}/{result.known_attack_records:,}) | "
            f"{result.unseen_id_records:,} "
            f"({result.unseen_normal_records:,}/{result.unseen_attack_records:,}) | "
            f"{len(result.unseen_ids):,} | {result.unseen_windows:,} | "
            f"{result.unseen_only_windows:,} |"
        )

    lines.extend(
        [
            "",
            "## Capture boundaries and data handling",
            "",
            "Each file was processed independently and its timestamps were shifted "
            "to seconds since that capture's first valid record. Original ordering "
            "was checked, and gaps were retained in the relative timestamps; no "
            "windows were filled across gaps or joined across files. The normal "
            "capture was split chronologically, so its training and held-out windows "
            "do not overlap.",
            "",
            "| Capture | Valid records read | Duration (s) | Gaps > 1 s | Maximum gap (s) |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    lines.append(
        f"| Normal training source | {run.normal_stats.record_count:,} | "
        f"{run.normal_stats.duration_seconds:.3f} | "
        f"{run.normal_stats.gaps_over_one_second:,} | "
        f"{run.normal_stats.max_gap_seconds:.3f} |"
    )
    for result in run.evaluations[1:]:
        stats = result.stats
        lines.append(
            f"| {result.name} | {stats.record_count:,} | "
            f"{stats.duration_seconds:.3f} | {stats.gaps_over_one_second:,} | "
            f"{stats.max_gap_seconds:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Limitations and leakage risks",
            "",
            dos_limitation,
            "- Unseen IDs are returned separately as novelty status and do not "
            "participate in the Isolation Forest anomaly score.",
            "- Every unseen-ID-containing DoS and Fuzzy window also contains an "
            "unseen-ID `T` label in these captures. Their novelty FPR therefore "
            "does not measure false alerts on normal-only unseen-ID traffic.",
            "- The normal holdout comes from the same capture as training. The "
            "chronological split prevents direct window overlap, but cannot eliminate "
            "capture-specific correlation or temporal drift.",
            "- Each attack category is represented by its provided capture, not by "
            "independent vehicles or repeated capture-level cross-validation.",
            "- The normal source has a truncated final line, which was skipped. "
            "Large attack-capture gaps are retained but their cause is not established.",
            "- Results use the existing one-second feature definitions and default "
            "Isolation Forest decision threshold; they are not evidence of vehicle "
            "deployment performance.",
            "- The normal holdout is not an independent calibration capture. No "
            "independent calibration result is claimed; per-ID calibration support "
            "is opt-in and was not used for these metrics.",
            "",
            "## Reproduction",
            "",
            "```powershell",
            "python -m scripts.train_evaluate_hcrl",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def run_pipeline(
    data_dir: Path = DEFAULT_DATA_DIR,
    model_path: Path = DEFAULT_MODEL_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
    train_fraction: float = TRAIN_FRACTION,
) -> TrainingRun:
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be strictly between 0 and 1")

    normal_path = data_dir / "normal_run_data.txt"
    metadata = CaptureStats()
    for _record in _iter_normal_records(normal_path, metadata):
        pass
    if metadata.record_count == 0:
        raise ValueError(f"No valid normal records found in {normal_path}")

    training_window_limit = math.floor(
        metadata.duration_seconds * train_fraction / WINDOW_SECONDS
    )
    if training_window_limit < 2:
        raise ValueError("Normal capture is too short for the chronological split")

    training_features: list[WindowFeatures] = []
    training_record_count = 0
    training_window_indices: set[int] = set()
    training_windows_by_id: Counter[int] = Counter()
    for window_index, records in _iter_windows(
        _iter_normal_records(normal_path, CaptureStats())
    ):
        if window_index >= training_window_limit:
            continue
        samples = extract_features(records, window_seconds=WINDOW_SECONDS)
        training_features.extend(samples)
        training_record_count += len(records)
        training_window_indices.add(window_index)
        training_windows_by_id.update(sample.can_id for sample in samples)

    detector = MLAnomalyDetector(
        window_seconds=WINDOW_SECONDS,
        contamination=CONTAMINATION,
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
    ).fit_features(
        training_features,
        training_capture_id=str(normal_path.resolve()),
    )
    known_ids = frozenset(training_windows_by_id)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(detector, model_path)

    evaluations: list[CaptureEvaluation] = []
    normal_test_stats = CaptureStats()
    evaluations.append(
        _score_capture(
            "Normal holdout",
            _iter_normal_records(normal_path, normal_test_stats),
            normal_test_stats,
            detector,
            known_ids,
            minimum_window_index=training_window_limit,
        )
    )

    for attack_name, filename in ATTACK_FILES:
        path = data_dir / filename
        stats = CaptureStats()
        evaluations.append(
            _score_capture(
                attack_name,
                _iter_attack_records(path, attack_name, stats),
                stats,
                detector,
                known_ids,
            )
        )

    run = TrainingRun(
        training_record_count=training_record_count,
        training_feature_count=len(training_features),
        training_time_windows=len(training_window_indices),
        training_windows_by_id=dict(training_windows_by_id),
        training_cutoff_seconds=training_window_limit * WINDOW_SECONDS,
        normal_stats=metadata,
        evaluations=evaluations,
        model_path=model_path,
        report_path=report_path,
        calibration_status=detector._calibration_status,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(build_report(run), encoding="utf-8")
    return run


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--train-fraction",
        type=float,
        default=TRAIN_FRACTION,
        help="chronological fraction of normal capture reserved for training",
    )
    args = parser.parse_args(argv)
    run = run_pipeline(
        data_dir=args.data_dir,
        model_path=args.model_path,
        report_path=args.report_path,
        train_fraction=args.train_fraction,
    )
    report = run.report_path.read_text(encoding="utf-8")
    print(report)
    print(f"Model saved to {run.model_path}")
    print(f"Evaluation report written to {run.report_path}")


if __name__ == "__main__":
    main()
