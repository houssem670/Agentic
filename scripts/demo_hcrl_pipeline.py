"""Replay HCRL captures through the existing detector and agent workflow."""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from unittest.mock import patch

from agents.orchestrator.orchestrator import run_workflow
from agents.report_agent.report_agent import save_security_report
from main import (
    HCRL_DATA_PROVENANCE,
    HCRL_MODEL_PROVENANCE,
    _load_hcrl_ml_detector,
    ml_prediction_to_event,
)
from models.diagnostic_report import DiagnosticReport
from models.security_assessment import SecurityAssessment
from models.security_event import SecurityEvent
from scripts.train_evaluate_hcrl import (
    CaptureEvaluation,
    CaptureStats,
    DEFAULT_DATA_DIR,
    DEFAULT_MODEL_PATH,
    DEFAULT_REPORT_PATH,
    TRAIN_FRACTION,
    WINDOW_SECONDS,
    _iter_attack_records,
    _iter_normal_records,
    _iter_windows,
    _score_capture,
)
from tools.anomaly_detector.ml_detector import (
    MLAnomalyDetector,
    WindowPrediction,
    extract_features,
)
from tools.traffic_simulator.simulator import CanRecord


DEFAULT_BENCHMARK_DIR = Path("reports/hcrl_benchmark")
DEFAULT_BENCHMARK_REPORT = DEFAULT_BENCHMARK_DIR / "demo_report.md"
DEFAULT_BENCHMARK_RESULTS = DEFAULT_BENCHMARK_DIR / "results.json"
GEAR_CAPTURE = "gear_dataset.csv"
GEAR_ATTACK_NAME = "Gear spoofing"
GEAR_DEMO_CAN_ID = 0x43F
DOS_CAPTURE = "DoS_dataset.csv"
DOS_ATTACK_NAME = "DoS"


@dataclass
class HcrlDemoResult:
    report_path: Path
    results_path: Path
    training_cutoff_seconds: int
    normal_evaluation: CaptureEvaluation
    gear_evaluation: CaptureEvaluation
    dos_evaluation: CaptureEvaluation
    selected_event: SecurityEvent | None
    selected_event_truth_ids: tuple[int, ...]
    workflow: dict | None
    dos_novelty_example: dict | None
    agent_mode: str


def _format_metric(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def _metric_dict(metrics) -> dict:
    return asdict(metrics)


def _evaluation_dict(evaluation: CaptureEvaluation) -> dict:
    per_id = {
        f"0x{can_id:03X}": {
            "windows": item.windows,
            "attack_windows": item.attack_windows,
            "metrics": _metric_dict(item.metrics),
            "false_positive_features": {
                name: asdict(diagnostic)
                for name, diagnostic in item.false_positive_features.items()
            },
        }
        for can_id, item in sorted(evaluation.per_id_evaluations.items())
    }
    return {
        "capture": evaluation.name,
        "capture_records": evaluation.stats.record_count,
        "capture_duration_seconds": evaluation.stats.duration_seconds,
        "timestamp_regressions": evaluation.stats.timestamp_regressions,
        "equal_timestamps": evaluation.stats.equal_timestamps,
        "gaps_over_one_second": evaluation.stats.gaps_over_one_second,
        "maximum_gap_seconds": evaluation.stats.max_gap_seconds,
        "skipped_incomplete_final_lines": (
            evaluation.stats.skipped_incomplete_final_lines
        ),
        "tested_records": evaluation.tested_records,
        "known_id_records": evaluation.known_id_records,
        "unseen_id_records": evaluation.unseen_id_records,
        "known_normal_records": evaluation.known_normal_records,
        "known_attack_records": evaluation.known_attack_records,
        "unseen_normal_records": evaluation.unseen_normal_records,
        "unseen_attack_records": evaluation.unseen_attack_records,
        "tested_windows": evaluation.tested_windows,
        "known_windows": evaluation.known_windows,
        "known_attack_windows": evaluation.known_attack_windows,
        "unseen_windows": evaluation.unseen_windows,
        "unseen_only_windows": evaluation.unseen_only_windows,
        "unseen_ids": [f"0x{can_id:03X}" for can_id in sorted(evaluation.unseen_ids)],
        "known_id_metrics": _metric_dict(evaluation.metrics),
        "unseen_novelty_metrics": _metric_dict(evaluation.unseen_metrics),
        "per_id": per_id,
    }


def _prediction_for_window(
    detector: MLAnomalyDetector,
    records: Sequence[CanRecord],
) -> WindowPrediction:
    features = extract_features(records, window_seconds=WINDOW_SECONDS)
    if not features or len({sample.window_index for sample in features}) != 1:
        raise ValueError("Expected records from exactly one non-empty HCRL window.")
    predictions = detector.predict_features(features)
    if len(predictions) != 1 or predictions[0].window_index != features[0].window_index:
        raise RuntimeError("HCRL detector output did not match the input window.")
    return predictions[0]


def _find_gear_positive(
    data_dir: Path,
    detector: MLAnomalyDetector,
    known_ids: frozenset[int],
) -> tuple[SecurityEvent | None, tuple[int, ...]]:
    path = data_dir / GEAR_CAPTURE
    stats = CaptureStats()
    for _, records in _iter_windows(
        _iter_attack_records(path, GEAR_ATTACK_NAME, stats)
    ):
        prediction = _prediction_for_window(detector, records)
        truth_ids = tuple(
            sorted(
                {
                    record.can_id
                    for record in records
                    if record.label != "normal" and record.can_id in known_ids
                }
            )
        )
        confirmed_ids = set(truth_ids).intersection(prediction.anomalous_can_ids)
        if not confirmed_ids:
            continue
        if stats.first_timestamp is None:
            raise RuntimeError(f"No capture origin was recorded for {path}.")

        # Strip the HCRL truth labels before event conversion and agent handling.
        unlabeled_records = [
            replace(record, label="normal") for record in records
        ]
        event = ml_prediction_to_event(
            prediction,
            unlabeled_records,
            detector,
            f"HCRL:{GEAR_CAPTURE}",
            datetime.fromtimestamp(stats.first_timestamp, timezone.utc),
            model_provenance=HCRL_MODEL_PROVENANCE,
            calibration_status=detector._calibration_status,
            data_provenance=HCRL_DATA_PROVENANCE,
        )
        return event, tuple(sorted(confirmed_ids))
    return None, ()


def _find_dos_novelty(
    data_dir: Path,
    detector: MLAnomalyDetector,
    known_ids: frozenset[int],
) -> dict | None:
    path = data_dir / DOS_CAPTURE
    stats = CaptureStats()
    for _, records in _iter_windows(
        _iter_attack_records(path, DOS_ATTACK_NAME, stats)
    ):
        prediction = _prediction_for_window(detector, records)
        unseen_injected_ids = tuple(
            sorted(
                {
                    record.can_id
                    for record in records
                    if record.label != "normal"
                    and record.can_id not in known_ids
                }
            )
        )
        if not unseen_injected_ids:
            continue
        return {
            "status": "unseen / requires review",
            "window_index": prediction.window_index,
            "window_start": prediction.start,
            "window_end": prediction.end,
            "unseen_ids": [
                f"0x{can_id:03X}" for can_id in prediction.unseen_can_ids
            ],
            "unseen_injected_ids": [
                f"0x{can_id:03X}" for can_id in unseen_injected_ids
            ],
            "known_ml_anomalous_ids": [
                f"0x{can_id:03X}" for can_id in prediction.anomalous_can_ids
            ],
            "known_injected_ids": [
                f"0x{record.can_id:03X}"
                for record in records
                if record.label != "normal" and record.can_id in known_ids
            ],
            "is_isolation_forest_anomaly": prediction.is_anomaly,
            "sent_to_agents": False,
        }
    return None


def _mock_security_agent(event: SecurityEvent) -> SecurityAssessment:
    return SecurityAssessment(
        threat_type=None,
        risk_level="UNKNOWN",
        summary=(
            "Mock provider: workflow routing was exercised; "
            "this is not an attack attribution."
        ),
        observed_facts=[
            f"Detection rule: {event.detection_rule}",
            f"CAN ID: {event.can_id}",
        ],
        unknowns=["No external security provider was called."],
    )


def _mock_diagnostic_agent(event: SecurityEvent) -> DiagnosticReport:
    return DiagnosticReport(
        event_id=event.event_id,
        diagnostic_summary=(
            "Mock provider: the HCRL event was passed through the diagnostic node."
        ),
        supporting_evidence=list(event.evidence),
        unknowns=["No external diagnostic provider was called."],
        root_cause_confirmed=False,
        confidence=0.0,
        analysis_method="MOCK",
    )


def _run_event_workflow(event: SecurityEvent, agent_mode: str) -> dict:
    if agent_mode == "mock":
        with (
            patch(
                "agents.orchestrator.orchestrator.security_agent",
                side_effect=_mock_security_agent,
            ),
            patch(
                "agents.orchestrator.orchestrator.diagnostic_agent",
                side_effect=_mock_diagnostic_agent,
            ),
        ):
            return run_workflow(event, persist_report=False)
    if agent_mode == "live":
        return run_workflow(event, persist_report=False)
    raise ValueError("agent_mode must be 'mock' or 'live'")


def _check_output_paths(report_path: Path, results_path: Path) -> None:
    report_resolved = report_path.resolve()
    results_resolved = results_path.resolve()
    protected_paths = {
        DEFAULT_MODEL_PATH.resolve(),
        DEFAULT_REPORT_PATH.resolve(),
        Path("reports/security_report.md").resolve(),
    }
    if report_resolved == results_resolved:
        raise ValueError("The benchmark report and results paths must differ.")
    if report_resolved in protected_paths or results_resolved in protected_paths:
        raise ValueError(
            "Benchmark outputs must not overwrite the HCRL model, "
            "evaluation report, or application security report."
        )


def _scenario_report_lines(evaluation: CaptureEvaluation) -> list[str]:
    metrics = evaluation.metrics
    return [
        f"### {evaluation.name}",
        "",
        f"- Parsed capture records: {evaluation.stats.record_count:,}.",
        f"- Capture duration: {evaluation.stats.duration_seconds:.3f} seconds.",
        f"- Windows scored for known IDs: {evaluation.known_windows:,} "
        f"of {evaluation.tested_windows:,} tested windows.",
        f"- Known-ID injected windows: {evaluation.known_attack_windows:,}.",
        f"- Known-ID confusion counts: TP {metrics.true_positive:,}, "
        f"FP {metrics.false_positive:,}, TN {metrics.true_negative:,}, "
        f"FN {metrics.false_negative:,}.",
        f"- Known-ID precision / recall / F1 / FPR: "
        f"{_format_metric(metrics.precision)} / "
        f"{_format_metric(metrics.recall)} / "
        f"{_format_metric(metrics.f1)} / "
        f"{_format_metric(metrics.false_positive_rate)}.",
        f"- Unseen-ID windows / IDs / injected records: "
        f"{evaluation.unseen_windows:,} / "
        f"{', '.join(f'0x{can_id:03X}' for can_id in sorted(evaluation.unseen_ids)) or 'none'} / "
        f"{evaluation.unseen_attack_records:,}.",
        f"- Timestamp gaps over one second: "
        f"{evaluation.stats.gaps_over_one_second:,}; maximum gap "
        f"{evaluation.stats.max_gap_seconds:.3f} seconds.",
        "",
    ]


def _build_report(
    detector: MLAnomalyDetector,
    training_cutoff_seconds: int,
    result: HcrlDemoResult,
) -> str:
    lines = [
        "# Offline HCRL Benchmark Replay",
        "",
        "> Public benchmark replay only. This is not a production or vehicle test.",
        "",
        "## Model and method",
        "",
        f"- Model provenance: {HCRL_MODEL_PROVENANCE}.",
        f"- Window size: {WINDOW_SECONDS:g} second; model IDs: "
        f"{len(detector._models)}.",
        f"- Calibration status: `{detector._calibration_status}`.",
        "- The model was loaded, not retrained. The default application model and "
        "existing HCRL evaluation report were not written.",
        "- HCRL `R`/`T` labels were used only to calculate evaluation truth and "
        "select the one Gear demonstration event after prediction. Labels were "
        "stripped before event conversion; detector input consists of features.",
        "- Capture files were parsed independently, in timestamp order. No capture "
        "was concatenated with another; empty time gaps were not filled.",
        "- Isolation Forest anomaly scores are relative window scores, not "
        "probabilities. The reported window score is the maximum score among "
        "known IDs in that window.",
        "",
        "## Scenario results",
        "",
        *_scenario_report_lines(result.normal_evaluation),
        f"Training/holdout boundary: relative second {training_cutoff_seconds}; "
        "normal holdout is the chronological tail of the same capture used for "
        "training, not an independent capture.",
        "",
        *_scenario_report_lines(result.gear_evaluation),
        f"Target Gear ID: `0x{GEAR_DEMO_CAN_ID:03X}`. Only a prediction that was "
        "anomalous for a known ID with an HCRL `T` label was selected for the "
        "agent workflow. The `T` label was not passed to the detector or agents.",
        "",
        *_scenario_report_lines(result.dos_evaluation),
        "DoS novelty is reported separately as `unseen / requires review`; it is "
        "not claimed as an Isolation Forest detection. DoS windows were not sent "
        "to the agents.",
        "",
        "## Agent workflow",
        "",
        f"- Agent mode: `{result.agent_mode}`.",
        f"- Known-ID events sent to LangGraph: "
        f"{1 if result.workflow is not None else 0}.",
        "- Unseen-only windows sent as confirmed attacks: 0.",
        "",
    ]
    if result.selected_event is None:
        lines.extend(
            [
                "No Gear window satisfied the known-ID prediction and `T`-label "
                "selection criteria; no event was sent to LangGraph.",
                "",
            ]
        )
    else:
        event = result.selected_event
        lines.extend(
            [
                f"- Selected event: `{event.event_id}` at "
                f"{event.timestamp.isoformat()}, CAN ID(s) `{event.can_id}`.",
                f"- HCRL evaluation truth (kept outside the event): `T` on "
                f"{', '.join(f'0x{can_id:03X}' for can_id in result.selected_event_truth_ids)}.",
                "",
                "### Generated event report",
                "",
                result.workflow["report"] if result.workflow else "No workflow result.",
                "",
            ]
        )
    if result.dos_novelty_example is None:
        lines.extend(
            [
                "No unseen injected DoS window was found by the streaming scan.",
                "",
            ]
        )
    else:
        example = result.dos_novelty_example
        lines.extend(
            [
                "### DoS unseen-ID example",
                "",
                f"- Status: **{example['status']}**.",
                f"- Capture-relative window: {example['window_start']:.0f}–"
                f"{example['window_end']:.0f} seconds.",
                f"- Unseen injected ID(s): "
                f"{', '.join(example['unseen_injected_ids'])}.",
                f"- Known IDs flagged by Isolation Forest in the same window: "
                f"{', '.join(example['known_ml_anomalous_ids']) or 'none'}.",
                "- This novelty example was not sent to LangGraph.",
                "",
            ]
        )
    lines.extend(
        [
            "## Limitations",
            "",
            "- The normal holdout comes from the same capture as training and is "
            "not independent validation.",
            "- The HCRL model is not independently calibrated; no calibration "
            "result is claimed.",
            "- HCRL is a public laboratory benchmark with injected traffic. Its "
            "results do not establish performance against real-world attacks or "
            "on a real vehicle.",
            "- DoS injected traffic is unseen-ID novelty for this model; no "
            "known-ID DoS recall is claimed.",
            "- In `mock` mode, Security and Diagnostic Agent provider calls are "
            "stubbed. The Report Agent and LangGraph orchestration still run.",
            "",
        ]
    )
    return "\n".join(lines)


def _results_payload(
    detector: MLAnomalyDetector,
    result: HcrlDemoResult,
) -> dict:
    selected_event = result.selected_event
    event_payload = None
    if selected_event is not None:
        event_payload = {
            "event_id": selected_event.event_id,
            "timestamp": selected_event.timestamp.isoformat(),
            "event_type": selected_event.event_type,
            "can_id": selected_event.can_id,
            "detection_rule": selected_event.detection_rule,
            "anomaly_score": selected_event.metadata.get("anomaly_score"),
            "evidence": selected_event.evidence,
            "metadata": selected_event.metadata,
            "evaluation_truth_ids": [
                f"0x{can_id:03X}"
                for can_id in result.selected_event_truth_ids
            ],
        }
    return {
        "model": {
            "path": str(DEFAULT_MODEL_PATH),
            "provenance": HCRL_MODEL_PROVENANCE,
            "window_seconds": detector.window_seconds,
            "trained_can_ids": [
                f"0x{can_id:03X}" for can_id in sorted(detector._models)
            ],
            "calibration_status": detector._calibration_status,
            "retrained": False,
        },
        "training_cutoff_seconds": result.training_cutoff_seconds,
        "agent_mode": result.agent_mode,
        "agent_event_count": 1 if result.workflow is not None else 0,
        "normal_holdout": _evaluation_dict(result.normal_evaluation),
        "gear_capture": _evaluation_dict(result.gear_evaluation),
        "dos_capture": _evaluation_dict(result.dos_evaluation),
        "selected_event": event_payload,
        "agent_trace": result.workflow.get("agent_trace", [])
        if result.workflow
        else [],
        "dos_unseen_example": result.dos_novelty_example,
    }


def run_hcrl_demo(
    data_dir: Path = DEFAULT_DATA_DIR,
    report_path: Path = DEFAULT_BENCHMARK_REPORT,
    results_path: Path = DEFAULT_BENCHMARK_RESULTS,
    agent_mode: str = "mock",
) -> HcrlDemoResult:
    if agent_mode not in {"mock", "live"}:
        raise ValueError("agent_mode must be 'mock' or 'live'")
    if not data_dir.is_dir():
        raise FileNotFoundError(f"HCRL data directory not found: {data_dir}")
    _check_output_paths(report_path, results_path)

    detector = _load_hcrl_ml_detector()
    normal_path = data_dir / "normal_run_data.txt"
    training_capture_id = getattr(detector, "_training_capture_id", None)
    if (
        not isinstance(training_capture_id, str)
        or Path(training_capture_id).name.casefold() != normal_path.name.casefold()
    ):
        raise ValueError(
            "The loaded HCRL model does not identify normal_run_data.txt "
            "as its training capture."
        )

    normal_capture_stats = CaptureStats()
    for _record in _iter_normal_records(normal_path, normal_capture_stats):
        pass
    if normal_capture_stats.record_count == 0:
        raise ValueError(f"No valid normal records found in {normal_path}")
    training_window_limit = math.floor(
        normal_capture_stats.duration_seconds * TRAIN_FRACTION / WINDOW_SECONDS
    )
    if training_window_limit < 2:
        raise ValueError("Normal HCRL capture is too short for the training split.")

    known_ids = frozenset(detector._models)
    training_ids: set[int] = set()
    for window_index, records in _iter_windows(
        _iter_normal_records(normal_path, CaptureStats())
    ):
        if window_index >= training_window_limit:
            break
        training_ids.update(record.can_id for record in records)
    if training_ids != known_ids:
        raise ValueError(
            "The loaded model's CAN IDs do not match the training portion of "
            "normal_run_data.txt."
        )

    normal_test_stats = CaptureStats()
    normal_evaluation = _score_capture(
        "Normal known-ID holdout",
        _iter_normal_records(normal_path, normal_test_stats),
        normal_test_stats,
        detector,
        known_ids,
        minimum_window_index=training_window_limit,
    )

    gear_stats = CaptureStats()
    gear_evaluation = _score_capture(
        "Gear known-ID capture",
        _iter_attack_records(
            data_dir / GEAR_CAPTURE,
            GEAR_ATTACK_NAME,
            gear_stats,
        ),
        gear_stats,
        detector,
        known_ids,
    )

    dos_stats = CaptureStats()
    dos_evaluation = _score_capture(
        "DoS unseen-ID capture",
        _iter_attack_records(
            data_dir / DOS_CAPTURE,
            DOS_ATTACK_NAME,
            dos_stats,
        ),
        dos_stats,
        detector,
        known_ids,
    )

    selected_event, truth_ids = _find_gear_positive(
        data_dir,
        detector,
        known_ids,
    )
    workflow = (
        _run_event_workflow(selected_event, agent_mode)
        if selected_event is not None
        else None
    )
    dos_novelty_example = _find_dos_novelty(
        data_dir,
        detector,
        known_ids,
    )

    result = HcrlDemoResult(
        report_path=report_path,
        results_path=results_path,
        training_cutoff_seconds=training_window_limit,
        normal_evaluation=normal_evaluation,
        gear_evaluation=gear_evaluation,
        dos_evaluation=dos_evaluation,
        selected_event=selected_event,
        selected_event_truth_ids=truth_ids,
        workflow=workflow,
        dos_novelty_example=dos_novelty_example,
        agent_mode=agent_mode,
    )
    report = _build_report(detector, training_window_limit, result)
    payload = _results_payload(detector, result)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    save_security_report(report, report_path)
    results_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_BENCHMARK_REPORT,
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=DEFAULT_BENCHMARK_RESULTS,
    )
    parser.add_argument(
        "--agent-mode",
        choices=("mock", "live"),
        default="mock",
        help=(
            "mock is offline and default; live calls configured external/local "
            "LLM providers for the single selected Gear event"
        ),
    )
    args = parser.parse_args(argv)
    result = run_hcrl_demo(
        data_dir=args.data_dir,
        report_path=args.report_path,
        results_path=args.results_path,
        agent_mode=args.agent_mode,
    )
    print(f"Benchmark report: {result.report_path}")
    print(f"Structured results: {result.results_path}")
    print(
        "Known-ID events sent to LangGraph: "
        f"{1 if result.workflow is not None else 0}"
    )


if __name__ == "__main__":
    main()
