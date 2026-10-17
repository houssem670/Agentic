"""Deterministic, synthetic checks for the existing CAN detectors."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import can

from tools.anomaly_detector.anomaly_detector import detect_frequency_anomaly
from tools.anomaly_detector.replay_detector import detect_replay_attack


DEFAULT_SCENARIOS_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "benchmarks"
    / "can_detection_scenarios.json"
)


def _messages(payloads: list[list[int]], interval: float) -> list[can.Message]:
    return [
        can.Message(
            arbitration_id=0x123,
            data=payload,
            is_extended_id=False,
            timestamp=index * interval,
        )
        for index, payload in enumerate(payloads)
    ]


def _scenario(name: str, expected: bool, detected: bool) -> dict[str, Any]:
    return {
        "scenario_id": name,
        "name": name,
        "expected": "anomaly" if expected else "normal",
        "actual": "anomaly" if detected else "normal",
        "passed": expected == detected,
    }


def _invalid_case(
    name: str,
    expected_error: str,
    operation: Callable[[], object],
) -> dict[str, Any]:
    try:
        operation()
    except (TypeError, ValueError) as exc:
        actual_error = type(exc).__name__
    else:
        actual_error = None

    return {
        "name": name,
        "expected_error": expected_error,
        "actual_error": actual_error,
        "passed": actual_error == expected_error,
    }


def _detect_scenario(scenario: dict[str, Any]) -> bool:
    if scenario.get("family") == "frequency":
        return detect_frequency_anomaly(
            can_id="0x123",
            count=scenario["count"],
            window_seconds=scenario["window_seconds"],
            threshold=scenario["threshold"],
        ).anomaly
    if scenario.get("family") == "replay":
        messages = _messages(
            scenario["payloads"],
            scenario["interval_seconds"],
        )
        return detect_replay_attack(messages) is not None
    raise ValueError(f"Unknown benchmark detector family: {scenario.get('family')}")


def run_benchmark(scenarios_path: Path = DEFAULT_SCENARIOS_PATH) -> dict[str, Any]:
    """Run labeled synthetic cases and calculate binary classification metrics."""
    dataset = json.loads(scenarios_path.read_text(encoding="utf-8"))
    if not isinstance(dataset, dict) or not isinstance(dataset.get("scenarios"), list):
        raise ValueError("Benchmark fixture must contain a scenarios list.")

    scenarios = []
    for definition in dataset["scenarios"]:
        scenario_id = definition.get("scenario_id")
        expected_label = definition.get("expected")
        if not scenario_id or expected_label not in {"normal", "anomaly"}:
            raise ValueError("Each benchmark case needs an ID and expected label.")
        detected = _detect_scenario(definition)
        result = _scenario(
            scenario_id,
            expected_label == "anomaly",
            detected,
        )
        result["description"] = definition.get("description", "")
        result["family"] = definition["family"]
        scenarios.append(result)

    true_positive = sum(
        case["expected"] == "anomaly" and case["actual"] == "anomaly"
        for case in scenarios
    )
    false_positive = sum(
        case["expected"] == "normal" and case["actual"] == "anomaly"
        for case in scenarios
    )
    true_negative = sum(
        case["expected"] == "normal" and case["actual"] == "normal"
        for case in scenarios
    )
    false_negative = sum(
        case["expected"] == "anomaly" and case["actual"] == "normal"
        for case in scenarios
    )

    invalid_inputs = [
        _invalid_case(
            "frequency rejects negative count",
            "ValueError",
            lambda: detect_frequency_anomaly("0x123", -1, 5, 100),
        ),
        _invalid_case(
            "frequency rejects zero window",
            "ValueError",
            lambda: detect_frequency_anomaly("0x123", 10, 0, 100),
        ),
        _invalid_case(
            "replay rejects non-CAN message input",
            "TypeError",
            lambda: detect_replay_attack([None]),
        ),
        _invalid_case(
            "replay rejects non-finite timestamp",
            "ValueError",
            lambda: detect_replay_attack(
                [can.Message(arbitration_id=0x123, data=[], timestamp=float("nan"))]
            ),
        ),
        _invalid_case(
            "replay rejects invalid minimum repetition count",
            "ValueError",
            lambda: detect_replay_attack([], min_repetitions=1),
        ),
    ]

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    return {
        "scope": (
            f"Dataset {dataset.get('dataset_id', 'unspecified')} is synthetic. "
            "These unit-scale results do not estimate performance on real vehicle traffic."
        ),
        "dataset_id": dataset.get("dataset_id"),
        "provenance": dataset.get("provenance", "UNSPECIFIED"),
        "scenarios": scenarios,
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
        "metrics": {
            "precision": ratio(true_positive, true_positive + false_positive),
            "recall": ratio(true_positive, true_positive + false_negative),
            "false_positive_rate": ratio(
                false_positive, false_positive + true_negative
            ),
            "false_negative_rate": ratio(
                false_negative, false_negative + true_positive
            ),
        },
        "invalid_inputs": invalid_inputs,
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), indent=2))