import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence
from uuid import uuid4

import can
import joblib

from tools.can_analyzer.can_analyzer import (
    analyze_can_messages,
    analyze_can_traffic,
    capture_can_messages,
)
from tools.anomaly_detector.ml_detector import (
    MLAnomalyDetector,
    WindowPrediction,
)
from tools.traffic_simulator.simulator import (
    ATTACK_LABELS,
    CanRecord,
    TrafficSimulator,
)
from agents.orchestrator.orchestrator import run_workflow
from agents.report_agent.report_agent import save_security_report
from models.security_event import SecurityEvent


SIMULATED_DURATION = 60.0
RULE_WINDOW_SECONDS = 5.0
ML_WINDOW_SECONDS = 1.0
TRAINING_DURATION = 300.0
MODEL_PATH = Path("models/ml_detector.joblib")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automotive CAN Security Platform")
    parser.add_argument(
        "--detector",
        choices=("rules", "ml", "both"),
        default="rules",
        help="détecteur à utiliser",
    )
    parser.add_argument(
        "--source",
        choices=("vcan0", "simulated"),
        default="vcan0",
        help="source du trafic CAN",
    )
    return parser.parse_args(argv)


def _load_or_train_ml_detector() -> MLAnomalyDetector:
    if MODEL_PATH.exists():
        detector = joblib.load(MODEL_PATH)
        if not isinstance(detector, MLAnomalyDetector):
            raise TypeError(f"Le modèle chargé depuis {MODEL_PATH} est invalide.")
        return detector

    training_records = TrafficSimulator(
        duration=TRAINING_DURATION,
        seed=7,
    ).generate(attacks=())
    detector = MLAnomalyDetector(
        window_seconds=ML_WINDOW_SECONDS,
        contamination=0.001,
        random_state=42,
    ).fit(training_records)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(detector, MODEL_PATH)
    return detector


def _records_from_messages(messages: Sequence[can.Message]) -> list[CanRecord]:
    if not messages:
        return []

    first_timestamp = min(message.timestamp for message in messages)
    return [
        CanRecord(
            timestamp=message.timestamp - first_timestamp,
            can_id=message.arbitration_id,
            dlc=message.dlc,
            data=bytes(message.data),
            label="normal",
        )
        for message in messages
    ]


def _messages_from_records(records: Sequence[CanRecord]) -> list[can.Message]:
    return [
        can.Message(
            timestamp=record.timestamp,
            arbitration_id=record.can_id,
            data=record.data,
            is_extended_id=record.can_id > 0x7FF,
        )
        for record in records
    ]


def _analyze_simulated_rules(records: Sequence[CanRecord]) -> list[SecurityEvent]:
    detections: list[SecurityEvent] = []
    window_count = int(SIMULATED_DURATION / RULE_WINDOW_SECONDS)
    for window_index in range(window_count):
        start = window_index * RULE_WINDOW_SECONDS
        end = start + RULE_WINDOW_SECONDS
        window_records = [
            record for record in records if start <= record.timestamp < end
        ]
        detections.extend(
            analyze_can_messages(
                _messages_from_records(window_records),
                window_seconds=RULE_WINDOW_SECONDS,
                threshold=100,
                channel="simulated",
            )
        )
    return detections


def ml_prediction_to_event(
    prediction: WindowPrediction,
    records: Sequence[CanRecord],
    detector: MLAnomalyDetector,
    channel: str,
    started_at: datetime,
) -> SecurityEvent:
    if not prediction.is_anomaly:
        raise ValueError("Une prédiction normale ne peut pas produire un événement.")

    window_records = [
        record
        for record in records
        if prediction.start <= record.timestamp < prediction.end
    ]
    can_ids = prediction.anomalous_can_ids
    formatted_ids = [f"0x{can_id:03X}" for can_id in can_ids]
    evidence = [
        f"Score d'anomalie Isolation Forest (relatif, non probabiliste) : "
        f"{prediction.anomaly_score:.6f}"
    ]

    for can_id, formatted_id in zip(can_ids, formatted_ids):
        evidence.append(f"CAN ID : {formatted_id}")
        features = detector.most_deviant_features(window_records, can_id)
        if features:
            evidence.extend(
                f"Caractéristique éloignée de la normale : {feature}"
                for feature in features
            )
        else:
            evidence.append(
                "Aucun profil normal appris pour cet ID ; "
                "les écarts de caractéristiques ne sont pas comparables."
            )

    window_seconds = prediction.end - prediction.start
    provenance = (
        "SYNTHETIC_TEST_FIXTURE" if channel == "simulated" else "LIVE_CAPTURE"
    )
    return SecurityEvent(
        event_id=f"ML-{uuid4().hex[:12]}",
        timestamp=started_at + timedelta(seconds=prediction.start),
        event_type="CAN_ANOMALY",
        can_id=", ".join(formatted_ids) or "Unknown",
        channel=channel,
        message_count=len(window_records),
        window_seconds=window_seconds,
        observed_rate=(
            len(window_records) / window_seconds if window_seconds > 0 else 0.0
        ),
        detection_rule="ISOLATION_FOREST",
        anomaly=True,
        attack_type=None,
        evidence=evidence,
        metadata={
            "detector": "isolation_forest",
            "anomaly_score": prediction.anomaly_score,
            "window_start": prediction.start,
            "window_end": prediction.end,
            "anomalous_can_ids": list(can_ids),
            "data_provenance": provenance,
        },
    )


def _ml_events(
    records: Sequence[CanRecord],
    detector: MLAnomalyDetector,
    channel: str,
    started_at: datetime,
) -> list[SecurityEvent]:
    return [
        ml_prediction_to_event(
            prediction,
            records,
            detector,
            channel,
            started_at,
        )
        for prediction in detector.predict(records)
        if prediction.is_anomaly
    ]


def main(detector: str = "rules", source: str = "vcan0") -> None:
    print("=" * 45)
    print(" AUTOMOTIVE CAN SECURITY PLATFORM ")
    print("=" * 45)

    detections: list[SecurityEvent]

    # Keep the original default capture and detector path unchanged.
    if source == "vcan0" and detector == "rules":
        detections = analyze_can_traffic(
            window_seconds=5,
            threshold=100,
        )
    else:
        started_at = datetime.now(timezone.utc)
        if source == "simulated":
            records = TrafficSimulator(
                duration=SIMULATED_DURATION,
                seed=42,
            ).generate(ATTACK_LABELS)
            messages: list[can.Message] = []
            print(
                f"Generated {len(records)} simulated CAN frames "
                f"over {SIMULATED_DURATION:.0f} seconds."
            )
        else:
            messages = capture_can_messages(
                window_seconds=RULE_WINDOW_SECONDS,
                channel="vcan0",
            )
            records = _records_from_messages(messages)

        detections = []
        if detector in ("rules", "both"):
            if source == "simulated":
                detections.extend(_analyze_simulated_rules(records))
            else:
                detections.extend(
                    analyze_can_messages(
                        messages,
                        window_seconds=RULE_WINDOW_SECONDS,
                        threshold=100,
                        channel="vcan0",
                    )
                )

        if detector in ("ml", "both"):
            ml_detector = _load_or_train_ml_detector()
            detections.extend(
                _ml_events(records, ml_detector, source, started_at)
            )

    print("\n=== SECURITY ANALYSIS & DIAGNOSTICS ===")

    reports = []

    # Analyze every detected anomaly
    for detection in detections:
        if not detection.anomaly:
            continue

        print(f"\n{'=' * 45}")
        print(f"Anomaly detected: {detection.attack_type or detection.detection_rule}")
        print(f"CAN ID: {detection.can_id}")
        print(f"Detection rule: {detection.detection_rule}")

        try:
            workflow = run_workflow(detection, persist_report=False)
        except Exception as exc:
            print(
                "[Orchestrator] Workflow failed: "
                f"{type(exc).__name__}"
            )
            continue

        assessment = workflow["assessment"]
        diagnostic = workflow["diagnostic"]

        print("\n--- SECURITY ASSESSMENT ---")
        print(f"Threat type: {assessment.threat_type}")
        print(f"Risk level: {assessment.risk_level}")
        print(f"Summary: {assessment.summary}")

        print("\n--- DIAGNOSTIC AGENT ---")
        print(f"Analysis method: {diagnostic.analysis_method}")
        print(f"Confidence: {diagnostic.confidence:.2f}")
        print(f"Root cause confirmed: {diagnostic.root_cause_confirmed}")
        print(diagnostic.diagnostic_summary)

        reports.append(workflow["report"])
        print("[Report Agent] Report generated successfully.")

    # Save all generated reports into one Markdown file
    if reports:
        combined_report = "\n\n---\n\n".join(reports)

        try:
            output_path = save_security_report(
                combined_report,
                "reports/security_report.md",
            )
            print(f"\nReport saved to: {output_path}")

        except Exception as exc:
            print(
                f"[Report Agent] Could not save report: "
                f"{type(exc).__name__}: {exc}"
            )
    else:
        print("\nNo anomalous events to report.")

    print("\n=== ANALYSIS COMPLETE ===")


if __name__ == "__main__":
    arguments = _parse_args()
    main(detector=arguments.detector, source=arguments.source)
