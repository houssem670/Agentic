from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib

import main
from agents.report_agent.report_agent import (
    generate_security_report,
    save_security_report,
)
from models.diagnostic_report import DiagnosticReport
from models.security_assessment import SecurityAssessment
from tools.anomaly_detector.ml_detector import (
    MLAnomalyDetector,
    WindowPrediction,
)
from tools.traffic_simulator.simulator import CanRecord, TrafficSimulator


class TestMainML(unittest.TestCase):
    def setUp(self):
        self.detector = MLAnomalyDetector().fit(
            TrafficSimulator(duration=12.0, seed=7).generate(attacks=())
        )

    def test_ml_window_converts_to_security_event_with_evidence(self):
        records = [
            CanRecord(
                timestamp=5.1 + index * 0.1,
                can_id=0x100,
                dlc=8,
                data=bytes((index, 255, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)),
                label="spoofing",
            )
            for index in range(5)
        ]
        records.append(
            CanRecord(
                timestamp=5.6,
                can_id=0x700,
                dlc=2,
                data=b"\x01\x02",
                label="normal",
            )
        )
        prediction = WindowPrediction(
            window_index=5,
            start=5.0,
            end=6.0,
            is_anomaly=True,
            anomaly_score=0.375,
            anomalous_can_ids=(0x100,),
            unseen_can_ids=(0x700,),
        )

        event = main.ml_prediction_to_event(
            prediction,
            records,
            self.detector,
            "simulated",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            model_provenance=main.HCRL_MODEL_PROVENANCE,
            calibration_status="not_independently_calibrated",
        )

        self.assertEqual(event.detection_rule, "ISOLATION_FOREST")
        self.assertEqual(event.can_id, "0x100")
        self.assertEqual(event.metadata["anomaly_score"], 0.375)
        self.assertEqual(event.metadata["anomalous_can_ids"], [0x100])
        self.assertEqual(event.metadata["unseen_can_ids"], [0x700])
        self.assertEqual(
            event.metadata["model_provenance"],
            main.HCRL_MODEL_PROVENANCE,
        )
        self.assertEqual(
            event.metadata["calibration_status"],
            "not_independently_calibrated",
        )
        self.assertEqual(
            event.metadata["message_count_scope"],
            "all_frames_in_window",
        )
        self.assertEqual(event.message_count, 6)
        self.assertEqual(event.observed_rate, 6.0)
        self.assertEqual(
            event.metadata["data_provenance"],
            "SYNTHETIC_TEST_FIXTURE",
        )
        self.assertTrue(event.anomaly)
        self.assertIsNone(event.attack_type)
        self.assertTrue(any("CAN ID : 0x100" in item for item in event.evidence))
        self.assertTrue(
            any("unseen / requires review" in item for item in event.evidence)
        )
        self.assertTrue(
            any("toutes les trames de la fenêtre" in item for item in event.evidence)
        )
        self.assertTrue(
            any(
                "Caractéristique éloignée de la normale" in item
                for item in event.evidence
            )
        )

        hcrl_event = main.ml_prediction_to_event(
            prediction,
            records,
            self.detector,
            "HCRL:gear_dataset.csv",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            model_provenance=main.HCRL_MODEL_PROVENANCE,
            calibration_status="not_independently_calibrated",
            data_provenance=main.HCRL_DATA_PROVENANCE,
        )
        self.assertEqual(
            hcrl_event.metadata["data_provenance"],
            "HCRL_BENCHMARK",
        )

    def test_hcrl_model_selector_defaults_and_requires_an_ml_detector(self):
        default_args = main._parse_args(["--detector", "ml"])
        hcrl_args = main._parse_args(
            ["--detector", "ml", "--ml-model", "hcrl"]
        )

        self.assertEqual(default_args.ml_model, "default")
        self.assertEqual(hcrl_args.ml_model, "hcrl")
        with self.assertRaises(SystemExit):
            main._parse_args(["--ml-model", "hcrl"])

    def test_hcrl_loader_rejects_missing_and_invalid_models(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "hcrl_ml_detector.joblib"
            with patch.object(main, "HCRL_MODEL_PATH", model_path):
                with self.assertRaisesRegex(
                    FileNotFoundError,
                    "no default-model fallback",
                ):
                    main._load_hcrl_ml_detector()

                joblib.dump({"not": "an ML model"}, model_path)
                with self.assertRaisesRegex(TypeError, "not an MLAnomalyDetector"):
                    main._load_hcrl_ml_detector()

                wrong_window = MLAnomalyDetector(window_seconds=2.0).fit(
                    TrafficSimulator(duration=12.0, seed=8).generate(attacks=())
                )
                joblib.dump(wrong_window, model_path)
                with self.assertRaisesRegex(ValueError, "1-second windows"):
                    main._load_hcrl_ml_detector()

                invalid_status = self.detector
                invalid_status._calibration_status = "unknown"
                joblib.dump(invalid_status, model_path)
                with self.assertRaisesRegex(ValueError, "calibration status"):
                    main._load_hcrl_ml_detector()

    def test_hcrl_loader_accepts_uncalibrated_model_with_explicit_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "hcrl_ml_detector.joblib"
            joblib.dump(self.detector, model_path)
            output = StringIO()
            with (
                patch.object(main, "HCRL_MODEL_PATH", model_path),
                redirect_stdout(output),
            ):
                loaded = main._load_hcrl_ml_detector()

        self.assertIsInstance(loaded, MLAnomalyDetector)
        self.assertIn("not independently calibrated", output.getvalue())

    def test_hcrl_loader_reports_corrupt_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "hcrl_ml_detector.joblib"
            model_path.write_bytes(b"not a joblib model")
            with patch.object(main, "HCRL_MODEL_PATH", model_path):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "Could not load HCRL ML model",
                ):
                    main._load_hcrl_ml_detector()

    def test_hcrl_selection_does_not_call_default_loader(self):
        with (
            patch.object(
                main,
                "_load_hcrl_ml_detector",
                return_value=self.detector,
            ) as hcrl_loader,
            patch.object(
                main,
                "_load_or_train_ml_detector",
                side_effect=AssertionError("default model path must not be used"),
            ) as default_loader,
            patch.object(main, "_ml_events", return_value=[]) as ml_events,
            redirect_stdout(StringIO()),
        ):
            main.main(detector="ml", source="simulated", ml_model="hcrl")

        hcrl_loader.assert_called_once()
        default_loader.assert_not_called()
        self.assertEqual(
            ml_events.call_args.kwargs["model_provenance"],
            main.HCRL_MODEL_PROVENANCE,
        )
        self.assertEqual(
            ml_events.call_args.kwargs["calibration_status"],
            "not_independently_calibrated",
        )

    def test_unseen_only_windows_are_reported_without_events(self):
        class PredictionStub:
            def predict(self, records):
                return [
                    WindowPrediction(
                        window_index=0,
                        start=0.0,
                        end=1.0,
                        is_anomaly=False,
                        anomaly_score=0.0,
                        anomalous_can_ids=(),
                        unseen_can_ids=(0x700,),
                    )
                ]

        output = StringIO()
        with redirect_stdout(output):
            events = main._ml_events(
                [
                    CanRecord(0.1, 0x700, 2, b"\x01\x02", "normal"),
                ],
                PredictionStub(),
                "simulated",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                model_provenance=main.HCRL_MODEL_PROVENANCE,
                calibration_status="not_independently_calibrated",
            )

        self.assertEqual(events, [])
        self.assertIn("unseen / requires review", output.getvalue())
        self.assertIn("Not classified as confirmed attacks", output.getvalue())

    @unittest.skipUnless(
        main.HCRL_MODEL_PATH.is_file(),
        "HCRL model artifact is required for this integration test",
    )
    def test_hcrl_model_has_no_confirmed_alerts_on_normal_simulator_ids(self):
        detector = main._load_hcrl_ml_detector()
        records = TrafficSimulator(duration=60, seed=42).generate(attacks=())
        output = StringIO()

        with redirect_stdout(output):
            events = main._ml_events(
                records,
                detector,
                "simulated",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                model_provenance=main.HCRL_MODEL_PROVENANCE,
                calibration_status=detector._calibration_status,
            )

        predictions = detector.predict(records)
        simulator_ids = {record.can_id for record in records}
        self.assertTrue(simulator_ids.isdisjoint(detector._models))
        self.assertTrue(predictions)
        self.assertTrue(all(not prediction.is_anomaly for prediction in predictions))
        self.assertTrue(all(prediction.unseen_can_ids for prediction in predictions))
        self.assertEqual(events, [])
        self.assertIn("unseen / requires review", output.getvalue())

    @unittest.skipUnless(
        main.HCRL_MODEL_PATH.is_file(),
        "HCRL model artifact is required for this integration test",
    )
    def test_hcrl_simulated_demo_routes_mixed_events_and_saves_ml_evidence(self):
        args = main._parse_args(
            [
                "--source",
                "simulated",
                "--detector",
                "ml",
                "--ml-model",
                "hcrl",
            ]
        )
        security_result = SecurityAssessment(
            risk_level="UNKNOWN",
            summary="Mocked assessment for the HCRL integration test.",
        )
        diagnostic_result = DiagnosticReport(
            diagnostic_summary="Mocked diagnosis for the HCRL integration test.",
            analysis_method="MOCK",
        )

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "security_report.md"

            def save_to_temp(report, _output_path):
                return save_security_report(report, report_path)

            with (
                patch(
                    "agents.orchestrator.orchestrator.security_agent",
                    return_value=security_result,
                ) as mock_security,
                patch(
                    "agents.orchestrator.orchestrator.diagnostic_agent",
                    return_value=diagnostic_result,
                ) as mock_diagnostic,
                patch(
                    "agents.orchestrator.orchestrator.generate_security_report",
                    wraps=generate_security_report,
                ) as mock_report_agent,
                patch.object(
                    main,
                    "save_security_report",
                    side_effect=save_to_temp,
                ) as mock_save,
                redirect_stdout(StringIO()),
            ):
                main.main(
                    detector=args.detector,
                    source=args.source,
                    ml_model=args.ml_model,
                )

            security_events = [
                call.args[0] for call in mock_security.call_args_list
            ]
            diagnostic_events = [
                call.args[0] for call in mock_diagnostic.call_args_list
            ]
            report_events = [
                call.kwargs["event"] for call in mock_report_agent.call_args_list
            ]
            self.assertTrue(security_events)
            self.assertEqual(
                [event.event_id for event in security_events],
                [event.event_id for event in diagnostic_events],
            )
            self.assertEqual(
                [event.event_id for event in security_events],
                [event.event_id for event in report_events],
            )
            self.assertTrue(
                any(
                    event.metadata["anomalous_can_ids"]
                    and event.metadata["unseen_can_ids"]
                    for event in security_events
                )
            )
            for event in security_events:
                self.assertEqual(event.detection_rule, "ISOLATION_FOREST")
                self.assertEqual(
                    event.metadata["model_provenance"],
                    main.HCRL_MODEL_PROVENANCE,
                )
                self.assertEqual(
                    event.metadata["calibration_status"],
                    "not_independently_calibrated",
                )
                self.assertFalse(
                    set(event.metadata["anomalous_can_ids"]).intersection(
                        event.metadata["unseen_can_ids"]
                    )
                )

            self.assertTrue(report_path.is_file())
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("Isolation Forest (relatif, non probabiliste)", report)
            self.assertIn(main.HCRL_MODEL_PROVENANCE, report)
            self.assertIn("not_independently_calibrated", report)
            self.assertIn("unseen / requires review", report)
            self.assertTrue(
                "byte_" in report
                or "frame_count=" in report
                or "payload_entropy=" in report
            )
            first_event = security_events[0]
            first_anomalous_id = first_event.metadata["anomalous_can_ids"][0]
            self.assertIn(f"0x{first_anomalous_id:03X}", report)
            self.assertIn(
                f"{first_event.metadata['anomaly_score']:.6f}",
                report,
            )
            mock_save.assert_called_once()

    def test_simulated_ml_mode_runs_with_mocked_agents(self):
        args = main._parse_args(["--source", "simulated", "--detector", "ml"])
        self.assertEqual(
            (args.source, args.detector, args.ml_model),
            ("simulated", "ml", "default"),
        )

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(
                    main,
                    "MODEL_PATH",
                    Path(directory) / "ml_detector.joblib",
                ),
                patch.object(
                    main,
                    "_load_hcrl_ml_detector",
                    side_effect=AssertionError("default model must not load HCRL"),
                ),
                patch.object(
                    main,
                    "capture_can_messages",
                    side_effect=AssertionError("simulated mode must not open vcan0"),
                ),
                patch(
                    "agents.orchestrator.orchestrator.security_agent",
                    return_value=SecurityAssessment(
                        risk_level="UNKNOWN",
                        summary="Mocked security assessment.",
                    ),
                ) as mock_security,
                patch(
                    "agents.orchestrator.orchestrator.diagnostic_agent",
                    return_value=DiagnosticReport(
                        diagnostic_summary="Mocked diagnosis.",
                        analysis_method="MOCK",
                    ),
                ) as mock_diagnostic,
                patch(
                    "agents.orchestrator.orchestrator.generate_security_report",
                    return_value="# Mocked report",
                ) as mock_report,
                patch.object(
                    main,
                    "save_security_report",
                    return_value="reports/security_report.md",
                ) as mock_save,
                redirect_stdout(StringIO()),
            ):
                main.main(detector=args.detector, source=args.source)

        self.assertGreater(mock_security.call_count, 0)
        self.assertEqual(mock_security.call_count, mock_diagnostic.call_count)
        self.assertEqual(mock_security.call_count, mock_report.call_count)
        mock_save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
