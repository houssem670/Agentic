# AutoSentinel AI: Project File Guide

This guide describes the checked-out source as it exists now, including local
HCRL additions. The repository has pre-existing modified, deleted, ignored, and
untracked files; this guide does not imply that all of them are committed.

## Architecture at a glance

There are two distinct processing paths:

1. **Live CAN path:** `main.py` captures SocketCAN frames from `vcan0`, or uses
   an in-memory synthetic source when `--source simulated` is selected. Rules
   and/or the optional Isolation Forest produce `SecurityEvent` records. Each
   anomalous event can be interpreted by the LangGraph agents and written to a
   Markdown report.
2. **Offline HCRL path:** scripts parse local HCRL captures, train/evaluate or
   load the HCRL Isolation Forest, and optionally replay selected evaluation
   results through LangGraph. This path does not capture from `vcan0`.

The synthetic simulator and its fixture-based evaluations are a third,
self-contained way to create or score traffic; they are not the HCRL data path.

## 1. CAN simulation and transport

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `tools/traffic_simulator/simulator.py` | Creates deterministic normal and labeled attack traffic, saves/loads CSV, and can send frames over virtual CAN. | `CanRecord`, `TrafficSimulator.generate`, `save_csv`, `load_csv`, `send_live`, `main` | Duration, seed, attack set and optional attack windows. | `CanRecord` values in memory, a CSV in offline mode, or frames sent to `vcan0` in live mode. | Standard library; imports `python-can` only for `send_live`. | Offline simulation; optional live virtual-CAN transmission; tests. | Essential |
| `tools/traffic_simulator/__init__.py` | Makes the simulator folder an importable Python package. | Package marker. | Python package imports. | Package namespace. | Python. | All. | Supporting |
| `tests/test_traffic_simulator.py` | Checks deterministic generation, CSV round-trips, attack labels and input validation. | `TestTrafficSimulator` | Synthetic parameters and temporary CSV files. | Test assertions. | `unittest`, simulator. | Testing. | Supporting |

`TrafficSimulator` generates normal messages on a fixed set of standard CAN
IDs using per-ID periods and small seeded variations. Attack windows are split
across flooding, replay, spoofing and fuzzing unless overridden. Flooding
creates dense traffic on ID `0x000`; replay repeats a short normal sequence;
spoofing emits altered data using ID `0x300`; fuzzing chooses random standard
IDs and eight random bytes. These labels describe simulator fixtures, not proof
that a live frame is malicious.

The simulator's `--mode offline` command writes CSV and does not need SocketCAN.
`--mode live` opens a `python-can` SocketCAN bus on `vcan0` and sends each
generated frame against elapsed monotonic time. The analyzer is a separate
process: start it while the simulator is sending if the goal is to capture that
traffic.

## 2. CAN capture, preprocessing and deterministic detection

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `tools/can_analyzer/can_analyzer.py` | Captures CAN messages and invokes the frequency and repeated-frame detectors. | `capture_can_messages`, `analyze_can_messages`, `analyze_can_traffic` | `python-can` messages from a selected SocketCAN channel and a time window. | A list of `SecurityEvent` records, including non-anomalous per-ID frequency observations. | `python-can`, the two rule detectors and `SecurityEvent`. | Live capture; synthetic/in-memory analysis; tests. | Essential |
| `tools/anomaly_detector/anomaly_detector.py` | Implements the strict per-ID message-rate threshold. | `detect_frequency_anomaly` | CAN ID, message count, observation duration and threshold. | A `SecurityEvent`; anomaly is true only when rate is strictly greater than threshold. | `SecurityEvent`. | Live rules; synthetic evaluation; tests. | Essential |
| `tools/anomaly_detector/replay_detector.py` | Flags runs of identical consecutive CAN frames occurring within a short burst. | `detect_replay_attack` | Ordered `python-can` messages and optional repetition/burst limits. | A `REPLAY_SUSPECTED` event, or `None`. | `python-can`, `SecurityEvent`. | Live rules; synthetic evaluation; tests. | Essential |
| `models/security_event.py` | Shared structured record for detector facts and evidence. | `SecurityEvent` dataclass | Detector measurements, timestamps, identifiers, evidence and metadata. | A typed event passed to agents and reports. | Python dataclasses and typing. | Live; offline; training/evaluation boundaries; tests. | Essential |
| `tools/anomaly_detector/benchmark.py` | Runs the small fixed synthetic rule-detector benchmark. | `run_benchmark` | `data/benchmarks/can_detection_scenarios.json`. | Printed per-case results, invalid-input checks and fixture metrics. | Both rule detectors, `python-can`, JSON fixture. | Offline evaluation; tests. | Supporting |
| `data/benchmarks/can_detection_scenarios.json` | Hand-authored normal/anomaly cases for detector consistency checks. | JSON scenario records. | Fixed counts or synthetic frame payloads. | Expected labels consumed by the benchmark and tests. | `benchmark.py`, `tests/test_can_benchmark.py`. | Testing/offline evaluation. | Supporting |

The live capture function opens a SocketCAN bus on `vcan0`, receives until
the requested duration expires, then shuts down the bus in `finally`.
`analyze_can_messages` counts messages by arbitration ID for frequency checks
and also checks the ordered message stream for repeated-frame suspicion. It
adds provenance metadata (`LIVE_CAPTURE` for `vcan0`, otherwise
`SYNTHETIC_TEST_FIXTURE`). The frequency detector uses
`count / window_seconds > threshold`; the default main entry point uses a
five-second window and a threshold of 100 messages/second.

Preprocessing is intentionally limited: live `python-can` messages are
converted to `CanRecord` values for the ML path, with timestamps rebased to
the first captured message. HCRL records are separately parsed and validated
by the HCRL training script. There is no DBC decoding or conversion of payload
bytes into vehicle signals in the inspected code.

## 3. Feature extraction and Isolation Forest

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `tools/anomaly_detector/ml_detector.py` | Extracts the fixed 21 numerical features and fits/predicts with one Isolation Forest per CAN ID. | `FEATURE_NAMES`, `WindowFeatures`, `WindowPrediction`, `FeatureDeviation`, `extract_features`, `MLAnomalyDetector.fit`, `fit_features`, `predict`, `predict_features`, `calibrate_thresholds`, `most_deviant_features` | `CanRecord` sequences, or already extracted per-ID/per-window feature vectors. | Per-ID feature vectors and window predictions with relative anomaly scores, anomalous IDs and unseen IDs. | scikit-learn `IsolationForest`, simulator's `CanRecord`. | Live optional ML; synthetic evaluation; HCRL training/evaluation; tests. | Essential |
| `models/ml_detector.joblib` | Default model artifact, created on demand by the live ML path if absent. | Serialized `MLAnomalyDetector`. | Synthetic normal traffic generated by `main.py` if no default model exists. | A default detector loaded by later live ML runs. | `main.py`, `joblib`, `ml_detector.py`. | Live ML training/loading. | Supporting; generated locally |
| `tests/test_ml_detector.py` | Tests feature extraction, training, prediction, calibration and edge conditions. | `TestMLAnomalyDetector` | Synthetic `CanRecord` input and temporary artifacts. | Test assertions. | `unittest`, detector and simulator. | Testing. | Supporting |
| `tests/test_main_ml.py` | Tests main-entry ML selection, model handling and conversion of predictions into events. | `TestMainML` | Mocked model, messages and workflow boundaries. | Test assertions. | `main.py`, `unittest`, `joblib`. | Testing. | Supporting |

The 21 features are calculated for each CAN ID in each time window:

1. frame count;
2. mean and population standard deviation of inter-frame intervals;
3. distinct payload count and payload-byte entropy;
4. mean of each of the eight byte positions; and
5. population standard deviation of each of the eight byte positions.

Thus `5 + 8 + 8 = 21`. Missing byte positions contribute no sample for that
position; an empty position is represented as zero.

`MLAnomalyDetector` fits an independent `IsolationForest` for each CAN ID using
normal-labeled records only. Predictions produce one result per occupied
window. The anomaly score is the negative decision-function score (a relative
ranking value, not a probability). Unknown IDs are reported separately as
unseen; they do not get an Isolation Forest score. Optional threshold
calibration requires separately identified independent normal capture data,
but the HCRL training run described here does not activate that calibration.

In the live application, the default model path is `models/ml_detector.joblib`.
If absent, `main.py` generates 300 seconds of synthetic normal traffic and
fits that default model; it does not use HCRL data. The HCRL model is a
different explicit artifact and is never substituted silently.

## 4. Synthetic evaluation scripts

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `scripts/evaluate_rules.py` | Evaluates frequency and replay rules on labeled synthetic one-second windows. | `split_windows`, `calculate_metrics`, `evaluate_windows`, `generate_evaluation_windows`, `main` | Seeded 180-second synthetic traffic and configured attack windows. | `reports/evaluation_rules.md`. | Simulator, both rule detectors, `python-can`. | Offline evaluation. | Supporting |
| `scripts/evaluate_ml.py` | Compares rules, ML and their OR-combination across selected random seeds. | `parse_seeds`, `evaluate_seed`, `build_report`, `main` | Synthetic normal training traffic plus regenerated synthetic test scenarios. | `reports/evaluation_comparison.md`. | `evaluate_rules.py`, simulator and ML detector. | Offline evaluation/training. | Supporting |
| `tests/test_evaluate_rules.py` | Validates window splitting and rule-evaluation calculations. | `TestRulesEvaluation` | Synthetic records and fixtures. | Test assertions. | `unittest`, evaluation module. | Testing. | Supporting |
| `tests/test_evaluate_ml.py` | Validates seed parsing and summary calculations. | `TestEvaluateML` | Seed strings and metric samples. | Test assertions. | `unittest`, `evaluate_ml.py`. | Testing. | Supporting |

These scripts are separate from HCRL. `evaluate_ml.py` fits a temporary
in-memory detector on 300 seconds of generated normal traffic (seed 7), then
evaluates each selected seed. It does not write the HCRL model.

## 5. HCRL dataset, training and demonstration

The following dataset and model files exist locally in the current worktree,
but are not tracked in the Git index. The dataset files are large; do not
delete or overwrite them as part of routine cleanup.

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `datasets/hcrl/normal_run_data.txt` | HCRL normal capture used for training and chronological holdout evaluation. | Raw capture records. | Timestamp, standard CAN ID, DLC, payload and marker fields. | Parsed normal `CanRecord` values. | HCRL parser in `scripts/train_evaluate_hcrl.py` and demo. | Training/offline evaluation. | Essential to HCRL workflow |
| `datasets/hcrl/DoS_dataset.csv` | HCRL DoS capture; includes labels and unseen-ID traffic. | Raw capture records. | CSV capture rows with `R`/`T` labels. | Parsed evaluation records and separately reported novelty. | HCRL training/demo scripts. | Offline evaluation/demo. | Essential to these HCRL commands |
| `datasets/hcrl/Fuzzy_dataset.csv` | HCRL fuzzy-injection capture. | Raw capture records. | CSV capture rows with `R`/`T` labels. | Parsed evaluation records. | HCRL training script. | Offline evaluation. | Essential to HCRL training/evaluation |
| `datasets/hcrl/gear_dataset.csv` | HCRL gear-spoofing capture; also supplies the demo's selected event. | Raw capture records. | CSV capture rows with `R`/`T` labels. | Parsed evaluation records; at most one selected Gear event. | HCRL training/demo scripts. | Offline evaluation/demo. | Essential to these HCRL commands |
| `datasets/hcrl/RPM_dataset.csv` | HCRL RPM-spoofing capture. | Raw capture records. | CSV capture rows with `R`/`T` labels. | Parsed evaluation records. | HCRL training script. | Offline evaluation. | Essential to HCRL training/evaluation |
| `scripts/train_evaluate_hcrl.py` | Parses and validates each HCRL capture, trains the existing detector on normal-only data, then evaluates the holdout and attack captures. | `CaptureStats`, `CaptureEvaluation`, `_iter_normal_records`, `_iter_attack_records`, `_iter_windows`, `_score_capture`, `build_report`, `run_pipeline`, `main` | Five HCRL files; default training fraction is the chronological first 70% of the normal capture. | `models/hcrl_ml_detector.joblib` and `reports/hcrl_ml_evaluation.md`; training overwrites those output paths. | Existing feature extractor/detector, `joblib`, metrics from `evaluate_rules.py`. | Training/offline evaluation. | Essential to HCRL training |
| `models/hcrl_ml_detector.joblib` | Serialized per-CAN-ID model produced by the HCRL training command and loaded only when selected. | Serialized `MLAnomalyDetector`, including training-capture and calibration metadata. | HCRL normal-only training features. | HCRL-trained detector for `main.py` or offline demo. | `main.py`, HCRL scripts and `joblib`. | Live optional ML; offline demo. | Essential to HCRL model execution |
| `scripts/demo_hcrl_pipeline.py` | Loads (does not retrain) the HCRL model, scores selected HCRL captures and sends at most one qualifying Gear event through LangGraph. | `_score_capture` clients, `_find_gear_positive`, `_find_dos_novelty`, `_run_event_workflow`, `run_hcrl_demo`, `main` | Existing model, normal capture, Gear and DoS captures. | Dedicated Markdown and JSON under `reports/hcrl_benchmark/`; mock mode makes no provider calls. | `main.py` model/event helpers, HCRL parser/scorer, agents and report saver. | Offline demonstration; optionally external LLM calls with `--agent-mode live`. | Supporting |
| `scripts/verify_hcrl_artifacts.py` | Computes SHA-256 fingerprints and optionally checks a caller-supplied trusted manifest. | `REQUIRED_ARTIFACTS`, `sha256_file`, `calculate_artifact_hashes`, `load_expected_hashes`, `main` | Five HCRL data files plus the HCRL model; optional external JSON digest manifest. | Printed hashes or match/mismatch status; does not write files. | Python standard library. | Offline verification/testing. | Supporting |
| `tests/test_hcrl_training.py` | Tests HCRL parsing/training/evaluation behavior using controlled fixtures. | `TestHcrlTraining` | Temporary or synthetic HCRL-formatted records. | Test assertions. | `unittest`, HCRL training script. | Testing. | Supporting |
| `tests/test_hcrl_demo.py` | Tests HCRL demonstration routing and outputs with deterministic detector/provider substitutes. | `TestHcrlDemo` | Test captures and mocked agents/model. | Test assertions and temporary outputs. | `unittest`, HCRL demo. | Testing. | Supporting |
| `tests/test_verify_hcrl_artifacts.py` | Tests digest computation, manifest validation and CLI results. | `TestVerifyHcrlArtifacts` | Temporary fixture files and manifest data. | Test assertions. | `unittest`, verifier. | Testing. | Supporting |

HCRL parser labels are used as evaluation truth: `R` is normal and `T` is
injected. Training passes only the chronological normal-data portion into
fitting. Attack capture labels are not part of feature vectors. Normal holdout
comes from the tail of the same capture, so it is not independent validation.
In the demo, HCRL labels are used to choose an eligible Gear demonstration
event only after prediction; labels are stripped before the event reaches the
agents. DoS unseen-ID novelty is reported separately, not called an Isolation
Forest detection and not sent to LangGraph.

The verifier's hashes are only fingerprints unless a trusted manifest is
provided through an independently trusted channel. The checked-out `.gitignore`
excludes the HCRL model; large benchmark captures are local artifacts, not
ordinary source files.

## 6. Main application and HCRL model selection

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `main.py` | Entry point that selects a traffic source and detector, converts detections into events, invokes the workflow and saves combined reports. | `_parse_args`, `_load_or_train_ml_detector`, `_load_hcrl_ml_detector`, `_records_from_messages`, `ml_prediction_to_event`, `_ml_events`, `main` | CLI choices for detector (`rules`, `ml`, `both`), source (`vcan0`, `simulated`) and ML model (`default`, `hcrl`). | Printed results and `reports/security_report.md` when anomalies produce reports. | Analyzer, simulator, ML detector, LangGraph orchestrator, Report Agent and `SecurityEvent`. | Live application; synthetic source; HCRL model inference. | Essential |
| `scripts/__init__.py` | Makes scripts importable for `python -m scripts...` commands. | Package marker. | Python module invocation/import. | Package namespace. | Python. | CLI/testing. | Supporting |

`main.py --ml-model hcrl` explicitly loads `models/hcrl_ml_detector.joblib`;
it errors if the model is missing or its type, one-second window, known IDs or
calibration metadata are invalid. It does not fall back to the default model
and does not retrain HCRL. The default model path and HCRL model path are
separate.

When each event's workflow succeeds, `main.py` gathers the generated Markdown
blocks and saves them together. It calls the orchestrator with
`persist_report=False`, so the graph does not overwrite the report once per
event. A workflow exception is printed and that event's report is skipped.

## 7. Agents, workflow and report models

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `agents/security_agent/security_agent.py` | Builds an evidence-grounded security interpretation and tries configured providers in order. | `security_agent` | A detector-produced `SecurityEvent`; local RAG results; environment provider configuration. | `SecurityAssessment`, or an exception when neither provider returns valid JSON. | Gemini SDK, dotenv, OpenRouter helper, RAG and assessment model. | Live/HCRL demo; mocked in tests. | Essential to live interpretation |
| `agents/diagnostic_agent/diagnostic_agent.py` | Produces cautious diagnostic hypotheses and checks; validates model output and returns evidence-only fallback if providers fail. | `_parse_diagnostic_response`, `_fallback_diagnostic`, `diagnostic_agent` | A `SecurityEvent` plus local RAG context. | `DiagnosticReport`; root cause is not confirmed by this event alone. | Gemini SDK, dotenv, OpenRouter helper, RAG, event/report models. | Live/HCRL demo; mocked in tests. | Essential to live interpretation |
| `agents/orchestrator/orchestrator.py` | Defines the sequential LangGraph that runs Security, Diagnostic and Report nodes and records per-node status/duration. | `WorkflowState`, `security_node`, `diagnostic_node`, `report_node`, `build_workflow`, `run_workflow` | A `SecurityEvent` and persistence option. | Assessment, diagnostic, Markdown, optional saved path, errors and agent trace. | LangGraph, three agents, report and data models. | Live; HCRL demo; tests. | Essential |
| `agents/report_agent/report_agent.py` | Converts detector and agent outputs into a structured Markdown report and saves it. | `_data_provenance`, `generate_security_report`, `save_security_report` | Event, security assessment and diagnostic report. | Markdown text and optionally a saved path. It does not call an LLM. | Three data models and filesystem. | Live; offline HCRL demo; tests. | Essential |
| `models/security_assessment.py` | Typed output contract for security interpretation. | `SecurityAssessment` | Provider assessment fields. | Structured risk, facts, unknowns, recommendations and confidence. | Dataclasses. | Agent workflow/testing. | Essential |
| `models/diagnostic_report.py` | Typed output contract for diagnostic findings. | `DiagnosticReport` | Diagnostic analysis fields. | Structured findings, evidence, uncertainty, checks and confidence. | Dataclasses. | Agent workflow/testing. | Essential |
| `tests/test_security_agent.py` | Checks Security Agent interpretation and provider handling without real API requests. | `TestSecurityAgent` | Mock events and mocked SDK/HTTP responses. | Test assertions. | `unittest`, security agent, orchestrator. | Testing. | Supporting |
| `tests/test_diagnostic_agent.py` | Checks response validation, provider fallbacks and safe diagnostic output. | `TestDiagnosticAgent` | Mock events and mocked provider responses. | Test assertions. | `unittest`, diagnostic agent. | Testing. | Supporting |
| `tests/test_orchestrator.py` | Checks graph sequencing, fallback behavior, trace data and report persistence choices. | `TestOrchestrator` | Test event and mocked agent/report functions. | Test assertions. | `unittest`, orchestrator and main. | Testing. | Supporting |
| `tests/test_report_agent.py` | Checks provenance, Markdown formatting and report saving. | `TestReportAgent` | Test event, assessment and diagnostic objects. | Test assertions and temporary report files. | `unittest`, report agent and models. | Testing. | Supporting |
| `tests/test_openrouter_provider.py` | Tests request construction and validation for the OpenRouter helper. | `TestOpenRouterProvider` | Mock prompt, key, model and HTTP response. | Test assertions. | `unittest`, requests and provider helper. | Testing. | Supporting |

The graph is a fixed sequence, not a planner: Security → Diagnostic → Report.
The agents each receive the original `SecurityEvent`; the diagnostic agent
does not consume the security assessment as its input. Security prefers
Gemini, then OpenRouter. If Security still fails, the orchestration node
creates an `UNKNOWN` assessment. Diagnostic independently tries Gemini then
OpenRouter and constructs a safe fallback if both fail. The Report Agent
formats the existing evidence and agent results; it does not create new
findings.

## 8. Local retrieval and LLM provider

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `rag/retriever.py` | Implements local paragraph chunking, bilingual tokenization/query expansion and BM25-style lexical ranking. | `tokenize`, `expand_query`, `load_chunks`, `retrieve` | Query and text documents in `rag/documents/`. | Ranked local passages with source, chunk ID and score. | Python standard library. | Agent prompt construction; tests/manual use. | Supporting |
| `rag/rag_pipeline.py` | Formats retrieved passages for inclusion in an agent prompt. | `build_rag_context` | Query and top-k count. | Search results plus concatenated context text. | `rag.retriever`. | Agent prompt construction. | Supporting |
| `rag/documents/automotive_diagnostics.txt` | Local reference text for diagnostic retrieval. | Text sections. | Loaded at retrieval time. | BM25 chunks. | `rag/retriever.py`. | Agent context. | Supporting |
| `rag/documents/automotive_standards.txt` | Local summary text on automotive standards topics. | Text sections. | Loaded at retrieval time. | BM25 chunks. | `rag/retriever.py`. | Agent context. | Supporting |
| `rag/documents/can_attacks.txt` | Local reference text on CAN attack concepts. | Text sections. | Loaded at retrieval time. | BM25 chunks. | `rag/retriever.py`. | Agent context. | Supporting |
| `rag/documents/can_fundamentals.txt` | Local CAN fundamentals reference text. | Text sections. | Loaded at retrieval time. | BM25 chunks. | `rag/retriever.py`. | Agent context. | Supporting |
| `rag/documents/can_replay_security.txt` | Local reference text on repeated/replay traffic. | Text sections. | Loaded at retrieval time. | BM25 chunks. | `rag/retriever.py`. | Agent context. | Supporting |
| `rag/documents/intrusion_detection.txt` | Local reference text on intrusion detection. | Text sections. | Loaded at retrieval time. | BM25 chunks. | `rag/retriever.py`. | Agent context. | Supporting |
| `rag/SOURCES.md` | Records source/reference links for the RAG documents. | Source register. | Read by maintainers. | Research provenance notes. | RAG document set. | Documentation/maintenance. | Supporting |
| `agents/openrouter_provider.py` | Calls the OpenRouter OpenAI-compatible chat-completions API with a fixed timeout and validates the response shape. | `openrouter_chat_completion` | Prompt, `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`. | Response text or explicit exception. | `requests`. | Live provider fallback; mocked tests. | Supporting |

The retriever reads local `.txt` files and applies BM25-like lexical scoring;
it does not use embeddings or an external retrieval service. Both agents call
it independently. Its output is reference context, not evidence that an attack
or fault occurred.

## 9. Flask dashboard and web assets

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `backend/app/dashboard.py` | Creates the Flask app, parses reports, archives distinct report content, exposes read-only JSON/report routes and sanitizes rendered Markdown. | `parse_report`, `create_app`, report parsing/rendering helpers. | Markdown report path; default is `reports/security_report.md`, override with `SECURITY_REPORT_PATH`. | Dashboard page, report-backed summaries/events, report history and download responses. | Flask, `markdown`, `bleach`, report files. | Local dashboard; API tests. | Supporting |
| `backend/app/templates/dashboard.html` | Defines the single-page dashboard layout and references frontend assets. | Overview, traffic, threats, workflow, diagnostics and reports sections. | Flask rendering and static assets. | HTML page. | `dashboard.py`, JavaScript/CSS assets. | Local dashboard. | Supporting |
| `backend/app/static/dashboard.js` | Loads summary, events, latest report and health APIs; updates dashboard state and event-table interactions. | Main browser controller. | Dashboard API JSON. | Updated page content, sorting/filtering/pagination and status displays. | Flask routes and template DOM. | Local dashboard. | Supporting |
| `backend/app/static/dashboard-charts.js` | Renders report-derived counts/charts and explicit unavailable states for missing data. | Chart rendering and report-derived metrics. | Dashboard events and summary. | Visual charts/KPIs. | Template DOM and dashboard API data. | Local dashboard. | Supporting |
| `backend/app/static/dashboard-history.js` | Lists archived reports and loads/downloads selected report details. | Archive interactions. | `/api/reports`, `/api/report` and download route. | Report-history UI and report content. | Flask routes, `dashboard.js`, template DOM. | Local dashboard. | Supporting |
| `backend/app/static/dashboard-report.js` | Presents the report content in a structured report viewer. | Report viewer behavior. | Sanitized report HTML. | Interactive report view. | Template DOM and report API. | Local dashboard. | Supporting |
| `backend/app/static/dashboard-palette.js` | Adds palette/theme selection behavior. | Palette controls. | Browser storage and DOM. | Presentation-only changes. | Template DOM. | Local dashboard. | Optional presentation |
| `backend/app/static/css/tokens.css` | Shared visual tokens. | CSS variables. | Stylesheet cascade. | Colors, spacing and typography tokens. | `dashboard.html`. | Local dashboard. | Supporting |
| `backend/app/static/css/base.css` | Global reset and base page styles. | Base styles. | HTML elements. | Base presentation. | `dashboard.html`. | Local dashboard. | Supporting |
| `backend/app/static/css/layout.css` | Dashboard layout and responsive structural styles. | Layout styles. | Template classes. | Page and panel layout. | `dashboard.html`. | Local dashboard. | Supporting |
| `backend/app/static/css/components.css` | Shared UI component styles. | Cards, tables, badges and controls. | Template classes. | Component presentation. | `dashboard.html`. | Local dashboard. | Supporting |
| `backend/app/static/css/autosentinel-theme.css` | AutoSentinel theme layer. | Theme rules. | Template classes/tokens. | Theme presentation. | Base/component styles. | Local dashboard. | Supporting |
| `backend/app/static/css/autosentinel-photos.css` | Hero imagery and visual-photo layer. | Image styles. | Template image elements. | Presentation. | Theme styles and static image files. | Local dashboard. | Optional presentation |
| `backend/app/static/css/autosentinel-charts.css` | Chart-specific visual styles. | Chart styles. | Chart DOM. | Presentation. | Dashboard chart script. | Local dashboard. | Supporting |
| `backend/app/static/css/autosentinel-palette.css` | Palette presentation rules. | Palette styles. | Palette classes. | Presentation. | Palette script. | Local dashboard. | Optional presentation |
| `backend/app/static/css/autosentinel-report.css` | Structured report-viewer styles. | Report-view styles. | Report DOM. | Presentation. | Report script. | Local dashboard. | Supporting |
| `backend/app/static/autosentinel-mark.svg`, `backend/app/static/img/banner-car.jpg`, `backend/app/static/img/hero-car.jpg` | Branding/hero visual assets referenced by the template and styles. | Image assets. | Static-file serving. | Decorative dashboard imagery. | Template/CSS. | Local dashboard. | Optional presentation |
| `backend/tests/unit/test_dashboard.py` | Tests report parsing, API outputs, provenance/freshness, history behavior and HTML sanitization. | `TestDashboard` | Temporary report files and Flask test client. | Test assertions. | `unittest`, dashboard module. | Testing. | Supporting |

The dashboard does **not** capture CAN traffic or call an LLM. It reads
generated Markdown, reports parsed event and agent information, and archives
distinct report contents when report-history endpoints are accessed. It
displays recorded event counts, detection/risk summaries, an event table,
agent traces, diagnostic fields, provenance/freshness and report history.
It cannot derive total bus frames, implement an alert lifecycle or infer
missing report facts. It binds to `127.0.0.1` when run as a module.

## 10. Configuration, package markers and remaining tests

| File path | Responsibility | Main functions/classes | Input | Output | Dependencies | Execution context | Importance |
|---|---|---|---|---|---|---|---|
| `requirements.txt` | Pins Python packages used directly and packages in the current dependency set. | Package/version declarations. | `pip install -r requirements.txt`. | Python environment. | pip and package index. | Setup/testing/runtime. | Essential |
| `.env.example` | Shows the expected LLM environment-variable names without populated credentials. | `GEMINI_API_KEY`, `GEMINI_MODEL`, `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`. | Copied by a developer to a private `.env`. | Provider configuration. | Agent modules and dotenv. | Live provider setup. | Supporting |
| `.gitignore` | Excludes local environment/secrets, caches, model artifacts and generated report files. | Ignore rules. | Git status/add operations. | Prevents selected local files from normal tracking. | Git. | Maintenance. | Supporting |
| `README.md` | Existing project overview, installation and command instructions. | User-facing README. | Maintainers and users. | Project introduction. | Source tree. | Documentation. | Supporting; some history/dashboard details may lag code |
| `agents/orchestrator/__init__.py`, `agents/report_agent/__init__.py`, `backend/app/__init__.py`, `backend/app/agents/__init__.py`, `backend/app/models/__init__.py`, `backend/app/tools/__init__.py`, `backend/app/tools/mock/__init__.py`, `scripts/__init__.py`, `tools/__init__.py`, `tools/anomaly_detector/__init__.py`, `tools/can_analyzer/__init__.py`, `tools/traffic_simulator/__init__.py` | Package markers for imports and module execution. | Package namespace; no identified processing logic. | Python imports. | Importable packages. | Python. | All. | Supporting |
| `tests/test_anomaly_detector.py`, `tests/test_replay_detector.py` | Unit tests for frequency and repeated-frame rules. | Detector test cases. | Synthetic event/frame inputs. | Assertions. | `unittest`, detector modules. | Testing. | Supporting |
| `tests/test_can_benchmark.py` | Tests the fixed synthetic detector benchmark. | Benchmark test cases. | JSON fixture and detector behavior. | Assertions. | `unittest`, benchmark module. | Testing. | Supporting |
| `tests/test_traffic_simulator.py` | Tests simulator generation and CSV behavior. | Simulator test cases. | Synthetic parameters and temporary files. | Assertions. | `unittest`, simulator. | Testing. | Supporting |
| `tests/test_evaluate_rules.py`, `tests/test_evaluate_ml.py` | Tests synthetic offline evaluator helpers. | Evaluation test cases. | Deterministic values and generated fixture traffic. | Assertions. | `unittest`, scripts. | Testing. | Supporting |
| `tests/test_security_agent.py`, `tests/test_diagnostic_agent.py`, `tests/test_openrouter_provider.py` | Tests provider and agent contracts with mocks, not live API calls. | Agent/provider test cases. | Mock events and HTTP/SDK responses. | Assertions. | `unittest`, agents/provider. | Testing. | Supporting |
| `tests/test_orchestrator.py`, `tests/test_report_agent.py`, `tests/test_main_ml.py` | Tests workflow, reporting and main ML integration. | Integration/unit test cases. | Mocked services and detector inputs. | Assertions and temporary output files. | `unittest`, application modules. | Testing. | Supporting |
| `tests/test_hcrl_training.py`, `tests/test_hcrl_demo.py`, `tests/test_verify_hcrl_artifacts.py` | Tests the local HCRL pipeline and artifact verifier. | HCRL test cases. | Fixtures and temporary artifacts. | Assertions. | `unittest`, HCRL scripts. | Testing. | Supporting |

Data files under `reports/` are generated or retained run outputs, not source
modules. Their status and cleanup decisions are described in
`CLEANUP_REPORT.md`.

## End-to-end execution flow

1. A sender produces CAN frames. It may be an external simulator process
   transmitting to `vcan0`, or `main.py --source simulated`, which generates
   records in memory without a CAN interface.
2. For the live `vcan0` source, `main.py` calls the analyzer to receive
   messages for five seconds by default. For the simulated source, it creates
   a 60-second synthetic capture. These are separate source modes.
3. Rules count frames per CAN ID and check consecutive identical frames.
   When ML is selected, `main.py` converts messages into time-relative
   `CanRecord` values, extracts one-second per-ID feature vectors and invokes
   either the default synthetic-trained model or the explicitly selected HCRL
   model.
4. An anomalous detector result becomes a `SecurityEvent` carrying measured
   values, evidence, provenance and ML metadata where applicable.
5. `main.py` calls `run_workflow` for each anomalous event. LangGraph runs the
   Security Agent, Diagnostic Agent and Report Agent in sequence.
6. Each interpreting agent retrieves local BM25 passages. Gemini is tried
   first when configured, then OpenRouter. The Diagnostic Agent has its own
   evidence-based fallback; the orchestrator supplies a safe unknown security
   assessment if the Security Agent fails.
7. The Report Agent formats the event and agent results as Markdown. Main
   combines the reports from that invocation and writes
   `reports/security_report.md` once.
8. The dashboard reads that Markdown and any archived report files. It does
   not re-run detection or agent analysis.

The **HCRL training/evaluation flow is separate**: parse the five local
captures; fit on only the first chronological 70% of normal traffic; serialize
to `models/hcrl_ml_detector.joblib`; score the normal tail and four attack
captures; write `reports/hcrl_ml_evaluation.md`. The optional demo loads that
model without retraining, evaluates normal/Gear/DoS subsets, may route one
eligible Gear event through LangGraph, and writes under
`reports/hcrl_benchmark/`.
