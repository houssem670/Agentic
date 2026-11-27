# AutoSentinel AI: Architecture Overview

## Purpose and safety boundary

AutoSentinel AI is an educational CAN-anomaly analysis prototype. Its
deterministic detectors produce observations; optional agents interpret those
observations and assemble reports. It is intended for synthetic data and
isolated virtual CAN testing, not deployment on a real vehicle.

The codebase contains distinct traffic-generation, live-capture, synthetic
evaluation, HCRL training/evaluation and dashboard paths. In particular, the
live CAN path is not the HCRL training path.

## System components

```text
                        LIVE / SYNTHETIC APPLICATION
┌────────────────────┐       ┌─────────────────────────────┐
│ simulator process  │──────▶│ vcan0 / SocketCAN           │
│ --mode live        │       │ python-can receive          │
└────────────────────┘       └──────────────┬──────────────┘
                                             │
               ┌────────────────────────────┘
               │ or --source simulated (in-memory, no vcan0)
               ▼
┌────────────────────────────┐
│ main.py                    │
│ source + detector selection│
└──────────┬─────────────────┘
           ├─ Rules: rate threshold + repeated-frame suspicion
           └─ ML: 21 features / CAN ID / 1-second window
                         │
                         ▼
                 SecurityEvent(s)
                         │ anomalous events
                         ▼
┌──────────────────────────────────────────────────────────┐
│ LangGraph: Security Agent → Diagnostic Agent → Report    │
│ Each interpreting agent may retrieve local BM25 passages │
└───────────────────────────┬──────────────────────────────┘
                            ▼
             reports/security_report.md
                            │ read-only analysis input
                            ▼
                  Flask dashboard (loopback)

                   OFFLINE HCRL PIPELINE
┌──────────────────────────────────────────────────────────┐
│ datasets/hcrl: normal + DoS, Fuzzy, Gear, RPM captures   │
└───────────────────────────┬──────────────────────────────┘
                            ▼
       strict parser → normal-only chronological training
                            │
                            ▼
            per-ID Isolation Forest, 21 features
                            │
                ┌───────────┴────────────┐
                ▼                        ▼
     HCRL model artifact       capture-level evaluation
     models/hcrl_ml_detector   reports/hcrl_ml_evaluation.md
                │
                ▼ (optional; no retraining)
       offline benchmark demo → reports/hcrl_benchmark/
       selected known-ID Gear event → LangGraph (at most one)
       unseen-ID DoS novelty → report only, not a confirmed attack
```

## Live CAN and synthetic application flow

### 1. Frame generation and transport

`tools/traffic_simulator/simulator.py` generates a `CanRecord` sequence.
Normal traffic uses six standard CAN IDs and fixed nominal periods with
seeded timing/data variations. The supported synthetic attack labels are
flooding, replay, spoofing and fuzzing. The records contain timestamp, CAN ID,
DLC, payload bytes and a label.

There are two ways the main application can use the simulator:

- `python -m tools.traffic_simulator.simulator --mode live` sends generated
  frames on a Linux SocketCAN interface named `vcan0`. The sender and
  `main.py` listener are separate processes; the listener must be active
  during transmission.
- `python main.py --source simulated` generates a 60-second traffic sequence
  in memory and passes it directly into analysis. This does not open a CAN
  socket and does not send anything to `vcan0`.

Offline CSV generation via simulator `--mode offline` is a third mode. It is
for producing/reloading fixture data, not for socket capture.

### 2. Capture and preprocessing

With the default `--source vcan0`, `main.py` invokes
`capture_can_messages(window_seconds=5, channel="vcan0")` through
`analyze_can_traffic`. The analyzer opens a `python-can` SocketCAN bus,
collects messages until the capture duration expires, and always shuts down
the bus. `main.py` calls `analyze_can_messages` on the captured messages.

When ML is selected, `_records_from_messages` converts each message to a
`CanRecord` and subtracts the earliest message timestamp so the record timeline
starts at zero. Captured records are marked `normal` because live capture does
not include HCRL-style truth labels. This path does not decode vehicle signals.

In simulated-memory mode, `main.py` receives the simulator's `CanRecord`
objects directly. Rules are applied across twelve five-second windows in the
60-second generated sequence; the ML detector uses one-second windows.

### 3. Rule detections

`detect_frequency_anomaly` counts frames by CAN ID for the requested window.
It calculates `count / window_seconds` and flags only a strictly greater than
the configured threshold (default 100 messages/second). The resulting event
includes the measurement, threshold and evidence.

`detect_replay_attack` compares consecutive messages using CAN arbitration ID,
payload bytes and standard/extended frame format. Five identical frames
within 100 milliseconds can produce a `REPLAY_SUSPECTED` event. That is a
suspicion heuristic, not evidence of attacker intent or proof of a replay.

The analyzer also creates per-ID frequency records that are not anomalous.
`main.py` sends only anomalous events to the agent workflow.

### 4. Optional Isolation Forest detection and 21 features

For each occupied CAN-ID/time-window group, `extract_features` computes:

- `frame_count`;
- `interval_mean`, `interval_std`;
- `distinct_payloads`, `payload_entropy`;
- `byte_0_mean` through `byte_7_mean`; and
- `byte_0_std` through `byte_7_std`.

This is 21 numeric features in total. `MLAnomalyDetector` has an independent
Isolation Forest for every CAN ID observed during fitting. During prediction,
it builds the same features and scores the matching per-ID model. A CAN ID
with no trained model is returned as `unseen_can_ids`, not scored by the
Isolation Forest.

Main supports these combinations:

| Command option | Behavior |
|---|---|
| `--detector rules` | Rule path only; this is the default. |
| `--detector ml` | Isolation Forest only. |
| `--detector both` | Rule and ML events from the selected source. |
| `--ml-model default` | Load `models/ml_detector.joblib`, or create it from 300 seconds of synthetic normal traffic if it does not exist. |
| `--ml-model hcrl` | Explicitly load `models/hcrl_ml_detector.joblib`; a missing/invalid model is an error. It never silently substitutes or retrains. |

The default model and HCRL model are not interchangeable. Isolation Forest
scores are relative scores, not attack probabilities. A missing HCRL model is
not auto-trained by the application.

### 5. Event-to-agent path

`main.py` converts each ML anomaly prediction into a `SecurityEvent` with the
anomaly score, window bounds, CAN IDs, detector/model provenance and any
feature deviations. Rule-based events use the same event model and include
detector evidence/provenance.

For each anomalous event, `main.py` calls
`run_workflow(event, persist_report=False)`. The LangGraph is a fixed,
sequential graph:

1. **Security Agent:** interprets the event evidence, retrieves local context,
   tries Gemini and then OpenRouter, and returns a structured risk assessment.
   If the Security Agent cannot return valid data, the graph node records a
   safe `UNKNOWN` assessment.
2. **Diagnostic Agent:** independently retrieves local context, tries Gemini
   and then OpenRouter, validates its JSON fields, and returns hypotheses,
   unknowns and recommended checks. If neither provider returns valid data,
   it returns evidence-only fallback output. It does not confirm the vehicle
   root cause from the event alone.
3. **Report Agent:** combines event, security and diagnostic values into
   Markdown. It does not call an LLM.

Each node records a status and measured elapsed time in the execution trace.
Provider errors are represented by exception types/statuses rather than being
treated as successful analysis. Main joins the Markdown reports for the run
and writes `reports/security_report.md` once.

## Local RAG and providers

`rag/retriever.py` loads local text files from `rag/documents/`, splits them
into paragraph-like chunks, tokenizes English/French terms, expands selected
queries and calculates BM25-style lexical scores. `rag/rag_pipeline.py`
formats the top passages for agent prompts. There is no embedding model or
remote search service in this path.

The agent modules read these environment variable names:

- `GEMINI_API_KEY`, `GEMINI_MODEL`;
- `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`.

Gemini is tried first when a Gemini key is configured; OpenRouter is the
secondary provider. The OpenRouter helper sends an HTTP request with a
30-second timeout. If no provider yields valid output, Security and Diagnostic
follow their distinct fallback/error paths described above. No API key is
required for the mock-mode HCRL demo or unit tests.

## Offline HCRL training and evaluation path

This is separate from CAN live capture and separate from the synthetic
`evaluate_rules` / `evaluate_ml` scripts.

1. `scripts/train_evaluate_hcrl.py` reads the five HCRL capture files from
   `datasets/hcrl/`.
2. It validates timestamps, standard CAN IDs, DLC and payload length. It
   processes each capture independently and preserves time gaps.
3. It reads the normal capture and uses the chronological first 70% of its
   duration to generate one-second features and fit the existing per-ID
   Isolation Forest. Only normal traffic goes into fitting.
4. It serializes the fitted detector to `models/hcrl_ml_detector.joblib`.
   This training command overwrites its selected model and evaluation report
   output paths; do not run it just to inspect the current model.
5. It evaluates the remaining normal-capture tail and DoS, Fuzzy, Gear and
   RPM capture files. `R`/`T` labels provide ground truth for metrics, not
   feature values. Unknown CAN IDs are evaluated separately from the trained
   forests.
6. It writes `reports/hcrl_ml_evaluation.md`. The normal tail is from the same
   capture as training, so results are not independent-capture validation.

`scripts/demo_hcrl_pipeline.py` is an inference/replay demonstration. It loads
the existing model, checks the model's training-capture identity and CAN-ID
coverage, evaluates the normal holdout, Gear and DoS captures, then optionally
sends at most one selected known-ID Gear anomaly through LangGraph. The HCRL
truth label is kept out of the event/agent payload. DoS traffic with unseen
IDs is described as `unseen / requires review`, not as a confirmed model
detection. The default `--agent-mode mock` makes no external provider calls.
Demo outputs go to `reports/hcrl_benchmark/` by default; they do not overwrite
the trained model or HCRL training report.

`scripts/verify_hcrl_artifacts.py` computes SHA-256 hashes for the five input
files and model. Without an independently trusted manifest these values are
only fingerprints, not authenticity checks.

## Reports and dashboard

`agents/report_agent/report_agent.py` builds a Markdown report from the
structured event and agent objects. The live application writes
`reports/security_report.md`; the HCRL demo has its own report/JSON outputs.

`backend/app/dashboard.py` parses the report format, returns report-backed
event/summary/health APIs, sanitizes Markdown HTML and can serve report
downloads. When report-history APIs run, it archives new distinct content in
`reports/history/`. The HTML/JavaScript renders overview cards, event tables,
detection/risk summaries, execution traces, diagnostics, provenance/freshness,
and report history. Missing measurements remain unavailable rather than being
invented. The dashboard does not trigger a capture, detector, model training,
or LLM request; it binds to loopback by default.

## Tests and evaluation limits

The root `tests/` suite exercises synthetic detection, simulation, model
features, agent mocks, orchestration, reports and HCRL helpers. Dashboard API
and report parsing tests are under `backend/tests/unit/`. Provider tests mock
network/SDK calls; they do not certify live service availability. Synthetic
metrics and HCRL benchmark metrics apply only to their supplied fixtures and
captures. No score in these files establishes production or real-vehicle
performance.

See `PROJECT_FILE_GUIDE.md` for file responsibilities and
`PROJECT_EXECUTION_GUIDE.md` for exact commands.
