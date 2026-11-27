# AutoSentinel AI: Project Execution Guide

This guide reflects the current command-line interfaces. Commands that write
models or reports are called out explicitly. Run all commands from the
repository root.

## 1. Environment and dependencies

The README recommends Python 3.12 and Linux or Ubuntu under WSL2 for SocketCAN.
Create a virtual environment and install the pinned dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install Linux CAN utilities if needed:

```bash
sudo apt update
sudo apt install can-utils
```

`can-utils` is a system package; `python-can` is installed from
`requirements.txt`.

## 2. Provider configuration

Make a private local environment file:

```bash
cp .env.example .env
```

Configure these existing variable names in `.env` as needed:

```dotenv
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash
OPENROUTER_API_KEY=
OPENROUTER_MODEL=inclusionai/ling-3.2-flash:free
```

The application tries Gemini first when configured and then OpenRouter.
The agents can return their fallback/error behavior if no provider returns
valid data. Never commit `.env` or paste credentials into reports.

The simulator, deterministic detector tests, offline synthetic evaluation,
HCRL training, HCRL demo in mock mode, verifier, and dashboard can be used
without making an LLM request. The live LangGraph interpretation may call the
configured provider endpoints.

## 3. Configure virtual CAN (Linux/WSL2)

Create and enable a virtual CAN interface:

```bash
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
ip link show vcan0
```

If `vcan0` already exists, skip the `ip link add` command. These commands
require a Linux environment with SocketCAN. A Windows Python environment alone
does not provide this Linux interface.

Only use `vcan0` and synthetic traffic for development. Do not connect
experimental scripts to a real vehicle.

## 4. Generate synthetic traffic

Create an offline CSV without SocketCAN:

```bash
python -m tools.traffic_simulator.simulator \
  --mode offline \
  --duration 180 \
  --seed 42 \
  --output reports/can_traffic.csv \
  --attacks flooding,replay,spoofing,fuzzing
```

The simulator's CLI defaults to offline mode, ten seconds, seed zero, and
`can_traffic.csv`. Supported attack labels are `flooding`, `replay`,
`spoofing`, and `fuzzing`; an empty `--attacks` value produces normal traffic.

To emit traffic to `vcan0` in a separate process:

```bash
python -m tools.traffic_simulator.simulator \
  --mode live \
  --duration 10 \
  --seed 42 \
  --attacks flooding,replay,spoofing,fuzzing
```

Start the application listener while that process is sending. For a
non-SocketCAN demonstration, `main.py --source simulated` generates its own
in-memory 60-second simulation; it does not transmit on or capture from
`vcan0`.

## 5. Run the application

Default behavior: capture five seconds from `vcan0` and run the deterministic
rules:

```bash
python main.py
```

Explicit CLI selections:

```bash
python main.py --detector rules --source vcan0
python main.py --detector ml --source vcan0 --ml-model default
python main.py --detector both --source vcan0 --ml-model default
python main.py --detector rules --source simulated
python main.py --detector both --source simulated --ml-model default
```

Valid `--detector` values are `rules`, `ml`, and `both`; valid `--source`
values are `vcan0` and `simulated`. The default ML model is
`models/ml_detector.joblib`; if it does not exist, the application trains it
from 300 seconds of generated normal traffic. The HCRL model is only used when
selected explicitly:

```bash
python main.py --detector ml --source vcan0 --ml-model hcrl
```

This requires an existing valid `models/hcrl_ml_detector.joblib`. The
application will not fall back to the default model or train an HCRL model.
Anomalies can trigger provider requests and the report file
`reports/security_report.md` can be overwritten by a new run. Use mock tests
or offline evaluation if you do not want provider calls or report writes.

## 6. Synthetic evaluations (not HCRL)

Run the fixed rules benchmark:

```bash
python -m tools.anomaly_detector.benchmark
```

It reads the hand-authored fixture at
`data/benchmarks/can_detection_scenarios.json` and prints per-scenario
outcomes. It does not write a report file.

Generate the longer synthetic rule evaluation:

```bash
python -m scripts.evaluate_rules
```

This writes `reports/evaluation_rules.md`.

Compare rules, ML and their OR-combination over the default five seeds:

```bash
python -m scripts.evaluate_ml
```

Choose a different seed list:

```bash
python -m scripts.evaluate_ml --seeds 42,43,44,45,46
```

This command trains an in-memory detector on synthetic normal traffic and
writes `reports/evaluation_comparison.md`. These synthetic metrics do not
measure HCRL or real-vehicle performance.

## 7. HCRL dataset verification and training

The HCRL commands expect these files under `datasets/hcrl/`:

```text
normal_run_data.txt
gear_dataset.csv
DoS_dataset.csv
Fuzzy_dataset.csv
RPM_dataset.csv
```

Calculate fingerprints without changing inputs:

```bash
python -m scripts.verify_hcrl_artifacts
```

The hashes are not proof of authenticity unless checked against a trusted
manifest obtained separately:

```bash
python -m scripts.verify_hcrl_artifacts --manifest trusted-hcrl-sha256.json
```

Train and evaluate the HCRL detector:

```bash
python -m scripts.train_evaluate_hcrl
```

This command **writes/replaces**
`models/hcrl_ml_detector.joblib` and
`reports/hcrl_ml_evaluation.md`. It parses all five captures, fits only on the
first chronological 70% of normal traffic, and evaluates the normal tail plus
the four attack captures. Do not run it just to inspect or replay the current
model. Optional CLI arguments are `--data-dir`, `--model-path`,
`--report-path`, and `--train-fraction`.

## 8. Offline HCRL demonstration

Replay the existing model with stubbed Security/Diagnostic providers:

```bash
python -m scripts.demo_hcrl_pipeline --agent-mode mock
```

The demo loads the model without retraining. It uses normal, Gear and DoS
captures; at most one qualifying known-ID Gear event is routed through
LangGraph. DoS unseen-ID traffic is reported as novelty for review. It does
not need `vcan0`, `can-utils` or API credentials in mock mode.

By default it writes `reports/hcrl_benchmark/demo_report.md` and
`reports/hcrl_benchmark/results.json`. To preserve existing outputs during a
trial, direct both files to a temporary directory:

```bash
python -m scripts.demo_hcrl_pipeline \
  --agent-mode mock \
  --report-path "$TMPDIR/autosentinel-demo.md" \
  --results-path "$TMPDIR/autosentinel-demo.json"
```

On Windows PowerShell, set the two output arguments to a new temporary folder
using PowerShell's `$env:TEMP` path. The Python CLI accepts `--data-dir`,
`--report-path`, `--results-path`, and `--agent-mode {mock,live}`. Live mode
may contact configured LLM providers for the selected event.

## 9. Run tests and inspect imports

Run the root unit tests:

```bash
python -m unittest discover -s tests -v
```

Run dashboard tests:

```bash
python -m unittest backend.tests.unit.test_dashboard -v
```

Check Python imports without starting capture or calling APIs:

```bash
python -c "import main; import agents.orchestrator.orchestrator; import backend.app.dashboard; import scripts.train_evaluate_hcrl; import scripts.demo_hcrl_pipeline; print('imports OK')"
```

Inspect application and HCRL CLI options without running pipelines:

```bash
python main.py --help
python -m scripts.train_evaluate_hcrl --help
python -m scripts.demo_hcrl_pipeline --help
python -m scripts.verify_hcrl_artifacts --help
python -m tools.traffic_simulator.simulator --help
python -m scripts.evaluate_ml --help
```

The training help command does not train or overwrite the model. Do not use
the training command as a validation shortcut when preserving the existing
model is required.

## 10. Launch the dashboard

Start the report-backed local Flask dashboard:

```bash
python -m backend.app.dashboard
```

Open <http://127.0.0.1:5000>. It reads the existing report; it does not start
CAN capture, run detectors, or call an LLM. The default path is
`reports/security_report.md`; an alternate path can be set before launch:

```bash
export SECURITY_REPORT_PATH=/path/to/security_report.md
python -m backend.app.dashboard
```

The server binds to loopback (`127.0.0.1`). API test routes include `/api/health`,
`/api/events`, `/api/summary`, `/api/reports`, `/api/reports/latest` and report
download endpoints. The dashboard also archives distinct report content under
`reports/history/` when report-history APIs are accessed.

## Outputs and limitations

| Command | Main output | Overwrites existing output? |
|---|---|---|
| `python main.py` | `reports/security_report.md`; may also create `models/ml_detector.joblib` when default ML is selected and absent. | Yes, the security report; default model is created only when absent. |
| `python -m scripts.evaluate_rules` | `reports/evaluation_rules.md` | Yes |
| `python -m scripts.evaluate_ml` | `reports/evaluation_comparison.md` | Yes |
| `python -m scripts.train_evaluate_hcrl` | HCRL model and HCRL evaluation report | Yes; retrains and replaces selected outputs |
| `python -m scripts.demo_hcrl_pipeline` | HCRL demo Markdown and JSON | Yes, at the selected output paths |
| `python -m tools.anomaly_detector.benchmark` | Console output | No report file |
| `python -m scripts.verify_hcrl_artifacts` | Console hashes/status | No |

Rule-based detections are heuristics. LLM assessments are interpretations,
not measured facts. HCRL and synthetic metrics describe their specific
captures/fixtures; neither establishes production detection performance or
vehicle safety.
