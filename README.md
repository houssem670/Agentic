<p align="center"><img src="backend/app/static/autosentinel-mark.svg" width="54" alt="AutoSentinel AI shield and network mark"></p>

# AutoSentinel AI

**Agentic AI for Automotive CAN Security**

An AI-assisted automotive cybersecurity platform for detecting suspicious CAN bus traffic, assessing potential threats, supporting diagnostics, and generating structured security reports.

AutoSentinel AI is the project's original product identity. It is an educational project name and does not imply a company, customer, certification, automotive manufacturer, vendor, or partnership endorsement.

## Overview

This project combines deterministic CAN traffic analysis with LLM-assisted security assessment. The detection layer identifies suspicious patterns, while AI agents help interpret the evidence and organize diagnostic findings.

The project is designed for **controlled experiments on a virtual CAN interface (`vcan0`)**, not for deployment on a real vehicle.

## Key Features

- **CAN traffic analysis:** analyzes traffic over configurable time windows.
- **Frequency anomaly detection:** identifies traffic rates exceeding a configurable threshold.
- **Replay-suspicion detection:** flags rapid repetitions of identical consecutive CAN frames.
- **Security Agent:** uses Google Gemini as the primary LLM and Ollama as a fallback.
- **Retrieval-Augmented Generation (RAG):** retrieves relevant automotive security and diagnostic knowledge.
- **Diagnostic Agent:** produces structured diagnostic findings and records uncertainties.
- **Report Agent:** generates Markdown security reports.
- **Orchestration:** coordinates agent execution and handles failures.
- **Automated tests:** validates detector behavior, fallback handling, orchestration, and reporting.

> Repeated CAN frames are an indicator for investigation, not proof of a malicious replay attack.

## Architecture

```text
Virtual CAN traffic (vcan0)
            |
            v
     CAN Traffic Analyzer
            |
            v
   Deterministic Detectors
   - Frequency anomalies
   - Replay suspicion
            |
            v
       Security Agent
       /            \
   Gemini          Ollama
            |
            v
      RAG Knowledge Base
            |
            v
      Diagnostic Agent
            |
            v
        Report Agent
            |
            v
   Markdown Security Report
```

`main.py` captures traffic and runs deterministic detection, then sends each anomalous event through the LangGraph workflow in `agents/orchestrator/orchestrator.py`. The graph runs the Security, Diagnostic, and Report nodes once per event. `main.py` combines returned reports and saves them once, so batch runs do not overwrite the report for each event. Gemini is tried when configured, with Ollama as the documented provider fallback; if both diagnostic providers fail or return invalid output, the diagnostic result contains only captured evidence, unknowns, and safe checks.

## Technology Stack

- Python
- Linux and SocketCAN
- `python-can` and `can-utils`
- Google Gemini API
- Ollama
- LangChain
- LangGraph
- Retrieval-Augmented Generation (RAG)
- Unit testing with `unittest`

## Requirements

- Python 3.12 recommended
- Linux or WSL2 with Ubuntu
- SocketCAN utilities (`can-utils`)
- A virtual CAN interface (`vcan0`)
- Ollama with the `llama3.2:3b` model
- A Gemini API key for the primary LLM (optional if using Ollama only)

## Installation

Clone the repository and enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd agentic-automotive-security
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Install `can-utils` if needed:

```bash
sudo apt update
sudo apt install can-utils
```

## Virtual CAN Setup

Load the required kernel modules and create a virtual CAN interface:

```bash
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

If `vcan0` already exists, skip the `ip link add` command.

Verify the interface:

```bash
ip link show vcan0
```

**Safety:** use only virtual CAN interfaces and synthetic traffic during development. Do not connect experimental detection or replay scripts to a real vehicle.

## Configuration

Create a local `.env` file:

```bash
cp .env.example .env
```

Configure the required variables:

```dotenv
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

Keep `.env` private. Never commit API keys or other secrets. If no Gemini key is configured, the Security Agent can use the configured Ollama fallback.

Install and start Ollama separately, then download the model:

```bash
ollama pull llama3.2:3b
```

## Running the Project

Activate the virtual environment and run:

```bash
python main.py
```

The application analyzes CAN traffic and processes detected anomalies through the LangGraph workflow. Generated reports are saved locally under `reports/`. This command requires an available `vcan0`; it is not a dashboard-only command.

For meaningful results, send synthetic test traffic through `vcan0` while the analyzer is running.

## Running Tests

Run the complete unit test suite:

```bash
python -m unittest discover -s tests -v
```

The root test suite covers frequency and replay detection, malformed CAN inputs, the synthetic benchmark, graph-backed `main.py` routing, mocked Security/Diagnostic Agent provider behavior, and report generation. Dashboard/API tests are run separately as documented in the Dashboard section. Agent tests mock provider calls; they do not require API credentials or a running Ollama service.

Run the deterministic synthetic detector benchmark:

```bash
python -m tools.anomaly_detector.benchmark
```

The benchmark prints expected and actual labels, invalid-input outcomes, and binary metrics for its small fixed synthetic cases. These metrics verify implementation behavior against those fixtures only; they do not estimate performance on real vehicle traffic. Thresholds are not changed by the benchmark.

## Dashboard

The local dashboard reads `reports/security_report.md` and does not start a CAN capture, rerun an analysis, or call an LLM. It extracts event and agent fields from report blocks already present in that file. Reports identify data provenance as `LIVE_CAPTURE`, `SYNTHETIC_TEST_FIXTURE`, or `UNSPECIFIED`; mixed files are labeled `MIXED`. Legacy test markers are treated as synthetic, and missing provenance is never assumed to be live. Reports with a recorded generation time older than 24 hours are marked stale. The current application does not persist a separate event history, so dashboard counts cover only report records currently available; older runs overwritten by `main.py` cannot be recovered. Historical trend charts remain unavailable until event history exists. Missing report fields remain unavailable rather than being inferred.

If a report has no parseable generation time, freshness is shown as unknown rather than inferred from the current time. A current generation timestamp does not prove that its underlying CAN data is live; use the provenance label as well.

Install the dashboard dependencies in the project environment:

```bash
python -m pip install -r requirements.txt
```

Start the dashboard from the project root:

```bash
python -m backend.app.dashboard
```

Open <http://127.0.0.1:5000>. The server binds to loopback only. Run `python main.py` separately when you want to capture CAN traffic and generate a new report; refreshing the dashboard only reloads existing files. An alternate report file can be configured with `SECURITY_REPORT_PATH` before starting the dashboard.

For historical analysis, the smallest non-invasive extension would be an append-only `reports/events.jsonl` file with one structured event/assessment/diagnostic record per report entry, including event and generation timestamps. The dashboard could read that file without changing detector or agent behavior; no historical records are synthesized or backfilled from the latest report.

Run dashboard API and report-parser tests with:

```bash
python -m unittest backend.tests.unit.test_dashboard -v
```

### Dashboard screenshots

Start the dashboard from the project root with `python -m backend.app.dashboard`, open <http://127.0.0.1:5000>, and use the browser's screenshot or operating-system capture tool. Keep the synthetic/live provenance badge and freshness label in frame, and do not present the current synthetic fixture as live vehicle data. Never include `.env` contents, API keys, or credentials in screenshots.

## Limitations

- A replay-suspicion alert does not establish attacker intent.
- LLM-generated assessments depend on model output and available evidence.
- Diagnostic results are advisory and should not be treated as confirmed root causes unless explicitly supported by evidence.
- This is a research and educational prototype, not a production automotive security system.

## Future Improvements

- Expand the CAN dataset with normal and attack scenarios.
- Add integration tests using synthetic SocketCAN traffic.
- Improve event correlation across CAN identifiers and time windows.
- Persist structured event records for cross-run correlation and trends.
- Evaluate detection precision and false-positive rates against labeled datasets.

## Simulation et évaluation

- `tools/traffic_simulator` génère des trames CAN synthétiques reproductibles, étiquetées normales ou comme flooding, replay, spoofing et fuzzing.
- En mode hors ligne, il produit un fichier horodaté sans utiliser `vcan0`.
- Le détecteur non supervisé Isolation Forest utilise un modèle par CAN ID, entraîné uniquement sur du trafic normal.
- Générer 180 s de trafic : `python -m tools.traffic_simulator.simulator --mode offline --duration 180 --seed 42 --output reports/can_traffic.csv --attacks flooding,replay,spoofing,fuzzing`.
- Évaluer les règles : `python -m scripts.evaluate_rules`.
- Évaluer les règles, le ML et leur combinaison OU : `python -m scripts.evaluate_ml --seeds 42,43,44,45,46`.
- Exécuter ces commandes depuis la racine du dépôt.

## Résultats et limites

Moyenne ± écart-type sur 5 scénarios simulés de 180 s, avec un entraînement sur 300 s de trafic normal :

| Détecteur | Précision | Recall | F1 | Faux positifs |
|---|---|---|---|---|
| Règles seules | 0.476 ± 0.008 | 0.835 ± 0.025 | 0.606 ± 0.010 | 0.263 ± 0.010 |
| ML seul (Isolation Forest) | 0.891 ± 0.045 | 0.950 ± 0.052 | 0.918 ± 0.030 | 0.034 ± 0.017 |
| Règles + ML (OU) | 0.498 ± 0.014 | 1.000 ± 0.000 | 0.665 ± 0.013 | 0.289 ± 0.017 |

### Limites

- Les données d'entraînement et de test sont synthétiques et proviennent du même simulateur.
- Le spoofing simulé se distingue en partie par sa fréquence ; il est donc plus facile à détecter qu'un spoofing réaliste.
- Chaque scénario comporte 40 fenêtres d'attaque.
- Aucune validation n'a été effectuée sur un jeu de données public (HCRL Car-Hacking, ROAD) ni sur un véhicule réel.
- Le seuil fixe des règles, 100 msg/s, correspond à la cadence d'un ID légitime, ce qui explique les faux positifs.
- La combinaison des règles et du ML en OU dégrade la précision.

### Prochaines étapes

Évaluer le détecteur sur HCRL ou ROAD et simuler un spoofing plus réaliste.

## Disclaimer

This project is intended for education and authorized security research in isolated test environments. Use virtual CAN interfaces and simulated traffic only.

## Author

**Houssem Fkih**
Telecommunications Engineering — Automotive Networking and Embedded Systems