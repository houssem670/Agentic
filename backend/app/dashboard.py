from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bleach
import markdown
from flask import Flask, jsonify, render_template, request, send_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_PATH = PROJECT_ROOT / "reports" / "security_report.md"
RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
RISK_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DATA_PROVENANCE_VALUES = {
    "LIVE_CAPTURE",
    "SYNTHETIC_TEST_FIXTURE",
    "UNSPECIFIED",
}
REPORT_STALE_AFTER_HOURS = 24
ALLOWED_HTML_TAGS = set(bleach.sanitizer.ALLOWED_TAGS).union(
    {
        "h1", "h2", "h3", "h4", "p", "hr", "br", "pre", "code",
        "blockquote", "ul", "ol", "li", "table", "thead", "tbody",
        "tr", "th", "td",
    }
)


def _sections(block: str) -> dict[str, str]:
    headings = list(re.finditer(r"(?m)^##\s+(.+?)\s*$", block))
    result: dict[str, str] = {}
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(block)
        title = re.sub(r"^\d+\.\s*", "", heading.group(1)).strip().lower()
        result[title] = block[heading.end():end]
    return result


def _table(section: str) -> dict[str, str]:
    lines = section.splitlines()
    for index, line in enumerate(lines[:-1]):
        if not line.strip().startswith("|") or not lines[index + 1].strip().startswith("|"):
            continue
        headers = [cell.strip() for cell in line.strip().strip("|").split("|")]
        separator = [cell.strip() for cell in lines[index + 1].strip().strip("|").split("|")]
        if not separator or not all(re.fullmatch(r":?-{3,}:?", cell) for cell in separator):
            continue
        values: dict[str, str] = {}
        for row in lines[index + 2:]:
            if not row.strip().startswith("|"):
                break
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            if len(cells) >= 2 and len(headers) >= 2:
                values[cells[0]] = cells[1]
        return values
    return {}


def _agent_trace(section: str) -> list[dict[str, Any]]:
    lines = section.splitlines()
    rows = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 4 or all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        if cells[0].lower() == "agent":
            continue
        try:
            duration_ms = float(cells[2])
        except ValueError:
            continue
        rows.append({
            "agent": cells[0],
            "status": cells[1],
            "duration_ms": duration_ms,
            "error_type": None if cells[3] == "Not recorded" else cells[3],
        })
    return rows


def _subsection(block: str, title: str) -> str:
    match = re.search(
        rf"(?ms)^###\s+{re.escape(title)}\s*\n(.*?)(?=^###\s+|^##\s+|\Z)",
        block,
    )
    return match.group(1).strip() if match else ""


def _list_items(value: str) -> list[str]:
    items = [re.sub(r"^\s*[-*+]\s+", "", line).strip() for line in value.splitlines()]
    items = [item for item in items if item and item.lower() != "none provided"]
    return [] if items == ["None provided"] else items


def _number(value: str | None) -> float | None:
    if not value:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", value.replace(",", ""))
    return float(match.group()) if match else None


def _confidence(value: str | None) -> float | None:
    if not value or value.strip().lower() in {"not available", "unknown"}:
        return None
    number = _number(value)
    if number is None:
        return None
    if "%" in value:
        number /= 100
    return number if 0 <= number <= 1 else None


def _record(block: str) -> dict[str, Any] | None:
    sections = _sections(block)
    info = _table(sections.get("report information", ""))
    evidence = _table(sections.get("detection evidence", ""))
    assessment = _table(sections.get("security assessment", ""))
    diagnostic = _table(sections.get("diagnostic analysis", ""))

    event_id = info.get("Event ID")
    if not event_id or "CAN ID" not in info:
        return None

    risk = assessment.get("Assessed risk level")
    risk = risk.upper() if risk and risk.upper() in RISK_LEVELS else None
    anomaly = evidence.get("Anomaly flagged", "").strip().lower()
    provenance = info.get("Data provenance", "").strip().upper()
    test_markers = ("TEST-", "MOCK-")
    is_synthetic = (
        event_id.upper().startswith(test_markers)
        or diagnostic.get("Analysis method", "").upper()
        in {"MOCK", "MOCK_TEST", "SYNTHETIC"}
        or "test synthétique" in sections.get("executive summary", "").lower()
    )
    if is_synthetic:
        provenance = "SYNTHETIC_TEST_FIXTURE"
    elif provenance not in DATA_PROVENANCE_VALUES:
        provenance = "UNSPECIFIED"
    return {
        "event_id": event_id,
        "scenario_id": info.get("Scenario ID") or None,
        "data_provenance": provenance,
        "timestamp": info.get("Event timestamp"),
        "can_id": info.get("CAN ID"),
        "channel": info.get("CAN interface"),
        "detection_rule": info.get("Detection rule"),
        "event_type": evidence.get("Event type"),
        "attack_type": evidence.get("Detector attack label"),
        "anomaly": anomaly == "true" if anomaly in {"true", "false"} else None,
        "message_count": _number(evidence.get("Message count")),
        "window_seconds": _number(evidence.get("Observation duration")),
        "observed_rate": _number(evidence.get("Observed rate")),
        "threshold": _number(evidence.get("Detector threshold")),
        "evidence": _list_items(_subsection(block, "Evidence recorded by the detector")),
        "generated_at": info.get("Generated at"),
        "execution_errors": _list_items(sections.get("orchestrator errors and limitations", "")),
        "workflow_provenance": (
            "LangGraph workflow (recorded execution trace)"
            if sections.get("agent execution trace")
            else "LangGraph orchestrator (recorded error section)"
            if "orchestrator errors and limitations" in sections
            else None
        ),
        "agent_trace": _agent_trace(sections.get("agent execution trace", "")),
        "security": {
            "threat_type": assessment.get("Threat classification"),
            "risk_level": risk,
            "confidence": _confidence(assessment.get("Assessment confidence")),
            "summary": sections.get("executive summary", "").strip(),
            "observed_facts": _list_items(_subsection(block, "Observed facts")),
            "interpretation": _subsection(block, "Security interpretation"),
            "unknowns": _list_items(_subsection(block, "Unknowns and limitations")),
            "investigation_steps": _list_items(_subsection(block, "Recommended investigation steps")),
            "mitigation_actions": _list_items(_subsection(block, "Recommended defensive actions")),
        },
        "diagnostic": {
            "event_id": diagnostic.get("Diagnostic event ID"),
            "summary": _subsection(block, "Diagnostic summary"),
            "analysis_method": diagnostic.get("Analysis method"),
            "confidence": _confidence(diagnostic.get("Diagnostic confidence")),
            "root_cause_confirmed": (
                diagnostic.get("Root cause confirmed", "").strip().lower() == "true"
                if diagnostic.get("Root cause confirmed", "").strip().lower() in {"true", "false"}
                else None
            ),
            "probable_causes": _list_items(_subsection(block, "Probable causes — hypotheses, not confirmed facts")),
            "supporting_evidence": _list_items(_subsection(block, "Supporting evidence")),
            "unknowns": _list_items(_subsection(block, "Diagnostic unknowns")),
            "recommended_checks": _list_items(_subsection(block, "Recommended diagnostic checks")),
        },
        "report_markdown": block.strip(),
    }


def parse_report(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract event and agent fields from the Report Agent's Markdown output."""
    blocks = [part.strip() for part in re.split(r"(?m)^\s*---+\s*$", text) if part.strip()]
    records: list[dict[str, Any]] = []
    invalid: list[str] = []
    for block in blocks:
        if not block.startswith("# Automotive CAN Security Report"):
            continue
        record = _record(block)
        if record is None:
            invalid.append("A report block is missing required event fields.")
        else:
            records.append(record)
    return records, invalid


def _report_path(app: Flask) -> Path:
    return Path(app.config["REPORT_PATH"])


def _load_report(app: Flask) -> tuple[str | None, list[dict[str, Any]], list[str]]:
    path = _report_path(app)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [], []
    except (OSError, UnicodeError):
        return None, [], ["The report file could not be read."]
    records, invalid = parse_report(text)
    return text, records, invalid


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or value.lower() in {"unknown", "not available"}:
        return None
    try:
        return datetime.fromisoformat(value.replace(" UTC", "+00:00"))
    except ValueError:
        return None


def _latest_timestamp(records: list[dict[str, Any]], field: str) -> str | None:
    dated = [
        (record.get(field), _parse_timestamp(record.get(field)))
        for record in records
    ]
    valid = [(value, parsed) for value, parsed in dated if value and parsed]
    return max(valid, key=lambda item: item[1])[0] if valid else None


def _report_freshness(generated_at: str | None) -> dict[str, Any]:
    generated = _parse_timestamp(generated_at)
    if generated is None:
        return {"state": "unknown", "age_hours": None, "threshold_hours": REPORT_STALE_AFTER_HOURS}
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    age_seconds = max((datetime.now(timezone.utc) - generated).total_seconds(), 0)
    age_hours = round(age_seconds / 3600, 1)
    state = "stale" if age_seconds > REPORT_STALE_AFTER_HOURS * 3600 else "current"
    return {"state": state, "age_hours": age_hours, "threshold_hours": REPORT_STALE_AFTER_HOURS}


def _report_provenance(records: list[dict[str, Any]]) -> str:
    values = {record["data_provenance"] for record in records}
    if not values:
        return "UNSPECIFIED"
    return values.pop() if len(values) == 1 else "MIXED"


def _render_markdown(text: str) -> str:
    rendered = markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "sane_lists"],
    )
    return bleach.clean(
        rendered,
        tags=ALLOWED_HTML_TAGS,
        attributes={"a": ["href", "title"], "th": ["align"], "td": ["align"]},
        protocols={"http", "https", "mailto"},
        strip=True,
    )


# ---------------------------------------------------------------------------
# History: every report file in the reports folder (and reports/history/)
# ---------------------------------------------------------------------------

def _report_files(app: Flask) -> list[Path]:
    """Current report first, then archived reports (newest file name first)."""
    main = _report_path(app)
    folder = main.parent
    candidates: list[Path] = [main] if main.is_file() else []
    for directory in (folder / "history", folder):
        if directory.is_dir():
            candidates.extend(sorted(directory.glob("*.md"), reverse=True))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def _archive_current_report(app: Flask) -> None:
    """Keep a copy of the current report in reports/history/ when its content is new.

    The Report Agent may overwrite security_report.md on every run. Copying each new
    version means earlier analyses stay available. The copy is idempotent: identical
    content is never archived twice.
    """
    main = _report_path(app)
    if not main.is_file():
        return
    try:
        data = main.read_bytes()
        if b"# Automotive CAN Security Report" not in data:
            return
        digest = hashlib.sha256(data).hexdigest()
        history = main.parent / "history"
        if history.is_dir():
            for existing in history.glob("*.md"):
                if hashlib.sha256(existing.read_bytes()).hexdigest() == digest:
                    return
        history.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        (history / f"security_report_{stamp}.md").write_bytes(data)
    except OSError:
        return


def _load_history(app: Flask) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Path]]:
    """Return (all unique records, report list, report id -> path)."""
    _archive_current_report(app)
    folder = _report_path(app).parent
    records: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    paths: dict[str, Path] = {}
    seen_hashes: set[str] = set()
    seen_keys: set[tuple[Any, ...]] = set()

    for path in _report_files(app):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        file_records, _ = parse_report(text)
        if not file_records:
            continue

        try:
            report_id = path.resolve().relative_to(folder.resolve()).as_posix()
        except ValueError:
            report_id = path.name
        paths[report_id] = path

        fresh = [
            record for record in file_records
            if (record["event_id"], record.get("timestamp"), record.get("generated_at")) not in seen_keys
        ]
        seen_keys.update(
            (record["event_id"], record.get("timestamp"), record.get("generated_at"))
            for record in file_records
        )
        for record in fresh:
            record["source_report"] = report_id
        records.extend(fresh)

        generated_at = _latest_timestamp(file_records, "generated_at")
        risks = [r["security"]["risk_level"] for r in file_records if r["security"].get("risk_level")]
        reports.append({
            "id": report_id,
            "file_name": path.name,
            "generated_at": generated_at,
            "record_count": len(file_records),
            "highest_risk": max(risks, key=lambda level: RISK_RANK.get(level, 0)) if risks else None,
            "data_provenance": _report_provenance(file_records),
            "freshness": _report_freshness(generated_at)["state"],
        })

    floor = datetime.min.replace(tzinfo=timezone.utc)

    def sort_key(report: dict[str, Any]) -> datetime:
        parsed = _parse_timestamp(report["generated_at"])
        if parsed is None:
            return floor
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    reports.sort(key=sort_key, reverse=True)
    return records, reports, paths


def create_app(report_path: str | Path | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["REPORT_PATH"] = Path(
        report_path or os.getenv("SECURITY_REPORT_PATH", DEFAULT_REPORT_PATH)
    )

    @app.after_request
    def no_store(response):
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/api/health")
    def health():
        text, records, invalid = _load_report(app)
        generated_at = _latest_timestamp(records, "generated_at")
        return jsonify({
            "status": "ok",
            "report_available": text is not None,
            "parseable_report_records": len(records),
            "invalid_report_blocks": len(invalid),
            "report_freshness": _report_freshness(generated_at),
            "data_provenance": _report_provenance(records),
        })

    @app.get("/api/events")
    def events():
        records, _, _ = _load_history(app)
        return jsonify({"events": [{key: value for key, value in record.items() if key != "report_markdown"} for record in records]})

    @app.get("/api/summary")
    def summary():
        records, reports, _ = _load_history(app)
        rules = Counter(record.get("detection_rule") for record in records if record.get("detection_rule"))
        risks = Counter(record["security"]["risk_level"] for record in records if record["security"].get("risk_level"))
        types = Counter(record.get("attack_type") or record.get("event_type") for record in records if record.get("attack_type") or record.get("event_type"))
        frequency_count = sum(1 for record in records if record.get("detection_rule") == "FREQUENCY_THRESHOLD")
        replay_count = sum(1 for record in records if record.get("detection_rule") == "CONSECUTIVE_FRAME_REPETITION" or record.get("attack_type") == "REPLAY_SUSPECTED")
        return jsonify({
            "total_security_events": len(records),
            "frequency_anomalies": frequency_count,
            "replay_suspicions": replay_count,
            "risk_levels": dict(risks),
            "event_types": dict(types),
            "reports_in_latest_file": len(records),
            "report_files": len(reports),
            "latest_analysis_timestamp": _latest_timestamp(records, "timestamp"),
            "latest_report_timestamp": _latest_timestamp(records, "generated_at"),
            "detection_rules": dict(rules),
            "history_available": len(records) > 1,
            "data_provenance": _report_provenance(records),
            "statistics_scope": "All parseable report records found in the reports folder and its history archive.",
        })

    @app.get("/api/reports")
    def report_list():
        _, reports, _ = _load_history(app)
        return jsonify({"reports": reports})

    @app.get("/api/report")
    def report_by_id():
        _, reports, paths = _load_history(app)
        report_id = request.args.get("id", "")
        path = paths.get(report_id)
        if path is None:
            return jsonify({"available": False, "error": "Unknown report."}), 404
        meta = next((report for report in reports if report["id"] == report_id), {})
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return jsonify({"available": False, "error": "The report could not be read."}), 404
        return jsonify({
            "available": True,
            "id": report_id,
            "html": _render_markdown(text),
            "generated_at": meta.get("generated_at"),
            "record_count": meta.get("record_count", 0),
        })

    @app.get("/api/report/download")
    def download_report_by_id():
        _, _, paths = _load_history(app)
        path = paths.get(request.args.get("id", ""))
        if path is None or not path.is_file():
            return jsonify({"error": "Unknown report."}), 404
        return send_file(path, as_attachment=True, download_name=path.name, mimetype="text/markdown")

    @app.get("/api/reports/latest")
    def latest_report():
        text, records, _ = _load_report(app)
        if text is None:
            return jsonify({
                "available": False,
                "html": "",
                "generated_at": None,
                "freshness": _report_freshness(None),
                "record_count": 0,
                "data_provenance": "UNSPECIFIED",
            })
        generated_at = _latest_timestamp(records, "generated_at")
        return jsonify({
            "available": True,
            "html": _render_markdown(text),
            "generated_at": generated_at,
            "freshness": _report_freshness(generated_at),
            "record_count": len(records),
            "data_provenance": _report_provenance(records),
        })

    @app.get("/api/reports/latest/download")
    def download_report():
        path = _report_path(app)
        if not path.is_file():
            return jsonify({"error": "No report is currently available."}), 404
        return send_file(path, as_attachment=True, download_name="security_report.md", mimetype="text/markdown")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)