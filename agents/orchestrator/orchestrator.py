from datetime import datetime, timezone
from time import perf_counter
from typing import Any, TypedDict

from langgraph.graph import StateGraph, START, END

from models.security_event import SecurityEvent
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport

from agents.security_agent.security_agent import security_agent
from agents.diagnostic_agent.diagnostic_agent import diagnostic_agent
from agents.report_agent.report_agent import (
    generate_security_report,
    save_security_report,
)


class WorkflowState(TypedDict):
    event: SecurityEvent
    assessment: SecurityAssessment
    security_provider: str
    diagnostic: DiagnosticReport
    report: str
    report_path: str
    errors: list[str]
    persist_report: bool
    agent_trace: list[dict[str, Any]]


def _trace_entry(
    agent: str,
    status: str,
    started_at: float,
    error_type: str | None = None,
) -> dict[str, Any]:
    entry = {
        "agent": agent,
        "status": status,
        "duration_ms": round((perf_counter() - started_at) * 1000, 3),
    }
    if error_type:
        entry["error_type"] = error_type
    return entry


def _append_agent_trace(report: str, trace: list[dict[str, Any]]) -> str:
    rows = [
        "| Agent | Status | Duration (ms) | Error type |",
        "|---|---|---:|---|",
    ]
    rows.extend(
        "| {agent} | {status} | {duration_ms:.3f} | {error_type} |".format(
            agent=entry["agent"],
            status=entry["status"],
            duration_ms=entry["duration_ms"],
            error_type=entry.get("error_type", "Not recorded"),
        )
        for entry in trace
    )
    return f"{report.rstrip()}\n\n## 7. Agent Execution Trace\n\n" + "\n".join(rows) + "\n"


def security_node(state: WorkflowState) -> dict:
    started_at = perf_counter()
    try:
        assessment = security_agent(state["event"])
        security_provider = getattr(assessment, "provider", "Unknown")
        if not isinstance(security_provider, str) or security_provider not in {
            "Gemini",
            "OpenRouter",
            "Safe fallback",
        }:
            security_provider = "Unknown"
        return {
            "assessment": assessment,
            "security_provider": security_provider,
            "agent_trace": state.get("agent_trace", []) + [
                _trace_entry("Security Agent", "completed", started_at)
            ],
        }

    except Exception as exc:
        error_type = type(exc).__name__
        error = f"Security Agent failed: {error_type}"
        print(f"[Orchestrator] {error}")

        assessment = SecurityAssessment(
            threat_type=state["event"].attack_type,
            risk_level="UNKNOWN",
            summary=(
                "Security assessment unavailable. "
                "Manual investigation is required."
            ),
            observed_facts=[
                f"CAN ID: {state['event'].can_id}",
                f"Detection rule: {state['event'].detection_rule}",
            ],
            unknowns=[
                "The security assessment could not be completed."
            ],
            provider="Safe fallback",
        )

        return {
            "assessment": assessment,
            "security_provider": "Safe fallback",
            "errors": state.get("errors", []) + [error],
            "agent_trace": state.get("agent_trace", []) + [
                _trace_entry(
                    "Security Agent",
                    "fallback",
                    started_at,
                    error_type,
                )
            ],
        }


def diagnostic_node(state: WorkflowState) -> dict:
    started_at = perf_counter()
    try:
        diagnostic = diagnostic_agent(state["event"])
        provider_errors = getattr(diagnostic, "provider_errors", [])
        status = (
            "fallback"
            if diagnostic.analysis_method == "FALLBACK" or provider_errors
            else "completed"
        )
        return {
            "diagnostic": diagnostic,
            "agent_trace": state.get("agent_trace", []) + [
                _trace_entry(
                    "Diagnostic Agent",
                    status,
                    started_at,
                    ", ".join(provider_errors) if provider_errors else None,
                )
            ],
        }

    except Exception as exc:
        error_type = type(exc).__name__
        error = f"Diagnostic Agent failed: {error_type}"
        print(f"[Orchestrator] {error}")

        diagnostic = DiagnosticReport(
            event_id=state["event"].event_id,
            diagnostic_summary=(
                "Diagnostic analysis unavailable. "
                "Manual investigation is required."
            ),
            unknowns=[
                "The Diagnostic Agent could not complete its analysis."
            ],
            recommended_checks=[
                "Inspect the captured CAN frames.",
                "Compare the traffic with a trusted normal baseline.",
            ],
            root_cause_confirmed=False,
            confidence=0.0,
            analysis_method="FALLBACK",
        )

        return {
            "diagnostic": diagnostic,
            "errors": state.get("errors", []) + [error],
            "agent_trace": state.get("agent_trace", []) + [
                _trace_entry(
                    "Diagnostic Agent",
                    "fallback",
                    started_at,
                    error_type,
                )
            ],
        }


def report_node(state: WorkflowState) -> dict:
    errors = list(state.get("errors", []))
    started_at = perf_counter()
    report_status = "completed"
    report_error_type = None

    try:
        report = generate_security_report(
            event=state["event"],
            assessment=state["assessment"],
            diagnostic=state["diagnostic"],
            security_provider=state.get("security_provider", "Unknown"),
        )

    except Exception as exc:
        report_error_type = type(exc).__name__
        report_status = "fallback"
        error = f"Report generation failed: {report_error_type}"
        errors.append(error)
        print(f"[Orchestrator] {error}")

        event = state["event"]
        assessment = state["assessment"]
        diagnostic = state["diagnostic"]
        security_provider = state.get("security_provider", "Unknown")
        if not isinstance(security_provider, str) or security_provider not in {
            "Gemini",
            "OpenRouter",
            "Safe fallback",
        }:
            security_provider = "Unknown"

        report = f"""# Automotive CAN Security Report

## Detection
- Generated at: {datetime.now(timezone.utc).isoformat()}
- Event ID: {event.event_id}
- Scenario ID: {event.metadata.get('scenario_id', 'Not assigned')}
- Data provenance: {event.metadata.get('data_provenance', 'UNSPECIFIED')}
- Event timestamp: {event.timestamp.isoformat()}
- CAN ID: {event.can_id}
- Channel: {event.channel}
- Attack suspicion: {event.attack_type}
- Detection rule: {event.detection_rule}
- Message count: {event.message_count}
- Detection evidence: {', '.join(event.evidence) or 'Not recorded'}

## Security Assessment
- Provider: {security_provider}
- Risk level: {assessment.risk_level}
- Summary: {assessment.summary}

## Diagnostic Analysis
- Summary: {diagnostic.diagnostic_summary}
- Root cause confirmed: {diagnostic.root_cause_confirmed}
- Confidence: {diagnostic.confidence}

## Errors and Limitations
{chr(10).join('- ' + item for item in errors) or '- None'}
"""

    if errors:
        report += (
            "\n\n## Orchestrator Errors and Limitations\n\n"
            + "\n".join(f"- {error}" for error in errors)
            + "\n"
        )

    trace = list(state.get("agent_trace", [])) + [
        _trace_entry(
            "Report Agent",
            report_status,
            started_at,
            report_error_type,
        )
    ]
    report = _append_agent_trace(report, trace)

    if not state["persist_report"]:
        return {
            "report": report,
            "report_path": "",
            "errors": errors,
            "agent_trace": trace,
        }

    try:
        report_path = save_security_report(
            report,
            "reports/security_report.md",
        )
        print(f"[Report Agent] Report saved: {report_path}")

    except Exception as exc:
        error = f"Report saving failed: {type(exc).__name__}"
        errors.append(error)
        report_path = ""
        print(f"[Orchestrator] {error}")
        print("[Orchestrator] Report content remains available in memory.")

    return {
        "report": report,
        "report_path": report_path,
        "errors": errors,
        "agent_trace": trace,
    }


def build_workflow():
    workflow = StateGraph(WorkflowState)

    workflow.add_node("security", security_node)
    workflow.add_node("diagnostic", diagnostic_node)
    workflow.add_node("report", report_node)

    workflow.add_edge(START, "security")
    workflow.add_edge("security", "diagnostic")
    workflow.add_edge("diagnostic", "report")
    workflow.add_edge("report", END)

    return workflow.compile()


def run_workflow(
    event: SecurityEvent,
    persist_report: bool = True,
) -> WorkflowState:
    app = build_workflow()

    initial_state: WorkflowState = {
        "event": event,
        "assessment": SecurityAssessment(),
        "security_provider": "Unknown",
        "diagnostic": DiagnosticReport(),
        "report": "",
        "report_path": "",
        "errors": [],
        "persist_report": persist_report,
        "agent_trace": [],
    }

    return app.invoke(initial_state)
