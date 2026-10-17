
from tools.can_analyzer.can_analyzer import analyze_can_traffic
from agents.orchestrator.orchestrator import run_workflow
from agents.report_agent.report_agent import save_security_report


def main():
    print("=" * 45)
    print(" AUTOMOTIVE CAN SECURITY PLATFORM ")
    print("=" * 45)

    # 1. Capture CAN traffic and run deterministic detectors
    detections = analyze_can_traffic(
        window_seconds=5,
        threshold=100,
    )

    print("\n=== SECURITY ANALYSIS & DIAGNOSTICS ===")

    reports = []

    # 2. Analyze every detected anomaly
    for detection in detections:
        if not detection.anomaly:
            continue

        print(f"\n{'=' * 45}")
        print(f"Anomaly detected: {detection.attack_type}")
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

    # 6. Save all generated reports into one Markdown file
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
    main()