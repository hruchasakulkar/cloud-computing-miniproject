"""
End-to-End Pipeline Evaluation
Member 3: Agent Intelligence + Security (Integrated with Member 2)

Evaluates the complete pipeline against:
1. Attack events
2. Normal events

Pipeline:
Detection → Investigation → Risk → Response → Supervisor
"""

import csv
from pathlib import Path
from collections import Counter

# Import Detection
try:
    from detection_agent import DetectionAgent
    detector = DetectionAgent()
except ImportError:
    detector = None
    print("Warning: DetectionAgent not found.")

from investigation_agent import investigate_event
from risk_agent import assess_risk
from response_agent import generate_response
from supervisor import supervise_response


# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ATTACK_LOGS = PROJECT_ROOT / "data" / "attack_logs.csv"
NORMAL_LOGS = PROJECT_ROOT / "data" / "normal_logs.csv"


# ---------------------------------------------------------
# PROCESS ONE EVENT
# ---------------------------------------------------------

def process_event(event):
    
    detection = None
    if detector:
        detection = detector.analyze(event)

    investigation = investigate_event(event)

    risk = assess_risk(
        {
            **investigation,
            "events": [event]
        }
    )

    response = generate_response(
        investigation,
        risk
    )

    supervisor = supervise_response(
        investigation,
        risk,
        response
    )

    return {
        "event": event,
        "detection": detection,
        "investigation": investigation,
        "risk": risk,
        "response": response,
        "supervisor": supervisor
    }


# ---------------------------------------------------------
# LOAD CSV
# ---------------------------------------------------------

def load_events(filepath):

    with open(filepath, newline="") as file:
        return list(csv.DictReader(file))


# ---------------------------------------------------------
# EVALUATE DATASET
# ---------------------------------------------------------

def evaluate_dataset(events, dataset_name):

    results = [
        process_event(event)
        for event in events
    ]
    
    detections = [
        result["detection"]
        for result in results
        if result.get("detection") is not None
    ]

    investigations = [
        result["investigation"]
        for result in results
    ]

    risks = [
        result["risk"]
        for result in results
    ]

    supervisors = [
        result["supervisor"]
        for result in results
    ]

    incident_types = Counter(
        result["incident_type"]
        for result in investigations
    )

    severities = Counter(
        result["severity"]
        for result in risks
    )

    supervisor_decisions = Counter(
        result["decision"]
        for result in supervisors
    )

    risk_scores = [
        result["risk_score"]
        for result in risks
    ]

    suspicious_events = sum(
        1
        for investigation in investigations
        if investigation["incident_type"] != "unknown"
    )

    unknown_events = sum(
        1
        for investigation in investigations
        if investigation["incident_type"] == "unknown"
    )

    approved_actions = sum(
        len(result["approved_actions"])
        for result in supervisors
    )

    rejected_actions = sum(
        len(result["rejected_actions"])
        for result in supervisors
    )

    average_risk = (
        sum(risk_scores) / len(risk_scores)
        if risk_scores
        else 0
    )

    # -----------------------------------------------------
    # PRINT RESULTS
    # -----------------------------------------------------

    print("\n" + "=" * 65)
    print(f"{dataset_name} DATASET EVALUATION")
    print("=" * 65)

    print(f"\nTotal events:        {len(events)}")
    print(f"ML Detections (M2):  {len(detections)}")
    print(f"Suspicious (M3):     {suspicious_events}")
    print(f"Unknown events:      {unknown_events}")
    print(f"Average risk score:  {average_risk:.2f}")

    print("\nIncident Types:")
    print(incident_types)

    print("\nSeverity Distribution:")
    print(severities)

    print("\nSupervisor Decisions:")
    print(supervisor_decisions)

    print(f"\nApproved actions:    {approved_actions}")
    print(f"Rejected actions:    {rejected_actions}")

    return {
        "results": results,
        "ml_detections": len(detections),
        "incident_types": incident_types,
        "severities": severities,
        "supervisor_decisions": supervisor_decisions,
        "suspicious_events": suspicious_events,
        "unknown_events": unknown_events,
        "average_risk": average_risk
    }


# ---------------------------------------------------------
# ATTACK SCENARIO BREAKDOWN
# ---------------------------------------------------------

def evaluate_attack_scenarios(results):

    scenarios = Counter(
        result["event"].get("scenario")
        for result in results
    )

    print("\n" + "=" * 65)
    print("ATTACK SCENARIO BREAKDOWN")
    print("=" * 65)

    for scenario in sorted(scenarios):

        scenario_results = [
            result
            for result in results
            if result["event"].get("scenario") == scenario
        ]
        
        ml_caught = len([r for r in scenario_results if r.get("detection") is not None])

        scores = [
            result["risk"]["risk_score"]
            for result in scenario_results
        ]

        incidents = Counter(
            result["investigation"]["incident_type"]
            for result in scenario_results
        )

        severities = Counter(
            result["risk"]["severity"]
            for result in scenario_results
        )

        print(f"\n{scenario}")
        print("-" * 65)

        print(f"Events:              {len(scenario_results)}")
        print(f"ML Detected:         {ml_caught}/{len(scenario_results)} ({(ml_caught/len(scenario_results))*100:.1f}%)")
        print(f"Average risk:        {sum(scores) / len(scores):.2f}")
        print(f"Min risk:            {min(scores)}")
        print(f"Max risk:            {max(scores)}")
        print(f"Incident types:      {incidents}")
        print(f"Severity:            {severities}")


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

if __name__ == "__main__":

    attack_events = load_events(ATTACK_LOGS)
    normal_events = load_events(NORMAL_LOGS)

    attack_summary = evaluate_dataset(attack_events, "ATTACK")
    evaluate_attack_scenarios(attack_summary["results"])
    normal_summary = evaluate_dataset(normal_events, "NORMAL")

    print("\n" + "=" * 65)
    print("FINAL PIPELINE SUMMARY")
    print("=" * 65)

    print(f"\nAttack events:       {len(attack_events)}")
    print(f"Attack ML Detected:  {attack_summary['ml_detections']}")
    print(f"Attack unknown:      {attack_summary['unknown_events']}")

    print(f"\nNormal events:       {len(normal_events)}")
    print(f"Normal ML False Pos: {normal_summary['ml_detections']}")
    print(f"Normal suspicious:   {normal_summary['suspicious_events']}")

    print(f"\nAttack avg risk:     {attack_summary['average_risk']:.2f}")
    print(f"Normal avg risk:     {normal_summary['average_risk']:.2f}")

    print("\nPipeline evaluation complete.")
