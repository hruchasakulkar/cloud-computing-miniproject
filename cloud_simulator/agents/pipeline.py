"""
End-to-End Security Agent Pipeline
Member 2 (Detection) + Member 3 (Intelligence & Security)

Pipeline:

Cloud Event
    ↓
Detection Agent (ML Anomaly)
    ↓
Investigation Agent
    ↓
Risk Assessment Agent
    ↓
Response Agent
    ↓
Supervisor / Policy Engine
    ↓
Final Decision
"""

import csv
from pathlib import Path

# Try importing the Detection Agent from Member 2
try:
    from detection_agent import DetectionAgent
    detector = DetectionAgent()
except ImportError:
    detector = None
    print("Warning: DetectionAgent not found. Pipeline will skip ML detection step.")

from investigation_agent import investigate_event
from risk_agent import assess_risk
from response_agent import generate_response
from supervisor import supervise_response


# ---------------------------------------------------------
# 1. PROCESS ONE EVENT
# ---------------------------------------------------------

def process_event(event):
    """
    Run one cloud event through the complete
    integrated security pipeline.
    """
    # Step 0: Detection (Member 2 ML Anomaly)
    detection_result = None
    if detector:
        detection_result = detector.analyze(event)

    # Step 1: Investigation
    investigation_result = investigate_event(event)

    # Step 2: Risk assessment
    # Correlate detection score into risk if desired, or pass events
    risk_result = assess_risk(
        {
            **investigation_result,
            "events": [event]
        }
    )
    
    # If ML detection caught something but investigation was 'unknown', bump risk a bit conceptually 
    # (Leaving this simple to match existing contract)

    # Step 3: Response recommendation
    response_result = generate_response(
        investigation_result,
        risk_result
    )

    # Step 4: Supervisor policy validation
    supervisor_result = supervise_response(
        investigation_result,
        risk_result,
        response_result
    )

    return {
        "event": event,
        "detection": detection_result,
        "investigation": investigation_result,
        "risk": risk_result,
        "response": response_result,
        "supervisor": supervisor_result
    }


# ---------------------------------------------------------
# 2. PRINT ONE RESULT
# ---------------------------------------------------------

def print_result(result):
    event = result["event"]
    detection = result.get("detection")
    investigation = result["investigation"]
    risk = result["risk"]
    response = result["response"]
    supervisor = result["supervisor"]

    print("\n" + "=" * 60)
    print("END-TO-END SECURITY PIPELINE (Integrated)")
    print("=" * 60)

    print("\nEVENT")
    print("-" * 60)
    print(f"Event ID:     {event.get('event_id')}")
    print(f"User:         {event.get('username')}")
    print(f"Action:       {event.get('action')}")
    print(f"Resource:     {event.get('resource_id')}")
    print(f"Status:       {event.get('status')}")

    print("\nDETECTION (ML Anomaly by Member 2)")
    print("-" * 60)
    if detection:
        print(f"ML Alert:      Detected!")
        print(f"Severity:      {detection.get('severity')}")
        print(f"Anomaly Score: {detection.get('anomaly_score')}")
        print(f"Latency:       {detection.get('detection_latency_sec')}s")
    else:
        print("ML Alert:      None (Normal Event or Missed)")

    print("\nINVESTIGATION (Member 3)")
    print("-" * 60)
    print(f"Incident Type: {investigation.get('incident_type')}")
    print(f"Confidence:    {investigation.get('confidence')}")
    print(f"Evidence:      {investigation.get('evidence')}")

    print("\nRISK ASSESSMENT")
    print("-" * 60)
    print(f"Risk Score:    {risk.get('risk_score')}/100")
    print(f"Severity:      {risk.get('severity')}")
    print(f"Risk Factors:  {risk.get('risk_factors')}")

    print("\nRESPONSE")
    print("-" * 60)
    for action in response.get("actions", []):
        print(f"- {action}")

    print("\nSUPERVISOR")
    print("-" * 60)
    print(f"Decision:      {supervisor.get('decision')}")
    print(f"Approved:      {supervisor.get('approved_actions')}")
    print(f"Rejected:      {supervisor.get('rejected_actions')}")

    print("\nFINAL REASON")
    print("-" * 60)
    print(supervisor.get("reason"))
    print("=" * 60)


# ---------------------------------------------------------
# 3. TEST WITH ONE ATTACK EVENT
# ---------------------------------------------------------

if __name__ == "__main__":
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    ATTACK_LOGS = PROJECT_ROOT / "data" / "attack_logs.csv"

    with open(ATTACK_LOGS, newline="") as file:
        events = list(csv.DictReader(file))

    # Test an event that the anomaly detector is known to catch (e.g. brute_force or data_exfiltration)
    test_event = next(
        event
        for event in events
        if event.get("scenario") == "data_exfiltration"
    )

    result = process_event(test_event)
    print_result(result)
