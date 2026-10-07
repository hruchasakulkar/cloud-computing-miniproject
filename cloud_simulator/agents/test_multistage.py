import csv
from pathlib import Path

from investigation_agent import investigate_events
from risk_agent import assess_risk
from response_agent import generate_response
from supervisor import supervise_response

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ATTACK_LOGS = PROJECT_ROOT / "data" / "attack_logs.csv"


with open(ATTACK_LOGS, newline="") as file:
    events = list(csv.DictReader(file))


# select one event from each attack scenario
selected_events = []

for scenario in [
    "brute_force",
    "privilege_escalation",
    "data_exfiltration",
    "logging_disabled"
]:
    event = next(
        event for event in events
        if event.get("scenario") == scenario
    )
    selected_events.append(event)


# -----------------------------------------------------
# INVESTIGATION
# -----------------------------------------------------

investigation = investigate_events(selected_events)


# -----------------------------------------------------
# RISK
# -----------------------------------------------------

risk = assess_risk(investigation)


# -----------------------------------------------------
# RESPONSE
# -----------------------------------------------------

response = generate_response(
    investigation,
    risk
)


# -----------------------------------------------------
# SUPERVISOR
# -----------------------------------------------------

supervisor = supervise_response(
    investigation,
    risk,
    response
)


# -----------------------------------------------------
# OUTPUT
# -----------------------------------------------------

print("\n" + "=" * 65)
print("MULTI-STAGE ATTACK TEST")
print("=" * 65)

print("\nEVENTS ANALYZED:")
for event in selected_events:
    print(
        f"- {event['scenario']}: "
        f"{event['action']} | "
        f"{event['username']}"
    )

print("\nINVESTIGATION")
print("-" * 65)
print("Incident type:", investigation["incident_type"])
print("Confidence:", investigation["confidence"])
print("Evidence:", investigation["evidence"])
print("Explanation:", investigation["explanation"])

print("\nRISK")
print("-" * 65)
print("Risk score:", risk["risk_score"])
print("Severity:", risk["severity"])
print("Risk factors:", risk["risk_factors"])

print("\nRESPONSE")
print("-" * 65)
for action in response["actions"]:
    print("-", action)

print("\nSUPERVISOR")
print("-" * 65)
print("Decision:", supervisor["decision"])
print("Approved:", supervisor["approved_actions"])
print("Rejected:", supervisor["rejected_actions"])
print("Reason:", supervisor["reason"])

print("\n" + "=" * 65)

