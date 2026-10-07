"""
Investigation Agent
Member 3: Agent Intelligence + Security

Analyzes suspicious cloud events and identifies possible
security incident types using explainable evidence patterns.
"""


# ---------------------------------------------------------
# 1. DATA NORMALIZATION
# ---------------------------------------------------------

def _normalize_event(event):
    """
    Convert CSV string values into the appropriate Python types.
    """

    normalized = event.copy()

    # Convert bytes_out from CSV string to integer
    try:
        normalized["bytes_out"] = int(
            normalized.get("bytes_out", 0)
        )
    except (ValueError, TypeError):
        normalized["bytes_out"] = 0

    # Convert MFA from CSV string to boolean
    mfa_value = normalized.get("mfa", True)

    if isinstance(mfa_value, str):
        normalized["mfa"] = mfa_value.lower() == "true"
    else:
        normalized["mfa"] = bool(mfa_value)

    return normalized


# ---------------------------------------------------------
# 2. HELPER FUNCTIONS
# ---------------------------------------------------------

def _is_non_admin_role(role):
    """Check whether the user does not have an administrative role."""
    return role not in ["CloudAdmin", "SecurityAnalyst"]


def _is_large_data_transfer(event):
    """Check whether an event involves unusually large data transfer."""
    return event.get("bytes_out", 0) >= 1_000_000


def _is_sensitive_resource(event):
    """Check whether the accessed resource is high sensitivity."""
    resource_id = event.get("resource_id", "")

    sensitive_keywords = [
        "customer_data",
        "iam_user_database",
        "cloudtrail_logs",
        "application_db"
    ]

    return any(
        keyword in resource_id
        for keyword in sensitive_keywords
    )


# ---------------------------------------------------------
# 3. INDIVIDUAL EVENT INVESTIGATION
# ---------------------------------------------------------

def investigate_event(event):
    """
    Investigate a single suspicious cloud event.

    Returns:
        dict containing detected evidence and possible incident type.
    """

    # Normalize CSV values before analysis
    event = _normalize_event(event)

    evidence = []
    incident_type = "unknown"

    action = event.get("action")
    role = event.get("role")
    status = event.get("status")
    mfa = event.get("mfa", True)

    # ---------------------------------------------
    # BRUTE FORCE
    # ---------------------------------------------

    if action == "ConsoleLogin" and status == "Failed":
        evidence.append("failed_console_login")
        incident_type = "brute_force"

    # ---------------------------------------------
    # PRIVILEGE ESCALATION
    # ---------------------------------------------

    if action == "AttachAdminPolicy":
        evidence.append("admin_policy_attachment")

        if _is_non_admin_role(role):
            evidence.append("non_admin_user")

        if status == "Success":
            evidence.append("successful_privilege_change")

        if mfa is False:
            evidence.append("mfa_not_used")

        incident_type = "privilege_escalation"

    # ---------------------------------------------
    # DATA EXFILTRATION
    # ---------------------------------------------

    if action == "GetObject":

        large_transfer = _is_large_data_transfer(event)
        sensitive_resource = _is_sensitive_resource(event)

        if large_transfer:
            evidence.append("large_data_transfer")

        if sensitive_resource:
            evidence.append("sensitive_resource_access")

        # Large data transfer is required for classification
        if large_transfer:
            incident_type = "data_exfiltration"

    # ---------------------------------------------
    # LOGGING DISABLED
    # ---------------------------------------------

    if action == "StopLogging":
        evidence.append("cloud_logging_disabled")

        if status == "Success":
            evidence.append("logging_change_successful")

        incident_type = "logging_disabled"

    # ---------------------------------------------
    # CONFIDENCE
    # ---------------------------------------------

    confidence = calculate_confidence(
        incident_type,
        evidence
    )

    return {
        "incident_type": incident_type,
        "confidence": confidence,
        "evidence": evidence,
        "event": event
    }

# ---------------------------------------------------------
# 4. CONFIDENCE CALCULATION
# ---------------------------------------------------------

def calculate_confidence(incident_type, evidence):
    """
    Calculate an explainable confidence score.

    The score is based on the amount of supporting evidence.
    """

    if incident_type == "unknown":
        return 0.0

    evidence_count = len(evidence)

    if incident_type == "brute_force":
        if evidence_count >= 1:
            return 0.85

    if incident_type == "privilege_escalation":
        if evidence_count >= 4:
            return 0.95

        if evidence_count >= 2:
            return 0.85

        if evidence_count >= 1:
            return 0.70

    if incident_type == "data_exfiltration":
        if evidence_count >= 2:
            return 0.95

        if evidence_count >= 1:
            return 0.75

    if incident_type == "logging_disabled":
        if evidence_count >= 2:
            return 0.95

        if evidence_count >= 1:
            return 0.85

    return 0.50


# ---------------------------------------------------------
# 5. MULTI-EVENT INVESTIGATION
# ---------------------------------------------------------

def investigate_events(events):
    """
    Investigate a collection of suspicious cloud events.

    This allows the agent to correlate multiple events
    into a single incident.
    """

    if not events:
        return {
            "incident_type": "unknown",
            "confidence": 0.0,
            "evidence": [],
            "events": [],
            "explanation": "No suspicious events were provided."
        }

    # Sort events chronologically
    sorted_events = sorted(
        events,
        key=lambda event: event.get("timestamp", "")
    )

    all_evidence = []
    detected_types = []

    for event in sorted_events:
        result = investigate_event(event)

        if result["incident_type"] != "unknown":
            detected_types.append(
                result["incident_type"]
            )

        all_evidence.extend(
            result["evidence"]
        )

    # Remove duplicate evidence
    all_evidence = list(
        dict.fromkeys(all_evidence)
    )

    # -----------------------------------------------------
    # MULTI-STAGE COMPROMISED ACCOUNT
    # -----------------------------------------------------

    if (
        "privilege_escalation" in detected_types
        and "data_exfiltration" in detected_types
    ):
        incident_type = "compromised_account"
        confidence = 0.95

        explanation = (
            "The event sequence indicates a possible compromised "
            "account followed by privilege escalation and sensitive "
            "data access."
        )

    # -----------------------------------------------------
    # MULTIPLE ATTACK TYPES
    # -----------------------------------------------------

    elif len(set(detected_types)) > 1:
        incident_type = "multi_stage_attack"
        confidence = 0.90

        explanation = (
            "Multiple suspicious activity patterns were detected "
            "within the provided event sequence."
        )

    # -----------------------------------------------------
    # SINGLE ATTACK TYPE
    # -----------------------------------------------------

    elif detected_types:
        incident_type = detected_types[0]

        confidence = max(
            calculate_confidence(
                incident_type,
                all_evidence
            ),
            0.70
        )

        explanation = (
            f"Evidence patterns are consistent with "
            f"{incident_type.replace('_', ' ')}."
        )

    # -----------------------------------------------------
    # NO RECOGNIZED ATTACK
    # -----------------------------------------------------

    else:
        incident_type = "unknown"
        confidence = 0.0

        explanation = (
            "No recognized security incident pattern "
            "was identified."
        )

    return {
        "incident_type": incident_type,
        "confidence": round(confidence, 2),
        "evidence": all_evidence,
        "events": sorted_events,
        "explanation": explanation
    }


# ---------------------------------------------------------
# 6. TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_event = {
        "timestamp": "2026-10-02T10:00:00+00:00",
        "event_id": "test-001",
        "user_id": "user_004",
        "username": "intern_jay",
        "role": "ReadOnly",
        "source_ip": "203.0.113.10",
        "action": "AttachAdminPolicy",
        "resource_id": "iam_user_database",
        "resource_type": "IAM",
        "region": "ap-south-1",
        "status": "Success",
        "bytes_out": 0,
        "mfa": False
    }

    result = investigate_event(sample_event)

    print("\nInvestigation Result:")
    print(result)