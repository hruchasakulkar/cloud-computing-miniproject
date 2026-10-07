"""
Risk Assessment Agent
Member 3: Agent Intelligence + Security

Calculates the security risk of an investigated incident
using deterministic and explainable security factors.
"""


# ---------------------------------------------------------
# 1. DATA NORMALIZATION
# ---------------------------------------------------------

def _normalize_event(event):
    """
    Convert CSV string values into appropriate Python types.
    """

    normalized = event.copy()

    try:
        normalized["bytes_out"] = int(
            normalized.get("bytes_out", 0)
        )
    except (ValueError, TypeError):
        normalized["bytes_out"] = 0

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
    return role not in ["CloudAdmin", "SecurityAnalyst"]


def _is_large_data_transfer(event):
    return event.get("bytes_out", 0) >= 1_000_000


def _is_sensitive_resource(event):
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
# 3. BASE RISK
# ---------------------------------------------------------

def _get_base_risk(incident_type):
    """
    Assign a base risk score according to incident type.

    These values are project-defined policy values,
    not universal security standards.
    """

    base_risk = {
        "unknown": 0,
        "brute_force": 30,
        "logging_disabled": 55,
        "data_exfiltration": 60,
        "privilege_escalation": 70,
        "multi_stage_attack": 75,
        "compromised_account": 80
    }

    return base_risk.get(incident_type, 20)


# ---------------------------------------------------------
# 4. RISK ASSESSMENT
# ---------------------------------------------------------

def assess_risk(investigation_result):
    """
    Calculate an explainable risk score from an
    investigation result.
    """

    if not investigation_result:
        return {
            "risk_score": 0,
            "severity": "LOW",
            "risk_factors": [],
            "recommended_priority": "LOW"
        }

    incident_type = investigation_result.get(
        "incident_type",
        "unknown"
    )

    confidence = investigation_result.get(
        "confidence",
        0.0
    )

    events = investigation_result.get(
        "events",
        []
    )

    risk_score = _get_base_risk(incident_type)
    risk_factors = []

    normalized_events = [
        _normalize_event(event)
        for event in events
    ]

    # -----------------------------------------------------
    # FACTOR 1: INVESTIGATION CONFIDENCE
    # -----------------------------------------------------

    if confidence >= 0.90:
        risk_score += 5
        risk_factors.append(
            "high_investigation_confidence"
        )

    elif confidence >= 0.75:
        risk_score += 3
        risk_factors.append(
            "moderate_investigation_confidence"
        )

    # -----------------------------------------------------
    # FACTOR 2: PRIVILEGE ESCALATION
    # -----------------------------------------------------

    privilege_change = False

    for event in normalized_events:

        if event.get("action") == "AttachAdminPolicy":

            privilege_change = True

            if event.get("status") == "Success":
                risk_score += 10
                risk_factors.append(
                    "successful_privilege_change"
                )

            if _is_non_admin_role(
                event.get("role", "")
            ):
                risk_score += 5
                risk_factors.append(
                    "non_admin_attempted_privilege_escalation"
                )

    # -----------------------------------------------------
    # FACTOR 3: MFA
    # -----------------------------------------------------

    mfa_not_used = any(
        event.get("mfa") is False
        for event in normalized_events
    )

    if mfa_not_used:
        risk_score += 5
        risk_factors.append(
            "mfa_not_used"
        )

    # -----------------------------------------------------
    # FACTOR 4: SENSITIVE RESOURCE ACCESS
    # -----------------------------------------------------

    sensitive_access = any(
        _is_sensitive_resource(event)
        for event in normalized_events
    )

    if sensitive_access:
        risk_score += 5
        risk_factors.append(
            "sensitive_resource_access"
        )

    # -----------------------------------------------------
    # FACTOR 5: LARGE DATA TRANSFER
    # -----------------------------------------------------

    large_transfer = any(
        _is_large_data_transfer(event)
        for event in normalized_events
    )

    if large_transfer:
        risk_score += 10
        risk_factors.append(
            "large_data_transfer"
        )

    # -----------------------------------------------------
    # FACTOR 6: LOGGING DISABLED
    # -----------------------------------------------------

    logging_disabled = any(
        event.get("action") == "StopLogging"
        and event.get("status") == "Success"
        for event in normalized_events
    )

    if logging_disabled:
        risk_score += 10
        risk_factors.append(
            "cloud_logging_disabled"
        )

    # -----------------------------------------------------
    # 5. CAP SCORE
    # -----------------------------------------------------

    risk_score = min(risk_score, 100)

    # -----------------------------------------------------
    # 6. DETERMINE SEVERITY
    # -----------------------------------------------------

    if risk_score >= 75:
        severity = "CRITICAL"

    elif risk_score >= 50:
        severity = "HIGH"

    elif risk_score >= 25:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "risk_factors": list(dict.fromkeys(risk_factors)),
        "recommended_priority": severity
    }


# ---------------------------------------------------------
# 7. TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_investigation = {
        "incident_type": "privilege_escalation",
        "confidence": 0.95,
        "events": [
            {
                "action": "AttachAdminPolicy",
                "role": "ReadOnly",
                "status": "Success",
                "mfa": False,
                "bytes_out": 0,
                "resource_id": "iam_user_database"
            }
        ]
    }

    result = assess_risk(
        sample_investigation
    )

    print("\nRisk Assessment Result:")
    print(result)

