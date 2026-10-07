"""
Response Agent
Member 3: Agent Intelligence + Security

Generates safe, simulated response actions based on
investigation results and risk assessment.

The agent recommends actions only.
It does not execute real cloud operations.
"""


# ---------------------------------------------------------
# 1. RESPONSE ACTION DEFINITIONS
# ---------------------------------------------------------

RESPONSE_ACTIONS = {
    "brute_force": [
        "lock_suspicious_account",
        "block_source_ip",
        "alert_security_team"
    ],

    "privilege_escalation": [
        "revoke_suspicious_privilege",
        "restrict_affected_account",
        "alert_security_team"
    ],

    "data_exfiltration": [
        "restrict_data_access",
        "isolate_affected_account",
        "alert_security_team"
    ],

    "logging_disabled": [
        "restore_cloud_logging",
        "restrict_affected_account",
        "alert_security_team"
    ],

    "compromised_account": [
        "revoke_suspicious_credentials",
        "restrict_affected_account",
        "preserve_investigation_evidence",
        "alert_security_team"
    ],

    "multi_stage_attack": [
        "restrict_affected_account",
        "revoke_suspicious_credentials",
        "preserve_investigation_evidence",
        "alert_security_team"
    ]
}


# ---------------------------------------------------------
# 2. ACTION DESCRIPTIONS
# ---------------------------------------------------------

ACTION_DESCRIPTIONS = {
    "lock_suspicious_account":
        "Temporarily lock the suspicious user account.",

    "block_source_ip":
        "Simulate blocking the suspicious source IP.",

    "alert_security_team":
        "Generate a security alert for administrator review.",

    "revoke_suspicious_privilege":
        "Simulate removal of the suspicious privilege change.",

    "restrict_affected_account":
        "Restrict the affected account from sensitive operations.",

    "restrict_data_access":
        "Restrict access to the affected sensitive data.",

    "isolate_affected_account":
        "Simulate isolating the affected account.",

    "restore_cloud_logging":
        "Simulate restoring cloud activity logging.",

    "revoke_suspicious_credentials":
        "Simulate revoking suspicious credentials.",

    "preserve_investigation_evidence":
        "Preserve relevant evidence for further investigation."
}


# ---------------------------------------------------------
# 3. RESPONSE AGENT
# ---------------------------------------------------------

def generate_response(investigation_result, risk_result):
    """
    Generate a simulated response recommendation.

    Parameters:
        investigation_result: output from Investigation Agent
        risk_result: output from Risk Agent

    Returns:
        Dictionary containing recommended response actions.
    """

    if not investigation_result or not risk_result:
        return {
            "incident_type": "unknown",
            "risk_score": 0,
            "severity": "LOW",
            "actions": [],
            "explanation": "Insufficient information for response."
        }

    incident_type = investigation_result.get(
        "incident_type",
        "unknown"
    )

    risk_score = risk_result.get(
        "risk_score",
        0
    )

    severity = risk_result.get(
        "severity",
        "LOW"
    )

    actions = RESPONSE_ACTIONS.get(
        incident_type,
        []
    )

    # -----------------------------------------------------
    # UNKNOWN INCIDENT
    # -----------------------------------------------------

    if incident_type == "unknown":
        actions = ["continue_monitoring"]
    elif severity == "LOW":
        actions = actions[:2] + ["alert_security_team"]
    elif severity == "MEDIUM":
        actions = actions[:2] + ["alert_security_team"]
    elif severity in ["HIGH", "CRITICAL"]:
        actions = actions

    # -----------------------------------------------------
    # LOW RISK
    # -----------------------------------------------------

    if severity == "LOW" and incident_type != "unknown":
        actions = [
            "continue_monitoring",
            "alert_security_team"
        ]

    # -----------------------------------------------------
    # MEDIUM RISK
    # -----------------------------------------------------

    elif severity == "MEDIUM":
        actions = actions[:2] + [
            "alert_security_team"
        ]

    # -----------------------------------------------------
    # HIGH / CRITICAL
    # -----------------------------------------------------

    elif severity in ["HIGH", "CRITICAL"]:
        # Keep all predefined response actions.
        actions = actions

    explanation = (
        f"Response generated for {incident_type.replace('_', ' ')} "
        f"with a risk score of {risk_score}/100 and "
        f"{severity} severity."
    )

    return {
        "incident_type": incident_type,
        "risk_score": risk_score,
        "severity": severity,
        "actions": actions,
        "action_descriptions": [
            ACTION_DESCRIPTIONS.get(
                action,
                "No description available."
            )
            for action in actions
        ],
        "explanation": explanation
    }


# ---------------------------------------------------------
# 4. TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_investigation = {
        "incident_type": "privilege_escalation",
        "confidence": 0.95,
        "evidence": [
            "admin_policy_attachment",
            "non_admin_user",
            "successful_privilege_change",
            "mfa_not_used"
        ],
        "events": [
            {
                "action": "AttachAdminPolicy",
                "role": "ReadOnly",
                "status": "Success",
                "mfa": False,
                "resource_id": "iam_user_database"
            }
        ]
    }

    sample_risk = {
        "risk_score": 95,
        "severity": "CRITICAL",
        "risk_factors": [
            "high_investigation_confidence",
            "successful_privilege_change",
            "non_admin_attempted_privilege_escalation",
            "mfa_not_used",
            "sensitive_resource_access"
        ],
        "recommended_priority": "CRITICAL"
    }

    result = generate_response(
        sample_investigation,
        sample_risk
    )

    print("\nResponse Agent Result:")
    print(result)

