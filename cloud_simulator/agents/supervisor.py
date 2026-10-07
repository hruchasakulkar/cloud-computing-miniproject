"""
Supervisor / Policy Engine
Member 3: Agent Intelligence + Security

Validates response recommendations against predefined
security policies before simulated execution.

The Supervisor does not perform real cloud actions.
It only approves, rejects, or escalates proposed actions.
"""


# ---------------------------------------------------------
# 1. ALLOWED RESPONSE ACTIONS
# ---------------------------------------------------------

ALLOWED_ACTIONS = {
    "lock_suspicious_account",
    "block_source_ip",
    "alert_security_team",

    "revoke_suspicious_privilege",
    "restrict_affected_account",

    "restrict_data_access",
    "isolate_affected_account",

    "restore_cloud_logging",

    "revoke_suspicious_credentials",
    "preserve_investigation_evidence",

    "continue_monitoring"
}


# ---------------------------------------------------------
# 2. HIGH-RISK ACTIONS
# ---------------------------------------------------------

HIGH_RISK_ACTIONS = {
    "revoke_suspicious_privilege",
    "restrict_affected_account",
    "restrict_data_access",
    "isolate_affected_account",
    "revoke_suspicious_credentials"
}


# ---------------------------------------------------------
# 3. INCIDENT-SPECIFIC POLICIES
# ---------------------------------------------------------

INCIDENT_ACTION_POLICY = {
    "unknown": {
        "continue_monitoring"
    },

    "brute_force": {
        "lock_suspicious_account",
        "block_source_ip",
        "alert_security_team",
        "continue_monitoring"
    },

    "privilege_escalation": {
        "revoke_suspicious_privilege",
        "restrict_affected_account",
        "alert_security_team"
    },

    "data_exfiltration": {
        "restrict_data_access",
        "isolate_affected_account",
        "alert_security_team"
    },

    "logging_disabled": {
        "restore_cloud_logging",
        "restrict_affected_account",
        "alert_security_team"
    },

    "compromised_account": {
        "revoke_suspicious_credentials",
        "restrict_affected_account",
        "preserve_investigation_evidence",
        "alert_security_team"
    },

    "multi_stage_attack": {
        "restrict_affected_account",
        "revoke_suspicious_credentials",
        "preserve_investigation_evidence",
        "alert_security_team"
    }
}


# ---------------------------------------------------------
# 4. POLICY CHECK
# ---------------------------------------------------------

def check_action_policy(incident_type, action, severity):
    """
    Determine whether a proposed response action is
    permitted by the security policy.
    """

    # Action must be known to the security system.
    if action not in ALLOWED_ACTIONS:
        return {
            "decision": "REJECT",
            "reason": "Action is not defined in the security policy."
        }

    # Incident-specific policy must exist.
    allowed_for_incident = INCIDENT_ACTION_POLICY.get(
        incident_type,
        set()
    )

    if action not in allowed_for_incident:
        return {
            "decision": "REJECT",
            "reason": (
                "Action is not permitted for this incident type."
            )
        }

    # High-risk actions require HIGH or CRITICAL severity.
    if action in HIGH_RISK_ACTIONS:

        if severity not in ["HIGH", "CRITICAL"]:
            return {
                "decision": "REJECT",
                "reason": (
                    "High-impact action requires HIGH or "
                    "CRITICAL severity."
                )
            }

    return {
        "decision": "APPROVE",
        "reason": "Action satisfies the configured security policy."
    }


# ---------------------------------------------------------
# 5. SUPERVISOR
# ---------------------------------------------------------

def supervise_response(
    investigation_result,
    risk_result,
    response_result
):
    """
    Validate every response action proposed by the
    Response Agent.
    """

    if not investigation_result:
        return {
            "decision": "ESCALATE",
            "approved_actions": [],
            "rejected_actions": [],
            "reason": "Missing investigation result."
        }

    if not risk_result:
        return {
            "decision": "ESCALATE",
            "approved_actions": [],
            "rejected_actions": [],
            "reason": "Missing risk assessment."
        }

    if not response_result:
        return {
            "decision": "ESCALATE",
            "approved_actions": [],
            "rejected_actions": [],
            "reason": "Missing response recommendation."
        }

    incident_type = investigation_result.get(
        "incident_type",
        "unknown"
    )

    severity = risk_result.get(
        "severity",
        "LOW"
    )

    risk_score = risk_result.get(
        "risk_score",
        0
    )

    proposed_actions = response_result.get(
        "actions",
        []
    )

    approved_actions = []
    rejected_actions = []
    policy_results = []

    # -----------------------------------------------------
    # CHECK EACH PROPOSED ACTION
    # -----------------------------------------------------

    for action in proposed_actions:

        result = check_action_policy(
            incident_type,
            action,
            severity
        )

        policy_results.append({
            "action": action,
            "decision": result["decision"],
            "reason": result["reason"]
        })

        if result["decision"] == "APPROVE":
            approved_actions.append(action)

        else:
            rejected_actions.append(action)

    # -----------------------------------------------------
    # FINAL SUPERVISOR DECISION
    # -----------------------------------------------------

    if rejected_actions:
        decision = "ESCALATE"

        reason = (
            "One or more proposed actions failed the "
            "security policy and require administrator review."
        )

    elif approved_actions:
        decision = "APPROVE"

        reason = (
            "All proposed response actions satisfy "
            "the configured security policies."
        )

    else:
        decision = "ESCALATE"

        reason = (
            "No response actions were available for approval."
        )

    return {
        "decision": decision,
        "incident_type": incident_type,
        "risk_score": risk_score,
        "severity": severity,
        "approved_actions": approved_actions,
        "rejected_actions": rejected_actions,
        "policy_results": policy_results,
        "reason": reason
    }


# ---------------------------------------------------------
# 6. TEST
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

    sample_response = {
        "incident_type": "privilege_escalation",
        "risk_score": 95,
        "severity": "CRITICAL",
        "actions": [
            "revoke_suspicious_privilege",
            "restrict_affected_account",
            "alert_security_team"
        ]
    }

    result = supervise_response(
        sample_investigation,
        sample_risk,
        sample_response
    )

    print("\nSupervisor Result:")

    for key, value in result.items():
        print(f"{key}: {value}")

