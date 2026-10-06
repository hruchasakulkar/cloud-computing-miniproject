from pathlib import Path
import json
import time

import pandas as pd
import plotly.express as px
import streamlit as st


# ============================================================
# CONFIG
# ============================================================

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
EVAL = ROOT / "evaluation"

st.set_page_config(
    page_title="Agentic Cloud Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# DATA LOADERS
# ============================================================

def load_csv(path):
    try:
        return pd.read_csv(path) if path.exists() else pd.DataFrame()
    except Exception:
        return pd.DataFrame()


def load_json(path):
    try:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


normal_df = load_csv(DATA / "normal_logs.csv")
attack_df = load_csv(DATA / "attack_logs.csv")
alerts_data = load_json(DATA / "detection_alerts.json")
metrics = load_json(EVAL / "metrics.json")
experiments = load_json(EVAL / "experiments_report.json")
# Combine the complete original cloud logs so the ML detector
# receives every feature used during model training.
combined_logs = pd.concat(
    [normal_df, attack_df],
    ignore_index=True,
).drop_duplicates(subset=["event_id"])
if isinstance(alerts_data, list):
    alerts_df = pd.DataFrame(alerts_data)
elif isinstance(alerts_data, dict) and isinstance(alerts_data.get("alerts"), list):
    alerts_df = pd.DataFrame(alerts_data["alerts"])
elif isinstance(alerts_data, dict) and alerts_data:
    alerts_df = pd.DataFrame([alerts_data])
else:
    alerts_df = pd.DataFrame()


# ============================================================
# AGENT PIPELINE
# ============================================================

try:
    from agents.pipeline import process_event
    PIPELINE_AVAILABLE = True
    PIPELINE_ERROR = ""
except Exception as exc:
    PIPELINE_AVAILABLE = False
    PIPELINE_ERROR = str(exc)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ Security Console")
st.sidebar.caption("Agentic Cloud Security • Research Prototype")

page = st.sidebar.radio(
    "Navigate",
    [
        "Overview",
        "Activity Logs",
        "Agent Pipeline",
        "Incident Details",
        "Experiments",
    ],
)

st.sidebar.divider()
st.sidebar.warning(
    "SIMULATION MODE\n\n"
    "This prototype operates on simulated cloud activity logs. "
    "No real cloud remediation or destructive actions are executed."
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Agentic Cloud Security")
st.caption(
    "Multi-Agent AI for autonomous cloud threat detection, investigation, "
    "risk assessment and policy-validated response."
)

st.info(
    "RESEARCH PROTOTYPE  •  SIMULATED CLOUD ENVIRONMENT",
    icon="🔬",
)


# ============================================================
# HELPERS
# ============================================================

def find_metric(data, names):
    if not isinstance(data, dict):
        return None

    for name in names:
        if name in data:
            return data[name]

    for value in data.values():
        if isinstance(value, dict):
            found = find_metric(value, names)
            if found is not None:
                return found

    return None


def display_value(value):
    if value is None:
        return "Unavailable"
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


def get_nested_dict(result, *names):
    if not isinstance(result, dict):
        return {}

    for name in names:
        value = result.get(name)
        if isinstance(value, dict):
            return value

    return {}


def scenario_column(df):
    for column in [
        "scenario",
        "attack_scenario",
        "attack_type",
        "incident_type",
    ]:
        if column in df.columns:
            return column
    return None


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    st.header("01 • Security Overview")

    total_events = len(normal_df) + len(attack_df)
    total_alerts = len(alerts_df)
    attack_events = len(attack_df)

    high_critical = 0

    if not alerts_df.empty:
        for column in ["severity", "risk_level", "level"]:
            if column in alerts_df.columns:
                high_critical = alerts_df[column].astype(str).str.upper().isin(
                    ["HIGH", "CRITICAL"]
                ).sum()
                break

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Events", f"{total_events:,}")
    c2.metric("Detection Alerts", f"{total_alerts:,}")
    c3.metric("Attack Events", f"{attack_events:,}")
    c4.metric("High / Critical", f"{high_critical:,}")

    st.success(
        "Threat activity detected in the simulated environment. "
        "Review alerts and run incidents through the multi-agent pipeline.",
        icon="🔎",
    )

    left, right = st.columns(2)

    with left:
        st.subheader("Event Distribution")

        distribution = pd.DataFrame(
            {
                "Category": [
                    "Normal Activity",
                    "Attack Activity",
                    "Detection Alerts",
                ],
                "Count": [
                    len(normal_df),
                    len(attack_df),
                    len(alerts_df),
                ],
            }
        )

        fig = px.bar(
            distribution,
            x="Category",
            y="Count",
            text="Count",
        )
        fig.update_layout(
            template="plotly_dark",
            xaxis_title=None,
            yaxis_title="Events",
        )
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Attack Scenario Distribution")

        column = scenario_column(attack_df)

        if column:
            counts = (
                attack_df[column]
                .astype(str)
                .value_counts()
                .reset_index()
            )
            counts.columns = ["Scenario", "Count"]

            fig = px.bar(
                counts,
                x="Scenario",
                y="Count",
                text="Count",
            )
            fig.update_layout(
                template="plotly_dark",
                xaxis_title=None,
                yaxis_title="Events",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack-scenario column is available.")


# ============================================================
# ACTIVITY LOGS
# ============================================================

elif page == "Activity Logs":

    st.header("02 • Activity Logs")

    combined = pd.concat(
        [
            normal_df.assign(activity_type="Normal"),
            attack_df.assign(activity_type="Attack"),
        ],
        ignore_index=True,
    )

    if combined.empty:
        st.warning("No activity logs are available.")
    else:
        search = st.text_input(
            "Search logs",
            placeholder="username, resource, action, IP, scenario...",
        )

        filtered = combined

        if search:
            mask = pd.Series(False, index=filtered.index)

            for column in filtered.columns:
                mask |= (
                    filtered[column]
                    .astype(str)
                    .str.contains(search, case=False, na=False)
                )

            filtered = filtered[mask]

        st.caption(
            f"Showing {len(filtered):,} of {len(combined):,} events"
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            height=600,
            hide_index=True,
        )


# ============================================================
# AGENT PIPELINE
# ============================================================

elif page == "Agent Pipeline":

    st.header("03 • Multi-Agent Security Pipeline")

    st.write(
        "Each suspicious event is passed through specialized agents before "
        "the Supervisor validates the proposed response."
    )

    pipeline = [
        ("01", "🔎", "Detection Agent", "Detect anomalous activity"),
        ("02", "🕵️", "Investigation Agent", "Investigate evidence"),
        ("03", "⚖️", "Risk Assessment", "Calculate risk and severity"),
        ("04", "🚨", "Response Agent", "Generate response actions"),
        ("05", "🛡️", "Supervisor", "Validate response policy"),
    ]

    cols = st.columns(5)

    for col, (number, icon, name, description) in zip(cols, pipeline):
        with col:
            st.subheader(f"{icon} {name}")
            st.caption(f"Step {number}")
            st.write(description)

    st.divider()

    if alerts_df.empty:
        st.info("No detection alerts are available.")
    else:
        st.subheader("Run an Incident")

        selected_index = st.selectbox(
            "Detection alert",
            range(len(alerts_df)),
            format_func=lambda x: f"Alert {x + 1}",
        )

        selected_alert = alerts_df.iloc[selected_index].to_dict()

        # Detection alerts already contain the complete original cloud
        # event inside the raw_log field. Use it for the ML detector.
        raw_log = selected_alert.get("raw_log")

        if isinstance(raw_log, dict):
            selected_event = raw_log.copy()

            # Preserve detection-specific metadata for the downstream agents.
            for key, value in selected_alert.items():
                if key != "raw_log" and key not in selected_event:
                    selected_event[key] = value
        else:
            selected_event = selected_alert

        with st.expander("Selected Event", expanded=True):
            st.json(selected_event)

        if st.button(
            "▶ Run Multi-Agent Analysis",
            type="primary",
            use_container_width=True,
        ):
            if not PIPELINE_AVAILABLE:
                st.error("The agent pipeline could not be imported.")
                st.code(PIPELINE_ERROR, language="text")
            else:
                with st.spinner(
                    "Running Detection → Investigation → Risk → Response → Supervisor..."
                ):
                    start = time.perf_counter()

                    try:
                        result = process_event(selected_event)
                        elapsed = time.perf_counter() - start

                        st.success(
                            f"Pipeline completed in {elapsed:.3f} seconds."
                        )

                        if isinstance(result, dict):
                            investigation = get_nested_dict(
                                result,
                                "investigation",
                                "investigation_result",
                            )
                            risk = get_nested_dict(
                                result,
                                "risk",
                                "risk_assessment",
                            )
                            response = get_nested_dict(
                                result,
                                "response",
                                "response_result",
                            )
                            supervisor = get_nested_dict(
                                result,
                                "supervisor",
                                "supervisor_result",
                            )

                            incident_type = (
                                investigation.get("incident_type")
                                or investigation.get("type")
                                or result.get("incident_type")
                                or "Unknown"
                            )

                            confidence = (
                                investigation.get("confidence")
                                or result.get("confidence")
                                or "Unavailable"
                            )

                            risk_score = (
                                risk.get("risk_score")
                                or risk.get("score")
                                or result.get("risk_score")
                                or "Unavailable"
                            )

                            severity = (
                                risk.get("severity")
                                or risk.get("risk_level")
                                or result.get("severity")
                                or "Unavailable"
                            )

                            a, b, c, d = st.columns(4)

                            a.metric("Incident", str(incident_type))
                            b.metric("Confidence", display_value(confidence))
                            c.metric("Risk Score", display_value(risk_score))
                            d.metric("Severity", str(severity))

                            st.subheader("Agent Reasoning")

                            tabs = st.tabs(
                                [
                                    "Detection",
                                    "Investigation",
                                    "Risk",
                                    "Response",
                                    "Supervisor",
                                ]
                            )

                            detection = get_nested_dict(
                                result,
                                "detection",
                                "detection_result",
                            )

                            with tabs[0]:
                                st.json(detection)

                            with tabs[1]:
                                st.json(investigation)

                            with tabs[2]:
                                st.json(risk)

                            with tabs[3]:
                                st.json(response)

                            with tabs[4]:
                                st.json(supervisor)

                        else:
                            st.write(result)

                    except Exception as exc:
                        st.error("The selected event could not be processed.")
                        st.exception(exc)


# ============================================================
# INCIDENT DETAILS
# ============================================================

elif page == "Incident Details":

    st.header("04 • Incident Details")

    if alerts_df.empty:
        st.info("No detection alerts are available.")
    else:
        selected_index = st.selectbox(
            "Select incident",
            range(len(alerts_df)),
            format_func=lambda x: f"Incident {x + 1}",
        )

        incident = alerts_df.iloc[selected_index]

        left, right = st.columns(2)

        with left:
            st.subheader("Detection Information")

            for column, value in incident.items():
                if pd.isna(value):
                    continue

                st.write(f"**{column.replace('_', ' ').title()}**")
                st.write(str(value))

        with right:
            st.subheader("Raw Event")
            st.json(incident.to_dict())

        st.divider()

        st.subheader("Explainability")

        explanation_columns = [
            "reason",
            "reasons",
            "evidence",
            "anomaly_reason",
            "explanation",
        ]

        found = False

        for column in explanation_columns:
            if column in incident.index and not pd.isna(incident[column]):
                found = True
                st.info(
                    f"**{column.replace('_', ' ').title()}**\n\n"
                    f"{incident[column]}"
                )

        if not found:
            st.info(
                "The current detection output does not contain a "
                "dedicated explanation field."
            )


# ============================================================
# EXPERIMENTS
# ============================================================

elif page == "Experiments":

    st.header("05 • Experiments & Evaluation")

    st.write(
        "Values shown here are loaded directly from the project's existing "
        "evaluation outputs. No performance values are fabricated."
    )

    st.subheader("Detection Metrics")

    precision = find_metric(metrics, ["precision"])
    recall = find_metric(metrics, ["recall", "true_positive_rate"])
    f1 = find_metric(metrics, ["f1", "f1_score"])
    fpr = find_metric(metrics, ["false_positive_rate", "fpr"])

    a, b, c, d = st.columns(4)

    a.metric(
        "Precision",
        display_value(precision) if precision is not None else "Unavailable",
    )
    b.metric(
        "Recall",
        display_value(recall) if recall is not None else "Unavailable",
    )
    c.metric(
        "F1 Score",
        display_value(f1) if f1 is not None else "Unavailable",
    )
    d.metric(
        "False Positive Rate",
        display_value(fpr) if fpr is not None else "Unavailable",
    )

    metric_rows = []

    for name, value in {
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
        "False Positive Rate": fpr,
    }.items():
        if value is not None:
            try:
                metric_rows.append(
                    {"Metric": name, "Value": float(value)}
                )
            except Exception:
                pass

    if metric_rows:
        metric_df = pd.DataFrame(metric_rows)

        fig = px.bar(
            metric_df,
            x="Metric",
            y="Value",
            text="Value",
        )
        fig.update_traces(
            texttemplate="%{text:.3f}",
            textposition="outside",
        )
        fig.update_layout(
            template="plotly_dark",
            yaxis=dict(range=[0, 1], title="Score"),
            xaxis_title=None,
        )
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("View metrics.json"):
        if metrics:
            st.json(metrics)
        else:
            st.info("metrics.json is unavailable.")

    with st.expander("View experiments_report.json"):
        if experiments:
            st.json(experiments)
        else:
            st.info("experiments_report.json is unavailable.")


# ============================================================
# FOOTER
# ============================================================

st.divider()
st.caption(
    "Agentic Cloud Security • Multi-Agent AI Research Prototype • "
    "Simulated Cloud Environment"
)
