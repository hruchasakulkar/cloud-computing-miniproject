# ML Detection Module (Member 2)

This module handles the machine learning-based anomaly detection pipeline for the Agentic Cloud Security project. It is responsible for ingesting simulated cloud activity logs, identifying anomalous behavior, and passing structured alerts to the downstream Investigation Agent.

## Deliverables Completed

*   **Dataset Preprocessing & Feature Engineering:** Automatically handles categorical encoding (OneHotEncoder) for cloud roles, actions, regions, and statuses, as well as formatting boolean values (MFA).
*   **Anomaly Model:** Implements an `IsolationForest` (Scikit-learn) model to detect outliers without relying on labeled attack data during the core algorithmic scoring.
*   **Evaluation Metrics:** Calculates Precision, Recall, F1-Score, and False Positive Rate (FPR) based on the simulated test sets.
*   **Detection Agent:** A lightweight Python class (`DetectionAgent`) that evaluates single log entries in real-time, calculates detection latency, assigns a severity based on the anomaly score, and structures the output as a JSON contract.

## Key Files

*   `train_model.py`: Script to process `normal_logs.csv` and `attack_logs.csv`, train the anomaly detection model, and output the evaluation metrics.
*   `agents/detection_agent.py`: The live agent interface. Exposes the `analyze(log_entry)` method used by the pipeline to trigger security alerts.
*   `models/anomaly_model.pkl`: The serialized Sklearn pipeline containing the preprocessor and trained Isolation Forest model.
*   `evaluation/metrics.json`: The generated metrics from the latest training run.

## How to Run

1.  **Train the Model:**
    ```bash
    python train_model.py
    ```
    *This will generate/overwrite `models/anomaly_model.pkl` and `evaluation/metrics.json`.*

2.  **Test the Detection Agent standalone:**
    ```bash
    python agents/detection_agent.py
    ```
    *This will run a sample log entry through the model and print the JSON alert.*
