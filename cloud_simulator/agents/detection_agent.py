import os
import json
import pickle
import pandas as pd
import time

class DetectionAgent:
    def __init__(self, model_path=None):
        if model_path is None:
            # Default to the models directory in the project
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_path = os.path.join(base_dir, 'models', 'anomaly_model.pkl')
            
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
            
    def analyze(self, log_entry):
        """
        Analyzes a single cloud log entry and determines if it is an anomaly.
        
        Args:
            log_entry (dict): A dictionary representing a single log row.
            
        Returns:
            dict or None: Returns an alert JSON if anomalous, else None.
        """
        start_time = time.time()
        
        # Convert single dict to DataFrame for the pipeline
        # Ensure mfa is int for consistent processing
        log_copy = log_entry.copy()
        if 'mfa' in log_copy:
            log_copy['mfa'] = int(log_copy['mfa'] == 'True' or log_copy['mfa'] is True or log_copy['mfa'] == 1)
            
        df = pd.DataFrame([log_copy])
        
        # Make prediction (-1 for anomaly, 1 for normal)
        prediction = self.model.predict(df)[0]
        
        # Calculate latency
        latency = time.time() - start_time
        
        if prediction == -1:
            # Optionally, get the anomaly score (lower is more anomalous)
            score = self.model.decision_function(df)[0]
            
            # Format the output contract for Member 3's Investigation Agent
            alert = {
                "alert_id": f"alert-{log_entry.get('event_id', 'unknown')}",
                "timestamp": log_entry.get('timestamp'),
                "user_id": log_entry.get('user_id'),
                "action": log_entry.get('action'),
                "resource_id": log_entry.get('resource_id'),
                "source_ip": log_entry.get('source_ip'),
                "anomaly_score": round(float(score), 4),
                "severity": "High" if score < -0.1 else "Medium",
                "detection_latency_sec": round(latency, 4),
                "raw_log": log_entry
            }
            return alert
            
        return None

if __name__ == '__main__':
    # Simple test
    agent = DetectionAgent()
    sample_log = {
        "timestamp": "2026-09-30T14:53:06.872652+00:00",
        "event_id": "test-1234",
        "user_id": "user_001",
        "role": "CloudAdmin",
        "source_ip": "1.2.3.4", # unusual IP
        "action": "DeleteVpc",
        "resource_id": "prod_vpc",
        "region": "us-east-1",
        "status": "Success",
        "bytes_out": 500,
        "mfa": False
    }
    
    result = agent.analyze(sample_log)
    if result:
        print("Anomaly Detected!")
        print(json.dumps(result, indent=2))
    else:
        print("Log is normal.")
