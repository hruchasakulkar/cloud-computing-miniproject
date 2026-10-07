import os
import json
import time
import pandas as pd
from agents.detection_agent import DetectionAgent

def run_experiments():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, 'data')
    eval_dir = os.path.join(base_dir, 'evaluation')
    
    os.makedirs(eval_dir, exist_ok=True)
    
    agent = DetectionAgent()
    
    # --- Experiment E1: Normal Activity (Measure FPR and Baseline Latency) ---
    print("Running Experiment E1: Normal Activity...")
    normal_df = pd.read_csv(os.path.join(data_dir, 'normal_logs.csv'))
    
    e1_results = {
        "total_events": len(normal_df),
        "false_positives": 0,
        "total_latency_sec": 0
    }
    
    for _, row in normal_df.iterrows():
        log_dict = row.to_dict()
        start = time.time()
        alert = agent.analyze(log_dict)
        e1_results["total_latency_sec"] += (time.time() - start)
        
        if alert is not None:
            e1_results["false_positives"] += 1
            
    e1_results["false_positive_rate"] = e1_results["false_positives"] / e1_results["total_events"]
    e1_results["avg_latency_ms"] = (e1_results["total_latency_sec"] / e1_results["total_events"]) * 1000
    print(f"E1 Results: FPR = {e1_results['false_positive_rate']:.2%}, Avg Latency = {e1_results['avg_latency_ms']:.2f} ms")


    # --- Experiment E2: Attack Activity (Measure Detection Rate per Scenario) ---
    print("\nRunning Experiment E2: Attack Scenarios...")
    attack_df = pd.read_csv(os.path.join(data_dir, 'attack_logs.csv'))
    
    # Dictionary to hold metrics per scenario
    scenario_metrics = {}
    total_true_positives = 0
    total_attacks = len(attack_df)
    total_attack_latency = 0
    
    # Store all generated alerts for Member 3
    generated_alerts = []
    
    for _, row in attack_df.iterrows():
        log_dict = row.to_dict()
        scenario = log_dict.get("scenario", "unknown")
        
        if scenario not in scenario_metrics:
            scenario_metrics[scenario] = {"total": 0, "detected": 0}
            
        scenario_metrics[scenario]["total"] += 1
        
        start = time.time()
        alert = agent.analyze(log_dict)
        total_attack_latency += (time.time() - start)
        
        if alert is not None:
            scenario_metrics[scenario]["detected"] += 1
            total_true_positives += 1
            generated_alerts.append(alert)
            
    # Calculate detection rates per scenario
    e2_results = {
        "overall_detection_rate": total_true_positives / total_attacks,
        "avg_latency_ms": (total_attack_latency / total_attacks) * 1000,
        "scenarios": {}
    }
    
    for sc, counts in scenario_metrics.items():
        rate = counts["detected"] / counts["total"] if counts["total"] > 0 else 0
        e2_results["scenarios"][sc] = {
            "total_attacks": counts["total"],
            "detected": counts["detected"],
            "detection_rate": rate
        }
        print(f"Scenario '{sc}': Detection Rate = {rate:.2%}")
        
    print(f"Overall Detection Rate (Recall): {e2_results['overall_detection_rate']:.2%}")
    
    # Save experiments report
    final_report = {
        "E1_Normal_Activity": e1_results,
        "E2_Attack_Scenarios": e2_results
    }
    
    report_path = os.path.join(eval_dir, 'experiments_report.json')
    with open(report_path, 'w') as f:
        json.dump(final_report, f, indent=4)
    print(f"\nSaved detailed experiment metrics to {report_path}")
    
    # Save alerts for Member 3 to integrate easily
    alerts_path = os.path.join(data_dir, 'detection_alerts.json')
    with open(alerts_path, 'w') as f:
        json.dump(generated_alerts, f, indent=4)
    print(f"Saved {len(generated_alerts)} mock alerts to {alerts_path} for Member 3 to use in Day 3.")

if __name__ == '__main__':
    run_experiments()
