import pandas as pd
import numpy as np
import pickle
import json
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, 'data')
    models_dir = os.path.join(base_dir, 'models')
    eval_dir = os.path.join(base_dir, 'evaluation')
    
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(eval_dir, exist_ok=True)
    
    # 1. Load data
    normal_df = pd.read_csv(os.path.join(data_dir, 'normal_logs.csv'))
    attack_df = pd.read_csv(os.path.join(data_dir, 'attack_logs.csv'))
    
    # Combine datasets
    df = pd.concat([normal_df, attack_df], ignore_index=True)
    
    # Target label: 'is_attack' is 1 for attack, 0 for normal
    y_true = df['is_attack'].astype(int).values
    
    # 2. Feature Engineering & Preprocessing
    # Features selected for anomaly detection
    categorical_features = ['role', 'action', 'region', 'status']
    numerical_features = ['bytes_out']
    boolean_features = ['mfa']
    
    # Convert MFA to int
    df['mfa'] = df['mfa'].astype(int)
    
    features = categorical_features + numerical_features + boolean_features
    X = df[features]
    
    # Preprocessor using OneHotEncoder for categorical
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ],
        remainder='passthrough' # Leave numerical and boolean as is
    )
    
    # 3. Model Definition
    # Contamination is the expected proportion of outliers. We can estimate it or set to a reasonable default like 0.1
    # since we injected 400 attacks and 1000 normal events (~28.5% attacks). We'll set 0.28.
    contamination_rate = len(attack_df) / len(df)
    
    model = IsolationForest(
        n_estimators=100, 
        contamination=contamination_rate, 
        random_state=42
    )
    
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('model', model)
    ])
    
    # 4. Train Model
    print("Training Isolation Forest Model...")
    pipeline.fit(X)
    
    # 5. Evaluate Model
    # IsolationForest outputs -1 for outliers, 1 for inliers
    preds = pipeline.predict(X)
    
    # Convert predictions to match our labels: 1 for anomaly/attack, 0 for normal
    y_pred = np.where(preds == -1, 1, 0)
    
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    metrics = {
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "false_positive_rate": float(fpr),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn)
    }
    
    print("\nModel Evaluation Metrics:")
    for k, v in metrics.items():
        print(f"{k}: {v:.4f}")
        
    with open(os.path.join(eval_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=4)
        
    # 6. Save Model
    model_path = os.path.join(models_dir, 'anomaly_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(pipeline, f)
        
    print(f"\nModel successfully saved to {model_path}")
    print(f"Metrics saved to {os.path.join(eval_dir, 'metrics.json')}")

if __name__ == '__main__':
    main()
