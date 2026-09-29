"""
Training module for Intrusion Detection System Machine Learning models.

Trains Logistic Regression (supervised), Random Forest (supervised), and
Isolation Forest (unsupervised) models. Saves the best model and evaluation metrics.

Supervised Learning (LR, RF):
Requires labeled data (NORMAL, SUSPICIOUS) to learn decision boundaries.
Pros: High accuracy on known attack signatures.
Cons: Can struggle with zero-day (novel) attacks if they don't resemble training data.

Unsupervised Learning (Isolation Forest):
Learns what "normal" traffic looks like and flags anomalies (outliers).
Pros: Can detect zero-day attacks by identifying deviations from normal baselines.
Cons: Higher false positive rates; unusual but benign traffic is flagged.

Why accuracy alone is insufficient:
Network traffic is highly imbalanced (e.g., 99% normal, 1% attacks).
A model predicting "NORMAL" always would achieve 99% accuracy but fail completely
at intrusion detection. Metrics like Precision, Recall, and F1 are critical.
"""

import os
import argparse
import json
import pandas as pd
import numpy as np

try:
    import joblib
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.metrics import classification_report, confusion_matrix
except ImportError as e:
    print(f"Warning: Import failed: {e}")
    print("Run: pip install scikit-learn pandas joblib")

# Import evaluation functions from our module
try:
    from ml.evaluate import evaluate_model, print_evaluation_report, compare_models
except ImportError:
    try:
        from evaluate import evaluate_model, print_evaluation_report, compare_models
    except ImportError:
        evaluate_model = None


def compute_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """Computes necessary derived features for the dataset."""
    df_out = df.copy()
    
    # Avoid division by zero
    dur = df_out['duration_seconds'].replace(0, 0.001)
    
    if 'bytes_per_second' not in df_out.columns:
        df_out['bytes_per_second'] = df_out['byte_count'] / dur
    if 'packets_per_second' not in df_out.columns:
        df_out['packets_per_second'] = df_out['packet_count'] / dur
    
    conn = df_out['connection_count'].replace(0, 1)
    if 'failure_ratio' not in df_out.columns:
        df_out['failure_ratio'] = df_out.get('failed_connection_count', 0) / conn
        
    pkts = df_out['packet_count'].replace(0, 1)
    if 'syn_ratio' not in df_out.columns:
        df_out['syn_ratio'] = df_out.get('syn_count', 0) / pkts
        
    if 'connection_rate' not in df_out.columns:
        df_out['connection_rate'] = df_out['connection_count'] / dur
        
    return df_out

def main():
    parser = argparse.ArgumentParser(description="Train ML models for IDS detection.")
    parser.add_argument('--data-path', type=str, default='data/network_traffic.csv', help='Path to training data')
    parser.add_argument('--output-dir', type=str, default='models/', help='Directory to save outputs')
    parser.add_argument('--model-type', type=str, choices=['all', 'rf', 'lr', 'if'], default='all', help='Model to train')
    args = parser.parse_args()

    print(f"Loading data from {args.data_path}...")
    try:
        df = pd.read_csv(args.data_path)
    except FileNotFoundError:
        print(f"Error: Could not find {args.data_path}. Please generate data first.")
        return

    # 2. Compute derived features
    df = compute_derived_features(df)
    
    features = [
        'packet_count', 'byte_count', 'duration_seconds',
        'bytes_per_second', 'packets_per_second',
        'connection_count', 'failed_connection_count',
        'syn_count', 'rst_count', 'average_packet_size',
        'failure_ratio', 'syn_ratio', 'connection_rate'
    ]
    
    # Verify all features exist
    for f in features:
        if f not in df.columns:
            df[f] = 0.0
            
    # 3. Handle missing values and infinities
    X_raw = df[features].copy()
    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_raw.fillna(0, inplace=True)
    
    # 5. Encode labels: NORMAL=0, SUSPICIOUS=1
    if 'label' not in df.columns:
        print("Error: Dataset must contain a 'label' column with NORMAL/SUSPICIOUS values.")
        return
        
    y = (df['label'].str.upper() == 'SUSPICIOUS').astype(int)
    
    # 6. Split 80/20 train/test with stratification
    print("Splitting data (80% train, 20% test) with stratification...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Scale features
    print("Scaling features with StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    models_to_train = {}
    if args.model_type in ['all', 'lr']:
        models_to_train['LogisticRegression'] = LogisticRegression(max_iter=1000, random_state=42)
    if args.model_type in ['all', 'rf']:
        models_to_train['RandomForest'] = RandomForestClassifier(n_estimators=100, random_state=42)
    if args.model_type in ['all', 'if']:
        # Contamination estimates the proportion of outliers in the data
        contamination = min(0.5, max(0.01, sum(y_train) / len(y_train)))
        models_to_train['IsolationForest'] = IsolationForest(contamination=contamination, random_state=42)
        
    # 7 & 8. Train and evaluate
    results = []
    trained_models = {}
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    for name, model in models_to_train.items():
        print(f"\nTraining {name}...")
        
        # Fit model
        if name == 'IsolationForest':
            # Unsupervised: train mostly on normal traffic (or all traffic since IF is robust)
            # but for standard usage, we just fit on X_train_scaled
            model.fit(X_train_scaled)
        else:
            model.fit(X_train_scaled, y_train)
            
        trained_models[name] = model
        
        # Evaluate
        print(f"Evaluating {name}...")
        res = evaluate_model(model, X_test_scaled, y_test, name)
        results.append(res)
        
        # Print formatted reports
        print_evaluation_report(res)
        
        # Print scikit-learn classification report
        y_pred = model.predict(X_test_scaled)
        if name == 'IsolationForest':
            y_pred = np.where(y_pred == -1, 1, 0)
        
        print(f"\nDetailed Classification Report - {name}:")
        print(classification_report(y_test, y_pred, target_names=['NORMAL', 'SUSPICIOUS'], zero_division=0))
        
        # Optional: Save confusion matrix plot
        try:
            from ml.evaluate import plot_confusion_matrix
        except ImportError:
            from evaluate import plot_confusion_matrix
        plot_path = os.path.join(args.output_dir, f"{name}_cm.png")
        plot_confusion_matrix(res['confusion_matrix'], name, save_path=plot_path)

    if len(results) > 1:
        compare_models(results)
        
    # 9. Save best model (based on F1 score to balance P/R)
    best_result = max(results, key=lambda x: x['f1'])
    best_model_name = best_result['model_name']
    best_model = trained_models[best_model_name]
    
    print(f"\nBest model based on F1 Score: {best_model_name} (F1: {best_result['f1']:.4f})")
    
    bundle = {
        'model': best_model,
        'scaler': scaler,
        'feature_names': features,
        'model_name': best_model_name
    }
    
    model_save_path = os.path.join(args.output_dir, 'ids_model.joblib')
    joblib.dump(bundle, model_save_path)
    print(f"Saved best model bundle to {model_save_path}")
    
    # 10. Save evaluation results
    eval_save_path = os.path.join(args.output_dir, 'evaluation_results.json')
    with open(eval_save_path, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"Saved evaluation results to {eval_save_path}")

if __name__ == "__main__":
    main()
