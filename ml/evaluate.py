"""
Model evaluation and visualization module.

Provides comprehensive functions to evaluate machine learning models for Intrusion
Detection, including metric calculations, reports, and visualization.

Important concepts in cybersecurity ML evaluation:
- Precision: Important because high false positive rates cause alert fatigue,
  leading security teams to ignore warnings.
- Recall: Crucial because missing a real attack (false negative) can compromise
  the entire system.
- F1 Score: Balances precision and recall. Useful when we need a single metric
  that considers both false positives and false negatives.
- ROC-AUC: Measures how well the model ranks predictions (probability scores).
- Security Focus: Security teams often focus on maximizing recall (catching attacks)
  while keeping false positive volume (which impacts precision) manageable.
"""

import json
from typing import Dict, List, Any, Optional
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix, classification_report
    )
except ImportError:
    pass  # Allow import to succeed even if sklearn is not installed yet


def evaluate_model(model: Any, X_test: np.ndarray, y_test: np.ndarray, model_name: str) -> Dict[str, Any]:
    """
    Evaluates a trained model on test data and returns key metrics.
    
    Args:
        model: Trained sklearn-compatible model
        X_test: Test features
        y_test: True labels (0 for NORMAL, 1 for SUSPICIOUS)
        model_name: Name of the model for identification
        
    Returns:
        Dictionary containing calculated metrics
    """
    y_pred = model.predict(X_test)
    
    # Isolation Forest specific handling (it returns 1 for inliers and -1 for outliers)
    if hasattr(model, 'offset_') or "Isolation" in model_name:
        # Assuming we mapped normal=1 to 0 and anomaly=-1 to 1 in training,
        # but if we use standard IF:
        # Convert IF predictions (-1 anomaly, 1 normal) to (1 suspicious, 0 normal)
        y_pred = np.where(y_pred == -1, 1, 0)
    
    try:
        # Try to get probabilities for ROC-AUC
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, 'decision_function'):
            # Normalize decision function to 0-1 range roughly
            decision = model.decision_function(X_test)
            if "Isolation" in model_name:
                # For IF, lower decision scores mean more anomalous
                y_proba = -decision
            else:
                y_proba = decision
            y_proba = (y_proba - y_proba.min()) / (y_proba.max() - y_proba.min() + 1e-10)
        else:
            y_proba = y_pred
            
        roc_auc = roc_auc_score(y_test, y_proba)
    except Exception:
        roc_auc = 0.0
        
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    return {
        "model_name": model_name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": cm
    }

def print_evaluation_report(results: Dict[str, Any]) -> None:
    """
    Pretty-prints all metrics from an evaluation result.
    """
    print(f"\n{'='*40}")
    print(f"Evaluation Report: {results['model_name']}")
    print(f"{'='*40}")
    print(f"Accuracy:  {results['accuracy']:.4f}")
    print(f"Precision: {results['precision']:.4f}")
    print(f"Recall:    {results['recall']:.4f}")
    print(f"F1 Score:  {results['f1']:.4f}")
    print(f"ROC-AUC:   {results['roc_auc']:.4f}")
    print("-" * 40)
    
    cm = results['confusion_matrix']
    if isinstance(cm, list) and len(cm) == 2:
        print("Confusion Matrix:")
        print(f"True Neg (Normal): {cm[0][0]} | False Pos (Alarm): {cm[0][1]}")
        print(f"False Neg (Miss):  {cm[1][0]} | True Pos (Hit):   {cm[1][1]}")
    print(f"{'='*40}\n")

def compare_models(results_list: List[Dict[str, Any]]) -> None:
    """
    Compares multiple models side by side.
    """
    print(f"\n{'='*80}")
    print(f"{'Model Name':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10} | {'ROC-AUC':<10}")
    print(f"{'-'*80}")
    
    for res in results_list:
        print(f"{res['model_name']:<20} | {res['accuracy']:<10.4f} | {res['precision']:<10.4f} | "
              f"{res['recall']:<10.4f} | {res['f1']:<10.4f} | {res['roc_auc']:<10.4f}")
    print(f"{'='*80}\n")

def plot_confusion_matrix(cm: List[List[int]], model_name: str, save_path: Optional[str] = None) -> None:
    """
    Creates and optionally saves confusion matrix plot using matplotlib.
    """
    cm_array = np.array(cm)
    plt.figure(figsize=(6, 5))
    plt.imshow(cm_array, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(f'Confusion Matrix - {model_name}')
    plt.colorbar()
    
    classes = ['Normal (0)', 'Suspicious (1)']
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes)
    plt.yticks(tick_marks, classes)
    
    thresh = cm_array.max() / 2.
    for i in range(cm_array.shape[0]):
        for j in range(cm_array.shape[1]):
            plt.text(j, i, format(cm_array[i, j], 'd'),
                     horizontalalignment="center",
                     color="white" if cm_array[i, j] > thresh else "black")
            
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path)
        print(f"Saved confusion matrix plot to {save_path}")
    else:
        plt.show()
    plt.close()

def plot_roc_curve(y_true: np.ndarray, y_proba: np.ndarray, model_name: str, save_path: Optional[str] = None) -> None:
    """
    Plots the Receiver Operating Characteristic (ROC) curve.
    """
    try:
        from sklearn.metrics import roc_curve, auc
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(6, 5))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'ROC Curve - {model_name}')
        plt.legend(loc="lower right")
        
        if save_path:
            plt.savefig(save_path)
            print(f"Saved ROC curve plot to {save_path}")
        else:
            plt.show()
        plt.close()
    except Exception as e:
        print(f"Could not plot ROC curve: {e}")

def plot_feature_importance(model: Any, feature_names: List[str], save_path: Optional[str] = None) -> None:
    """
    Plots feature importance for tree-based models.
    """
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(10, 6))
        plt.title("Feature Importances")
        plt.bar(range(len(feature_names)), importances[indices], align="center")
        plt.xticks(range(len(feature_names)), [feature_names[i] for i in indices], rotation=45, ha='right')
        plt.xlim([-1, len(feature_names)])
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path)
            print(f"Saved feature importance plot to {save_path}")
        else:
            plt.show()
        plt.close()
    else:
        print(f"Model {type(model).__name__} does not have feature_importances_ attribute.")
