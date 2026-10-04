"""Evaluate a saved model on the same deterministic held-out split."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.predict import DEFAULT_MODEL_PATH
from ml.train_model import DEFAULT_DATASET, load_xy


def evaluate_model(dataset: str | Path = DEFAULT_DATASET, model_path: str | Path = DEFAULT_MODEL_PATH) -> dict:
    try:
        import joblib
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        raise RuntimeError("Install requirements.txt to use optional ML evaluation") from exc
    bundle = joblib.load(model_path)
    X, y = load_xy(dataset)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    model = bundle["model"]
    model_name = bundle["model_name"]
    if model_name == "isolation_forest":
        threshold = float(bundle.get("threshold", 0.0))
        raw = model.decision_function(X_test)
        predictions = [1 if float(score) < threshold else 0 for score in raw]
    else:
        probabilities = model.predict_proba(X_test)[:, list(model.classes_).index(1)] if hasattr(model, "classes_") else model.predict_proba(X_test)[:, 1]
        predictions = [int(float(p) >= float(bundle.get("threshold", 0.5))) for p in probabilities]
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predictions, average="binary", zero_division=0)
    return {
        "model_name": model_name,
        "train_rows": len(y_train),
        "test_rows": len(y_test),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        "labels": ["NORMAL", "SUSPICIOUS"],
        "note": "Calculated from an actual held-out test split of synthetic data.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH))
    args = parser.parse_args()
    result = evaluate_model(args.dataset, args.model_path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
