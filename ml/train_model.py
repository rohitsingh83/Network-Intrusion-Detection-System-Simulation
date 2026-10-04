"""Train and evaluate an optional model on the included synthetic CSV.

Example: python -m ml.train_model --model random_forest
Metrics are computed from a stratified held-out split; results are not
representative of real networks because the dataset is synthetic.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from ids.feature_extractor import extract_network_features
from ml.predict import DEFAULT_MODEL_PATH, ML_FEATURES

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "data" / "network_traffic.csv"


def load_xy(dataset_path: str | Path) -> tuple[list[list[float]], list[int]]:
    path = Path(dataset_path)
    vectors: list[list[float]] = []
    labels: list[int] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            features = extract_network_features(row)
            vectors.append([float(features.get(name, 0.0)) for name in ML_FEATURES])
            labels.append(1 if row.get("label", "NORMAL").upper() == "SUSPICIOUS" else 0)
    return vectors, labels


def train_model(
    dataset_path: str | Path = DEFAULT_DATASET,
    model_name: str = "random_forest",
    model_path: str | Path | None = None,
    metrics_path: str | Path | None = None,
    random_state: int = 42,
) -> dict[str, Any]:
    try:
        import joblib
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise RuntimeError("Install requirements.txt to use optional ML training") from exc

    X, y = load_xy(dataset_path)
    if len(set(y)) < 2 or len(y) < 20:
        raise ValueError("Training requires at least 20 records from both classes")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=random_state, stratify=y
    )

    if model_name == "random_forest":
        model = RandomForestClassifier(
            n_estimators=160, max_depth=16, min_samples_leaf=2,
            class_weight="balanced", n_jobs=-1, random_state=random_state,
        )
        model.fit(X_train, y_train)
        probabilities = model.predict_proba(X_test)[:, list(model.classes_).index(1)]
        predictions = (probabilities >= 0.5).astype(int).tolist()
    elif model_name == "logistic_regression":
        model = make_pipeline(
            StandardScaler(),
            LogisticRegression(class_weight="balanced", max_iter=1500, random_state=random_state),
        )
        model.fit(X_train, y_train)
        probabilities = model.predict_proba(X_test)[:, 1]
        predictions = (probabilities >= 0.5).astype(int).tolist()
    elif model_name == "isolation_forest":
        normal_X = [row for row, label in zip(X_train, y_train) if label == 0]
        model = IsolationForest(
            n_estimators=180, contamination="auto", random_state=random_state,
        ).fit(normal_X)
        raw = model.decision_function(X_test)
        # Use the training-normal 5th percentile as a documented operating threshold.
        normal_scores = sorted(float(value) for value in model.decision_function(normal_X))
        threshold = normal_scores[max(0, int(0.05 * (len(normal_scores) - 1)))]
        predictions = [1 if float(score) < threshold else 0 for score in raw]
        probabilities = [1.0 / (1.0 + __import__("math").exp(max(-40.0, min(40.0, float(score - threshold) * 8.0)))) for score in raw]
    else:
        raise ValueError("model_name must be random_forest, logistic_regression, or isolation_forest")

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="binary", zero_division=0
    )
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1]).tolist()
    metrics = {
        "model_name": model_name,
        "dataset": str(Path(dataset_path).name),
        "rows": len(y),
        "train_rows": len(y_train),
        "test_rows": len(y_test),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "confusion_matrix_labels": ["NORMAL", "SUSPICIOUS"],
        "confusion_matrix": matrix,
        "threshold": 0.5 if model_name != "isolation_forest" else float(threshold),
        "note": "Measured on a held-out split of synthetic records; not production efficacy.",
    }

    destination = Path(model_path) if model_path else ROOT / "models" / f"{model_name}_model.joblib"
    destination.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": model,
        "model_name": model_name,
        "feature_names": ML_FEATURES,
        "threshold": metrics["threshold"],
        "metrics": metrics,
    }
    joblib.dump(bundle, destination)
    output_metrics = Path(metrics_path) if metrics_path else ROOT / "models" / f"{model_name}_evaluation.json"
    output_metrics.parent.mkdir(parents=True, exist_ok=True)
    output_metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(f"Model saved to: {destination}")
    print(f"Evaluation saved to: {output_metrics}")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a detector using generated CSV flow features.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--model", choices=["random_forest", "logistic_regression", "isolation_forest"], default="random_forest")
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--metrics-path", default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train_model(args.dataset, args.model, args.model_path, args.metrics_path, args.seed)


if __name__ == "__main__":
    main()
