# Optional ML evaluation record

Measured command in this workspace:

```bash
python -m ml.train_model --model random_forest
```

The command generated a stratified 75/25 train/test split from `data/network_traffic.csv`, fitted the configured Random Forest on 3,750 training records, and calculated metrics on 1,250 held-out records. The exact measured output is stored in `models/random_forest_evaluation.json`.

| Metric | Measured value |
|---|---:|
| Accuracy | 1.0000 |
| Precision (suspicious) | 1.0000 |
| Recall (suspicious) | 1.0000 |
| F1 (suspicious) | 1.0000 |
| Confusion matrix (actual rows × predicted columns) | `[[938, 0], [0, 312]]` |

Labels are ordered `NORMAL`, `SUSPICIOUS`; rows are actual values, columns are predictions. In this synthetic split, TN=938, FP=0, FN=0, TP=312.

**Interpretation:** the generated scenarios encode label-correlated feature patterns by design, so this result demonstrates that the training/evaluation path runs and can separate this synthetic dataset. It does **not** establish performance on real networks, detect actual attacks, or justify deployment decisions. Change the seed/features, test cross-scenario generalization, evaluate external approved data separately, tune thresholds, and report confidence/false-positive impacts before drawing stronger conclusions.
