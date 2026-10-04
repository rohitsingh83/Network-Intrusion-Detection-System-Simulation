# Optional ML artifacts

Run `python -m ml.train_model --model random_forest` to regenerate a local `*.joblib` bundle. Binary model artifacts are ignored by Git so a repository clone remains reproducible from source and the included synthetic CSV. The measured evaluation summary `random_forest_evaluation.json` is versionable and records metrics from the current fixed-seed split; see `../reports/ML_EVALUATION.md` for interpretation and limitations.
