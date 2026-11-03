
"""Tune SecureWork AI's Random Forest using training-only cross-validation.

The official test partition is deliberately not used for model selection.
The existing baseline model and metadata are never overwritten.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import sklearn
from sklearn.model_selection import GridSearchCV, StratifiedKFold

from app.ml.data_loader import load_dataset
from app.ml.preprocessor import make_pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = PROJECT_ROOT / "models" / "comparison" / "rf_tuning"
OUTPUT_FILE = OUTPUT_DIR / "tuning_results.json"

RANDOM_STATE = 42


def main() -> int:
    print("Loading the existing UNSW-NB15 dataset split...")
    bundle = load_dataset()

    # Only the official training partition is used during tuning.
    X_train = bundle.X_train
    y_train = bundle.y_train

    print(f"Training rows: {len(X_train):,}")
    print(f"Features: {X_train.shape[1]}")
    print(f"Training class distribution:\n{y_train.value_counts().sort_index()}")
    print("\nThe official test partition will not be used for tuning.")

    pipeline = make_pipeline(X_train, random_state=RANDOM_STATE)

    # Eight deliberately selected configurations rather than an exhaustive
    # search, to keep runtime manageable on a desktop.
    parameter_grid = [
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [24],
            "classifier__min_samples_leaf": [1],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [150],
            "classifier__max_depth": [24],
            "classifier__min_samples_leaf": [1],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [18],
            "classifier__min_samples_leaf": [2],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [30],
            "classifier__min_samples_leaf": [2],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [None],
            "classifier__min_samples_leaf": [2],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [24],
            "classifier__min_samples_leaf": [4],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [24],
            "classifier__min_samples_leaf": [2],
            "classifier__max_features": [0.7],
            "classifier__class_weight": ["balanced_subsample"],
        },
        {
            "classifier__n_estimators": [100],
            "classifier__max_depth": [24],
            "classifier__min_samples_leaf": [2],
            "classifier__max_features": ["sqrt"],
            "classifier__class_weight": ["balanced"],
        },
    ]

    cv = StratifiedKFold(
        n_splits=3,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    search = GridSearchCV(
        estimator=pipeline,
        param_grid=parameter_grid,
        scoring={
            "f1": "f1",
            "precision": "precision",
            "recall": "recall",
        },
        refit="f1",
        cv=cv,
        n_jobs=1,
        verbose=2,
        return_train_score=False,
        error_score="raise",
    )

    print("\nStarting Random Forest tuning.")
    print("Expected work: 8 configurations × 3 folds = 24 model fits.")
    print("Each model uses its own train-fitted preprocessing pipeline.\n")

    started = time.perf_counter()
    search.fit(X_train, y_train)
    elapsed = time.perf_counter() - started

    results = pd.DataFrame(search.cv_results_)
    results = results.sort_values("rank_test_f1")

    candidates = []
    for _, row in results.iterrows():
        candidates.append({
            "rank_by_mean_cv_f1": int(row["rank_test_f1"]),
            "parameters": row["params"],
            "mean_cv_f1": float(row["mean_test_f1"]),
            "std_cv_f1": float(row["std_test_f1"]),
            "mean_cv_precision": float(row["mean_test_precision"]),
            "mean_cv_recall": float(row["mean_test_recall"]),
            "mean_fit_time_seconds": float(row["mean_fit_time"]),
        })

    output = {
        "experiment": "Random Forest training-only hyperparameter tuning",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "UNSW-NB15 official training partition only",
        "training_rows": int(len(X_train)),
        "feature_count": int(X_train.shape[1]),
        "cv": {
            "strategy": "StratifiedKFold",
            "folds": 3,
            "shuffle": True,
            "random_state": RANDOM_STATE,
        },
        "selection_metric": "mean cross-validation attack F1",
        "configurations_tested": len(candidates),
        "elapsed_seconds": elapsed,
        "scikit_learn_version": sklearn.__version__,
        "best_parameters": search.best_params_,
        "best_mean_cv_f1": float(search.best_score_),
        "candidates": candidates,
        "notes": [
            "The official test partition was not used for model selection.",
            "The existing baseline model and metadata were not overwritten.",
            "Cross-validation results are estimates, not real-world guarantees.",
        ],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("\n========== TUNING SUMMARY ==========")
    print(f"Elapsed time: {elapsed / 60:.1f} minutes")
    print(f"Best mean CV attack F1: {search.best_score_:.5f}")
    print("Best parameters:")
    print(json.dumps(search.best_params_, indent=2))
    print("\nTop candidates:")
    print(results[
        [
            "rank_test_f1",
            "mean_test_f1",
            "std_test_f1",
            "mean_test_precision",
            "mean_test_recall",
            "mean_fit_time",
        ]
    ].head(8).to_string(index=False))
    print(f"\nFull results saved to: {OUTPUT_FILE}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
