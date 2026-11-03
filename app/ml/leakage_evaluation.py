
"""Leakage-aware evaluation for the SecureWork AI IDS.

This script combines the official UNSW-NB15 training and testing CSVs,
groups identical feature vectors, and splits by group to prevent identical
feature vectors from appearing in both evaluation partitions.

It saves results separately under:
    models/comparison/leakage_aware/

It does NOT overwrite the Phase 4 model or official split results.

Important:
- This is a new grouped evaluation, not the official UNSW-NB15 test result.
- Conflicting labels for identical feature vectors are retained and reported.
- The evaluation is offline and does not enable live IDS predictions.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

# Allow running this file directly from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.preprocessor import make_pipeline
from app.ml.comparison import evaluate_fitted_model


DATA_DIR = PROJECT_ROOT / "dataset"
TRAIN_CSV = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_CSV = DATA_DIR / "UNSW_NB15_testing-set.csv"


OUTPUT_DIR = PROJECT_ROOT / "models" / "comparison" / "leakage_aware"
METRICS_PATH = OUTPUT_DIR / "metrics.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20
TARGET_COLUMN = "label"
EXCLUDED_COLUMNS = {"id", "label", "attack_cat"}


def _read_csv(path: Path) -> pd.DataFrame:
    """Read a dataset CSV and validate its required target column."""
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {path}\n"
            "Place the official UNSW-NB15 CSV files in the project's data folder."
        )

    frame = pd.read_csv(path, low_memory=False)

    if TARGET_COLUMN not in frame.columns:
        raise ValueError(
            f"Required target column '{TARGET_COLUMN}' is missing from {path.name}."
        )

    if frame.empty:
        raise ValueError(f"Dataset file is empty: {path}")

    return frame


def _feature_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Separate model features and labels, excluding identifiers and target text."""
    excluded = [column for column in EXCLUDED_COLUMNS if column in frame.columns]
    features = frame.drop(columns=excluded).copy()

    labels = pd.to_numeric(frame[TARGET_COLUMN], errors="raise").astype("int8")

    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError("Expected binary labels: 0 for normal and 1 for attack.")

    # Normalize column order so train/test feature schemas can be compared.
    features = features.reindex(sorted(features.columns), axis=1)

    return features, labels


def load_combined_dataset() -> tuple[
    pd.DataFrame,
    pd.Series,
    dict[str, Any],
]:
    """Load and combine official train/test data without fitting on either set."""
    train_raw = _read_csv(TRAIN_CSV)
    test_raw = _read_csv(TEST_CSV)

    X_train_official, y_train_official = _feature_frame(train_raw)
    X_test_official, y_test_official = _feature_frame(test_raw)

    if list(X_train_official.columns) != list(X_test_official.columns):
        raise ValueError(
            "Official training and testing feature columns do not match."
        )

    X = pd.concat(
        [X_train_official, X_test_official],
        ignore_index=True,
    )
    y = pd.concat(
        [y_train_official, y_test_official],
        ignore_index=True,
    )

    metadata = {
        "training_csv": TRAIN_CSV.name,
        "testing_csv": TEST_CSV.name,
        "official_training_rows": int(len(X_train_official)),
        "official_testing_rows": int(len(X_test_official)),
        "combined_rows": int(len(X)),
        "feature_count": int(X.shape[1]),
        "official_training_label_counts": {
            str(int(label)): int(count)
            for label, count in y_train_official.value_counts().sort_index().items()
        },
        "official_testing_label_counts": {
            str(int(label)): int(count)
            for label, count in y_test_official.value_counts().sort_index().items()
        },
        "combined_label_counts": {
            str(int(label)): int(count)
            for label, count in y.value_counts().sort_index().items()
        },
    }

    return X, y.reset_index(drop=True), metadata


def create_feature_groups(
    X: pd.DataFrame,
    y: pd.Series,
) -> tuple[np.ndarray, dict[str, Any]]:
    """Assign identical feature rows to the same group.

    Factorization is performed on the feature rows only, not the labels.
    Therefore, identical feature vectors with conflicting labels still belong
    to the same group and cannot be split across train and test.

    Pandas factorization avoids constructing a large MultiIndex for the entire
    dataset, helping reduce memory overhead.
    """
    if len(X) != len(y):
        raise ValueError("Feature and label row counts do not match.")

    # Convert each row to a stable hash, then verify collisions by grouping
    # the original feature rows when assigning final group IDs.
    #
    # hash_pandas_object is used to reduce the amount of temporary memory.
    row_hashes = pd.util.hash_pandas_object(X, index=False).to_numpy(
        dtype=np.uint64
    )

    hash_frame = pd.DataFrame({"row_hash": row_hashes})
    hash_group_ids, _ = pd.factorize(hash_frame["row_hash"], sort=False)

    # Verify hash collisions: rows with the same hash but different feature
    # values must not be treated as the same group.
    groups = np.empty(len(X), dtype=np.int64)
    next_group_id = 0

    # Most hashes occur once. Only inspect repeated hashes in detail.
    hash_counts = pd.Series(row_hashes).value_counts()
    repeated_hashes = set(
        hash_counts.index[hash_counts.to_numpy() > 1].tolist()
    )

    unique_hash_mask = ~pd.Series(row_hashes).isin(repeated_hashes).to_numpy()
    unique_positions = np.flatnonzero(unique_hash_mask)

    groups[unique_positions] = np.arange(
        next_group_id,
        next_group_id + len(unique_positions),
        dtype=np.int64,
    )
    next_group_id += len(unique_positions)

    # For repeated hashes, compare actual rows to protect against collisions.
    repeated_positions = np.flatnonzero(~unique_hash_mask)

    if len(repeated_positions):
        repeated_frame = X.iloc[repeated_positions].copy()
        repeated_frame = repeated_frame.reset_index(drop=True)

        # Factorize actual feature rows; labels are intentionally excluded.
        repeated_group_ids, _ = pd.factorize(
            pd.MultiIndex.from_frame(repeated_frame),
            sort=False,
        )

        # Map each local repeated-row group to a globally unique group ID.
        local_to_global: dict[int, int] = {}

        for position, local_group_id in zip(
            repeated_positions,
            repeated_group_ids,
        ):
            local_id = int(local_group_id)

            if local_id not in local_to_global:
                local_to_global[local_id] = next_group_id
                next_group_id += 1

            groups[position] = local_to_global[local_id]

    group_label_frame = pd.DataFrame(
        {
            "group": groups,
            "label": y.to_numpy(),
        }
    )

    labels_per_group = group_label_frame.groupby("group")["label"].nunique()
    conflicting_groups = labels_per_group[labels_per_group > 1]

    group_sizes = pd.Series(groups).value_counts()

    metadata = {
        "unique_feature_groups": int(len(np.unique(groups))),
        "duplicate_rows_beyond_first_occurrence": int(len(X) - len(np.unique(groups))),
        "groups_with_multiple_rows": int((group_sizes > 1).sum()),
        "largest_group_size": int(group_sizes.max()),
        "conflicting_label_group_count": int(len(conflicting_groups)),
        "rows_in_conflicting_label_groups": int(
            group_label_frame["group"].isin(conflicting_groups.index).sum()
        ),
        "grouping_uses_labels": False,
        "hash_collision_protection": "Repeated hashes are grouped by actual feature values.",
    }

    return groups, metadata


def make_grouped_split(
    X: pd.DataFrame,
    y: pd.Series,
    groups: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Create a deterministic group split with both classes in each partition."""
    if len(X) != len(groups):
        raise ValueError("Feature and group row counts do not match.")

    if y.nunique() != 2:
        raise ValueError("The combined dataset must contain both binary classes.")

    # Try deterministic seeds until both partitions contain both classes.
    # This checks only label presence, not model performance.
    for seed in range(RANDOM_STATE, RANDOM_STATE + 100):
        splitter = GroupShuffleSplit(
            n_splits=1,
            test_size=TEST_SIZE,
            random_state=seed,
        )
        train_indices, test_indices = next(
            splitter.split(X, y, groups=groups)
        )

        train_labels = set(y.iloc[train_indices].unique())
        test_labels = set(y.iloc[test_indices].unique())

        train_groups = set(groups[train_indices])
        test_groups = set(groups[test_indices])

        if (
            train_labels == {0, 1}
            and test_labels == {0, 1}
            and train_groups.isdisjoint(test_groups)
        ):
            return train_indices, test_indices, {
                "random_state": seed,
                "requested_test_size": TEST_SIZE,
                "actual_training_rows": int(len(train_indices)),
                "actual_testing_rows": int(len(test_indices)),
                "actual_test_fraction": float(
                    len(test_indices) / len(X)
                ),
                "training_label_counts": {
                    str(int(label)): int(count)
                    for label, count in (
                        y.iloc[train_indices]
                        .value_counts()
                        .sort_index()
                        .items()
                    )
                },
                "testing_label_counts": {
                    str(int(label)): int(count)
                    for label, count in (
                        y.iloc[test_indices]
                        .value_counts()
                        .sort_index()
                        .items()
                    )
                },
                "train_test_group_overlap": 0,
            }

    raise RuntimeError(
        "Could not create a valid group split with both classes in each "
        "partition after 100 deterministic seeds."
    )


def run_evaluation() -> dict[str, Any]:
    """Run a fresh Random Forest evaluation on the grouped split."""
    print("Loading official UNSW-NB15 CSV files...", flush=True)
    X, y, dataset_metadata = load_combined_dataset()

    print(f"Combined rows: {len(X):,}", flush=True)
    print(f"Features: {X.shape[1]}", flush=True)

    print("Grouping identical feature vectors...", flush=True)
    groups, group_metadata = create_feature_groups(X, y)

    print(
        f"Unique feature groups: {group_metadata['unique_feature_groups']:,}",
        flush=True,
    )
    print(
        "Groups with conflicting labels: "
        f"{group_metadata['conflicting_label_group_count']:,}",
        flush=True,
    )

    print("Creating leakage-aware grouped split...", flush=True)
    train_indices, test_indices, split_metadata = make_grouped_split(
        X, y, groups
    )

    X_train = X.iloc[train_indices]
    y_train = y.iloc[train_indices]
    X_test = X.iloc[test_indices]
    y_test = y.iloc[test_indices]

    # Defensive check: no identical feature group may cross the split.
    if not set(groups[train_indices]).isdisjoint(set(groups[test_indices])):
        raise AssertionError("Feature groups overlap between train and test.")

    print(
        f"Training rows: {len(X_train):,}; testing rows: {len(X_test):,}",
        flush=True,
    )
    print("Building and fitting a fresh Random Forest pipeline...", flush=True)

    pipeline = make_pipeline(X_train, random_state=RANDOM_STATE)

    start_time = time.perf_counter()
    pipeline.fit(X_train, y_train)
    training_seconds = time.perf_counter() - start_time

    print("Evaluating held-out grouped test partition...", flush=True)

    evaluation = evaluate_fitted_model(
        name="Random Forest - leakage-aware grouped split",
        model=pipeline,
        X_test=X_test,
        y_test=y_test,
        training_time_seconds=training_seconds,
        configuration={
            "random_state": RANDOM_STATE,
            "split_method": "GroupShuffleSplit",
            "test_size": TEST_SIZE,
            "feature_count": int(X_train.shape[1]),
        },
        supports_probability=True,
    )

    # Convert NumPy values to JSON-compatible values.
    evaluation = json.loads(
        json.dumps(evaluation, default=_json_default)
    )

    results: dict[str, Any] = {
        "evaluation_type": "combined official CSVs with feature-grouped split",
        "warning": (
            "These metrics are from a new grouped evaluation, not the official "
            "UNSW-NB15 test split. Identical feature vectors are kept in one "
            "partition. Identical vectors with conflicting labels remain "
            "ambiguous and are reported in metadata. Results do not establish "
            "real-world performance or enable live IDS predictions."
        ),
        "dataset": dataset_metadata,
        "feature_groups": group_metadata,
        "split": split_metadata,
        "model": {
            "name": "Random Forest",
            "random_state": RANDOM_STATE,
            "training_seconds": float(training_seconds),
        },
        "metrics": evaluation,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print("\nLeakage-aware evaluation completed.", flush=True)
    print(f"Results saved to: {METRICS_PATH}", flush=True)
    print(json.dumps(results["metrics"], indent=2), flush=True)

    return results



def _json_default(value: Any) -> Any:
    """Convert common NumPy scalar values into JSON-compatible values."""
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON.")


if __name__ == "__main__":
    run_evaluation()
