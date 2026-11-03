"""Dataset discovery, validation, target conversion, and train/test loading."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "dataset"
TARGET_COLUMN = "label"
LEAKAGE_COLUMNS = ("id", "attack_cat")


class DatasetError(ValueError):
    """Raised when the dataset files or labels are not suitable for training."""


@dataclass(frozen=True)
class DatasetSplit:
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    dataset_files: tuple[str, ...]
    split_type: str
    target_mapping: dict[int, str]
    excluded_columns: tuple[str, ...]
    cross_split_feature_overlap_rows: int = 0
    cross_split_conflicting_label_rows: int = 0

    @property
    def feature_names(self) -> list[str]:
        return list(self.X_train.columns)


def _read_csv(path: Path) -> pd.DataFrame:
    """Read CSV with BOM handling and a legacy-encoding fallback."""
    try:
        frame = pd.read_csv(path, encoding="utf-8-sig", low_memory=False)
    except UnicodeDecodeError:
        frame = pd.read_csv(path, encoding="cp1252", low_memory=False)
    frame.columns = [str(column).replace("\ufeff", "").strip() for column in frame.columns]
    if frame.columns.duplicated().any():
        raise DatasetError(f"CSV has duplicate column names after normalization: {path.name}")
    return frame


def convert_target(frame: pd.DataFrame, target_column: str = TARGET_COLUMN) -> pd.Series:
    """Validate the official binary label and return 0=Normal, 1=Attack.

    If ``attack_cat`` is supplied, its values are checked against ``label`` so
    an inverted or inconsistent mapping fails instead of being guessed.
    """
    if target_column not in frame:
        raise DatasetError(f"Required binary target column {target_column!r} is missing.")
    raw = frame[target_column]
    if raw.isna().any():
        raise DatasetError(f"Target column {target_column!r} contains missing values.")
    try:
        numeric = pd.to_numeric(raw, errors="raise")
    except (TypeError, ValueError) as exc:
        raise DatasetError("The binary label must contain numeric 0/1 values.") from exc
    values = set(numeric.unique().tolist())
    if not values or not values.issubset({0, 1}):
        raise DatasetError(f"Expected binary label values 0 and 1; found {sorted(values)!r}.")
    target = numeric.astype("int8").rename(target_column)

    if "attack_cat" in frame:
        categories = frame["attack_cat"].astype("string").str.strip()
        if categories.isna().any() or categories.eq("").any():
            raise DatasetError("attack_cat contains empty values and cannot verify label semantics.")
        is_normal = categories.str.casefold().eq("normal")
        inconsistent = (is_normal & target.ne(0)) | (~is_normal & target.ne(1))
        if inconsistent.any():
            raise DatasetError("label conflicts with attack_cat; expected Normal=0 and attacks=1.")
    return target


def _feature_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, tuple[str, ...]]:
    y = convert_target(frame)
    excluded = tuple(column for column in LEAKAGE_COLUMNS if column in frame.columns)
    drop_columns = [TARGET_COLUMN, *excluded]
    X = frame.drop(columns=drop_columns).copy()
    if X.empty or X.shape[1] == 0:
        raise DatasetError("No input features remain after removing target/leakage columns.")
    for column in X.select_dtypes(include="number").columns:
        X[column] = X[column].replace([float("inf"), float("-inf")], float("nan"))
    return X, y, excluded


def _cross_split_overlap(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> tuple[int, int]:
    """Count test feature rows seen in train and labels absent for that row."""
    train_hashes = pd.util.hash_pandas_object(X_train, index=False)
    test_hashes = pd.util.hash_pandas_object(X_test, index=False)
    labels_by_features: dict[int, set[int]] = {}
    for feature_hash, label in zip(train_hashes, y_train):
        labels_by_features.setdefault(int(feature_hash), set()).add(int(label))
    matches = [
        (int(feature_hash), int(label))
        for feature_hash, label in zip(test_hashes, y_test)
        if int(feature_hash) in labels_by_features
    ]
    conflicts = sum(label not in labels_by_features[feature_hash] for feature_hash, label in matches)
    return len(matches), conflicts


def _find_dataset_files(dataset_dir: Path) -> tuple[Path, Path | None, Path | None]:
    if not dataset_dir.is_dir():
        raise DatasetError(f"Dataset directory does not exist: {dataset_dir}")
    csv_files = sorted(path for path in dataset_dir.glob("*.csv") if path.is_file())
    train_files = [path for path in csv_files if "training-set" in path.name.casefold()]
    test_files = [path for path in csv_files if "testing-set" in path.name.casefold()]
    if len(train_files) > 1 or len(test_files) > 1:
        raise DatasetError("Multiple training or testing-set CSVs found; dataset selection is ambiguous.")
    if train_files and test_files:
        return train_files[0], test_files[0], None
    candidates = [
        path for path in csv_files
        if "feature" not in path.name.casefold()
        and "description" not in path.name.casefold()
        and "training-set" not in path.name.casefold()
        and "testing-set" not in path.name.casefold()
    ]
    if len(candidates) == 1:
        return candidates[0], None, candidates[0]
    if train_files and not test_files and len(csv_files) == 1:
        return train_files[0], None, train_files[0]
    raise DatasetError(
        "Expected one official training/testing CSV pair or one labeled CSV for a stratified split."
    )


def load_dataset(
    dataset_dir: str | Path = DEFAULT_DATASET_DIR,
    test_size: float = 0.2,
    random_state: int = 42,
) -> DatasetSplit:
    """Load official train/test files, or stratify a single labeled CSV."""
    directory = Path(dataset_dir).resolve()
    train_path, test_path, single_path = _find_dataset_files(directory)
    train_frame = _read_csv(train_path)
    if train_frame.empty:
        raise DatasetError(f"Training data is empty: {train_path.name}")
    X_train, y_train, excluded = _feature_frame(train_frame)

    if test_path is not None:
        test_frame = _read_csv(test_path)
        if test_frame.empty:
            raise DatasetError(f"Test data is empty: {test_path.name}")
        if list(train_frame.columns) != list(test_frame.columns):
            raise DatasetError("Official training and testing CSVs do not have identical column order/schema.")
        X_test, y_test, test_excluded = _feature_frame(test_frame)
        if excluded != test_excluded or list(X_train.columns) != list(X_test.columns):
            raise DatasetError("Training and testing feature columns differ after target removal.")
        files = (train_path.name, test_path.name)
        split_type = "official_train_test"
        overlap_rows, conflicting_rows = _cross_split_overlap(X_train, y_train, X_test, y_test)
    else:
        if not 0 < test_size < 1:
            raise DatasetError("test_size must be between 0 and 1.")
        X_train, X_test, y_train, y_test = train_test_split(
            X_train,
            y_train,
            test_size=test_size,
            random_state=random_state,
            stratify=y_train,
        )
        files = (single_path.name,) if single_path is not None else (train_path.name,)
        split_type = "stratified_random"
        overlap_rows, conflicting_rows = 0, 0

    if y_train.nunique() != 2 or y_test.nunique() != 2:
        raise DatasetError("Both training and test partitions must contain Normal and Attack records.")
    return DatasetSplit(
        X_train=X_train.reset_index(drop=True),
        X_test=X_test.reset_index(drop=True),
        y_train=y_train.reset_index(drop=True),
        y_test=y_test.reset_index(drop=True),
        dataset_files=files,
        split_type=split_type,
        target_mapping={0: "Normal", 1: "Attack"},
        excluded_columns=excluded,
        cross_split_feature_overlap_rows=overlap_rows,
        cross_split_conflicting_label_rows=conflicting_rows,
    )


def class_distribution(target: pd.Series) -> dict[str, int]:
    """Return named class counts using the documented 0/1 mapping."""
    counts = target.value_counts().to_dict()
    return {"Normal": int(counts.get(0, 0)), "Attack": int(counts.get(1, 0))}
