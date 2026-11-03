"""Reusable train-fitted preprocessing and Random Forest pipeline factory."""
from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

RANDOM_FOREST_CONFIG: dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": 24,
    "min_samples_leaf": 2,
    "class_weight": "balanced_subsample",
    "random_state": 42,
    "n_jobs": -1,
}


def make_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    """Build numeric and categorical transforms from training feature dtypes."""
    categorical = [
        column for column in features.columns
        if pd.api.types.is_object_dtype(features[column].dtype)
        or pd.api.types.is_string_dtype(features[column].dtype)
        or isinstance(features[column].dtype, pd.CategoricalDtype)
        or pd.api.types.is_bool_dtype(features[column].dtype)
    ]
    numerical = [column for column in features.columns if column not in categorical]
    transformers: list[tuple[str, Any, list[str]]] = []
    if numerical:
        transformers.append((
            "numeric",
            Pipeline([("imputer", SimpleImputer(strategy="median"))]),
            numerical,
        ))
    if categorical:
        transformers.append((
            "categorical",
            Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=True)),
            ]),
            categorical,
        ))
    if not transformers:
        raise ValueError("At least one numeric or categorical feature is required.")
    return ColumnTransformer(transformers=transformers, remainder="drop")


def make_pipeline(features: pd.DataFrame, random_state: int = 42) -> Pipeline:
    """Create the complete preprocessing → Random Forest model pipeline."""
    config = {**RANDOM_FOREST_CONFIG, "random_state": random_state}
    return Pipeline([
        ("preprocessor", make_preprocessor(features)),
        ("classifier", RandomForestClassifier(**config)),
    ])
