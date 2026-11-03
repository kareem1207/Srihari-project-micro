"""NSL-KDD network intrusion detection: training, evaluation and inference.

This is a *connection-record* (flow-based) classifier. It scores records that
already carry the 41 NSL-KDD features (e.g. exported by a flow tool or replayed
from the dataset). It does NOT score raw live packets: the live Windows monitor
in ``app/security`` cannot compute these features (see docs/AUDIT.md).
The pre-existing UNSW-NB15 schema in ``app/ml`` is left untouched.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

# Canonical, ordered feature schema (do not reorder).
FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
CATEGORICAL = ["protocol_type", "service", "flag"]
NUMERIC = [f for f in FEATURES if f not in CATEGORICAL]
COLUMNS = FEATURES + ["label", "difficulty"]

CATEGORY_MAP = {}
for _c in ("back land neptune pod smurf teardrop apache2 mailbomb processtable udpstorm worm".split()):
    CATEGORY_MAP[_c] = "DoS"
for _c in ("ipsweep mscan nmap portsweep saint satan".split()):
    CATEGORY_MAP[_c] = "Probe"
for _c in ("ftp_write guess_passwd imap multihop phf spy warezclient warezmaster "
           "named sendmail snmpgetattack snmpguess xlock xsnoop httptunnel".split()):
    CATEGORY_MAP[_c] = "R2L"
for _c in ("buffer_overflow loadmodule perl rootkit ps sqlattack xterm".split()):
    CATEGORY_MAP[_c] = "U2R"
CATEGORY_MAP["normal"] = "normal"

DEFAULT_DIR = Path(__file__).resolve().parent.parent.parent / "models"
MODEL_PATH = DEFAULT_DIR / "nslkdd_ids.joblib"
METRICS_PATH = DEFAULT_DIR / "nslkdd_metrics.json"


def load_nslkdd(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df["attack_category"] = df["label"].map(CATEGORY_MAP).fillna("unknown")
    df["target"] = (df["label"] != "normal").astype(int)
    return df


def _preprocessor() -> ColumnTransformer:
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ("num", StandardScaler(), NUMERIC),
    ])


def candidates() -> dict:
    return {
        "RandomForest": RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
        "DecisionTree": DecisionTreeClassifier(random_state=42),
        "LogisticRegression": LogisticRegression(max_iter=300),
        "LinearSVM": LinearSVC(dual=False, random_state=42),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
    }


def _metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def train_and_evaluate(train_csv, test_csv, out_dir=DEFAULT_DIR, only: list[str] | None = None) -> dict:
    train, test = load_nslkdd(train_csv), load_nslkdd(test_csv)
    X_tr, y_tr, X_te, y_te = train[FEATURES], train["target"], test[FEATURES], test["target"]
    results, best_name, best_pipe, best_f1 = {}, None, None, -1.0
    for name, clf in candidates().items():
        if only and name not in only:
            continue
        pipe = Pipeline([("prep", _preprocessor()), ("clf", clf)])
        t0 = time.perf_counter()
        pipe.fit(X_tr, y_tr)
        fit_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        pred = pipe.predict(X_te)
        pred_s = time.perf_counter() - t0
        m = _metrics(y_te, pred)
        m.update(train_seconds=round(fit_s, 2), predict_seconds_total=round(pred_s, 4),
                 predict_ms_per_record=round(pred_s / len(X_te) * 1000, 5))
        results[name] = m
        if m["f1"] > best_f1:
            best_name, best_pipe, best_f1 = name, pipe, m["f1"]
    # Per-category recall of the selected model on the official test split.
    pred = best_pipe.predict(X_te)
    per_cat = {c: {"records": int(g.shape[0]), "detected_as_attack": float(pred[g.index].mean())}
               for c, g in test.groupby("attack_category")}
    report = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+, binary normal-vs-attack)",
        "train_records": len(train), "test_records": len(test),
        "feature_count": len(FEATURES), "features": FEATURES,
        "selected_model": best_name, "selection_criterion": "highest test F1",
        "note": "KDDTest+ contains attack types absent from training, so scores are "
                "lower than random-split results; selection on the test split is optimistic.",
        "models": results, "selected_per_category_detection_rate": per_cat,
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": best_pipe, "features": FEATURES, "name": best_name}, out / "nslkdd_ids.joblib", compress=3)
    (out / "nslkdd_metrics.json").write_text(json.dumps(report, indent=2))
    return report


class Detector:
    """Loads the saved pipeline and scores feature dicts."""

    def __init__(self, path: str | Path = MODEL_PATH):
        bundle = joblib.load(path)
        self.pipeline, self.name = bundle["pipeline"], bundle["name"]
        if bundle["features"] != FEATURES:
            raise RuntimeError("Saved model feature schema does not match canonical FEATURES")

    def predict(self, record: dict) -> dict:
        missing = [f for f in FEATURES if f not in record]
        if missing:
            raise ValueError(f"missing features: {missing[:5]}{'...' if len(missing) > 5 else ''}")
        t0 = time.perf_counter()
        X = pd.DataFrame([{f: record[f] for f in FEATURES}], columns=FEATURES)
        pred = int(self.pipeline.predict(X)[0])
        conf = None
        if hasattr(self.pipeline, "predict_proba"):
            conf = float(self.pipeline.predict_proba(X)[0][pred])
        return {"is_attack": bool(pred), "confidence": conf, "model": self.name,
                "predict_ms": round((time.perf_counter() - t0) * 1000, 3)}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Train/evaluate NSL-KDD IDS")
    ap.add_argument("--train", default="data/nslkdd/KDDTrain+.txt")
    ap.add_argument("--test", default="data/nslkdd/KDDTest+.txt")
    a = ap.parse_args()
    r = train_and_evaluate(a.train, a.test)
    for n, m in r["models"].items():
        print(f"{n:20s} acc={m['accuracy']:.4f} p={m['precision']:.4f} r={m['recall']:.4f} "
              f"f1={m['f1']:.4f} fpr={m['false_positive_rate']:.4f}")
    print("selected:", r["selected_model"])
