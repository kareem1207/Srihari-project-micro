"""Focused tests for the isolated offline IDS demonstration command."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

import joblib
import pandas as pd

from app.ml.offline_demo import DEMONSTRATION_LABEL, main, run_offline_demo
from app.ml.preprocessor import make_pipeline


def _fixture_frame(rows: int) -> pd.DataFrame:
    labels = [index % 2 for index in range(rows)]
    return pd.DataFrame({
        "id": range(rows),
        "dur": [float(index + 1) for index in range(rows)],
        "proto": ["tcp" if index % 3 else "udp" for index in range(rows)],
        "service": ["http" if index % 2 else "-" for index in range(rows)],
        "state": ["FIN" if index % 2 else "CON" for index in range(rows)],
        "attack_cat": ["Normal" if label == 0 else "Generic" for label in labels],
        "label": labels,
    })


class OfflineDemoTests(unittest.TestCase):
    def _create_offline_artifacts(self, root: Path) -> tuple[Path, Path]:
        dataset_dir = root / "dataset"
        dataset_dir.mkdir()
        train = _fixture_frame(20)
        test = _fixture_frame(10)
        train.to_csv(dataset_dir / "UNSW_NB15_training-set.csv", index=False, encoding="utf-8-sig")
        test.to_csv(dataset_dir / "UNSW_NB15_testing-set.csv", index=False, encoding="utf-8-sig")

        features = train.drop(columns=["id", "attack_cat", "label"])
        model = make_pipeline(features)
        model.fit(features, train["label"])
        model_path = root / "securework_ids.joblib"
        joblib.dump(model, model_path)
        return dataset_dir, model_path

    def test_uses_serialized_pipeline_with_held_out_data_and_documented_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir, model_path = self._create_offline_artifacts(Path(temporary))
            report = run_offline_demo(dataset_dir, model_path, sample_index=1)

        self.assertEqual(report["demonstration"], DEMONSTRATION_LABEL)
        self.assertEqual(report["scope"], "offline_dataset_only")
        self.assertEqual(report["split_type"], "official_train_test")
        self.assertEqual(report["feature_count"], 4)
        self.assertEqual(report["sample"]["true_label"], "Attack")
        self.assertIn(report["sample"]["predicted_label"], {"Normal", "Attack"})
        self.assertIsNotNone(report["sample"]["attack_probability"])
        self.assertEqual(report["metrics"]["test_samples"], 10)
        self.assertNotIn("features", report["sample"])

    def test_schema_mismatch_fails_closed_before_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir, model_path = self._create_offline_artifacts(Path(temporary))
            mismatched = _fixture_frame(20).drop(columns=["id", "attack_cat", "label", "state"])
            model = make_pipeline(mismatched)
            model.fit(mismatched, _fixture_frame(20)["label"])
            joblib.dump(model, model_path)

            with self.assertRaisesRegex(ValueError, "feature schema"):
                run_offline_demo(dataset_dir, model_path)

    def test_invalid_sample_index_is_reported_without_prediction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir, model_path = self._create_offline_artifacts(Path(temporary))
            with self.assertRaisesRegex(ValueError, "outside the held-out test partition"):
                run_offline_demo(dataset_dir, model_path, sample_index=10)

    def test_cli_returns_clear_nonzero_error_for_missing_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir, _ = self._create_offline_artifacts(Path(temporary))
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["--dataset", str(dataset_dir), "--model", str(Path(temporary) / "missing.joblib")])

        self.assertEqual(result, 2)
        self.assertIn("Offline demonstration failed", stderr.getvalue())
        self.assertIn("not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
