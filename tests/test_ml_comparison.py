"""Tests for the offline-only model comparison harness."""
import json
import tempfile
import unittest
from pathlib import Path

import joblib
import pandas as pd

from app.ml.comparison import (
    evaluate_fitted_model,
    make_dense_scaled_preprocessor,
    model_specs,
    run_comparison,
    save_comparison,
)
from app.ml.data_loader import DatasetSplit
from app.ml.preprocessor import make_pipeline


def fixture_split() -> DatasetSplit:
    train = pd.DataFrame({
        "dur": [0.1, 0.2, 1.2, 1.5, 0.3, 1.8, 0.4, 1.9],
        "proto": ["tcp", "udp", "tcp", "udp", "tcp", "udp", "tcp", "udp"],
        "state": ["CON", "FIN", "CON", "FIN", "CON", "FIN", "CON", "FIN"],
    })
    test = pd.DataFrame({
        "dur": [0.15, 1.4, 0.25, 1.7],
        "proto": ["tcp", "udp", "tcp", "udp"],
        "state": ["CON", "FIN", "CON", "FIN"],
    })
    return DatasetSplit(
        train, test, pd.Series([0, 1, 1, 1, 0, 1, 0, 1]), pd.Series([0, 1, 0, 1]),
        ("train.csv", "test.csv"), "official_train_test", {0: "Normal", 1: "Attack"}, (), 1, 0,
    )


class ComparisonHarnessTests(unittest.TestCase):
    def test_dense_preprocessor_is_train_fitted_and_dense(self) -> None:
        split = fixture_split()
        transformer = make_dense_scaled_preprocessor(split.X_train)
        train = transformer.fit_transform(split.X_train)
        test = transformer.transform(split.X_test)
        self.assertEqual(train.shape[0], len(split.X_train))
        self.assertEqual(test.shape[0], len(split.X_test))
        self.assertFalse(hasattr(train, "toarray"))

    def test_specs_mark_probability_and_stacking_configuration(self) -> None:
        specs = model_specs()
        self.assertFalse(specs["linear_svm"].supports_probability)
        self.assertTrue(specs["soft_voting"].supports_probability)
        self.assertEqual(specs["stacking"].configuration["cv"], 3)
        self.assertEqual(specs["stacking"].configuration["stack_method"], "predict_proba")

    def test_evaluate_fitted_model_records_latency_size_and_calibration(self) -> None:
        split = fixture_split()
        model = make_pipeline(split.X_train)
        model.fit(split.X_train, split.y_train)
        result = evaluate_fitted_model("fixture", model, split.X_test, split.y_test, 0.1, {}, True)
        self.assertIn("accuracy", result)
        self.assertGreater(result["model_size_bytes"], 0)
        self.assertIn("calibration", result)
        self.assertIn("inference_seconds_per_record", result)

    def test_comparison_uses_saved_baseline_and_writes_metadata(self) -> None:
        split = fixture_split()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model_path = root / "baseline.joblib"
            metadata_path = root / "training_metadata.json"
            baseline = make_pipeline(split.X_train)
            baseline.fit(split.X_train, split.y_train)
            joblib.dump(baseline, model_path)
            metadata_path.write_text(json.dumps({"metrics": {"training_time_seconds": 0.2}}))
            report = run_comparison(
                split, selected_models=("extra_trees",), model_path=model_path,
                metadata_path=metadata_path,
            )
            output = save_comparison(report, root / "comparison")
            saved = json.loads(output.read_text())
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["results"][0]["name"], "Random Forest (Phase 4 baseline)")
        self.assertEqual(saved["split"]["type"], "official_train_test")


if __name__ == "__main__":
    unittest.main()
