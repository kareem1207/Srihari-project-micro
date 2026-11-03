"""Unit tests for the Phase 4 loader, preprocessing, evaluation, and prediction API."""
import json
import tempfile
import unittest
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from app.ml.data_loader import DatasetError, convert_target, load_dataset
from app.ml.evaluate import calculate_fpr, evaluate_predictions
from app.ml.predict import load_model, predict, predict_proba
from app.ml.preprocessor import RANDOM_FOREST_CONFIG, make_pipeline, make_preprocessor
from app.ml.train import train_and_save


def fixture_frame(rows: int = 12) -> pd.DataFrame:
    labels = [index % 2 for index in range(rows)]
    categories = ["Normal" if label == 0 else "Generic" for label in labels]
    return pd.DataFrame({
        "id": range(rows),
        "dur": [float(index + 1) for index in range(rows)],
        "proto": ["tcp" if index % 3 else "udp" for index in range(rows)],
        "service": ["http" if index % 2 else "-" for index in range(rows)],
        "state": ["FIN" if index % 2 else "CON" for index in range(rows)],
        "attack_cat": categories,
        "label": labels,
    })


class MLDataLoaderTests(unittest.TestCase):
    def test_target_conversion_verifies_normal_and_attack_semantics(self) -> None:
        frame = fixture_frame()
        target = convert_target(frame)
        self.assertEqual(set(target.unique()), {0, 1})
        self.assertEqual(target.iloc[0], 0)
        self.assertEqual(target.iloc[1], 1)

    def test_inconsistent_target_and_attack_category_is_rejected(self) -> None:
        frame = fixture_frame()
        frame.loc[0, "label"] = 1
        with self.assertRaisesRegex(DatasetError, "conflicts"):
            convert_target(frame)

    def test_non_binary_target_is_rejected(self) -> None:
        frame = fixture_frame()
        frame.loc[0, "label"] = 2
        with self.assertRaisesRegex(DatasetError, "Expected binary"):
            convert_target(frame)

    def test_official_train_test_pair_is_used_and_leakage_columns_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            training = fixture_frame(20)
            testing = fixture_frame(10)
            training.to_csv(root / "UNSW_NB15_training-set.csv", index=False, encoding="utf-8-sig")
            testing.to_csv(root / "UNSW_NB15_testing-set.csv", index=False, encoding="utf-8-sig")
            (root / "NUSW-NB15_features.csv").write_text("not,a,model,data\n", encoding="utf-8")

            bundle = load_dataset(root)

        self.assertEqual(bundle.split_type, "official_train_test")
        self.assertEqual(bundle.dataset_files, ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"))
        self.assertEqual((len(bundle.X_train), len(bundle.X_test)), (20, 10))
        self.assertNotIn("id", bundle.X_train)
        self.assertNotIn("attack_cat", bundle.X_train)
        self.assertEqual(bundle.target_mapping, {0: "Normal", 1: "Attack"})
        self.assertEqual(bundle.cross_split_feature_overlap_rows, 10)
        self.assertEqual(bundle.cross_split_conflicting_label_rows, 0)

    def test_single_labeled_csv_gets_reproducible_stratified_split(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_frame(30).to_csv(Path(temporary) / "records.csv", index=False)
            first = load_dataset(temporary, test_size=0.25, random_state=9)
            second = load_dataset(temporary, test_size=0.25, random_state=9)
        self.assertEqual(first.split_type, "stratified_random")
        self.assertEqual(first.y_test.tolist(), second.y_test.tolist())
        self.assertEqual(first.y_test.value_counts().to_dict(), {0: 4, 1: 4})


class MLPreprocessorTests(unittest.TestCase):
    def test_preprocessor_handles_missing_values_and_unseen_categories(self) -> None:
        train = pd.DataFrame({"amount": [1.0, None, 3.0], "protocol": ["tcp", "udp", "tcp"]})
        test = pd.DataFrame({"amount": [None], "protocol": ["icmp"]})
        preprocessor = make_preprocessor(train)
        transformed_train = preprocessor.fit_transform(train)
        transformed_test = preprocessor.transform(test)
        self.assertEqual(transformed_train.shape[0], 3)
        self.assertEqual(transformed_test.shape[0], 1)

    def test_pipeline_uses_random_forest_and_configured_imbalance_handling(self) -> None:
        model = make_pipeline(fixture_frame().drop(columns=["id", "attack_cat", "label"]))
        classifier = model.named_steps["classifier"]
        self.assertIsInstance(classifier, RandomForestClassifier)
        self.assertEqual(classifier.n_estimators, RANDOM_FOREST_CONFIG["n_estimators"])
        self.assertEqual(classifier.class_weight, "balanced_subsample")
        self.assertIn("preprocessor", model.named_steps)


class MLEvaluationPredictionTests(unittest.TestCase):
    def test_fpr_calculation_including_zero_denominator(self) -> None:
        self.assertEqual(calculate_fpr(8, 2), 0.2)
        self.assertEqual(calculate_fpr(0, 0), 0.0)

    def test_metrics_name_confusion_matrix_and_classes(self) -> None:
        metrics = evaluate_predictions([0, 0, 1, 1], [0, 1, 0, 1])
        self.assertEqual(metrics["confusion_matrix"]["true_negative"], 1)
        self.assertEqual(metrics["confusion_matrix"]["false_positive"], 1)
        self.assertEqual(metrics["confusion_matrix"]["false_negative"], 1)
        self.assertEqual(metrics["confusion_matrix"]["true_positive"], 1)
        self.assertEqual(metrics["false_positive_rate"], 0.5)
        self.assertEqual(metrics["test_class_distribution"], {"Normal": 2, "Attack": 2})

    def test_model_artifact_load_and_prediction_result_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture_frame(40)
            X = source.drop(columns=["id", "attack_cat", "label"])
            y = source["label"]
            model = make_pipeline(X)
            model.fit(X, y)
            artifact = root / "securework_ids.joblib"
            joblib.dump(model, artifact)

            loaded = load_model(artifact)
            records = X.iloc[:2].to_dict(orient="records")
            predictions = predict(records, model=loaded)
            probabilities = predict_proba(records, model=loaded)

        self.assertEqual(len(predictions), 2)
        self.assertIn(predictions[0].label, {"Normal", "Attack"})
        self.assertIn(predictions[0].class_id, {0, 1})
        self.assertIsNotNone(predictions[0].probability)
        self.assertEqual(set(probabilities[0]), {"Normal", "Attack"})
        self.assertAlmostEqual(sum(probabilities[0].values()), 1.0)

    def test_training_saves_complete_pipeline_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture_frame(60)
            train = source.iloc[:40].reset_index(drop=True)
            test = source.iloc[40:].reset_index(drop=True)
            from app.ml.data_loader import DatasetSplit
            from app.ml.data_loader import _feature_frame
            X_train, y_train, excluded = _feature_frame(train)
            X_test, y_test, _ = _feature_frame(test)
            split = DatasetSplit(
                X_train, X_test, y_train, y_test, ("fixture.csv",),
                "test_fixture", {0: "Normal", 1: "Attack"}, excluded,
            )
            model_file = root / "models" / "securework_ids.joblib"
            metadata_file = root / "models" / "training_metadata.json"
            model, metadata = train_and_save(split, model_file, metadata_file)
            loaded = load_model(model_file)
            saved_metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            artifact_exists = model_file.is_file()

        self.assertTrue(artifact_exists)
        self.assertTrue(callable(loaded.predict))
        self.assertEqual(metadata["model_type"], "RandomForestClassifier")
        self.assertEqual(saved_metadata["target_mapping"], {"0": "Normal", "1": "Attack"})
        self.assertIn("accuracy", saved_metadata["metrics"])


if __name__ == "__main__":
    unittest.main()
