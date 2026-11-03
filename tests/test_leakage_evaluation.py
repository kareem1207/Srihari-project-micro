
"""Unit tests for leakage-aware feature grouping and splitting."""

import unittest

import numpy as np
import pandas as pd

from app.ml.leakage_evaluation import (
    create_feature_groups,
    make_grouped_split,
)


class FeatureGroupingTests(unittest.TestCase):
    def test_identical_feature_rows_share_a_group(self):
        X = pd.DataFrame(
            {
                "feature_a": [1.0, 2.0, 1.0, 3.0],
                "feature_b": ["tcp", "udp", "tcp", "icmp"],
            }
        )
        y = pd.Series([0, 1, 1, 0])

        groups, metadata = create_feature_groups(X, y)

        self.assertEqual(groups[0], groups[2])
        self.assertNotEqual(groups[0], groups[1])
        self.assertNotEqual(groups[0], groups[3])
        self.assertEqual(metadata["unique_feature_groups"], 3)

    def test_conflicting_labels_do_not_split_identical_rows(self):
        X = pd.DataFrame(
            {
                "duration": [10, 20, 10, 30],
                "protocol": ["tcp", "udp", "tcp", "icmp"],
            }
        )
        # Identical features have conflicting labels.
        y = pd.Series([0, 1, 1, 0])

        groups, metadata = create_feature_groups(X, y)

        self.assertEqual(groups[0], groups[2])
        self.assertEqual(metadata["conflicting_label_group_count"], 1)
        self.assertEqual(metadata["rows_in_conflicting_label_groups"], 2)

    def test_mismatched_feature_and_label_lengths_are_rejected(self):
        X = pd.DataFrame({"feature": [1, 2, 3]})
        y = pd.Series([0, 1])

        with self.assertRaisesRegex(ValueError, "row counts do not match"):
            create_feature_groups(X, y)

    def test_split_has_no_group_overlap_and_contains_both_classes(self):
        # Each feature row is unique in this dataset, so the grouping is
        # straightforward. Both classes have enough rows for a valid split.
        X = pd.DataFrame(
            {
                "feature_a": list(range(100)),
                "feature_b": [f"category_{i}" for i in range(100)],
            }
        )
        y = pd.Series([0, 1] * 50)

        groups, _ = create_feature_groups(X, y)
        train_idx, test_idx, metadata = make_grouped_split(X, y, groups)

        train_groups = set(groups[train_idx])
        test_groups = set(groups[test_idx])

        self.assertTrue(train_groups.isdisjoint(test_groups))
        self.assertEqual(set(y.iloc[train_idx].unique()), {0, 1})
        self.assertEqual(set(y.iloc[test_idx].unique()), {0, 1})
        self.assertEqual(metadata["train_test_group_overlap"], 0)

    def test_split_is_reproducible(self):
        X = pd.DataFrame(
            {
                "feature_a": list(range(100)),
                "feature_b": [f"item_{i}" for i in range(100)],
            }
        )
        y = pd.Series([0, 1] * 50)
        groups, _ = create_feature_groups(X, y)

        train_a, test_a, _ = make_grouped_split(X, y, groups)
        train_b, test_b, _ = make_grouped_split(X, y, groups)

        np.testing.assert_array_equal(train_a, train_b)
        np.testing.assert_array_equal(test_a, test_b)


if __name__ == "__main__":
    unittest.main()
