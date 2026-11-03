# SecureWork AI ML experiments

## Scope

`app/ml/tune_random_forest.py` and `app/ml/evaluate_tuned_rf.py` are offline
research scripts. They are separate from the Phase 4 baseline artifact and do
not enable live intrusion-detection inference.

## Candidate selection

`app/ml/tune_random_forest.py` uses training-only cross-validation to select
among its candidate Random Forest configurations. The official UNSW-NB15 test
partition is deliberately excluded from that selection process.

## Comparative evaluation

`app/ml/evaluate_tuned_rf.py` fits the named candidate configurations on the
official training partition and compares them on the official test partition.
That partition was already used in earlier project studies. Its results are
therefore comparative evidence for these experiments, not a fresh final
held-out evaluation.

## Boundaries

The experimental scripts write their comparison outputs under the ignored
`models/comparison/` directory. They do not overwrite
`models/securework_ids.joblib`, retrain the deployed Phase 4 baseline, or
change the live IDS feature-compatibility gate. Their measurements do not
establish that an offline candidate is compatible with live metadata-only
traffic.
