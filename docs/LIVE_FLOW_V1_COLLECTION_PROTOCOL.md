# live_flow_v1 controlled data-collection protocol

## Status

**Planning and validation only. Collection must not begin until every approval
checkpoint in this document is explicitly approved.** No institutional
approval, owner authorization, labels, traffic captures, or collection results
are asserted by this protocol.

## 1. Purpose and scope

The purpose is to create a future labelled dataset whose records conform to
the versioned, metadata-only live_flow_v1 schema. It may support evaluation of
a separately trained detector that uses this exact schema and collector.

It will not establish enterprise-grade protection, prove real-world attack
coverage, validate the existing UNSW-NB15 Phase 4 model for live traffic, or
authorize active security testing. The Phase 4 model and compatibility gate
remain separate and live inference remains disabled throughout collection.

## 2. Authorized environment

Collection is permitted only after explicit approval from the owner of every
device and network involved. Prefer an isolated lab network and owned test
devices. Never collect on a third-party, public, production, campus, or
workplace network without written authorization that defines scope and timing.

**Pending approval:** named environment owner, written authorization record,
allowed devices, time window, and storage location.

## 3. Scenario plan

### Benign scenarios

Collect representative legitimate activity only after authorization:

- ordinary web browsing;
- DNS resolution;
- approved operating-system and application updates;
- authorized file transfers using test content;
- video or voice calls between owned test endpoints;
- idle periods and normal connection setup/teardown; and
- other documented routine activity relevant to the approved environment.

Record each scenario ID, intended activity, participating owned device roles,
start/end timestamps, and known deviations. Do not infer labels from traffic
patterns alone.

### Controlled security scenarios

Use only safe, authorized lab scenarios with predeclared ground truth. This
protocol does not prescribe exploits, malware, credential collection, packet
injection, denial-of-service traffic, or activity against third-party systems.
Any future security scenario requires a separate review defining safety
controls, authorized systems, stopping conditions, and evidence for labels.

**Pending approval:** exact controlled scenarios, expected labels, evidence
sources, operators, and lab safety controls.

## 4. Session definitions and record metadata

Each capture session receives a unique opaque session ID. Store the following
session manifest separately from model features:

| Item | Required handling |
|---|---|
| Capture session ID | Unique, opaque identifier; do not reuse across sessions. |
| Scenario ID | Predefined scenario reference; no free-text sensitive content. |
| Start/end timestamps | Use a documented clock source and timezone-aware ISO 8601 value (numeric UTC offset or `Z`). |
| Schema and collector versions | Record live_flow_v1 and the exact collector version. |
| Interface and collector configuration | Record the `approved_external_usb_wifi` interface category separately from collector configuration. The exported configuration allow-list is idle timeout, finalization policy, and optional application version only. |
| Flow finalization reason | Retain idle_timeout or monitor_stopped for each exported record. |
| Label metadata | Store separately: assigned label, assigner, evidence, confidence, and review status. |

The schema record does not export endpoint IP addresses or ports. If a
separate manifest temporarily needs identifying metadata for lab
troubleshooting, protect it independently and do not join it into model
features.

## 5. Label provenance

Assign labels from documented scenario ground truth and contemporaneous
authorized evidence, not from the detector output. Every label requires:

- label name and taxonomy version;
- person or role assigning the label;
- evidence reference, such as approved scenario log or controlled experiment
  record;
- confidence level and a reason;
- independent review status; and
- timestamp of assignment or review.

Exclude sessions with unresolved, conflicting, or low-confidence labels from
supervised training and final evaluation. Retain them only if a later approved
policy defines a separate unlabelled-analysis use.

**Pending approval:** label taxonomy, confidence scale, reviewer roles, and
the evidence-retention policy.

## 6. Split isolation and leakage control

Allocate complete capture sessions to exactly one partition before collection:
training, validation, or final test. The final-test sessions must be selected
and sealed before model training or threshold selection.

- Do not split flows from one session across partitions.
- Keep repeated or related scenarios, device pairs, and near-duplicate session
  configurations in the same partition where possible.
- Deduplicate exact schema records within each partition and check for matching
  records across partitions.
- Review matching or conflicting records; do not resolve conflicts by copying
  labels or silently retaining one duplicate.
- Do not use validation or final-test records for feature selection,
  preprocessing fit, threshold choice, or model tuning.

**Pending approval:** session allocation, grouping key, deduplication rule,
and the final-test seal procedure.

## 7. Privacy, security, retention, and deletion

The collector must remain payload-free. Do not retain packet payloads,
credentials, message contents, or application bodies. Use opaque session IDs
and keep any temporary endpoint-identifying metadata separate from exported
features.

Before collection, approve:

- named data custodians and least-privilege access roles;
- encrypted storage location and access logging approach;
- retention period for exported records, manifests, and any temporary
  identifying metadata;
- deletion method, verification evidence, and responsible role; and
- incident procedure for accidental collection outside scope.

**Pending approval:** all retention periods, access controls, storage location,
and deletion procedure.

**Verified implementation boundary:** the current exporter validates that an
export manifest's retention deadline is exactly seven days after `actual_end`.
It does not schedule, initiate, or guarantee deletion of any file; deletion is
an explicit caller action and copied or backed-up data remains outside exporter
control.

## 8. Quality checks before modelling

Run and preserve results for the following checks without interpreting them as
model performance:

1. Schema version, feature order, value type, and missingness consistency.
2. Session-manifest completeness and collector configuration consistency.
3. Timestamp ordering, non-negative durations, and valid finalization reasons.
4. Per-feature missingness rates, including protocol-specific missingness.
5. Exact and near-duplicate records within and across partitions.
6. Label completeness, confidence distribution, and class balance.
7. Evidence of capture gaps, dropped packets, interface changes, clock issues,
   or collector restarts.
8. Distribution differences among sessions, scenarios, devices, and partitions.

Capture loss and partial observation remain limitations. They cannot be
reconstructed or treated as measured packet loss.

## 9. Predeclared evaluation plan

Before training, define the positive label, decision threshold process, and
acceptance criteria. Evaluate only once on the sealed final-test sessions after
all design choices are fixed.

Report:

- attack precision, recall, and F1;
- false-positive rate and alert rate over a documented time or flow volume;
- probability calibration;
- confusion matrix and per-scenario results;
- per-record and batch inference latency;
- CPU and memory use on documented hardware; and
- dataset-shift analysis across independent sessions and scenarios.

Do not describe a rule signal or a synthetic test result as an ML prediction.

**Pending approval:** positive-class definition, acceptance thresholds,
calibration approach, alert-rate denominator, and final-test reporting format.

## 10. Stop conditions

Stop collection or do not proceed to modelling when any of the following is
true:

- explicit owner authorization is absent, expired, or outside the intended
  scope;
- collection reaches an unapproved device or network;
- payloads, credentials, or unexpected identifiers are retained;
- the schema or collector configuration changes mid-study without a new
  version and review;
- labels lack provenance, have unresolved conflicts, or fail the approved
  confidence threshold;
- capture loss, missingness, clock issues, or duplicates prevent trustworthy
  interpretation;
- split isolation cannot be demonstrated; or
- approval checkpoints remain incomplete.

## 11. Approval checkpoints

All items require explicit approval before collection begins:

- [ ] Collection environment, network owner, devices, and time window approved.
- [ ] Benign and controlled scenarios documented with authorized ground truth.
- [ ] Label taxonomy, evidence, confidence, and reviewer process approved.
- [ ] Privacy, retention, access control, and deletion rules approved.
- [ ] live_flow_v1 schema, collector version, idle timeout, and finalization
      policy frozen.
- [ ] Training, validation, and sealed final-test session split plan documented.
- [ ] Deduplication and related-session grouping rules documented.
- [ ] Evaluation metrics, acceptance thresholds, and final-test procedure agreed.

Until all boxes are approved, this document authorizes neither traffic
collection nor model training.
