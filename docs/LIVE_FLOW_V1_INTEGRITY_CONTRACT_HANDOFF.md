# D20 in-memory integrity-contract handoff

## Status and scope

D20 introduced the pure in-memory `live_flow_integrity_v1` contract in
`app/security/live_flow_integrity.py`. It builds and verifies an immutable
candidate represented only by `InMemoryFile` byte sequences. It neither reads
nor writes a filesystem and is not connected to capture, the dashboard, SQLite,
IDS services, or model execution.

This is an in-memory contract milestone only. It does not make the filesystem
exporter, selected storage, or a pilot ready for use.

## Canonical bytes and protected content

Canonical JSON is encoded as UTF-8 without a BOM, uses LF line endings and one
trailing LF, and uses these JSON options:

```python
ensure_ascii=False
sort_keys=True
separators=(",", ":")
allow_nan=False
```

NDJSON consists of canonical JSON record lines. Validated records are sorted by
lexical `flow_id` before serialization. JSON object keys are alphabetically
serialized; the semantic feature order remains
`LIVE_FLOW_V1_FEATURE_NAMES` and is validated separately.

The integrity manifest protects exactly these files, in this fixed order:

1. `manifest.json`
2. `flow_records.ndjson`
3. `export_summary.json`

For each, `integrity.json` records its filename, exact byte count, and
lowercase SHA-256 digest. `integrity.json` has no self-hash. `completion.json`
contains the contract version, session ID, and SHA-256 digest of the exact
canonical `integrity.json` bytes. It has no completion timestamp.

## Verification outcomes

The verifier applies the following classification precedence:

1. `UNSUPPORTED_CONTRACT_VERSION`
2. `UNSUPPORTED_SCHEMA_VERSION`
3. `INCOMPLETE`
4. `INVALID_COMPLETE_CLAIM`
5. `INTEGRITY_INVALID`
6. `INTEGRITY_VALID_AUTHENTICITY_UNKNOWN`

Unsupported or missing contract/schema declarations take precedence when the
relevant enclosing version-bearing metadata is available and decodes as a JSON
object. Absent or unparseable enclosing metadata follows the implemented
`INCOMPLETE` or `INVALID_COMPLETE_CLAIM` path, as applicable. A missing
completion marker is `INCOMPLETE`. A present malformed completion marker, or
one present while required protected content or integrity metadata is missing,
is an `INVALID_COMPLETE_CLAIM`. After completion-marker handling reaches
exact-file validation, duplicate, extra, nested, path-like, malformed, or
wrongly typed file entries fail closed as `INTEGRITY_INVALID`.

## Inputs, validation, and privacy

`build_candidate()` reuses the existing `validate_export()` contract. It
rejects invalid or duplicate flow IDs, non-finite feature values, invalid
missingness, metadata mismatches, privacy-allowlist violations, and empty
batches before serialization. It accepts an `InMemoryExportCandidate` whose
`files` member is a tuple of `InMemoryFile` instances.

Malformed file entries, including a raw object, a non-string filename, or
non-byte content, are classified as `INTEGRITY_INVALID`. A malformed container
outside the supported shape, such as `InMemoryExportCandidate(files=None)`, may
raise rather than produce a structured classification; callers must supply the
documented tuple input.

Only the existing schema and manifest allowlists are serialized. The contract
does not serialize endpoint IP addresses, ports, packet payloads, credentials,
labels, dispositions, or free-text operator notes. SHA-256 establishes byte
consistency only: an actor who can modify both protected content and its
integrity metadata can produce a hash-consistent candidate. The valid result
therefore explicitly remains `INTEGRITY_VALID_AUTHENTICITY_UNKNOWN`.

## Prior test evidence

The prior focused run of `tests.test_live_flow_integrity` reported **21 passed,
0 failed, 0 errors, and 0 skipped**. This is prior evidence, not a new test run
or a claim about the current environment. The tests cover deterministic bytes,
record sorting and validation, protected-file hashes, completion dependency,
version precedence, incomplete and malformed candidates, privacy fields, and
the authenticity-unknown result.

## Explicit exclusions and release gates

D20 does not implement or authorize:

- filesystem safety, storage publication, deletion, or retention enforcement;
- selected-storage export or storage-validation-harness execution;
- packet capture or capture-to-export integration;
- database, dashboard, or other production UI integration;
- model training, model tuning, or live IDS inference; or
- pilot authorization or live data collection.

Selected-storage export remains **BLOCKED**, live IDS inference remains
**DISABLED**, and pilot readiness remains **NOT READY**.

## Later Windows filesystem qualification

The existing exporter still has pathname-based staging creation, writes,
publication, cleanup, recursive deletion, and receipt publication. Before any
selected-storage use can be considered, a separately approved design and
platform qualification must address pathname replacement races, junctions and
other reparse points, effective ACLs, no-replace publication, cleanup/deletion
and receipt handling, and recovery after interruption or volume failure.
Integrity bytes do not provide these filesystem guarantees.
