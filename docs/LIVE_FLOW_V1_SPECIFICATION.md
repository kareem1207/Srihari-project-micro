# live_flow_v1 schema and collection specification

## Status and scope

live_flow_v1 is a versioned, payload-free contract for a future detector. It
does not modify the Phase 4 UNSW-NB15 model, its 42-field compatibility gate,
dashboard behaviour, or IDS event persistence. Exporting a record is
instrumentation only; it neither labels a flow nor produces a detection.

The implementation is app.security.live_flow_schema. Its ordered feature
contract is LIVE_FLOW_V1_FEATURES, and every export contains:

- schema version: live_flow_v1;
- collector version: securework_flow_aggregator_v1;
- externally supplied capture-session ID and idle timeout;
- finalization reason (idle_timeout or monitor_stopped);
- first-observed-packet orientation convention; and
- feature values plus a reason for each null value.

Endpoint IP addresses and ports are deliberately absent from the exported
record. They remain in the in-memory CompletedFlow only long enough to derive
the is_sm_ips_ports feature.

## Orientation, boundaries, and units

A bidirectional flow uses an unordered endpoint-pair and protocol key. The
endpoint in the first packet observed by SecureWork is source; the other
endpoint is destination. These names do not identify a client, server, or the
direction used by UNSW-NB15.

Flows end after the configured idle timeout when a later packet is processed,
or when monitoring stops. Duration is last_seen minus first_seen, in seconds.
All byte fields use Scapy's captured len(packet), which is explicitly named
captured_bytes; it is not claimed to equal a network exporter byte counter.

## Ordered features

| Feature | Type / units | Calculation or observation | Minimum observation |
|---|---|---|---|
| protocol | string / categorical | Case-folded captured transport protocol. | One IPv4 packet |
| packet_count | integer / packets | All observed packets in the flow. | One packet |
| captured_bytes | integer / bytes | Sum of captured packet lengths. | One packet |
| observed_duration_seconds | number / seconds | last_seen minus first_seen; zero is a real value. | One packet |
| packet_rate_pps | number or null / packets per second | packet_count divided by duration. | Positive duration |
| captured_byte_rate_bps | number or null / bits per second | captured_bytes times 8 divided by duration. | Positive duration |
| source_packet_count, destination_packet_count | integer / packets | Directional counts using first-observed orientation. | One packet; zero is valid for destination |
| source_captured_bytes, destination_captured_bytes | integer / bytes | Directional captured-length totals. | One packet; zero is valid for destination |
| source_packet_fraction, destination_packet_fraction | number / fraction | Directional count divided by packet_count. | One packet |
| source_mean_captured_packet_bytes, destination_mean_captured_packet_bytes | number or null / bytes per packet | Directional bytes divided by directional count. | One packet in that direction |
| source_interpacket_ms, destination_interpacket_ms | number or null / milliseconds | Mean increasing timestamp interval in each direction. | Two packets in that direction |
| source_jitter_ms, destination_jitter_ms | number or null / milliseconds | Mean absolute change between adjacent directional intervals. | Three packets in that direction |
| source_ipv4_ttl, destination_ipv4_ttl | integer or null / IPv4 TTL | Latest retained directional IP TTL. | A packet with TTL |
| source_tcp_window, destination_tcp_window | integer or null / TCP window units | Latest retained directional TCP window. | TCP packet with window |
| source_initial_tcp_sequence, destination_initial_tcp_sequence | integer or null / TCP sequence number | First retained directional TCP sequence. | TCP packet with sequence |
| observed_tcp_state | string or null / diagnostic category | Existing handshake/reset/close observation. | TCP flags observed |
| synack_seconds, ackdat_seconds, tcp_handshake_seconds | number or null / seconds | Observed handshake elapsed times. | Complete respective observed handshake |
| is_sm_ips_ports | integer or null / binary | 1 only when both endpoint IPs and ports are equal; otherwise 0. | Both transport ports |

The schema feature order is an API contract. Additions require a new schema
version rather than reordering or silently changing these definitions.

## Missingness

The features mapping always contains every schema feature in the defined order.
A feature value of 0 is a measured numeric zero. A null value has a matching
missingness entry:

| Reason | Meaning |
|---|---|
| not_applicable | The protocol lacks the relevant concept, such as TCP headers for UDP, or transport ports for ICMP. |
| insufficient_observations | The calculation needs more timestamps or a positive duration. |
| not_observed | The protocol permits the field but this capture did not retain the required header or handshake evidence. |

No missing value is replaced with zero, median, or a Phase 4 preprocessing
value. Service, application payload fields, packet loss, and historical
connection-window counts are intentionally excluded because this collector
does not measure them.

## Future labelled-data collection requirements

Before a model is trained:

1. Freeze this schema, collector version, idle timeout, and finalization rules.
2. Record a unique capture-session ID and scenario metadata separately from
   features. Define benign and controlled attack labels before collection.
3. Use independent capture sessions for training, validation, and final test;
   do not split records from one session across partitions.
4. Deduplicate records within and across partitions using schema features plus
   session-aware flow identity. Review conflicting labels instead of retaining
   one arbitrarily.
5. Retain a data dictionary, collection date range, collector configuration,
   consent or authorization record, and label provenance.
6. Limit access to raw identifying metadata. Keep endpoint addresses separate
   from model features, minimise retention, and pseudonymise or remove them
   before analysis where feasible.
7. Predeclare attack precision, recall, F1, false-positive rate, probability
   calibration, per-record and batch inference latency, and dataset-shift
   checks across separate capture sessions.

No traffic collection, labelling, model fitting, threshold choice, or live
prediction is performed by this specification phase.
