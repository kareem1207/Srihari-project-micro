# UNSW-NB15 42-Feature Live Compatibility Audit

## Scope and evidence

This audit compares the exact Phase 4 model contract with the current
payload-free live collector. It is an implementation review, not an assertion
that similarly named fields have equivalent meaning.

The saved Phase 4 pipeline (`models/securework_ids.joblib`) declares these 42
inputs, in order:

```text
dur, proto, service, state, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl,
sload, dload, sloss, dloss, sinpkt, dinpkt, sjit, djit, swin, stcpb, dtcpb,
dwin, tcprtt, synack, ackdat, smean, dmean, trans_depth, response_body_len,
ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_dport_ltm, ct_dst_sport_ltm,
ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd, ct_flw_http_mthd, ct_src_ltm,
ct_srv_dst, is_sm_ips_ports
```

The training pipeline fits median imputation for numeric features and
most-frequent imputation plus one-hot encoding for `proto`, `service`, and
`state`. That preprocessing is part of the offline model; it is not a licence
to invent missing live semantics or submit null values for features the
extractor cannot observe.

The live collector has only the following sources:

- `PacketRecord`: timestamp, IPv4 source/destination, ports, transport
  protocol, `len(packet)`, TCP flags, IP TTL, TCP window, sequence, and ACK
  numbers. It retains no payload.
- `CompletedFlow`: aggregates an unordered endpoint pair by protocol, while
  keeping the **first observed packet orientation** as source/destination.
  It finalizes on a 30-second observed-idle boundary or monitoring stop.
- `candidate_features()`: emits a value only when observed or calculated. It
  never inserts zero for an unavailable value.

`dataset/NUSW-NB15_features.csv` describes the intended UNSW-NB15 fields. The
official training/testing CSVs used by Phase 4 provide the actual values but
do not contain source/destination identities or timestamps after the model's
42-feature projection. Consequently, exporter implementation details that are
not described by the feature reference cannot be independently validated from
the training inputs.

## Feature-by-feature mapping

**Faithful?** means the current live value has the required training meaning,
not merely the same name. `No` candidates are diagnostics only and remain
blocked from model inference. `Unavailable` means no candidate is emitted.

| Feature | UNSW-NB15 training semantics / units | Current live source and computation | Faithful? | Missing field or semantic mismatch |
|---|---|---|---|---|
| `dur` | Record total duration; unit not stated in the feature reference. | `last_seen - first_seen`, seconds, over only observed packets. | No | Idle/stop truncation and partial capture can change the flow boundary and duration. |
| `proto` | Transaction protocol, categorical. | IP transport protocol (`TCP`, `UDP`, `ICMP`, or `IP-n`) case-folded. | **Yes** | Only trained categories remain usable; unknown categories are handled by the offline encoder. |
| `service` | Service category such as HTTP, FTP, SMTP, SSH, DNS, or `-`. | Unavailable. | Unavailable | No service classifier or application/payload inspection. |
| `state` | Exporter connection/protocol state category such as `CON`, `FIN`, `RST`, or `-`. | TCP handshake summary such as `ESTABLISHED_OBSERVED`, `RESET_OBSERVED`, or `PARTIAL_OBSERVED`. | No | Different labels, partial observation, and no verified UNSW state machine. |
| `spkts` | Source-to-destination packet count, count. | Packets from first observed endpoint, count. | No | First observed orientation is not verified exporter source/client direction. |
| `dpkts` | Destination-to-source packet count, count. | Reverse-direction packets, count. | No | Same orientation mismatch. |
| `sbytes` | Source-to-destination transaction bytes, bytes. | Sum of `len(packet)` in first-observed direction, bytes. | No | Capture-layer byte length may differ from UNSW exporter byte accounting. |
| `dbytes` | Destination-to-source transaction bytes, bytes. | Sum of `len(packet)` in reverse direction, bytes. | No | Same byte-layer and orientation mismatch. |
| `rate` | Model feature; the supplied feature reference does not define its formula or unit. | `packet_count / dur`, packets/second, when duration is positive. | No | Training exporter formula/window is unverified. |
| `sttl` | Source-to-destination TTL value, integer hop-limit field. | Latest observed IPv4 TTL in first-observed direction. | No | Direction and aggregation rule are not verified. |
| `dttl` | Destination-to-source TTL value, integer hop-limit field. | Latest observed IPv4 TTL in reverse direction. | No | Direction and aggregation rule are not verified. |
| `sload` | Source bits per second. | `source_bytes * 8 / dur`, bits/second, when duration is positive. | No | Uses capture byte totals and observed duration. |
| `dload` | Destination bits per second. | `destination_bytes * 8 / dur`, bits/second, when duration is positive. | No | Uses capture byte totals and observed duration. |
| `sloss` | Source retransmitted or dropped packets, count. | Unavailable. | Unavailable | Passive, partial capture cannot reliably distinguish loss from missing capture or retransmission. |
| `dloss` | Destination retransmitted or dropped packets, count. | Unavailable. | Unavailable | Same limitation. |
| `sinpkt` | Source inter-packet arrival time, milliseconds. | Mean interval between observed first-direction packets, converted to milliseconds. | No | Orientation, capture timing, and aggregation convention are unverified. |
| `dinpkt` | Destination inter-packet arrival time, milliseconds. | Mean interval between observed reverse-direction packets, milliseconds. | No | Same limitation. |
| `sjit` | Source jitter, milliseconds. | Mean absolute difference between consecutive observed source-direction intervals, milliseconds. | No | This is a local diagnostic definition, not a verified UNSW jitter definition. |
| `djit` | Destination jitter, milliseconds. | Mean absolute difference between consecutive observed reverse-direction intervals, milliseconds. | No | Same limitation. |
| `swin` | Source TCP window advertisement value, integer. | Latest observed TCP window in first-observed direction. | No | Role and exporter aggregation rule are unverified; absent for non-TCP. |
| `stcpb` | Source TCP base sequence number, integer. | First observed TCP sequence in first-observed direction. | No | First captured sequence is not proven to be exporter base sequence. |
| `dtcpb` | Destination TCP base sequence number, integer. | First observed TCP sequence in reverse direction. | No | Same limitation. |
| `dwin` | Destination TCP window advertisement value, integer. | Latest observed TCP window in reverse direction. | No | Role and exporter aggregation rule are unverified; absent for non-TCP. |
| `tcprtt` | Sum of `synack` and `ackdat`; unit not stated in the feature reference. | SYN-to-final-ACK elapsed time in seconds, only after a fully observed handshake. | No | Training unit/exporter semantics are unverified; missing or reordered packets omit it. |
| `synack` | Time from SYN to SYN/ACK; unit not stated in the feature reference. | Observed SYN-to-SYN/ACK elapsed time in seconds. | No | Requires the complete relevant handshake in capture and has unverified training units. |
| `ackdat` | Time from SYN/ACK to ACK; unit not stated in the feature reference. | Observed SYN/ACK-to-final-ACK elapsed time in seconds. | No | Requires the complete relevant handshake and has unverified training units. |
| `smean` | Mean source flow packet size (`smeansz` in the feature reference), bytes. | `source_bytes / source_packets` using captured packet lengths. | No | Capture layer and first-observed direction are not UNSW exporter semantics. |
| `dmean` | Mean destination flow packet size (`dmeansz` in the feature reference), bytes. | `destination_bytes / destination_packets` using captured packet lengths. | No | Same limitation. |
| `trans_depth` | Pipelined HTTP request/response transaction depth, count. | Unavailable. | Unavailable | HTTP content is not inspected. |
| `response_body_len` | Uncompressed HTTP response-body content size, bytes. | Unavailable. | Unavailable | Payload and HTTP bodies are deliberately neither retained nor parsed. |
| `ct_srv_src` | Same service and source address among the exporter’s recent 100 connections, count. | Unavailable. | Unavailable | Requires service classification plus a validated 100-connection historical window. |
| `ct_state_ttl` | Count for a state and source/destination TTL range, count. | Unavailable. | Unavailable | Requires exporter-equivalent state labels, TTL ranges, and historical window rules. |
| `ct_dst_ltm` | Same destination address among the exporter’s recent 100 connections, count. | Unavailable. | Unavailable | No validated historical connection-window implementation. |
| `ct_src_dport_ltm` | Same source address and destination port among recent 100 connections, count. | Unavailable. | Unavailable | No validated historical connection-window implementation. |
| `ct_dst_sport_ltm` | Same destination address and source port among recent 100 connections, count. | Unavailable. | Unavailable | No validated historical connection-window implementation. |
| `ct_dst_src_ltm` | Same source/destination address pair among recent 100 connections, count. | Unavailable. | Unavailable | No validated historical connection-window implementation. |
| `is_ftp_login` | FTP user/password session indicator, binary. | Unavailable. | Unavailable | FTP credentials and commands are not inspected. |
| `ct_ftp_cmd` | FTP-command flow count, count. | Unavailable. | Unavailable | FTP commands are not inspected. |
| `ct_flw_http_mthd` | Flows with HTTP methods such as GET/POST, count. | Unavailable. | Unavailable | HTTP methods are not inspected. |
| `ct_src_ltm` | Same source address among the exporter’s recent 100 connections, count. | Unavailable. | Unavailable | No validated historical connection-window implementation. |
| `ct_srv_dst` | Same service and destination address among recent 100 connections, count. | Unavailable. | Unavailable | Requires service classification and validated history. |
| `is_sm_ips_ports` | 1 when source/destination IPs and ports are equal, otherwise 0. | Exact endpoint-IP-and-port equality test when both ports are known. | **Yes** | Omitted for protocols without both transport ports; where emitted, the binary rule matches. |

## Candidate-transform rules tested in code

`CompletedFlow.candidate_features()` deliberately has no fill-value path:

- a zero-duration flow omits `rate`, `sload`, and `dload`;
- fewer than two packets in a direction omits that direction’s inter-packet
  interval;
- fewer than three packets in a direction omits that direction’s jitter;
- an incomplete TCP handshake omits `synack`, `ackdat`, and `tcprtt`;
- absent ports omit `is_sm_ips_ports`;
- unsupported service, application, loss, and historical-count fields are
  never emitted.

The candidate transformations preserve their stated local units: packet counts,
captured bytes, packets/second, bits/second, milliseconds for interval/jitter,
and seconds for the observed handshake timers. These local units do not certify
their equality with every training exporter field.

## Live inference decision

Only `proto` and `is_sm_ips_ports` meet the current compatibility standard.
The other 40 required inputs are either unavailable or have non-equivalent
semantics. `FeatureCompatibilityReport.live_prediction_enabled` therefore
remains `False`, and `IDSService` refuses prediction and analysis start even if
a saved Phase 4 model is present.

Do not replace unavailable fields with zero, use pipeline imputation as a
substitute for unavailable collection, or relax this gate. A legitimate live
model would require a separately documented payload-free schema and labelled
flows captured with this same extractor, followed by independent training and
evaluation. That work is outside this audit.
