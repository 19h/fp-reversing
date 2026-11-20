# Version and capability replies in the current FairPlayIOKit build

The FairPlayIOKit image matching the loaded kext UUID returns version `0x4c0b0000` for selector 22 and capability word `0x000001f8` for selector 23 on the recovered base-provider paths. Both selectors accept zero structure input bytes and require a four-byte output buffer. The two UserClient methods copy a provider word to that buffer and return status zero after the provider returns. These are the first two method candidates on the successful-open continuation of the `fairplayd` path whose open and cleanup were observed under RAX. The task-local connection name, native caller and native method replies remain unknown. [Current source audit](triage_evidence/live_fairplay_metadata_audit.json.zst) [Observed daemon open](daemon_iokit_callsite_capture_report.md) [Daemon query ABI](daemon_iokit_census_report.md)

## Daemon call, IOKit transport and provider result

| Layer | Selector 22 | Selector 23 |
| --- | --- | --- |
| Daemon call to `IOConnectCallStructMethod` | `0x100364420` | `0x1004ba9c4` |
| Kernel dispatch record | `0xfffffe0008481f40` | `0xfffffe0008481f70` |
| UserClient method entry | `ucGetVersion` at `0xfffffe000a546258` | `ucGetProtocolCapabilities` at `0xfffffe000a5462b0` |
| Provider slot from vtable address point | `+0x8c0`, IA `0xc54a` | `+0x8c8`, IA `0xb3ee` |
| Base-provider branch stub | `uOxAg` at `0xfffffe000a546064` | `Q5TC6` at `0xfffffe000a54606c` |
| Getter entry and return-value load | `_V2F1SYee`, `0xfffffe000a5e3b2c` / `0xfffffe000a5e3d10` | `_QIWEiU`, `0xfffffe000a5e5b68` / `0xfffffe000a5e5d24` |
| Private four-byte value store | `0xfffffe000a6ab940` | `0xfffffe000a603440` |
| UserClient four-byte output store | `0xfffffe000a5462a0` | `0xfffffe000a5462f8` |
| Expected data on ordinary return | `00 00 0b 4c` | `f8 01 00 00` |

The daemon's successful-open continuation reads the connection output at state+4 B. The first method call submits selector 22, and the second submits selector 23. Both use a null input pointer, zero input extent and an output capacity of 4 B. In the current IOKit cache these dimensions select the inline path, with request extent `84 B + round_up(0 B, 4 B) = 84 B`. The framework emits request 2865 through the transport call at `0x184ebe090` and receives reply 2965. The destination is the successful open's connection send name with `COPY_SEND`. The local reply field specifies `MAKE_SEND_ONCE` on a distinct receive name. The recorded failed open reached neither method. [Daemon connection data flow](daemon_iokit_objects_report.md) [Current method emission and reply rights](live_iokit_mach_transport_report.md)

Request 2865 reaches stub `0xfffffe000be8152c`. On the ordinary path the connection converter checks kobject type `0x27`. The generic synchronous implementation selects the IOKit legacy method entry, and `IOUserClient::externalMethod` calls the FairPlay router via vtable +0x970 at `0xfffffe000c5b24e0`. The two dispatch records have flags 3, null target fields, zero this adjustments and exact input and output counts of 0 B and 4 B. The structure adapter at `0xfffffe000c5b47d4` checks those extents. A request that reaches the selected member supplies the client in X0 and the output pointer in X1. The member preserves that pointer in X19, loads its provider from client+0xd8 B, calls the provider via the selected slot, stores the low 32 bits of the returned value, and returns W0=0. The getter word and method status use separate destinations. [Current synchronous router](live_kext_selector26_report.md) [Open connection publication](live_fairplay_connection_report.md)

At getter entry the private result record is SP+0x10 B after frame reservation. The return load reads SP+0x14 B. The version adapter calls the original authenticated target at slot `0xfffffe00084913b8` before storing `0x4c0b0000` through its saved record pointer. The target, `0xfffffe000a5efda0`, writes a different word to its own input record. The version getter consumes the adapter's store. The capability leaf at `0xfffffe000a603438` writes `0x1f8` directly to result+4 B. Both getters also update controller state. The interpretation of individual capability bits and the effects of concurrent controller mutation remain bounded by the earlier source proofs. [Pinned record, effects and return proofs](kext_query_getter_values_report.md)

## Build comparison and daemon effects

Runtime build `26C5035r` reported kernel UUID `90195379-954d-3ca3-baac-327341f14211` and loaded FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. Both match the current collection. The audit reads that collection and the independently pinned earlier collection. It recaptures five functions using their compiler-recorded bounds, compares all 405 A64 instructions, and verifies the 60 changed instruction words as address-operand changes across 33 references. The value-store and return-load words agree byte-for-byte. Eight 256 B tables match byte-for-byte, and all 3,072 evaluations across the twelve bank identities agree with the prior equations. The slot checks include the eight pool literals, controller references and three authenticated function targets. [Current collection identity and method map](live_kext_selector26_report.md) [Pinned byte-bank proofs](kext_query_getter_values_report.md)

| Daemon query outcome | Guarded version word | Guarded capability word | Final decoded capability value |
| --- | --- | --- | --- |
| Both accepted | `0x4c0b0000` | `0x1f8` | `0x1f8` |
| Version accepted, capability rejected | `0x4c0b0000` | 0 | `0x8` from the version fallback |
| Version rejected, capability accepted | 0 | `0x1f8` | `0x1f8` |
| Both rejected | 0 | 0 | 0 |

Acceptance in the daemon requires API status zero and returned extent exactly 4 B. The second query still follows rejection of the first. When both pass, the cached capability field at state+0x14 B contains `0x1f8 XOR 0xc49697f0 = 0xc4969608` and the zero-capability fallback is skipped. Bit 3 by itself is compatible with a rejected capability query. These remain conditional daemon outcomes using the recaptured current provider values. [Daemon cache and fallback](daemon_query_fallback_report.md) [Pinned cross-layer acceptance cases](kext_query_getter_values_report.md)

## Native observation boundary

On 2026-11-20 the IOService registry still showed an active `fairplayd` child, ID `0x100001702`, under the selected service. The retained unified-log query for PID 3903 in the five-minute startup window beginning 2026-11-13 00:32:26 UTC returned zero selected log events. A similarly scoped query around the new `lskdd` instance on 2026-11-20 retained 40 startup events, none identifying an IOKit transaction. These counts describe the retained and visible log records. The startup transactions are unknown. [Native registry and identity](daemon_iokit_native_registry_report.md) [Earlier passive observation](fairplay_native_xpc_observation_report.md)

| ID | Premise and dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| M1 | The kernel and kext images correspond to the recorded host. Method and provider addresses depend on that build. | Requery the loaded UUIDs and rehash both collection inputs before applying the addresses to a new snapshot. | High |
| M2 | Runtime dispatch selects these base-provider vtable slots and the table entries retain the decoded target and controller roles. This is required for the two values. | Check the vtable and concrete call destinations in the same ordinary method observation. An override or different table epoch could select another path. | High |
| M3 | The record pointers and preserved frame refer to the same valid records across the authenticated calls, which return normally. This connects the stores to the getter loads and output copy. | Compare the reaching X0 pointer, caller-owned X19 pointer, record+4 B and both returns. | High |
| M4 | The open succeeds on the recovered daemon path and the query calls pass IOKit's and the daemon's checks. This is required for the expected cache state. | Correlate the open reply's connection descriptor, both method selectors and statuses, and output lengths on the same client epoch. | High |
| M5 | The log query sees retained records for the selected process and interval. Silence has limited diagnostic value. | Repeat under a separately authorized passive collection with positive IOKit visibility. | Low |

The [auditor](triage_evidence/audit_live_fairplay_metadata.py) is offline and runs in O(B + F + 256R) time and O(B + F) space for collection bytes B, fixup and symbol entries F and R byte-bank rules. It preserves compiler bounds, original pointer fields, instruction windows and value-store locations. The stock kernel was queried for identity and registry metadata. Successful native transport remains an open requirement of the broader investigation.

```sh
python3 triage_evidence/audit_live_fairplay_metadata.py "$CURRENT_COLLECTION" "$PINNED_COLLECTION"
```
