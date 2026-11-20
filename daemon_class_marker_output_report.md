# FairPlayIOKit discovery status output

In phase `0xb306`, the daemon's post-discovery relay preserves a 32-bit marker and publishes it at byte offset `0x10` in the original record supplied to `0x100559b7c`. The record is passed by the adapter at `0x10061748c`. Six offline profiles execute the output store and the ordinary outer return. The profiles distinguish three convenience-layer outcomes and the common replacement marker produced when redispatch suppresses a second class lookup. [Original-byte audit](triage_evidence/audit_daemon_class_marker_output.py) [Compressed receipt](triage_evidence/daemon_class_marker_output_audit.json.zst) [Adapter call](daemon_class_status_route_report.md)

## Record and control flow

Q is the original record address in X0. S is the retained outer stack pointer after the outer prologue. For this continuation, the epilogue publishes the marker directly as a little-endian u32. The branch after the load takes its index from W19 and leaves the marker in W8 for the store.

| Site | Observed operation |
| --- | --- |
| `0x100530450` | Save Q to S+0x30 B. |
| `0x10052b5f0` | Store the incoming W21 marker to S+0x804 B. |
| `0x10052b614` | Logical IA `0x80cf` edge to `0x1004d7760`. The route uses the saved phase and tests temporary pointer state before selecting the output block. |
| `0x1004905d4` | Use the live X9 continuation selected by the indexed load at `0x10048ce78`. It reaches `0x10062f86c` and then `0x1004d046c` on successive visits, via slots `0x10103f5d0` and `0x10103f638` with IA `0x28d8`. The load value is also stored to S+0x768 B at `0x10048ce7c`. |
| `0x1004b887c` | In the replayed frame, S+0x6a0 B is zero and W19 is `0xb306`. Index `0x2f23` selects slot `0x101051808`, IA `0x74c0`, to `0x100629bf8`. |
| `0x100629bfc`, `0x100629c04` | Load W8 from S+0x804 B and recover X0 from S+0x30 B. |
| `0x100629c0c` | Use index `0xaf91` = `0xb306 - 0x375`, slot `0x101091b78`, IA `0xe347`, to reach `0x10062b370`. |
| `0x10062b370` | Store W8 to Q+0x10 B. |
| `0x10062b374`–`0x10062b3a8` | Compare the saved and current stack guard, restore the frame on equality and return via `RETAB`. The stack-guard pointer is the original bind at `0x1010b1e18`. |

```text
W21 --> [S+0x804] --> W8 --> [Q+0x10] --> ordinary outer return
 X0 --> [S+0x030] --> X0 ---------^
```

## Returned values

| Modeled path | Q+0x10 B |
| --- | --- |
| Primary type-0 open returns `0xe00002c2`, saved flag 1 | `0x74c29dee` |
| Primary class skipped, saved flag 1 | `0x74c29dba` |
| Cached lock NULL, saved flag `0xffffffff` | `0x74c29d88` |
| Zero initial flag, restored context NULL and marker equal to `0x8b3dc651` | `0x74c29d88` |
| Zero initial flag, restored context NULL and marker differs from `0x8b3dc651` | `0x74c29d88` |
| Zero initial flag, restored context nonnull and marker equal to `0x8b3dc651` | `0x74c29d88` |

The outer memory write and the adapter's cursor calculation are separate outputs. The original adapter computes its cursor from the low 16 bits of the change in the first record word after the outer call returns. The marker is a daemon record status. Its higher-level interpretation and propagation into a client reply remain unknown. The archived RAX trace independently establishes the open result `0xe00002c2` and the following service and iterator releases. The trace does not identify this publication instruction or a native call reaching it. [Adapter cursor calculation](daemon_class_status_route_report.md) [Archived open and retirement](archived_iokit_open_retirement_report.md)

## Assumptions and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The pinned fairplayd image, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`, supplies the instructions and fixups. | All sites and logical targets. | Rehash the image and verify 111 original chained words. Test the 32-bit marker load and store over all marker bit patterns with four bit-vector queries. Hardware PAC remains unknown. |
| A2. The replay starts with the earlier phase and gate fixtures, including ordinary modeled library returns and initially zero temporary cells. | The six paths and their output values. | Vary the incoming flag, cache outcome and restored input pair. Check the original accesses, retained status, selected logical transfers and restored stack pointer. Other reaching states remain unknown. |
| A3. Q designates writable record memory distinct from the retained frame, and the ordinary epilogue sees an equal guard. | Exact output address and ordinary return. | Use six disjoint record addresses with known initial bytes, require a single 4 B store per record, and check all 64 B against the expected final record. Require arrival at the declared return address with SP restored to S+0xcd0 B. |

The receipt retains 442 logical authenticated transfers and records 203 instruction visits after the relay store in each replay, including the fixture return boundary. It captures one write and one read overlapping S+0x804 B in each complete trace. Replay time scales with instruction visits and receipt space scales with recorded transfers and events. Reproduce with `python3 -B triage_evidence/audit_daemon_class_marker_output.py` in the existing Unicorn, Capstone and Z3 environment. [Audit](triage_evidence/audit_daemon_class_marker_output.py) [Receipt](triage_evidence/daemon_class_marker_output_audit.json.zst)

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Higher-level consumer of Q+0x10 B | High | Recover the first reaching read of the same Q after the adapter returns and determine whether a client response includes its value. |
| Reachable temporary cells and successful or repeated discovery | High | Carry the original outer record through ordinary allocation and track S+0x340 B, S+0x6a0 B and S+0x808 B into the post-cleanup dispatch. |
| Native same-frame join to the open exchange | High | Correlate a native open caller and original record pointer with the later output store. Mach port names and emission sites remain those of the independently traced exchanges. |
