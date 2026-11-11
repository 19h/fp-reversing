# FPSD1200 session pool to process-event retirement

The original descriptor callback consumes a populated FPSD1200 session pool and requests retirement when the event PID matches encoded slot+140. It resets selected slot fields, requests CF invalidation/release and clears the CF reference. Slot+400 is not read on this route. This joins two independently produced source snapshots; native event delivery, continuous startup/session execution, CF effects and Mach-right destruction remain unknown. [FP1-FP8]

This continues the [watch lifetime report](fpsd1200_lifetime_report.md) and [descriptor-source report](daemon_descriptor_source_report.md). The full daemon/kext/deeper-interface investigation remains active.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FP1 | The pinned thin daemon and live IDA bytes identify the source. All address and instruction claims depend on this identity. | Rehash the image, 34 source spans, one additional writer range, 94 original rebases and 11 bind records; distinguish the thin image from IDB input metadata. |
| FP2 | The frozen successful FPSD1200 profile supplies the pool bytes and source-write footprint. Session provenance depends on its pinned predecessor receipt. | Verify checks, receipt, auditor and dependency hashes, the exact decoded profile hash and original PID store. This increment does not freshly replay that 10093981-visit prefix. |
| FP3 | Original descriptor initialization/setup and the session are distinct components. Their composition substitutes the session's exact pool pointer/count while preserving the descriptor state. Callback joins depend on this explicit handoff. | Freshly replay initializer/setup, check the complete starting and final RAM/CPU, compare the header before/after and pool hashes, and test live slot index1. Native temporal continuity remains unknown. |
| FP4 | Every event case supplies one successful `kevent` result and a 32-byte `EVFILT_PROC` record with the declared ident. Event-to-PID conclusions concern this contract. | Independently reconstruct all six API arguments and event bytes; compare matching/nonmatching PID and changed encoded field. Native process identity, exit generation and event feasibility remain unknown. |
| FP5 | CF identities, once, locks and PAC are explicit private models. Retirement findings identify original requests and stores. | Check all API arguments, original call sites, full CPU clobbers and source read/write journals. Native CF retain counts, port destruction, synchronization and hardware authentication remain unknown. |
| FP6 | Reader arithmetic phases are checked in complete CPU frames. The separately recovered writer equation is conditional on shift1. | Independently lift the actual straight-line instructions and solve all-u32 counterexample queries. Only shift1 among ARM shifts0..31 matches the frozen writer's selected input/output; the writer's full CPU phase is not freshly replayed here. |
| FP7 | Defined-byte masks mark earlier original writes or explicit controls, rather than transitive semantic origins. Diagnostic controls depend on this limited interpretation. | Rebuild the source footprint, compare every pool read/write mask and change slot+400. Initial A5 bytes and copied unknown inputs do not become semantically initialized merely because a later source store exists. |
| FP8 | Eight complete callback profiles and the stated local proofs bound this increment. Tail fields+880/+888 are zero in the selected source snapshot. | Verify the finite matrix, complete RAM and terminal CPU, source/SDK provenance and exact publication delta. Nonzero tail objects, later session operations and daemon/kext/deeper transitions remain separate obligations. |

## Primary evidence [FP1-FP3,FP8]

| Object | Identity / extent |
| --- | --- |
| Original thin arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, preferred base `0x100000000` |
| Live IDA input metadata | SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 34 selected spans and the additional 60-byte writer range match |
| New source catalog | 3501 distinct four-byte instructions / 14004 bytes; writer range is separately attested |
| Frozen session source | `queue7_success` in [lifetime checks](triage_evidence/fpsd1200_lifetime_checks.json.zst); exact decoded payload and predecessor fresh-replay receipt are pinned |
| Fresh descriptor origin | Original context initializer and `setup_fd7`; 22599 visits, complete source journals, CPU, API and mutable RAM comparisons |
| Primary SDK context | Four installed headers; arm64e compile-only checks of the event layout, callback type, CF option width and relevant API signatures |
| IDA knowledge search | Returned shared Mach-service callback fact6; no direct process-event/session-retirement evidence |

New evidence: [producer](triage_evidence/recover_fpsd1200_process.py), [source/profiles](triage_evidence/fpsd1200_process_checks.json.zst), [read-only IDA/SDK attestation](triage_evidence/fpsd1200_process_ida_readback.json.zst), [independent auditor](triage_evidence/audit_fpsd1200_process.py), [fresh audit receipt](triage_evidence/fpsd1200_process_audit.json.zst) and [publication verifier](triage_evidence/verify_fpsd1200_process_publication.py). No IDB mutation or native target/API execution occurs.

## Component and namespace join [FP2-FP5]

```text
original descriptor initialization/setup   frozen original FPSD1200 success
  kqueue -> CFFileDescriptor callback       pool, encoded PID, CF reference
                  |                                   |
                  +------ explicit snapshot join -----+
                                      |
                      callback 0x10044f23c
                                      |
               kevent(fd7, NULL, 0, output32, 1, NULL)
                                      |
                     EVFILT_PROC / event ident
                                      |
                    marker gate -> encoded PID match
                                      |
                    slot reset -> CF requests -> clear
```

| Interface / identity | Exact role and boundary |
| --- | --- |
| Header `0x1010c4cd8` | First16 bytes become the frozen FPSD1200 pair `(0x74000000,50)`; the older descriptor initializer's pool had100 slots. The count change is an explicit snapshot composition. |
| Session pool | 50 slots x896 bytes =44800 bytes; the private backing is65536 bytes with an explicit A5 tail. The source footprint marks1159 bytes written. |
| BSD descriptor7 | Preserved original setup state; the callback obtains it at call `0x10044f4d4` and requests one event at `0x10044f574`. It is not a Mach name. |
| Callback CF descriptor | Opaque modeled identity `0x5000020000`; read callbacks are re-enabled at `0x10044f5ec` and `0x1002656cc`. |
| Session CF endpoint | Opaque identity `0x77001000`, read from selected slot+0; CF invalidation/release requests use this reference. |
| Prior output Mach name | The predecessor success profile supplies raw name `0x6800` through its CFGetPort model and MIG reply. This callback neither calls CFGetPort nor independently resolves that name. |
| Mach transport / IOKit | No Mach-send, VM or IOKit import occurs in these callback intervals. No new outgoing Mach message or incoming Mach-right transfer is established here. |

The callback entry is reconstructed from the descriptor setup, not from a native CF scheduler. The parent component's other header fields, whole mutable snapshots and CPU state are retained. The explicit join replaces only the pool pair and supplies a separate mapping for the source-produced session pool; it does not establish that a native run reaches both components in this order.

## PID representation and marker predicate [FP1,FP4,FP6]

| Field / source | Established operation |
| --- | --- |
| Slot+140 (`0x8c`) | Actual encoded PID consumed by this callback |
| Producer store `0x100497638` | Frozen original u32 write `0x4f44c170` for audit PID `0x17161514` |
| Reader `0x1001fb82c` | Loads encoded PID; `0x1001fb830` loads the low32 event-ident bits |
| Comparator `0x1001fb8bc` | Original equality after obfuscated arithmetic, with W11=`0x19b1`, W9=`0x2795`, variable shift1 |
| Slot+876 (`0x36c`), read `0x10029a254` | Marker gate before PID consumption; stride896 and pool base are checked in complete CPU frames |
| Slot+400 (`0x190`) | No read on these paths; changing its value preserves original visits, journals, API requests, terminal CPU and the five inherited RAM regions |

All arithmetic below is modulo2^32. The original writer expression, conditional on shift1, reduces to:

```text
encodedPID = (PID XOR 0xff3fefff)
           + ((PID << 1) AND 0xfe7fdffe) + 0x38eebc5d
           = PID + 0x382eac5c

0x17161514 + 0x382eac5c = 0x4f44c170
```

The independently lifted reader predicate is equivalent for every u32 PID and stored value to `stored == PID + 0x382eac5c`. Its original intermediate candidate is `PID + 0x6a0ecd1a`, and the final difference is compared with `0xce1fdf42`; the constants sum to `0x382eac5c` modulo2^32. This is an additive representation, not an XOR inference from one observed pair. Reader phases are freshly checked. The writer equation remains phase-conditional; its selected frozen input/output has exactly one compatible ARM shift amount among0..31:1.

The marker comparison uses W4=`0xba8820b5` and threshold `0xfffffffe`:

```text
eligible(marker) = unsigned(marker - 0x4577df4b) < 0xfffffffe
                 = marker != 0x4577df49 AND marker != 0x4577df4a
```

Thus the gate does not mean `marker == 0x4577df4b`. A declared `0x4577df4c` control follows the same retirement route for a matching PID. This establishes the local predicate, without assigning native validity or a semantic state name to arbitrary marker values. Three producer queries and three independently source-lifted counterexample queries are UNSAT; none proves complete dispatcher behavior or native event feasibility.

## Exact retirement requests and stores [FP4,FP5,FP8]

| Order | Original location | Selected effect |
| ---: | --- | --- |
|1 | `0x10022de34`, `0x10025bc8c` | Reads slot+888 asNULL, then stores eight zero bytes there |
|2 | `0x1003f8830` | Stores marker `0x4577df49` at slot+876 |
|3 | `0x1003f8844` | Stores `0x8b3dc651` at slot+816 |
|4 | `0x1004840d4` | 48 original byte stores reset slot+820..867, descending within each16-byte block |
|5 | `0x1004973e0`, call `0x10025e648` | Loads slot+0 and requests `CFMachPortInvalidate(0x77001000)` |
|6 | `0x10025e654`, call `0x10025e6a4` | Reloads slot+0 and requests `CFRelease(0x77001000)` |
|7 | `0x10025e6ac` | Stores eight zero bytes at slot+0 |
|8 | `0x100265248` | Reads slot+880 asNULL; the nonzero continuation is outside these cases |

Each of the three16-byte reset blocks ends as `f8a4aa56b468661a90bc224e4c80de12`. The evidence establishes a pattern reset; it does not identify those bytes as a key or characterize the operation as encryption or zeroization. The complete matching path has52 pool store events. It scans all50 marker positions, including when the sole populated session is moved to slot index1; the same retirement writes then target that slot at base+896.

CF invalidation/release have record-only effects in the model. No conclusion follows about destruction of the previously returned Mach name, client-side rights, removal of native run-loop sources or destruction of the719-byte output VM owner. Original once/lock requests are checked, but do not establish native lock behavior or concurrency.

## Finite controls and validation [FP1-FP8]

| Profile | Control | Original visits | Retirement requested / pool stores |
| --- | --- | ---: | --- |
| `matching_audit_PID` | Exact frozen session and audit PID |7088 |Yes /52 |
| `different_PID` | Event ident15 |4045 |No /0 |
| `diagnostic_word_changed` | Slot+400=`0x17161514` |7088 |Yes /52 |
| `inactive_marker` | Marker `0x4577df49` |3999 |No /0 |
| `reserved_marker` | Marker `0x4577df4a` |3999 |No /0 |
| `other_marker` | Marker `0x4577df4c` |7088 |Yes /52 |
| `encoded_PID_changed` | Slot+140 encodes PID15, original event PID retained |4045 |No /0 |
| `live_slot_index1` | Single populated slot moved to index1 |7088 |Yes /52 |

| Fresh verification | Extent |
| --- | --- |
| Callback replay |44440 original visits,5734 reads,3688 writes and96 API contracts |
| Complete callback CPU frames |1052 including836 new process checkpoints; GP31, SP, NZCV and32 Q registers |
| Inherited final mutable RAM |19529728 bytes across eight cases; additional524288 pool bytes and524288 mask bytes |
| Pool observations |422 reads and208 store events; all50 marker addresses checked per case |
| Initializer/setup replay |22599 original visits,2809 reads,1083 writes,14 API contracts,34 complete CPU frames and4882432 final RAM bytes |
| Source / fixups |34 fresh IDA spans,3501 distinct callback instructions,94 original rebases and11 bind records; additional writer source attested |
| Local arithmetic |Three retained UNSAT queries plus three independently lifted source queries |
| Frozen session predecessor |Exact payload, checks, fresh-replay receipt and dependency hashes pinned; its original prefix is not freshly replayed in this increment |

The auditor does not import the new producer. It independently reconstructs the composition, controls, event/CF contracts, original CPU/read/write journals, final RAM, byte masks and exact field joins. The independent lifter admits only the selected straight-line W-register instructions and explicit symbolic loads/stores; ARM variable shifts use their low five bits. Complete original callback replay verifies the phases used by the reader proofs. Publication validation pins the successful fresh receipt; it does not itself execute instructions.

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1200_process.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1200_process_publication.py
```

Replay takes O(V+J+H*R+I) time and space O(J+H*R+I), for original visits V, journals J, full snapshots H, mutable bytes R and image I; SMT costs are separate. Byte extents and u32/u64 widths are explicit. Substantial JSON is Zstandard ultra22 archived with exact decompression comparison. Path checks inspect decoded metadata and typed RAM payloads; compressed binary alphabet coincidences do not denote paths.

## Bounded continuation opportunities [FP2-FP8]

| Impact | Discriminating next evidence |
| --- | --- |
| High | Recover source-produced nonzero slot+880/+888 objects and their ownership/deallocation contracts. Current zero-tail cases do not establish those continuations. |
| High | Join returned-session operations to daemon provider, IOKit user-client and deeper facilities with exact source and namespace pairing. This callback reaches no IOKit call. |
| High | Establish native startup-to-session continuity, event generation, CF source removal, right lifetimes and output-owner reclamation. Snapshot composition supplies none of these native effects. |
| Medium | Freshly checkpoint the writer's complete CPU phase and map the two excluded marker values to original producers; the exact reader predicate alone does not name all session states. |
| Medium | Trace slot+400's semantic origin and other consumers. Its non-use here does not establish a global absence of consumers. |

**QG1** passes: factual source, ABI and bounded state analysis. **QG2** passes: FP1-FP8 list assumptions, dependencies and falsification probes. **QG3** passes for this increment; the broad goal remains active. **QG4** passes: exact byte extents, widths, counts and modular arithmetic are reproducible. **QG5** passes within scope: reader phase versus conditional writer phase, pool composition versus native continuity, CF reference versus Mach name, write footprint versus semantic origin and requests versus effects remain distinct. **QG6** passes: original image/fixups, read-only live IDA, primary SDK, fresh independent replay, independent source lifting and pinned predecessor provenance support the claims. **QG7** passes: remaining questions have bounded impact labels.
