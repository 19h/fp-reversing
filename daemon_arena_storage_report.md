# First arena metadata, pointer publication and readiness

The original callback now continues from its first `malloc(90000)` boundary under a declared nonnull return H. Source initializes a partial descriptor at `0x1010B5EF0`, writes 48 bytes of arena metadata, creates reciprocal links between H and descriptor+48, and stores H into both formerly dead frame fields. It then publishes readiness byte 1 and reaches the next unproduced frame read at `0x1003ECB8C`. The imported allocator is a return summary; no native allocator or target process executes.

The post-allocation control word at `0x1010B6CB8` has a source-proven unsigned partition: **0/1 selects `0x100322418`; 2..0xFFFFFFFF selects `0x100332700`**, under the recovered incoming phase. The 64 complete prefix cases use value 1. They preserve all 375 preceding visits from the [arena-entry report](daemon_arena_entry_report.md), including the two certified dead loads. Those fields become defined only later, at the new source stores.

## Provenance and assumption register

Primary image: `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred image virtual addresses. [Contracts](triage_evidence/daemon_arena_storage_contracts.json) retain six original spans, 33 original fixups and 129 matched current IDA rows. [Profiles](triage_evidence/daemon_arena_storage_profiles.json) retain source visits, reads/writes, explicit allocator summaries, compressed full owner snapshots and masks. [Checks](triage_evidence/daemon_arena_storage_checks.json) reconstruct every retained byte/epoch and publication timeline. [Eleven source proof pairs](triage_evidence/daemon_arena_storage_proofs.json) cover 117 lifted instructions; a separate SAT witness establishes satisfiable storage premises. [Current IDA bytes](triage_evidence/daemon_arena_storage_live_ida.json) are checked against the backing file. No IDB mutation occurs.

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| AS1 | This exact daemon image is the intended implementation | All constants, PCs and layouts | Rehash source/opcodes/fixups and current IDA bytes; native daemon/kext build pairing remains unknown |
| AS2 | The recovered callback phase and source-produced roots precede the allocator | Selected fragments and full prefix | Preserve the entire preceding 375-visit sequence; vary controllers, frame placement and incoming registers |
| AS3 | The declared allocator returns fresh, aligned, valid H with extent 90,000 bytes | All owner addresses and pointer publications | Vary H, enforce exact requested extent and preserve unknown padding; actual native return remains unknown |
| AS4 | API return summaries define no allocated bytes | 48 known versus 89,952 unknown bytes | Poison with 0xA5/0xCC/0/0xFF while keeping masks zero; audit every later source-written byte |
| AS5 | The summary's register effects provide the stated ABI environment | Post-call phase continuity | Compare SP, X18-X29 and D8-D15 low64 before/after; overwrite caller scratch registers/SIMD state and NZCV |
| AS6 | Frame and owner are aligned, nonwrapping and disjoint from each other and the fixed source image | Symbolic memory/extent obligations | Check explicit bit-vector premises and SAT witness; reject aliases or an out-of-owner read |
| AS7 | The post-allocation phase constants apply to the isolated u32 control-word lift | Total 0/1 versus >=2 partition | Prove all u32 values with modular addition and unsigned comparisons; do not infer entry reachability for every value |
| AS8 | Concrete prefix cases use control word 1 without intervening external writers | Cache, readiness and final boundary | Audit exact source reads/writes and both CAS epochs; native interference and scheduling remain unknown |
| AS9 | Knownness/provenance describes defined analysis values and source writers under the declared API result | Cached H and owner metadata | Distinguish API-originated pointer values from source store PCs; retain zero masks for untouched bytes |
| AS10 | Pointer equations establish a graph, not complete allocator semantics | Reciprocal-link and marker interpretation | Identify actual traversal, split/coalescing/allocation/free consumers before assigning those roles |
| AS11 | Source publication order is observed in one private thread | Pointer-before-header and readiness timing | Establish native reader synchronization and feasible concurrent ordering separately |
| AS12 | This increment covers the first allocation's local storage/control interface | Reporting coverage | Continue alternate frame fields, owner consumers, lock lifecycle and actual Mach/IOKit transactions; full objective remains active |

## Recovered source-fragment roles

| Fragment | Supported role | Evidence limit |
| --- | --- | --- |
| 0x10032A4EC..0x10032A5E0 | Initialize first arena metadata after returning allocation | Source stores and next dispatch; no complete C-function boundary inferred |
| 0x100331DE4..0x100331E3C | Select post-allocation branch from u32 control word | Exact threshold requires the recovered incoming phase |
| 0x100322418..0x10032246C | Publish two frame caches of returned H | Both original source stores and next target proved |
| 0x10046C73C..0x10046C780 | Publish readiness and resume frame preparation | Readiness is partial state; callback return not reached |

The preceding entry and roots are established in the [frame report](daemon_frame_entry_report.md). Semantic names above describe selected instruction fragments and are reporting proposals, not changes to IDA names or ownership. [AS1,AS2]

## Allocation return and descriptor

The original call remains `0x10032A4E8`, through slot `0x10109FF58`, IA diversity `0x6AA4`, bound to `libSystem/_malloc`. X0 supplies size_t64 value 90,000 bytes. The new summary returns H, defines zero owner bytes, and writes no guest memory. It preserves SP, X18-X29 and the low 64 bits of D8-D15; it overwrites X1-X17, caller SIMD state including upper preserved-register halves, and NZCV. These are explicit model effects. [AS3-AS5]

Let D=`0x1010B5EF0`, L=D+48 and N=90,000 bytes. Source stores define the following descriptor fields:

| D-relative offset, bytes | Width | Value under declared return H | Producer PC |
| --- | --- | --- | --- |
| 0 | u64 | 0, preceding pre-call store | 0x10032A484 |
| 8 | pointer64 | H | 0x10032A520 |
| 16 / 20 | u32 / u32 | 0 / 10 | 0x10032A528 |
| 24 | 8-byte region | No source write in this prefix; original image word is 0x99960B5A | Unassigned semantic role |
| 32 / 36 | u32 / u32 | 1 / 0 | 0x10032A530 |
| 40 / 48 | u64 / u64 | 0x1AA4071F0801765B / 0 | 0x10032A544 |
| 56 / 64 | u64 / u64 | 0 / 0 | 0x10032A548 |
| 72 | pointer64 | H (field address L+24) | 0x10032A56C |
| 80 | pointer64 | H (field address L+32) | 0x10032A568 |

Source writes cover 80 of the 88 displayed bytes, including the preceding eight-byte zero store. The values 10 and 1 are established scalar words; their count/flag semantics remain unknown. The current image word at offset 24 is retained under the declared initial-image state and is not assigned an initialization or runtime-lifetime interpretation. [AS2,AS9]

## Arena markers and reciprocal links

Define M=`0x5E878C613B8123EA`. Exactly six eight-byte source stores define arena bytes:

| H-relative offset, bytes | Width | Source value | Producer PC |
| --- | --- | --- | --- |
| 0 | u64 | M | 0x10032A55C |
| 8 | u64 | M+89,976 = 0x5E878C613B828362 | 0x10032A5D0 |
| 24 / 32 | pointer64 / pointer64 | L / L | 0x10032A564 |
| N-24 = 89,976 | u64 | M+89,976 | 0x10032A58C |
| N-16 = 89,984 | u64 | M XOR 0x8000000000000000 = 0xDE878C613B8123EA | 0x10032A5A0 |

The 48 source-defined bytes occupy `[0,16)`, `[24,40)` and `[89976,89992)` relative to H. The other **89,952 bytes remain unknown**, including H+16..23 and the final eight allocated bytes. Physical zero backing in some cases does not change knownness. No source heap read occurs before the current boundary. [AS4,AS9]

The head/end word relationship is exact:

```text
(H+8).u64 = (H+N-24).u64 = M + (N-24)
(H+N-16).u64             = M XOR 2^63
```

The reciprocal pointer graph is also exact:

```text
             D + 72 = L + 24 ----> H
             D + 80 = L + 32 ----> H
                                    |
             L <---- H + 24 --------+
             L <---- H + 32

L = D + 48; each object's +24/+32 links point to the other object.
```

This supports an embedded circular-list interpretation and paired boundary-marker interpretation. Actual allocator traversal, size decoding, split/coalescing and release semantics remain unknown in this increment. [AS10]

## Frame caches, control partition and publication order

The returned pointer is preserved in X10 at `0x10032A5CC`. The source then publishes both caches:

| Frame field | Producer | Value and provenance transition |
| --- | --- | --- |
| F+0x5F8 | 0x100322440: STR X10,[SP,#0x5F8] | Previously unknown; now H from the declared malloc return, written by source |
| F+0x540 | 0x100322444: STR X0,[SP,#0x540] | Previously unknown; now H from the declared malloc return, written by source |

The earlier loads at `0x1003B5738`/`0x1003B573C` remain dead loads of unknown values at their original epochs. Later stores do not retroactively initialize those reads. At the new boundary, both cached words have all eight known/provenance bytes set by the source stores. [AS9]

For the recovered phase, `0x100331DE4` computes comparison constant `0xA2077531` and uses threshold `0x5DF88ACF`; the latter plus `0xA2077530` equals `0xFFFFFFFF`. The original CSEL/unsigned-overflow logic simplifies for every u32 S as follows:

| S at 0x1010B6CB8 | Index / slot | Target at BRAA 0x100331E38 |
| --- | --- | --- |
| 0 or 1 | 0x4570 / 0x10105CA70 | 0x100322418, cache-publication branch |
| 2..0xFFFFFFFF | 0x457C / 0x10105CAD0 | 0x100332700, alternate branch |

Both slots are original authenticated rebases with IA diversity `0xCFB7` and address-diversity zero. The all-u32 proof is a local control contract; the 64 complete prefix cases use S=1. [AS7,AS8]

Source then writes byte 1 at readiness address `0x1010C5798` using `0x10046C750`. The retained publication timelines establish:

| Event | Source visit index, selected cases | Known arena bytes before write | Gate word at write |
| --- | ---: | ---: | --- |
| Descriptor+8 receives H, 0x10032A520 | 389 | 0 | 0xA94EF |
| Frame+0x5F8 receives H, 0x100322440 | 469 | 48 | 0xA94EF |
| Frame+0x540 receives H, 0x100322444 | 470 | 48 | 0xA94EF |
| Readiness byte becomes 1, 0x10046C750 | 485 | 48 | 0xA94EF |

Thus descriptor pointer publication precedes the first source arena-header write. The gate word has the acquired-path encoding at those writes. This is source ordering in a serialized private execution; native visibility, reader synchronization and contention remain unknown. Readiness is published before callback completion and before the current unknown-frame boundary. Source indices are dimensionless observation counts, not time measurements. [AS8,AS11]

After readiness, original frame preparation and another CAS path run until **`0x1003ECB8C`, immediately before LDR X26,[SP,#0x5A8]**. The following SP+0x448 load also remains unclassified. The callback has not returned and no additional dead-load exception is introduced. The [earlier startup report](rpc502_startup_report.md) retains separate completed executions with an initially zero-filled stack; those premises are unchanged. [AS12]

## Verification and bounded continuation

All checks pass: 64 cases, 76,096 source visits with 64 explicit allocation summaries, 64 preserved preceding prefixes, eight fresh replays, 896 reconstructed frame snapshots, 5,760,000 reconstructed arena bytes, 128 original dead-load epochs, 128 source cache fields and 64 publication timelines. Eleven original/simplified source proof pairs cover 117 lifted instructions, with an independently checked SAT premise witness. Thirty-three original fixups and 129 current IDA rows match. No native target, allocator, IOKit, Mach or hardware PAC executes. [Checks](triage_evidence/daemon_arena_storage_checks.json), [preservation](triage_evidence/daemon_arena_storage_preservation.json), [scoped gates](triage_evidence/daemon_arena_storage_quality_gates.json).

| Impact | Next question | Evidence required |
| --- | --- | --- |
| High | SP+0x5A8 and SP+0x448 | First complete-register uses/kills or earlier feasible producers before extending known-state execution |
| High | Original arena consumers and lifecycle | Trace descriptor+8, head/end words and reciprocal links into actual allocation/release routines |
| High | Publication synchronization | Link native/feasible readers to the same gate or once state before assigning a visibility contract |
| High | Callback-to-IOKit continuity | Carry source-produced arena, lock and readiness state through actual caller records into transport |
| Medium | Alternate S>=2 path | Recover its local control/data effects without assuming cache or readiness publication |

The producer/audit costs O(C*(B+V+events+J*K+N)) time and O(largest artifact+V+events+N+4096J+K) working space per case, where N=90,000 bytes, J is demand pages and K is fixup records; retained output scales with C. Symbolic lift construction is O(I) DAG time/space, with a 30 s timeout per solver query. Storage premises require aligned, nonwrapping frame/owner regions, mutual disjointness and separation from the fixed image. The explicit SAT witness rules out an empty premise domain.

QG1 passes for factual analysis. QG2 passes with AS1-AS12. QG3 passes for this increment; the full interface objective remains active. QG4 passes for exact u32/u64 arithmetic, byte extents and software counts. QG5 passes with allocation summaries, source writes, untouched bytes, publication ordering and native synchronization distinguished. QG6 passes for byte/epoch reconstruction, original fixups, current IDA, source proofs and the SAT witness. QG7 passes with the impact-labeled continuation table. Native allocation outcome, complete strict-state startup, lifetime and downstream transport remain unknown.

Reproduce from the repository root with the source-discovery configuration and Python dependencies required by the scripts:

```sh
PYTHONPATH=triage_evidence python3 -P triage_evidence/probe_daemon_arena_storage.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/recover_daemon_arena_storage.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/prove_daemon_arena_storage.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_daemon_arena_storage.py
```

The subsequent [readiness/arena report](daemon_readiness_arena_report.md) joins the startup descriptor writer and later reader by address, proves the conditional marker equation, and compares fresh-startup and pre-constructor header values. The two epochs remain separate: 89976 B and 86620 B offsets reach different pending marker reads. This does not establish native allocator ownership or an uninterrupted startup-to-caller path.
