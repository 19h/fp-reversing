# Initialization dead loads and the first arena allocator boundary

The unknown reads at `0x1003B5738` and `0x1003B573C` do not supply inputs to the selected initialization path. They load X10 and X0, respectively; source overwrites each complete register before reading it or making a call. Two source liveness certificates and ten symbolic proof pairs establish this for arbitrary 64-bit values at both fields. The original instructions can therefore be examined without treating either stack word as initialized.

The new private probe reaches **`malloc(90000)` at `0x10032A4E8`** directly from callback entry `0x10045053C`, preserving both words as unknown. It stops before executing the imported allocator. Thirty-two cases cover four backing-bit patterns across the eight selected prefix environments; their final register states and source writes are invariant under those patterns. This extends the [frame report](daemon_frame_entry_report.md), whose strict known-value probe stopped before these loads. The other frame-read boundary at `0x1003ECB8C` remains unresolved.

## Provenance and assumptions

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. All addresses below are preferred virtual addresses in that image. [Contracts](triage_evidence/daemon_arena_entry_contracts.json) retain four original spans, exact operand-access certificates, the 256-input allocator bank and the original import binding. [Proofs](triage_evidence/daemon_arena_entry_proofs.json) retain ten original/simplified SMT pairs and three independently decoded format12 pointer records. [Current IDA bytes](triage_evidence/daemon_arena_entry_live_ida.json) contain 105 matched rows; folded-item byte coverage is limited to the supplied bytes. [Profiles](triage_evidence/daemon_arena_entry_profiles.json) and [checks](triage_evidence/daemon_arena_entry_checks.json) retain all source visits, memory epochs, unknown masks and fresh replay outcomes.

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| AE1 | The pinned daemon image is the intended source | Addresses, constants and call binding | Rehash original bytes/fixups and compare current IDA; native daemon/kext pairing remains unknown |
| AE2 | The selected serialized prefix has gate=0x5D96, flag=1, marker=0 and the recovered roots | Concrete path and allocator boundary | Preserve all preceding 287 source visits; vary controller words, frame placement and incoming registers |
| AE3 | F denotes valid mapped storage for the 3,040-byte callback frame, disjoint from source-image globals | Nonfaulting local loads at F+0x5F8/F+0x540 | Check both addresses/widths lie within the frame; native mapping or asynchronous effects are not modeled |
| AE4 | A load's complete architectural effects are represented by its destination register on these ordinary mapped-memory sites | Dead-load classification | Inspect original A64 opcodes, Capstone implicit/explicit register accesses, all intervening instructions and first full-register overwrite |
| AE5 | Selected branch/root preconditions and equal controller words hold during the source lift | Ten symbolic obligations | Recover the preceding source producers; reject interference or another branch rather than applying this certificate there |
| AE6 | W0/W10 writes zero-extend into X0/X10 | Full 64-bit kills | Inspect literal instruction encodings and compare complete final X registers for arbitrary two-word substitution |
| AE7 | Unknown backing bits are physical analysis storage choices, not initialized values | Finite executions and knownness | Exercise zero, 0xA5, all-ones and two asymmetric words; retain knownness/provenance zero before and after the path |
| AE8 | Original authenticated fixups identify target metadata | Two branches and malloc import | Independently decode targets, IA keys, diversity and import ordinal; hardware PAC remains untested |
| AE9 | Reaching a source call boundary does not establish an allocation result | Arena extent/ownership interpretation | Execute a declared returning allocator model and original subsequent consumers in a separate increment; native allocation remains unknown |
| AE10 | This increment concerns the selected callback prefix and first allocator interface | Coverage and scoped quality gates | Continue post-call data flow, the alternate unknown-frame path and actual daemon/kext transport; full objective remains active |

## Dead-load certificates

Let F be callback SP after the prologue. Its relation to entry SP E is F=E-`0xBE0`; FP=F+`0xBD0`. Both eight-byte reads lie within `[F,F+3040)`. The preceding report establishes this geometry and the source-produced controller/bank roots. [AE2,AE3]

| Unknown field | Original instruction | Destination | First full-register kill | Intervening consumption |
| --- | --- | --- | --- | --- |
| F+0x5F8, 8 bytes | 0x1003B5738: LDR X10,[SP,#0x5F8] | X10 | 0x10032A4BC: MOV W10,#0x56 | No X10/W10 read; no earlier call |
| F+0x540, 8 bytes | 0x1003B573C: LDR X0,[SP,#0x540] | X0 | 0x10032A4DC: MOV W0,#0x5F90 | No X0/W0 read; no earlier call |

The certificates inspect 151 operand-access steps in total, including each kill. W10's write clears the entire architectural X10, and W0's write clears X0. The instructions between each definition and kill include two authenticated branches whose source-resolved targets do not depend on either loaded value. No BL/BLR/BLRAA or system instruction precedes the kills in the certified path. [AE4-AE6]

The source lift retains both original loads with independent symbolic values S and T. It establishes the two branch destinations/modifiers, the final allocator target/arguments, the preallocation source store, and noninterference under simultaneous substitution `(S,T) -> (S2,T2)` for all 31 X registers, source-store addresses/values and the modeled dispatch equality/carry predicates. The original stack storage still contains its unknown bits. No claim of source initialization or equality of all physical RAM is made. [AE5-AE7]

This proof does not authorize skipping an arbitrary unknown load. Each permitted site is fixed by PC, frame-relative address, width, complete-register kill and verified intervening path. The new producer executes both original LDR instructions against mapped storage and records their unknown masks; it supplies no new frame fixture and marks neither word known. Other unknown private reads remain rejected. [AE3,AE4,AE7]

## Selected control and allocation ABI

At the preceding flag path, source arithmetic overwrites W11 after testing the flag. The selected phase entering `0x1003B5724` has W9=`0x8A9B8560` and W11=`0x266C4654`. W11 at that point is not the original flag value. These phase values are lifted from `0x1003308A0..0x1003308E4`, rather than inferred from a semantic label. [AE2,AE5]

```text
45053C callback entry
    |
35DF48 CAS gate -> 32BA0C root preparation -> 3308A0 flag path
                                                   |
                                                   v
                                                3B5724
                                      unknown X10/X0 loads
                                                   |
                                                3C24B8
                                                   |
                                                32A464
                                      descriptor+0 <- u64(0)
                                      kill old X10, then X0
                                                   |
                                                32A4E8
                                      malloc(size_t64 = 90000)
                                      boundary; call not executed
```

| Site | Original pointer slot | Target / binding | IA diversity |
| --- | --- | --- | --- |
| BRAA 0x1003B57D0 | 0x101086D58 | 0x1003C24B8 | 0x6587 |
| BRAA 0x1003C24E0 | 0x101085358 | 0x10032A464 | 0xB9E1 |
| BLRAA 0x10032A4E8 | 0x10109FF58 | libSystem/_malloc | 0x6AA4 |

All three original format12 records use IA and address-diversity zero. The malloc record is authenticated bind ordinal 140, library ordinal 12, import addend zero. The two branch records are authenticated rebases. These establish static binding metadata; no native code pointer or successful hardware authentication is inferred. [AE8]

The allocator selector uses byte banks `0x100E99700` and `0x100F4E190`, key `0x56`, additive index `0xCBF9`. All 256 byte inputs produce constant `0x14`, index `0xCC0D`, and slot `0x10109FF58`. Source `MOV W0,#0x5F90; MOVK W0,#1,LSL#16` establishes the size exactly:

```text
size = (1 * 65536 + 24464) bytes = 90000 bytes
X0   = zero_extend_64(W0)
X17  = 0x6AA4
```

At `0x10032A484`, source stores u64 zero at `0x1010B5EF0`, the descriptor base already identified in the [startup report](rpc502_startup_report.md). The current probe has not allocated an arena, published its pointer, initialized its contents or returned from this call. The earlier startup report's modeled allocation/publication remains separate evidence under its original environment premises. The semantic meaning of descriptor offset zero remains unknown. [AE9]

No Mach, IOKit, bootstrap or XPC emission is added by this prefix. It establishes the allocator interface and local frame/control relationship preceding later daemon work. [AE10]

## Verification and remaining interfaces

All checks pass: 32 cases, 12,000 original instruction visits, 64 permitted dead-load observations, 64 still-unknown boundary words, 192 reconstructed frame snapshots, 96 exact target-load epochs, 32 preserved preceding source prefixes and eight fresh replay cases. Each of eight prefix environments produces identical boundary registers, branches and source writes across four unknown backing patterns. Ten source proof pairs cover 103 lifted instructions. Original pointer decoding, all 256 bank inputs and 105 current IDA rows are checked independently. The allocator remains unexecuted. [Checks](triage_evidence/daemon_arena_entry_checks.json), [preservation](triage_evidence/daemon_arena_entry_preservation.json), [scoped gates](triage_evidence/daemon_arena_entry_quality_gates.json).

| Impact | Next interface question | Evidence required |
| --- | --- | --- |
| High | Original post-malloc descriptor and arena consumers | Carry a declared returned owner through source stores and later reads with extent/knownness tracking |
| High | Alternate boundary F+0x5A8 and subsequent F+0x448 | Recover first uses/kills and feasible source paths; reuse a dead-load exception only after a separate proof |
| High | Continuous strict-state startup through rwlock and IOKit calls | Compose source-produced state and allocation/lock/API outcomes without promoting unknown bytes |
| Medium | Native caller and allocation lifetime | Pair source ownership with actual callback invocation, allocator result and all release sites |
| Medium | New transport edge after the prepared workspace | Identify exact Mach/IOKit call, packet fields, connection and rights provenance |

Complexity: source certificate construction is O(I) time/space over the selected instructions; selector checking is O(256); finite execution and audit are O(C*(V+events+J*K)) time and O(largest artifact+C*(V+events)+4096J+K) retained space, where J counts demand pages and K counts fixup records. Solver timeout is 30 s per obligation; the proof covers arbitrary loaded bits rather than inferring generality from the four physical patterns.

QG1 passes for factual analysis. QG2 passes with AE1-AE10. QG3 passes for this selected interface increment; the broad objective remains active. QG4 passes for explicit u32/u64 semantics, exact byte extent and complexity. QG5 passes with unknown storage, register invariance, call reachability and allocation outcome distinguished. QG6 passes for source liveness, original/simplified SMT, byte/epoch audits, current IDA and fixup/import provenance. QG7 passes with the bounded impact-labeled continuation table. Native reachability, allocation result/lifetime and later transport remain unknown.

Reproduction from `/Users/___/dev/dylex/extracted`:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_arena_entry.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_arena_entry.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_arena_entry.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_arena_entry.py
```
