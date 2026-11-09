# Daemon initialization frame, atomic gate and post-rwlock workspace

The startup callback at `0x10045053C` produces the frame roots used by the paired rwlock creator and its continuation at `0x1003062A4`. Three retained completed-startup journals contain that ordered connection. Their stack begins zero-filled; they establish conditional private execution, not native startup or stack definedness. The new strict probe establishes the entry/gate prefix and stops before unproduced frame reads. It does not replace those reads with zero.

One preceding fixture assumption is corrected: frame+`0x390` is **`0x1010B7DD8`**, rather than `0x1010B7D48` used in the earlier local lifecycle probe. Source also establishes FP=SP+`0xBD0`, rather than the earlier fixture's SP+`0x600`. Eight fresh local compositions with both corrected inputs preserve the four initializer success/error combinations and the second-result state09 predicate. The earlier [lifecycle report](daemon_rwlock_lifecycle_report.md) and its artifacts remain frozen evidence under their declared premises.

The continuation calls internal byte-fill routine `0x10046FAF8` to clear 1,024 bytes at frame+`0x6F0`, then reserves 64 bytes through a frame cursor. This is a local memory operation; no Mach destination or right transfer is identified in the selected spans.

## Primary evidence and assumption register

Source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred source virtual addresses. [Contracts](triage_evidence/daemon_frame_entry_contracts.json) retain 14 original spans, seven exhaustive byte-bank selections, 28 independently decoded original fixups, 291 current IDA rows and three historical startup readbacks. [Profiles](triage_evidence/daemon_frame_entry_profiles.json), [independent checks](triage_evidence/daemon_frame_entry_checks.json) and [14 source proof pairs](triage_evidence/daemon_frame_entry_proofs.json) retain the finite and symbolic evidence. [Current IDA bytes](triage_evidence/daemon_frame_entry_live_ida.json) are checked against the backing file; pre-existing semantic names/comments are not independent proof.

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| FE1 | This exact arm64e image is the intended daemon | All addresses and layouts | Rehash backing file, original opcodes and pointer records; establish native daemon/kext build pairing separately |
| FE2 | Callback entry uses the retained ordinary stack/register ABI | Frame geometry and saves | Check prologue, all 12 GPR and eight SIMD low64 save slots; vary stack placement and incoming register bits |
| FE3 | Entry globals and guard are declared private fixtures | Finite prefix behavior | Vary both controller words, atomic word, flag and marker; compare source writes, not labels |
| FE4 | Single-thread CAS semantics describe only the private transition | Gate branch and retry edge | Check original CASAL opcode, returned expected register and word mutation; native contention/ordering remain unknown |
| FE5 | Original fixups identify un-authenticated target values | Selected dispatch edges | Decode original format12 words, check key/diversity and exhaustive banks; hardware PAC success remains unknown |
| FE6 | Unknown private stack bytes remain unknown in the new prefix probe | Current stop locations | Poison private storage and reject reads without source/fixture producers; do not seed the next field to progress |
| FE7 | Retained startup journals have their published zero-stack/API premises | Continuous entry-to-rwlock connection | Rehash historical corpus, read its source sequence and write epochs; arbitrary-stack continuous execution remains unproved |
| FE8 | Corrected local pair fixtures compose the recovered roots and geometry | Eight corrected pair outcomes | Freshly replay both placements and all four status pairs; full entry-to-pair strict execution remains unknown |
| FE9 | Fill arguments are u8-compatible values in finite tests | Exact byte-fill behavior | Exercise eight alignments, lengths 0..65 and 1,024, values 0/0x5A; wider fill argument behavior remains unclassified |
| FE10 | Cursor arithmetic is local modulo-2^64 arithmetic | 64-byte reservation formula | Prove arbitrary cursor formula; establish extent/lifetime before using it as a general allocator contract |
| FE11 | No selected source operation implies an external port transaction | IPC implications | Identify actual Mach/IOKit call arguments and emission PC before adding a port edge |
| FE12 | This increment covers frame provenance and local continuation only | Coverage and scoped quality gates | Continue from unknown frame reads and into the prepared workspace; broad interface objective remains active |

## Frame geometry and original producers

Let E be SP at callback entry and F be SP after the prologue. `STP D15,D14,[SP,#-0xA0]!` and `SUB SP,SP,#0xB40` establish F=E-`0xBE0` (3,040 bytes). The intermediate `ADD X29,SP,#0x90` establishes FP=E-16=F+`0xBD0`. Source saves D8-D15 as eight 64-bit values and X19-X30 as twelve 64-bit values. The saved guard occupies F+`0xB28`. The rwlock record FP-`0xD8` is therefore F+`0xAF8`. [FE1,FE2]

| F-relative field | Width, bytes | Source value | Producer PC |
| --- | ---: | --- | --- |
| +0x28 | 8 | Address of encoded startup status, 0x1010B6360 | 0x1004506D0 |
| +0x348 | 8 | 0x100F4E190, byte-bank root | 0x10032BB30 |
| +0x350 | 8 | 0x100E99700, byte-bank root | 0x10032BB0C |
| +0x360 | 8 | 0x101031FA0, byte-bank root | 0x10032BAD8 |
| +0x368 | 8 | 0x100FC4230, byte-bank root | 0x10032BA60 |
| +0x370 | 8 | 0x100F4E390, byte-bank root | 0x1004506A4 |
| +0x378 | 8 | 0x100E99A00, byte-bank root | 0x100450694 |
| +0x390 | 8 | 0x1010B7DD8, controller-word address | 0x10032BB6C |
| +0x398 | 8 | 0x1010C4670, controller-word address | 0x10032BB70 |
| +0x5C0 | 8 | Initial cursor 16 | 0x100450724 |

The historical readback captures these fields immediately before the first record-control store at `0x1002DAB80`. The cursor is again 16 there, but its most recent writer is **`0x100247598`**, not the entry initializer: intermediate cursor operations occurred. The default retained startup uses E=`0x70078000`, F=`0x70077420`, FP=`0x70077FF0`, record=`0x70077F18`. These are private addresses, not native addresses. [FE7]

At `0x100450650..0x100450680`, let A be the original 64-bit word at `0x1010B7DD8` and B the original word at `0x1010C4670`. Source publishes the same D at both locations:

```text
D = u64(((B - A - (F + 0x658)) XOR 0x73D046208EAED1A6)
        * 0x0A5CD4CF)
```

This controller update differs from the creator helper's separately recovered controller update. Common constants do not establish identical formulas or object identity. Source stores encoded status `0x8B3DC651` at `0x1010B6360` before acquiring the gate or completing startup. The preceding [startup report](rpc502_startup_report.md) already establishes that early status/readiness publications are insufficient completion markers. [FE3,FE7]

## Atomic gate and control flow

The first `BRAA` at `0x100450784` loads target slot `0x10107D7F0` and uses IA modifier `0xE58E`, selecting `0x10035DF48`. The new source proof covers every u32 value S at gate `0x1010B5DE0`:

| S before CASAL at 0x10035DF84 | Gate afterward | Index / slot | Target at 0x10035DFA4 |
| --- | --- | --- | --- |
| 0x5D96 | 0xA94EF | 0x8726 / 0x10107D820 | 0x10032BA0C |
| Any other u32 | S | 0x8720 / 0x10107D7F0 | 0x10035DF48, retry |

CASAL returns the previous word through W16; the following comparison selects the edge. This establishes the local compare/exchange and retry behavior. It does not establish fairness, timeout, concurrent ownership or native ordering. [FE4,FE5]

With the marker fixture zero, `0x10032BB88` reaches `0x1003308A0`. This reads u32 flag `0x1010B6CB8`. Zero selects `0x10046C73C`; nonzero selects `0x1003B5724`. The zero branch writes readiness byte 1 at `0x1010C5798` using `0x10046C750`, then reaches `0x10032C590`. Source `STR W19,[X7]` at `0x10032C59C` restores gate word `0x5D96`; this particular restoration is a plain STR, not a store-release instruction. A second CASAL is present at `0x1002BC398`. Marker fixture 1 takes a different selected route; its actual source sequence is retained. [FE3,FE4]

```text
45053C entry -> 35DF48 CAS gate -- mismatch --> 35DF48
                                |
                                +-- match -> 32BA0C roots/marker
                                               |
                          selected flag/marker continuations
                                               |
                          strict unknown-frame boundaries

retained completed startup, explicit zero-stack/API premises:
45053C -> ... -> 2DAB28 -> 2DAC48 -> 2DAD48 -> 1F1FF8
                                                       |
                                                       v
                                                    3062A4
                                                       |
                                                    30631C
                                                       |
                                                    46FAF8
```

The 96 new entry cases produce 72 failed-CAS retry boundaries, eight boundaries before `0x1003B5724` (the next code reads F+`0x5F8`), and 16 boundaries immediately before `0x1003ECB8C` (next read F+`0x5A8`). These are known source gaps, not native failures. No source producer for those values is invented. [FE6]

## Corrected pair and retained continuous evidence

The three historical cases are `initialized_worker`, `quantum250k_prefix` and `entropy_time_prefix`. Each completed callback journal contains, in order, entry `0x10045053C`, pair `0x1002DAB28`, calls `0x1002DAC48`/`0x1002DAD48`, state writer `0x1001F1FF8`, join `0x1003062A4` and fill call `0x10030631C`. Thirty predecessor field epochs are checked across them. This connects the local pair to the registered callback in those existing fixtures; it does not promote the earlier zero-stack observer bytes to defined inputs. No historical multi-million-step producer was rerun in this increment. [FE7]

Eight fresh corrected pair cases use F+`0x390`=`0x1010B7DD8`, FP=F+`0xBD0`, both placements and initializer status pairs (0,0), (0,16), (16,0), (16,16). Source writes the primary cell only after first success and the second cell only after second success; the caller still tests only the second result before state09. Failed-first/successful-second still publishes 09; successful-first/failed-second does not. The earlier wrong root was an explicit fixture, not a source fact. The correction does not change these observed local outcomes. Continuous execution with strict unknown-stack tracking remains unproved. [FE8]

## Join, byte-fill ABI and cursor

| Operation | Exact PC / source | Established ABI or effect |
| --- | --- | --- |
| Select internal fill | 0x100306304, slot0x1010A03C8 | Target0x10046FAF8, IA modifier0xAC7D |
| Fill call | 0x10030631C | X0=F+0x6F0, W1=0, W2=0x400=1,024 bytes |
| Internal fill body | 0x10046FAF8..0x10046FC5C | Alignment prefix, repeated 64-bit stores and byte tail; no imported call |
| Load old cursor C | 0x100306328 | u64 at F+0x5C0 |
| Reserve pointer | 0x10030632C / 0x100306338 | F+0x660+C -> F+0x250 |
| Preserve filled-region pointer | 0x100306334 | F+0x6F0 -> F+0x6E8 |
| Advance cursor | 0x100306330 / 0x10030635C | u64(C+64) -> F+0x5C0 |

The historical join cursor is 16, so the reservation pointer is F+`0x670` and the new cursor is 80. The cleared half-open range is `[F+0x6F0,F+0xAF0)`; it ends eight bytes before the rwlock record at F+`0xAF8`. Cursor reservation and byte-fill destination are distinct regions in this case. General allocation/lifetime semantics remain unknown. [FE7,FE10]

The 272 isolated fill cases cover all eight address residues modulo 8, two byte values and 17 lengths: 0,1,2,3,4,5,6,7,8,9,15,16,31,63,64,65,1,024. Writes remain within the requested extent and produce the expected bytes. For the aligned 1,024-byte zero case, X0 on return is destination+1,024; the routine does not preserve the original destination as a libc `memset` return would. Its exact contract for non-u8 fill arguments remains unknown. [FE9]

## Validation and bounded continuation

All scoped checks pass: 96 entry cases (30,248 original visits), 272 fill cases (11,838 visits), eight corrected pair cases (5,188 visits), 112 single-thread CAS observations, 14 original-source proof pairs over 73 lifted instructions, seven banks/1,792 inputs, 28 fixups and 291 current IDA rows. Eight entry cases, six fills and all eight corrected pairs are freshly replayed. Source byte/read/write epochs and 304 frame snapshots are independently reconstructed; three historical startup cases are read back separately. No native target, import, pthread, IOKit, Mach or hardware PAC executes. [Checks](triage_evidence/daemon_frame_entry_checks.json), [preservation](triage_evidence/daemon_frame_entry_preservation.json), [scoped gates](triage_evidence/daemon_frame_entry_quality_gates.json).

| Impact | Next investigation | Concrete falsification / completion criterion |
| --- | --- | --- |
| High | Symbolically classify F+0x5F8 and F+0x5A8 consumers | Prove whether arbitrary values cancel, or recover their feasible producers before strict continuation |
| High | Continue after cursor/workspace preparation | Identify first external callee, complete record fields and actual connection/port provenance |
| High | Compose corrected startup and full IOKit initializer | Carry source-produced state/cells through actual caller path, preserving explicit API outcomes |
| Medium | Census CAS/restoration sites using gate0x1010B5DE0 | Separate atomic acquisition, plain releases, operation-specific ownership and callback lifetimes |
| Medium | Recover cursor push/pop invariants | Link +32/+64 reservations with -32/-64 restorations under one proven frame, with bounds |
| Low | Recover wider fill-input semantics | Exhaustive low-width arithmetic or source proof; avoid assigning an unsupported libc prototype |

QG1 passes for factual technical analysis. QG2 passes with FE1-FE12 and falsification probes. QG3 passes for this increment; the full objective remains active. QG4 passes for explicit u8/u32/u64 arithmetic, byte extents and complexity. QG5 passes with the corrected root and the strict/historical evidence boundary stated. QG6 passes for pinned source, original fixups, current IDA bytes, finite epoch audits and reproducible SMT. QG7 passes with impact-labeled bounded continuations. Native pairing, contention, complete strict-stack startup and the next external workspace consumer remain unknown.

Reproduce with the local Python environment and installed Z3 paths used by the preceding reports:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_frame_entry.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_frame_entry.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_frame_entry.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_frame_entry.py
```
