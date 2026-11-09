# Client-state continuation: allocations, borrowed span and VM cleanup

The continuation after the Boolean collector requests a 32-byte object at
`0x100570148`, initializes 28 bytes, and requests a separate 16-byte object
at `0x100699858`. Its successful continuation uses the original caller's
`B+0` as a borrowed byte-buffer pointer and the low 32 bits of `B+8` as a
length. Its second-allocation failure route passes the first object into
VM cleanup. The exact imported-call frontier is `vm_deallocate` at
`0x1004776C0`.

These are source-established contracts under explicit private entry/API
models. No native allocation, VM operation, entitlement query or Mach IPC
was executed for this increment. The retained buffers' native ownership,
final object publication and final admission remain unknown. The broad
daemon/kext/interface investigation remains active.

## Evidence and reproduction

Original daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Source addresses are unslid VAs. Offsets, masks, selectors and status words
are hexadecimal; ordinary sizes and counts are decimal bytes unless stated.
F denotes the protected-core frame and B its original borrowed input record.
Private placements are F=`0x680004F230` and B=`0x6800001000`; these are
harness addresses, not native fixed addresses.

This extends the [Boolean collector](daemon_boolean_chain_report.md),
[secondary-result ABI](daemon_secondary_result_report.md), and
[caller handover](daemon_mig_handover_report.md). Original files suffice;
no new IDA query, IDB change or saved-analysis-memory change was performed.

Evidence comprises [first-allocation models](triage_evidence/daemon_client_object_profiles.json),
[second-allocation models](triage_evidence/daemon_client_object_pair_profiles.json),
[task-word cleanup models](triage_evidence/daemon_client_object_cleanup_profiles.json),
[original source/fixup ledgers](triage_evidence/daemon_client_object_contracts.json),
[16 original/simplified proof pairs](triage_evidence/daemon_client_object_proofs.json),
and [independent replay](triage_evidence/daemon_client_object_checks.json).
API returns and task names here are declared models, not observations from
the annotated RAX trace. No new pure host-libc experiment was performed.

From `/Users/___/dev/dylex/extracted`, apply the following prefix to each
script in the listed order:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

probe_daemon_client_object.py
probe_daemon_client_pair.py
probe_daemon_client_cleanup.py
recover_daemon_client_object.py
prove_daemon_client_object.py
validate_daemon_client_object.py
```

## Allocation and initialization contracts

Both allocation sites resolve the original authenticated bind at
`0x10109FF58` to `libSystem/_malloc`, IA diversity `0x6AA4`, address
diversity zero. The requested extents are 32 and 16 bytes, respectively.
They are distinct allocation epochs; neither result denotes a Mach port.

```text
Boolean collector -> malloc(32), 100570148
                       |
          +------------+--------------------+
          | NULL                            | non-NULL
          v                                 v
  status/error cleanup               initialize 28/32 bytes
  -> output-clear frontier                  |
                                            v
                                     malloc(16), 100699858
                                            |
                         +------------------+------------------+
                         | NULL                                | non-NULL
                         v                                     v
                 first-object cleanup                   clear 16/16 bytes
                 -> task-self data                            |
                 -> vm_deallocate frontier             borrowed-span gates
                                                       -> byte-read frontier
```

The first original initializer is `0x1005596C4..0x1005596E0`:

| Object offset | Width, bytes | Initialized value | Established role |
| --- | ---: | --- | --- |
| +00 | 8 | 0 | Cleanup later loads this as a VM address. |
| +08 | 4 | 8B3DC651 | Cleanup later XOR-decodes this as a size. |
| +0C | 4 | 8B3DC651 | Further semantic role unknown. |
| +10 | 4 | 8B3DC651 | Further semantic role unknown. |
| +14 | 4 | 4D8916DC | Further semantic role unknown. |
| +18 | 4 | 8B3DC651 | Further semantic role unknown. |
| +1C | 4 | Unwritten | Contents remain undefined in these models. |

`STR XZR` writes +00; the two `STP Wn,Wm` instructions each write two
four-byte fields. The final `STR W9` writes +18. The source saves the
allocation pointer at F+3650 at `0x1005596E4`.

A byte-array proof quantifies every initial byte and pointer word. It
establishes the exact initialized bytes, preservation of +1C..+1F, and
preservation of every address outside the 28-byte write footprint. This
is an abstract memory equation under a valid-object premise, not a native
pointer-validity proof. An unwritten tail alone establishes no exposure.

The second pointer is saved at F+2FF8 by `0x10069985C`. Its non-NULL route
executes `STP XZR,XZR,[X0]` at `0x1008C3890`, defining all 16 bytes as zero.
Its later semantic role and relationship to the first object's fields are
unknown; no field publication between the two allocations is asserted.

The [reconstructed C layouts and SDK signature probe](triage_evidence/daemon_client_object_sdk.c)
compile to [LLVM IR](triage_evidence/daemon_client_object_sdk.ll). These
check layout offsets and the local SDK's Mach/VM parameter widths. They
are analysis declarations; the installed SDK is not a matched target
runtime implementation.

## Original caller fields and bounded byte-reader entry

The frozen parent source expressions establish, for all input field bits,
that F+82D8 contains the original B+0 u64 and F+990 contains the original
B+8 u64. They are not replacement fixtures inserted at the allocation.

| Original field | Source use in this continuation | Width, bytes |
| --- | --- | ---: |
| B+00 | Borrowed byte-buffer pointer, later saved at F+3818 | 8 |
| B+08 | Low 32 bits used as length; high 32 bits do not affect this local length equation | 4 consumed from an 8-byte load |
| B+38 | Borrowed first output pointer, used by the allocation-NULL output-clearing route | 8 |
| B+40 | Borrowed second output pointer in the previously recovered output-clearing sequence | 8 |

Let L=`low32(u64(B+8))`. Original arithmetic at
`0x1005596E8..0x10055970C` stores `L XOR 0x8B3DC651` at F+3D1C.
Source-preserved W9 carries that value to F+7550 at `0x1006997CC`.
The input B+8 field itself is not thereby identified as encoded.
`0x1006997D0` saves B+0 at F+3818, and `0x1006997D4` initializes the
u64 cursor at F+4D50 to zero. The proof checks register preservation
across the intervening original blocks rather than silently joining cuts.
For `CMP X10,#0` at 0x10055972C, Capstone incorrectly marks X10 as written.
The audit corrects only the pinned bytes `5F0100F1` (word `0xF100015F`),
whose SUBS-XZR semantics write NZCV; the local proof also checks X10.

The next source predicates are:

```text
L64 = zero_extend_u32(u32(F+7550) XOR 8B3DC651)
C   = u64(F+4D50)
R   = u64(L64 - C)

1006D5510..1006D5514: unsigned L64 > C
1008CF2F4..1008CF2FC: u64(F+3818) != 0 on the continuing route
10076B274..10076B278: unsigned R > 9
10067046C:           index = C + 6
100670470:           read one byte at u64(F+3818) + index
```

For all encoded-length and cursor words, the continuing predicates imply
`C+6 < L64`, without index overflow: C is below a zero-extended u32 length.
This does not prove that adding the index to the borrowed pointer yields a
native valid address, that the pointee owns L bytes, or that later parser
accesses are bounded. The modeled caller uses non-NULL opaque pointer
values without pointee extents, so these continuous paths stop before the
read at `0x100670470`; that read is not counted as executed.

Selected original dispatch contracts are exact under the retained phases:

| Predicate / branch PC | Index if false / NULL | Index if true / non-NULL | IA diversity |
| --- | --- | --- | --- |
| malloc(32) result, 100570178 | 4146 -> 1004DE1D4 | 4157 -> 1005596AC | 0248 |
| Initial borrowed pointer, 100559758 | 6CD0 -> 1004DE1D4 | 6CD4 -> 100500A1C | F2AB |
| malloc(16) result, 100699888 | 70BC -> 1008C8B80 | 7081 -> 1008C3880 | 8233 |
| L64 > C, 1006D5534 | A62B -> 1006C47BC | A633 -> 1008CF2D8 | D638 |
| Saved pointer non-NULL, 1008CF324 | 9B55 -> 1008F045C | 9B50 -> 10076B268 | 1758 |
| R > 9, 10076B2A0 | 1A25 -> 1008F045C | 2496 -> 100670430 | 23E6 |

The table base is `0x101039EF0`; a slot is base+8*index. All listed
original words have address diversity zero. The NULL borrowed-pointer,
length-not-above-cursor, saved-pointer-NULL and at-most-nine alternatives
are static/formal recoveries, not new continuous CPU paths. The full
per-edge slot/word ledger is in the contracts artifact.

## Failure status and VM cleanup ABI

The first allocation's NULL route stores raw status `0x74C29D85` at
F+44A4 at `0x1004DE1E0`. XOR with `0x8B3DC651` yields `0xFFFF5BD4`;
its symbolic error name is unknown. The outer source reloads the four-byte
status and compares it with `0x8B3DC651` before its output-clearing join.
Current NULL-object models stop before `STR XZR,[X9]` at `0x10057A774`,
where X9 is the original B+38 pointee. Non-NULL input fields do not
establish their writable extents. No native failure or output fault was
observed.

On the second allocation's NULL route, cleanup eventually saves the first
allocation into F+1930 at `0x1005AA754`. The same save site is visited in
distinct cleanup epochs: its earlier saved value is zero, and its later
value is the first object's pointer. The later source at `0x100477648`
loads that pointer. Epochs must not be merged.

Strict models stop at `0x100477644`, before reading the unavailable
`mach_task_self_` imported data word. Sixteen additional models provide
explicit task-name words `0x00123403` or `0xFFFFFFFF`; only four bytes
are loaded. These are private tokens, not observed native port rights.
The source then reaches the following call and stops before executing it:

| Call / argument | Original source | Recovered value or equation |
| --- | --- | --- |
| `vm_deallocate`, call PC 1004776C0 | Slot 1010A00F8, IA 3893, addrdiv 0 | Original `/usr/lib/libSystem.B.dylib` authenticated bind, addends zero |
| X0, task name | 100477644, `LDR W0,[X8]` | zero_extend_u32(task-self word) |
| X1, address | 10047764C, `LDR X1,[X20]` | u64(object+00) |
| X2, size | 100477650 and 1004776A4 | zero_extend_u32(u32(object+08) XOR 8B3DC651) |

Source phase recovery gives W19=1074 at this cleanup, making the additive
size key exactly 8B3DC651. Separate fragment proofs and intervening write-set
checks preserve task, address, encoded size and key. A universal local proof
quantifies task-word, address and encoded-size bits at disjoint valid cells.

The initial object supplies address=0 and size=0 in all 16 call-frontier
models. This supports a VM-cleanup role for fields +00/+08. It establishes
neither a native VM result nor a Mach message ID, port-right emission,
disposition or kernel destination. Actual task-self resolution, library
transport and subsequent cleanup/free behavior remain unexecuted here.

## State consumers, assumptions and verification

Across these continuations, neither the u32 accumulated client state at
F+6ADC nor the converted legacy output at F+1280 is read after the first
allocation request and before the listed boundaries. All final client-bit
states remain those established by the predecessor collector. No final
policy meaning is assigned to the state, either allocation or zero status.

| ID | Premise / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CO1 | Pinned image/source bytes, original fixups and retained parent expressions identify these contracts. | Rehash image, match 2,703 unique visited opcodes, independently decode used slots/addends and rebuild parent-field equality. |
| CO2 | Fixed retained phases, controller states, file/BSS backing and predecessor API models define the continuous cases. | Preserve 80 predecessor prefixes, vary two environments and four Boolean combinations; native initialization remains unknown. |
| CO3 | Successful allocation models return separate valid private extents; bytes start undefined. | Check both regions' undefined masks before return, exact writes, 28/32 versus 16/16 definedness and changed physical backing. Native allocator results/feasibility remain unknown. |
| CO4 | Local symbolic frame/object/export cells are readable, writable as needed, and disjoint. | Byte-array initializer proofs and explicit fixed disjoint placements for multi-cell cleanup proofs; recover native owner/alias extents separately. |
| CO5 | Imported APIs preserve X18..X29; caller-clobbered GPRs/NZCV follow explicit models. Vector effects are outside scope. | Fresh CPU replay checks every declared transition, argument, preserved GPR and journaled effect. |
| CO6 | Borrowed B+0 and output pointers lack native pointee ownership evidence. | Stop before unavailable-owner reads/writes; establish actual caller spans before wider parser/output claims. Guarded indices alone are insufficient. |
| CO7 | Task-self words are private model tokens and PAC is logical. | Pin exact import slots/key/diversity; stop before vm_deallocate. Recover native namespace, library IPC and hardware authentication separately. |
| CO8 | Static alternatives, byte equality and status/state equations do not prove final admission or publication. | Keep unexecuted branch targets explicit; trace bit/numeric consumers, full parser and final output transfer. |

Sixteen original/simplified proof pairs solve UNSAT, including the 128-bit
parent input-field relation, all allocator pointer words, initial-byte
domains, u64/u32 length/cursor domains, guarded index and cleanup arguments.
Both forms of all 32 SMT files are rebuilt/read back and solved independently.

Fresh A64 replay checks 80 profiles over 296,416 source visits, 63,072 reads,
18,576 writes, 6,728 logical edges and 3,088 declared API transitions. It
verifies 128 allocation requests, 64 object32 initializers, 16 pair16
initializers, 64 borrowed-span contexts and 16 vm_deallocate call frontiers.
Every private source read has known bytes; uninterpreted read bytes are zero.
The five final frontiers each have 16 profiles. Counts include preserved
predecessor execution, not only the new suffixes. No native effects execute.

Probe/recovery/replay cost is O(total source visits + artifact/source bytes);
space is O(one private CPU map + journals). BV/array proofs add expression
DAG and solver resources. Widths, byte extents and modular equations are
exact; no timing or native failure rate is estimated.

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Establish the borrowed-buffer ABI and continue the parser. | Source-written caller B+0/B+8 provenance, actual pointee extent, length classes, header fields and later reads. |
| high | Follow VM cleanup return and allocator ownership. | Matching vm_deallocate return models, source cleanup/free requests, error preservation and final output publication. |
| high | Identify object field and client-state consumers. | Source-continuous loads of +0C/+10/+14/+18 and F+6ADC/F+1280, then actual operation effects. |
| medium | Recover static length/NULL alternatives continuously. | Parent-consistent input substitutions for zero/short lengths and valid owners, preserving complete source prefixes. |
| medium | Join task-self cleanup to deeper IPC. | Matched runtime wrapper, request framing, destination-right provenance and kernel receive path. A symbol name alone does not establish those joins. |

QG1: Pass; factual source and ABI analysis requires no normative judgment.

QG2: Pass for this increment; CO1-CO8 state assumptions, dependent results and falsification probes.

QG3: Pass for this increment; allocation, initialization, borrowed input, length/selector/status and VM-call contracts are covered. The broad objective remains incomplete.

QG4: Pass; widths, byte counts, modular equations, reproduction steps, SDK checks and complexity are explicit.

QG5: Pass within scope; initialized versus undefined bytes, cleanup epochs, static alternatives, guarded indices, native owner gaps and model task names are separated.

QG6: Pass; original bytes/fixups, frozen parent expressions, rebuilt SMT, compile-only SDK and independent source replay support the scoped claims.

QG7: Pass; impact-labeled continuations cover parser ownership, VM cleanup, state consumers, static alternatives and deeper transport.

Publication evidence: [preservation](triage_evidence/daemon_client_object_delivery.json)
and [quality gates](triage_evidence/daemon_client_object_quality_gates.json).
