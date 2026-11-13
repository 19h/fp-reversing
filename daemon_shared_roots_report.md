# Shared-core phase and bank initialization

Current bank-origin increment: The [bank-origin continuation](daemon_return_bank_origins_report.md) re-executes these existing bank writers in twelve strict initializer paths and verifies preservation to argument-read, audit-import and outer-RETAB boundaries. A separate later caller uses two explicit bank premises; no continuous initializer-to-caller join is claimed.

The original prefix from entry `0x10061A2D0` through setup boundary `0x1004C3634` now establishes the initial writers of ten fields used by the large-frame auxiliary callers. With protected tag `0x6CF4`, source writes the full u64 phase word `F+0x9D0=0x6CF4`, the dispatch table, controller addresses and three bank pairs. Eight strict profiles define all tracked bytes through actual source stores and preserve them until the boundary. The later control-flow connection into the nine emitters remains unproved. [SR1-SR10]

Primary source: `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [eight strict entry/setup profiles](triage_evidence/daemon_shared_roots_profiles.json), [writer ledgers and original source](triage_evidence/daemon_shared_roots_source.json), [six local source obligations](triage_evidence/daemon_shared_roots_proofs.json), [fresh replay and field checks](triage_evidence/daemon_shared_roots_checks.json), [preservation](triage_evidence/daemon_shared_roots_delivery.json), [scoped gates](triage_evidence/daemon_shared_roots_quality_gates.json). This increment uses the pinned backing image and retained source/helper evidence; no fresh IDA query or database mutation is performed.

## Architectural position and entry contract

The [RPC502 source report](daemon_rpc502_report.md) establishes the earlier wrapper's protected record and its call chain through `0x10065FFD8` to this entry. Its tag is 0x6CF4 and its operation word is 0xBC84919B. The new profiles start at the protected-core entry with explicitly declared record, cursor and private environment. They do not execute a native MIG transaction or reconstruct the complete wrapper prefix anew. [SR1,SR2]

```text
RPC502 wrapper / protected adapter             [retained source evidence]
  -> protected record: tag6CF4, operationBC84919B
  -> entry 0x10061A2D0                         [new profiles start here]
  -> original stack probe, large frame and source initialization
  -> F+9D0 := zero_extend64(decoded_tag)
  -> common setup writes bank roots and internal workspace
  -> stop before branch at 0x1004C3634
       |
       +-- original slot8061 -> 0x100610388
       `-- original slot80A4 -> 0x1004D4AAC

later auxiliary emitters: control/epoch connection still unresolved
```

Let P be the protected-record address, E be entry SP, and F be SP after frame reservation. Its input prefix contains:

| P-relative offset | Width | Declared representation / use |
| --- | ---: | --- |
| +0 | 8 bytes | U XOR 0x1C0B9F7CE10F2255; finite U values are explicit inputs |
| +8 | 4 bytes | Tag XOR K(P) |
| +0xC | 4 bytes | Operation XOR K(P) |
| +0x10 | 8 bytes | Borrowed downstream-record pointer; pointee remains unavailable here |

`K(P)=u32((low32(P) XOR 0xEAAE0AC9)*0x7398180B)`. A backward register slice identifies exactly 20 original instructions producing the consumed low32 key; its sole live input is X0=P. Interleaved string-byte copies are excluded by register def/use, and the source projection is checked against the original instructions. The all-u64 theorem proves this low32 identity. It does not assert pointer validity for arbitrary P. [SR2,SR3]

X1 points to a declared cursor word. No borrowed downstream-record byte is read before the new stopping point; the source only obtains its pointer at `0x1004C3620`. All 24 supplied input bytes remain unchanged. Later result fields and native input ownership remain outside this prefix. [SR2,SR4]

## Source-written initial fields

All offsets below are hexadecimal bytes relative to this F. These are preferred source virtual addresses and fixture-relative stack addresses.

| Field | Original writer PC | Source-produced u64 value | Established role in this interval |
| --- | --- | --- | --- |
| F+0x9D0 | `0x10061A980` | 0x0000000000006CF4 | Decoded tag/phase, upper32 zero |
| F+0x9D8 | `0x10061A97C` | 0x101039EF0 | Dispatch-table base |
| F+0x9C0 | `0x10061A764` | 0x1010C4670 | Runtime arithmetic-control word address |
| F+0x9C8 | `0x10061A75C` | 0x1010B8DC8 | Another runtime arithmetic-control word address |
| F+0x968 | `0x1004C2534` | 0x100FC4130 | Left bank used by 4F6/5C8/7FA caller rules |
| F+0x960 | `0x1004C2B30` | 0x101031EA0 | Matching right bank |
| F+0x5F0 | `0x1004C25CC` | 0x101031DA0 | Left bank in the declared 857 rule |
| F+0x5E0 | `0x1004C3480` | 0x100E99900 | Matching right bank |
| F+0x870 | `0x1004C26F4` | 0x100E99700 | Left bank in the declared 5DE rule |
| F+0x868 | `0x1004C2658` | 0x100F4E190 | Matching right bank |

Each tracked field receives exactly one overlapping write in each profile, with all eight bytes defined. The ledger checks every subsequent source read and establishes no overwrite before the boundary. Setup `0x1004C24A4..0x1004C3634` contains 129 source stores; the fields remain intact through that interval. This is a source-established initialization epoch in the eight profiles. Complete invariance of the entire prologue over all native global states is not proved. [SR4,SR5]

The local store theorem is stronger for the phase itself: for every u32 decoded tag T, `0x10061A90C..0x10061A980` stores `zero_extend64(T)` at F+0x9D0 and preserves the supplied u64 table value in its F+0x9D8 store. The theorem stops before the tag-indexed target load; arbitrary tags are not claimed to select valid entries. The profiled tag is always 0x6CF4. [SR3]

At `0x10061A73C..0x10061A758`, original pool words at `0x1010A4328` and `0x1010A6578`, plus their signed u64 biases, decode to 0x100FC4130 and 0x101031EA0. A separate theorem proves the additive relation if the loaded words both receive an arbitrary u64 delta. This is a local value identity, not a full native ASLR, loader or authentication test. [SR3,SR5]

## Connection to caller premises and its limits

The preceding [nine-emitter report](daemon_aux_callers_report.md) requires low32(F+0x9D0)=0x6CF4 for its five F+0x10CB8 constructors to emit mode0x471C. This prefix supplies an actual source writer for exactly that initial scalar, with upper32 zero. It also supplies the three bank pairs at the exact offsets consumed by those large-frame rules. It therefore establishes an initialization source compatible with their declared field premises. [SR6]

The controller at F+0x9C8 is specifically 0x1010B8DC8. The preceding standalone emitter profiles supplied 0x1010B66A8 as an explicit controller fixture. Both contexts remain separately recorded; the older profiles are unchanged. No native equality, replacement or uninterrupted transfer between those controller epochs is inferred. Bank cancellation covers arbitrary byte inputs under its root premises, but that does not establish the missing control path. [SR5,SR6]

A full join still requires reaching an emitter in this same frame with the fields preserved. The new source path stops before the first setup branch. The F+0x6C phase 0x8AB1 required by two smaller emitters also remains unresolved. Thus neither their source writers nor the separate 720-byte cleanup's output-base producer is supplied by this increment. No incoming/outgoing Mach right, message emission or IOKit transaction is established by these private stack/global writes. [SR6,SR9,SR10]

## Operation-dependent control and frame geometry

For tag0x6CF4, source `0x1004C244C..0x1004C24A0` decodes the operation, stores it at F+0x9B8, and selects the initial continuation index with a signed32 comparison:

| Operation predicate | Index stored at F+0x9A0 | Original slot | Target before the stopped branch |
| --- | --- | --- | --- |
| s32(operation) < s32(0xAD952088) | 0x80A4 | 0x10107A410 | 0x1004D4AAC |
| Otherwise | 0x8061 | 0x10107A1F8 | 0x100610388 |

Both original slots carry IA diversity0x8A50 and address diversity zero. The source equation is `index=0x8061 XOR (predicate ?0xC5:0)`. The opaque phase value written at F+0x928 is 0xB2F3. These formulas cover all u32 operation words in the local component. The actual RPC502 wrapper's 0xBC84919B value selects 0x8061; 0x80000000 is a stress input selecting the other branch. The profiles retain the original next target and stop before executing that branch. [SR3,SR7]

The prologue saves 128 bytes: twelve GPR values and four SIMD low64 values. It then reserves `16*4096+0xD50 = 65,536+3,408 = 68,944` local bytes. Therefore:

```text
F = E - (128 + 68,944) = E - 69,072 = E - 0x10DD0
FP = E - 128 + 112 = E - 16 = F + 0x10DC0
saved-guard address = FP - 0x88 = F + 0x10D38
```

The arithmetic theorem covers u64 modular values; valid nonwrapping ownership is a separate premise. Actual source stores and the original 108-byte stack-probe snapshot are checked in the finite CPU states. No native canary or hardware PAC validation is performed. [SR2,SR7]

## Census, verification and reproducibility

An aligned original-text census finds 13 literal `STR Xn,[SP,#0x9D0]` sites and 111 literal `STR Wn,[SP,#0x6C]` sites. Other literal counts are six at +0x968, eight at +0x960, ten at +0x9C0, eight at +0x9C8 and twelve at +0x9D8. Only the demonstrated prefix has established frame ownership here. Pair stores, aliased/computed bases, different widths and SP movement are outside this census. The same offset cannot globally be assigned a scalar or pointer type. [SR8]

Eight strict profiles vary placement, cursor/header bit patterns, controller inputs, fast/walking stack probe and both operation-gate outcomes. Unwritten private bytes remain unavailable; the only permitted undefined reads are unused values loaded by the original stack-probe page touches. Complete input records and all 80 tracked field instances are checked. The source setup never relies on a zero-filled private frame.

Fresh replay checks 13,056 source visits, including 12,624 daemon instructions and 432 frozen-helper instructions. It verifies 2,736 reads, 1,760 writes, 16 logical control edges, eight helper-preservation checks and both target slots. The six source obligations produce twelve original/simplified UNSAT files. The primary and replay passes use Unicorn; the local source equations supply separate semantic checks. The complete prologue's all-state invariance, native global initialization and a source path to a later emitter remain unproved. [SR1-SR8]

Using the preceding reports' pinned interpreter and Z3 environment:

```sh
python3 -P triage_evidence/probe_daemon_shared_roots.py
python3 -P triage_evidence/capture_daemon_shared_roots.py
python3 -P triage_evidence/prove_daemon_shared_roots.py
python3 -P triage_evidence/validate_daemon_shared_roots.py
```

Time is O(source visits + text words + BV/solver resources); space is O(one CPU map, journal/census and expression DAGs). The source-visit limit is20,000 per profile; all eight reach the specified boundary first. Machine fields are little-endian u32/u64. Extents and store/visit counts are exact integers.

## Assumption register

| ID | Premise or bounded assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- | --- |
| SR1 | Pinned original image/fixups and frozen helper snapshot identify the consumed code | Addresses, decode values and private execution | Rehash all dependencies; compare every retired daemon opcode |
| SR2 | Valid declared entry record/cursor, stack ownership and helper TLS cells apply | Strict entry-to-setup prefixes and geometry | Vary placements/header/cursor/backing; reject unproduced private reads; native inputs remain unknown |
| SR3 | Register projection and isolated original spans describe the stated local operations | Protected key, stores and signed operation gate | Rebuild def/use projection and all-word SMT obligations; no all-state whole-prologue claim |
| SR4 | Source-produced field identity is bounded to this one setup epoch | Ten writer/consumer mappings and preserved input record | Audit every overlapping write/read and all defined-byte masks through the stop |
| SR5 | Declared private image/controller values represent finite environments only | Observed pointer initialization and branch consistency | Exercise four controller patterns; establish native values/writers separately |
| SR6 | Matching initializer and emitter offsets do not prove control/epoch continuity | Compatibility with five large-frame callers | Follow original branches to each emitter and prove preservation; retain distinct controller fixtures |
| SR7 | Frame arithmetic and original target slots authorize logical bookkeeping | SP/FP relations, helper return and two next targets | Check source operands, eight actual states and original slot fields; hardware PAC remains unobserved |
| SR8 | Literal stores form a bounded candidate subset | Counts and unresolved smaller-frame phase writers | Extend pair/alias/width coverage; establish frame ownership before typing another site |
| SR9 | Protected-core records and routing values have no new port identity | IPC/ABI distinction | Require actual Mach/IOKit arguments, rights and emission locations before transport attribution |
| SR10 | Native caller environment, later emitter control and720-byte/driver joins remain unproved | Overall task scope | Compose original source paths and ownership across the remaining interfaces |

## Bounded continuation targets

| Impact | Evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Continue from the two original setup successors toward specific emitters | Actual phase/bank preservation and caller control epochs |
| High | Resolve the F+0x6C writer for smaller emitter frames | Source of required0x8AB1 |
| High | Follow the initialized controller0x1010B8DC8 and later field updates | Native environment, synchronization and differences from prior fixtures |
| Medium | Extend strict setup invariance across additional runtime/global states | Bounds of the finite initialization evidence |
| Medium | Join the later record/ownership consumers to original transport adapters | Daemon/kext/deeper and port-right continuity |

- QG1: Pass for factual technical analysis.
- QG2: Pass; SR1-SR10 identify premises, dependencies and falsification probes.
- QG3: Pass for this increment; the full interface objective remains active and incomplete.
- QG4: Pass; widths, byte extents, signed predicates, modular arithmetic and complexity are explicit.
- QG5: Pass within scope; initialization ownership, later epoch gaps, distinct controller contexts and finite/universal evidence are separated.
- QG6: Pass; pinned original code/fixups, source ledgers, strict profiles, local SMT and fresh CPU checks provide provenance.
- QG7: Pass; remaining frame, control and transport joins are impact-labeled.
