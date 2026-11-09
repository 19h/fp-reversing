# MIG operation constructors, record heads and stack-slot epochs

Original source now connects six MIG application wrappers to three protected-core operations: requests1000/1200 encode AD952088,1001/1201 encode8F7506EE, and1002/1202 encode8799A4F1. Four operation heads have explicit borrowed-record read and first-interface contracts. Three heads overwrite slots previously holding the decoded tag, operation or dispatch index. Those initial meanings cannot be carried into later phases without a new epoch check. [OH1-OH10]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [original source, constructors, MIG links and function starts](triage_evidence/daemon_operation_heads_source.json), [symbolic heads](triage_evidence/daemon_operation_heads_symbolic.json), [source proofs and retained counterexamples](triage_evidence/daemon_operation_heads_proofs.json), [fresh CPU/readback checks](triage_evidence/daemon_operation_heads_checks.json), [preservation](triage_evidence/daemon_operation_heads_delivery.json), and [scoped gates](triage_evidence/daemon_operation_heads_quality_gates.json). The [preceding dispatcher report](daemon_core_dispatch_report.md) supplies the source-established entry/setup epoch. No fresh IDA query or database mutation is needed for this increment.

## Incoming MIG-to-operation relationships

| Request ID | Original MIG stub | Direct BL site | Application wrapper | Operation literal PC | Decoded operation |
| --- | --- | --- | --- | --- | --- |
| 1000 | `0x100004C44` | `0x100004D78` | `0x10000647C` | `0x100006778` | `0xAD952088` |
| 1200 | `0x100004530` | `0x10000467C` | `0x100007B28` | `0x100007E1C` | `0xAD952088` |
| 1001 | `0x100004E1C` | `0x100004E50` | `0x100007FAC` | `0x10000813C` | `0x8F7506EE` |
| 1201 | `0x100004720` | `0x10000475C` | `0x1000072D8` | `0x100007488` | `0x8F7506EE` |
| 1002 | `0x100004E98` | `0x100004F30` | `0x100005BE8` | `0x100005DE0` | `0x8799A4F1` |
| 1202 | `0x1000047A4` | `0x100004844` | `0x1000060B4` | `0x100006278` | `0x8799A4F1` |

The machine-readable links contain each exact BL PC, original opcode, descriptor slot and original chained-pointer word. Original bytes normalize to the retained MIG headers/descriptors only after their pointer fixups are decoded; cached runtime pointer bytes are not compared directly with on-disk chained words. Source checks use the1000..1002 and1200..1204 tables, actual BL instructions, and original `LC_FUNCTION_STARTS` containing ranges. The function-start command contains1005 entries. A constructor's presence in a wrapper establishes the local source relationship, not successful native delivery or unconditional execution through every wrapper branch. [OH1,OH2,OH8]

The paired requests share a protected operation while retaining distinct MIG stubs, wrapper frames and wire contracts. They are not assigned a protocol-version relationship or identical endpoint admission policy. Those transport details remain in the [existing MIG ABI report](interface_abi_report.md). [OH8,OH10]

```text
MIG1000 /1200 -> distinct wrappers -> encoded operation AD952088 --+
MIG1001 /1201 -> distinct wrappers -> encoded operation 8F7506EE --+-> shared core
MIG1002 /1202 -> distinct wrappers -> encoded operation 8799A4F1 -+   tag6CF4
                                                                   |
                                     retained setup/dispatch epoch -+
                                       +-- record-head loads/stores
                                       `-- first call or branch frontier

auxiliary function A59BB4 contains a further A70E6EB4 constructor
  tag = W19 + 1D7B; tag6CF4 requires W19=4F79
  upstream phase, selected callee and native delivery remain unresolved
```

## Constructor codec and alignment boundary

Let P be the protected-record address. All seven source constructors encode the operation at P+12/u32 using XOR with `K(P)=u32((low32(P) XOR 0xEAAE0AC9)*0x7398180B)`. The six MIG wrappers similarly encode tag6CF4 at P+8/u32. The source key expressions are obfuscated arithmetic variants, not textual copies of this formula. [OH3,OH4]

| Constructor literal PC | Record address P | Tag after decoding | Proven constructor domain |
| --- | --- | --- | --- |
| `0x100005DE0` | FP-72 | 0x6CF4 | FP mod16=0 |
| `0x100006278` | FP-88 | 0x6CF4 | FP mod16=0 |
| `0x100007488` | FP-40 | 0x6CF4 | FP mod16=0 |
| `0x10000813C` | FP-40 | 0x6CF4 | FP mod16=0 |
| `0x100006778` | FP-128 | 0x6CF4 | FP mod16=0 |
| `0x100007E1C` | FP-128 | 0x6CF4 | Also valid for unrestricted u64 FP in the separate probe |
| `0x100A86D70` | FP-160 | u32(W19+0x1D7B) | FP mod16=0; W19 arbitrary u32 |

All address arithmetic in the theorems is modulo u64; readable/writable storage and nonwrapping native ownership are separate premises. Six unrestricted-FP equivalence hypotheses are SAT, with explicit counterexamples retained and independently reproduced as register arithmetic. The seventh unrestricted hypothesis is UNSAT. These counterexamples are outside the aligned constructor domain and establish no native misaligned call or defect. [OH3]

The direct aligned whole-constructor query timed out at30s in the exploratory attempt. The accepted evidence uses certified composition: an aligned pre-multiplication input identity; the original source MUL by0x7398180B; and tag/operation encoding identities for every u32 computed key. There are fourteen constructor lemmas for seven sites. The formal key cut is universally quantified and is not a runtime value assignment. Fresh CPU checks execute the source projection and actual paired field store, providing a separate check of the composition. [OH3,OH4,OH9]

The A70E6EB4 literal lies in original function-start interval `[0x100A59BB4,0x100ABCA64)`, the previously analyzed [auxiliary routine](daemon_output_base_report.md). Its decoded tag equals6CF4 if and only if W19=4F79. This identifies an additional local record constructor inside that routine. It does not prove the upstream phase, the later authenticated-call target, or a continuous auxiliary-to-core transaction. [OH5,OH10]

## Borrowed record-head contracts

The new symbolic continuations start immediately before the first borrowed-record read identified by the preceding dispatcher. Pointee bytes retain independent variables; the one pointer tested for NULL has an arbitrary u64 variable. Newly encountered writable-global contents also retain byte variables. No missing frame cell or unknown address is replaced with a chosen value. The operation and initialized setup/global context are inherited from the retained source prefix. [OH2,OH6,OH7]

Let B be the borrowed record pointer, F the retained core frame and E its entry stack. In the private witnesses, B=0x6800001000,F=0x680004F230 and E=0x6800060000. The diagnostic input window ends at B+72; this is not an established native allocation size.

| Operation | Source reads before first interface | Minimum accessed input endpoint | Additional source-derived references |
| --- | --- | ---: | --- |
| 8799A4F1 | u32 at+0,+4,+8,+12,+32; u64 at+16,+24,+40 | 48 bytes | Forms B+48,B+56,B+60; no pointee access through those new references yet |
| 8F7506EE | u32 at+0,+4; u64 at+8 | 16 bytes | Tests the full u64 at+8 against zero |
| A70E6EB4 | u64 at+0,+8,+56,+64 | 72 bytes | Requests a32-byte copy from B+24 |
| AD952088 | u32 at+0,+4,+56; u64 at+48,+64 | 72 bytes | Requests a32-byte copy from B+8; other large additive references remain opaque |

Widths identify source uses, not complete C structure types or pointer ownership. The requested copies stop before the helper call and are distinguished from bytes already read by the new heads. In particular, A70E6EB4's requested span is `[B+24,B+56)` and AD952088's is `[B+8,B+40)`. The helper has an existing source-established copy role; the new continuations do not execute either call. [OH6,OH7]

For8799A4F1, the u32 fields at B+8,B+12 and B+32 are stored after XOR0x8B3DC651. Pointer-sized fields at B+16,B+24 and B+40 are copied without that u32 transform. The source also advances the retained scratch cursor by48 bytes before the first call; valid ownership of a resulting native reservation remains a separate question. The proof product records individual frame destinations and checks all transformed values. [OH4,OH6]

## First architectural interfaces and epoch changes

| Operation/class | Frontier PC | Original selected slot | Established target / arguments before execution |
| --- | --- | --- | --- |
| 8799A4F1 | `0x100501D48` | `0x1010A0708` | `_CFMachPortGetPort`, IA/C662; X0 is opaque contents of cell0x1010C4D00 |
| 8F7506EE,+8=NULL | `0x1005EB828` | `0x101077120` | BRAA to0x100528DD8, IA/F90F; W6=0x8B3DC655 |
| 8F7506EE,+8!=NULL | `0x1005EB828` | `0x101077048` | BRAA to0x1005554B4, IA/F90F |
| A70E6EB4 | `0x100592F64` | `0x10109FC88` | Copy helper0x10046F89C, IA/34A1; X0=B+24,X1=F+0x5D68,W2=32 |
| AD952088 | `0x100466834` | `0x10109FC88` | Same helper; X0=B+8,X1=F+0xBC0,W2=32 |

Address diversity is zero for these original slots. The [registration report](daemon_registration_report.md) identifies cell0x1010C4D00 as the stored CF object for `com.apple.fpsd`. The new head loads its unknown contents; it neither recovers a native CF object nor calls `CFMachPortGetPort`. Thus no returned Mach name, destination right or message emission is established. [OH6-OH8]

The NULL branch selects the known result epilogue with raw word8B3DC655; under the retained status XOR codec it represents u32 value4. The new replay stops before the branch, so a completed return, native framework result and higher-level error-name identification are not claimed. The non-NULL successor's record processing is still open. [OH4,OH7]

| Operation | Original writer PC | Field overwritten | Earlier initialized role | New source value |
| --- | --- | --- | --- | --- |
| AD952088 | `0x100466700` | F+0x9D0, low32 | Decoded tag/phase6CF4 | u32(B+0); retained upper32 remain zero in this epoch |
| 8F7506EE | `0x1005EB7EC` | F+0x9B8, low32 | Decoded operation | u32(B+0) |
| 8799A4F1 | `0x100501C0C` | F+0x9A0, low32 | Dispatch index | u32(B+4) |

AD952088 additionally writes u64(B+48) at F+0x9A0 and u64(B+64) at F+0x9B8. The full-u64 F+0x9D0 theorem in this head depends on the source-established zero upper half from its parent epoch. These new writers are concrete examples of scalar/slot reuse; they do not establish a later path to any of the nine auxiliary emitters. In particular, the initial tag6CF4 cannot be assumed to survive this head at F+0x9D0. [OH2,OH4,OH10]

## Validation and reproducibility

The aligned adjacent-MOVZ/MOVK census checks3,712,489 pairs over14,849,960 original text bytes. It finds eight candidates: seven constructors and one dispatcher comparison. Computed, nonadjacent, X-register and non-text materializations remain outside this census. Constructor projections contain129 source instructions in total. [OH1,OH8]

Twenty-eight source obligations pass in original and simplified files: fourteen constructor lemmas, five interface targets, five field/argument contracts, two NULL-route targets, NULL-partition completeness/disjointness, and the nested-tag phase equivalence. Seven unrestricted-domain probe files retain six SAT counterexamples and one UNSAT result. Each probe and accepted formula is read back and solved independently of its generator's recorded status. [OH3,OH4,OH9]

Forty fresh CPU cases begin at protected-core entry0x10061A2D0, initialize explicit borrowed inputs, follow the retained setup/operation path and continue to the new frontier. Eight input/export/private-byte variants per symbolic class yield68,888 source visits,14,224 reads,9,352 writes,272 logical control edges and40 checked boundaries. Another56 constructor-store cases and six rejected-domain arithmetic cases execute1,205 instructions. No frontier call/branch executes, and no unavailable native value is inferred from a finite materialization. Z3 supplies scalar/source equations; Unicorn supplies the CPU checks. [OH2,OH6,OH7,OH9]

Using the pinned interpreter/environment from the preceding report, run `capture_daemon_operation_heads.py`, `daemon_operation_heads_symbolic.py`, `prove_daemon_operation_heads.py` and `validate_daemon_operation_heads.py` under `triage_evidence/`. The validator rebuilds source and symbolic products, reads the proof files, and repeats the CPU checks. Time is O(text words + source visits + cases*visits + BV/solver resources); space is O(one CPU map/journal + census and expression DAGs). Integer widths and byte counts are exact; native pointer validity and extents remain explicit premises.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OH1 | Pinned backing image, decoded fixups and LC_FUNCTION_STARTS define source locations | Rehash original inputs; regenerate table normalization, BL decoding, function ranges and literal census |
| OH2 | The retained tag6CF4/setup environment supplies this frame epoch | Fresh entry-to-frontier CPU replay; vary runtime controller/setup inputs separately before generalizing native invariance |
| OH3 | Six constructor identities require aligned FP; the accepted common domain is FP mod16=0 | Seven unrestricted probes retain six counterexamples; six CPU arithmetic replays reproduce rejection; aligned cases and local lemmas pass |
| OH4 | Local key/codec and head scalar semantics compose as recorded | Rebuild28 obligations, solve56 accepted files and compare actual CPU field stores/transfers; formal key cuts remain quantified |
| OH5 | The nested constructor's input phase is not recovered | All-u32 tag identity proves tag6CF4 iff W19=4F79; recover its upstream writer before claiming admission to that dispatcher |
| OH6 | Borrowed/global contents are arbitrary inputs; native extents are unknown | Independent byte variables, zero/max/patterned materializations, NULL/non-NULL classes and strict stop before unknown addresses/frame bytes |
| OH7 | Imported target identities and source copy-helper contracts are distinct from native call results | Check exact source slots/modifiers/arguments; stop before calls; vary fake export/CF-cell values without assigning native contents |
| OH8 | Literal and containing-wrapper relationships have bounded search coverage | One comparison is excluded from constructors; inspect computed/nonadjacent constructors and wrapper branch admission for completeness |
| OH9 | CPU and solver checks validate bounded source models, not hardware PAC/API effects | Original-opcode replay, separate Z3 equations, explicit logical PAC and source-projection versus continuous-path labels |
| OH10 | Later parser, auxiliary-emitter and driver joins require matching control and field epochs | Track each new writer to the actual consumer; equal slots, tags or authenticated-call modifiers alone do not establish a join |

## Bounded continuation and quality gates

| Impact | Next target | Information resolved |
| --- | --- | --- |
| High | Follow AD952088 after its copy through phase-slot consumers | Whether input+0 reaches an auxiliary mode computation and how the overwritten epoch is restored |
| High | Trace 8799A4F1 after the CF query and 8F7506EE's non-NULL successor | Service-name/result gates and the first payload consumers |
| High | Recover W19=4F79 and table/bank roots at the nested A70E6EB4 constructor | Actual auxiliary-to-protected-core control join and input-owner provenance |
| Medium | Map the six wrapper record fields back to each MIG wire/output field | Which values are externally supplied, trailer-derived, local output pointers or internal state |
| Medium | Derive controller/global invariance of the selected head targets | Scope beyond the retained setup environment |
| Low | Extend constructor census beyond adjacent MOVZ/MOVK pairs | Additional operation producers omitted by this bounded census |

QG1: Factual source/interface analysis requires no normative content.

QG2: OH1-OH10 identify dependent results, assumptions and falsification probes.

QG3: Six MIG constructor links, four record heads, five frontiers and three slot epochs are covered for this increment; the full goal remains active and incomplete.

QG4: u32/u64 widths, signedness/NULL domains, byte endpoints, modular arithmetic, exact counts and algorithmic complexity are explicit.

QG5: Aligned versus unrestricted proofs, symbolic input versus native value, containing-function versus control reachability, copied versus requested bytes and initial versus overwritten epochs are separated.

QG6: Original bytes, fixups, source-projected lemmas, retained rejection witnesses and fresh CPU/readback checks provide traceable provenance.

QG7: Impact-labeled continuations cover external control, data ownership, environmental state and cross-layer joins. No new native port/right transfer, Mach message or IOKit selector is established.
