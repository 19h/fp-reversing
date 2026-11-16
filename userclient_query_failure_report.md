# Query construction failure, cleanup and lower allocation ABI

The pinned source establishes conditional allocation-error status `0xce515bb2`, valid pending-node cleanup requests, and delivery to the three saved query callbacks. The lower typed allocator reduces adapter flags `0x8004` to `0x4` before adding its own flags. Native allocation outcomes, native retirement effects and whole-command reachability remain unknown.

This report extends [query construction](userclient_query_records_report.md), [query publication](userclient_query_publication_report.md), and [context lifecycle](userclient_context_lifecycle_report.md). It does not establish an additional incoming/outgoing Mach port or a new emission site. These are internal context, allocator and callback interfaces.

## Evidence and claim register

Primary evidence is the original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, and the normalized kext image, SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The selected kext words and banks agree between both images. Kernel adapter words come from the original collection; the normalized kext does not contain those kernel function bodies. No additional IDA evidence was needed.

The containing `_PRnut72j9` function is `0xfffffe000a635208..0xfffffe000a666930` exclusive, SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`. F denotes the selected stack frame, C the context, S the private workspace, J the pending 32 B node, and B its optional 14 B data allocation.

| Claim | Established result | Source and dependent assumptions |
| --- | --- | --- |
| QF1 | The original producer stores raw error `0xce515bb2` at F+0x9ec; same-slot null-data continuations retain it | `0xfffffe000a636678..0xfffffe000a636694`; QF-A1-A4 |
| QF2 | A valid J with null data skips data retirement and requests typed retirement of J | Gate `0xfffffe000a664078`, typed request `0xfffffe000a6641e4`; QF-A1-A6 |
| QF3 | Generic valid-J cleanup with nonnull B requests `_IOFreeData(B,14)`, clears J+0x18 on return, then requests typed retirement | Call `0xfffffe000a664134`, clear `0xfffffe000a66413c`; QF-A1-A6 |
| QF4 | Cleanup preserves raw status and C+0x58 through the saved constructor/request callbacks; the fixed error takes each callback's non-success branch | Return `0xfffffe000a664214`, C+0x260 and C+0x5a8; QF-A1-A6 |
| QF5 | The null-node constructor cut does not discharge cleanup's valid-node premise | Prefix stops before the first node load; QF-A1-A4, QF-A7. Native null allocation, fault and external trigger remain unknown |
| QF6 | Typed allocation forwards raw flags 0xd1004 or 0xd1044 at selected runtime zone/statistics cuts; null-zone fallback uses descriptor size32 and heap 0xfffffe0007f36938 | Kernel blocks below; QF-A1-A3, QF-A7 |
| QF7 | `_IOMallocData` forwards the full u64 requested size, heap 0xfffffe0007f8bfb0, raw flags0x31000 and null fourth argument to the lower size allocator | `0xfffffe000c4ba620..0xfffffe000c4ba638`; QF-A1-A3, QF-A7 |

## Error producer and conditional cleanup

The producer computes `u32(0xce515bb8-6)=0xce515bb2`. A literal SP-relative operand census across the complete containing function finds 48 accesses at displacement0x9ec, with exactly one store, at `0xfffffe000a636690`. This is a literal-operand inventory. It does not exclude stores through computed aliases or prove that the slot survives every intervening native path.

The three original query request packets and first node/data allocation paths are replayed from their existing source receipts. At the selected helper-return cut, J is a valid separate 32 B allocation and a null data result is stored at J+0x18. Each request reaches cleanup with X22=J, W23=the saved error, W27=0x37, W25=0x886a1ca3 and W28=0x7795e642.

```text
selected query constructor
  |
  +-- valid J; data result=0
        |
        +-- skip data free
        +-- request typed free of J
        +-- return through C+0x260
        +-- saved request callback at C+0x5a8
              raw error remains 0xce515bb2
```

| Cleanup operation | Original call/load site | Resolved ABI |
| --- | --- | --- |
| Optional data retirement | `0xfffffe000a664134` | `_IOFreeData` at0xfffffe000c4ba84c; X0=B; X1=zero-extended J.extent; for this query extent14 B; PAC modifier0x085d |
| Data field clear after ordinary return | `0xfffffe000a66413c` | J+0x18=0; next table index0x599 selects0xfffffe000a66414c |
| Typed-node retirement | `0xfffffe000a6641e4` | `_IOFreeTypeImpl` at0xfffffe000c4ba368; X0=descriptor0xfffffe000847bfa0; X1=J; modifier0x4d6a |
| Constructor return | `0xfffffe000a664214` | Table index0x63d selects0xfffffe000a664218; C+0x260 selects0xfffffe000a664230 |
| Request callback | `0xfffffe000a664260` | Target loaded from C+0x5a8; raw W23 preserved |

Three exhaustive two-bank compositions, 256 inputs each, resolve the original data-free pointer, typed-free pointer and descriptor pointer. Original chained-pointer metadata and modifiers are captured. Static target recovery does not authenticate native PAC.

The cleanup descriptor's normalized 64 B equals allocation descriptor0xfffffe000847b4a0. Its recovered name is `site.FPTTLVNode`, signature `1121`, flags0x64 and size32 B. Original name/signature pointers, strings and scalar fields corroborate these properties. The descriptor addresses differ; matching metadata does not establish runtime allocation identity or compatibility.

| Saved request | Callback | Non-success target for fixed error |
| --- | --- | --- |
| First | 0xfffffe000a656f8c | 0xfffffe000a65f358 |
| Second | 0xfffffe000a657018 | 0xfffffe000a65f358 |
| Third | 0xfffffe000a65f358 | 0xfffffe000a656f00 |

Each callback compares against raw SUCCESS0x31ae0066. The allocation error differs from SUCCESS, so the selected comparison rejects it. These internal targets do not establish the daemon-visible return status, whether subsequent code overwrites the status, or a complete provider transaction.

The selected cleanup return does not clear C+0x58. The proof reads the surviving context cell after ordinary free-call cuts; it does not dereference J after typed retirement. Native ownership, allocator effects, later cell consumers and synchronization remain unknown. The generic nonnull-data cleanup proof starts from a valid initialized pending-node cut; it does not claim that null-data allocation failure itself supplies a nonnull B.

For the separate null-node result cut, the source prefix does not establish valid pending-node storage. The audit stops before the first node load and checks its address expression only. It performs no null-address read and produces no native failure reproduction. Whether the original allocator can return null in this context is unknown.

## Lower allocator controls

| Original function | Compiler interval, exclusive end | SHA-256 |
| --- | --- | --- |
| `_IOMallocTypeImpl` | 0xfffffe000c4ba154..0xfffffe000c4ba170 | 2be5777872d60de5b0513968f8aaaaa1b3947085f183f933b4ba7b7607290029 |
| `_kalloc_type_impl` / `_kalloc_type_impl_external` | 0xfffffe000bcfeb8c..0xfffffe000bcfec2c | c2741f4a72af1e2a358007be4a36398fdc0aab0a092cd4ba85afafb495330892 |
| `_IOMallocData` | 0xfffffe000c4ba60c..0xfffffe000c4ba69c | 0bc800f390215db6847c0e74814ad727ac2d56d59c4b8c04eed740b600efd0dd |

Complete function bytes are captured for provenance. Only the selected instruction blocks are semantically modeled; complete byte capture is not complete allocator recovery.

The typed adapter tests descriptor flags bit0x10. For flags0x64 that bit is clear and it selects W1=0x8004. The lower prefix computes W10=W1 AND7 and W9=0x000d1000. Thus W10=4; the high adapter bits do not pass through this mask. The audit separately proves the three-bit mask for every incoming u32.

| Runtime state cut | X0 argument | X1 argument | W2 raw flags | Lower call target |
| --- | --- | --- | --- | --- |
| Descriptor first zone pointer nonzero; selected statistics count nonzero | First zone pointer | Descriptor statistics pointer | 0xd1004 | 0xfffffe000bd75c64 |
| First zone pointer nonzero; selected statistics count zero | Descriptor+0x30 pointer | Descriptor statistics pointer | 0xd1044 | 0xfffffe000bd75c64 |
| First zone pointer zero; descriptor flags0x64, size32 | Heap0xfffffe0007f36938 | 32 B | 0xd1004 | 0xfffffe000bcfe5b8; X3=0 |
| Data-allocation request | Heap0xfffffe0007f8bfb0 | Original u64 size | 0x31000 | 0xfffffe000bcfe5b8; X3=0 |

For the nonzero-zone alternatives, the original function loads the statistics pointer from descriptor+8, then reads TPIDR_EL1 and per-thread statistics before the branch. Those native state reads and branch selection are captured but not executed by the selected-block model. The two alternatives are conditional block-entry cuts; the analysis does not infer their runtime frequency. The null-zone fallback selects its heap using descriptor bits0x8000 and0x08 and masks size to24 bits. For the recovered descriptor, size32 is unchanged. Data size forwarding is u64; the query caller separately supplies14 B.

No source-level flag names from an unmatched XNU revision are needed for these raw-bit results. In particular, raw adapter flag0x8004 is insufficient evidence of a native non-failure guarantee. Conversely, masking that flag does not establish a native null result. Backend paths, panic/nonreturn behavior, scheduler state, allocator initialization and actual allocation/free effects remain unknown.

## Reproducible artifacts and assumption register

[Extractor](triage_evidence/recover_userclient_query_failure.py), [instruction audit](triage_evidence/audit_userclient_query_failure.py), [delivery verifier](triage_evidence/verify_userclient_query_failure_delivery.py), [checks archive](triage_evidence/userclient_query_failure_checks.json.zst), and [audit archive](triage_evidence/userclient_query_failure_audit.json.zst) contain the evidence and formula receipts.

Decoded checks SHA-256: `f380d2d20a463917d898a07e55961fcf50f80893c9787978d4e6248885fdb9a8`.

Decoded audit SHA-256: `206ccc839f9581abd6256dbf2bb14a9b1e89c90bdcb6f927b33d171ad46162b6`.

The audit proves 30 new nonvacuous source obligations, rechecks five predecessor obligations, models 154 newly selected instructions and 479 predecessor instructions, and accounts for 8,531 instruction instances across its recorded obligations. The three bank rules cover768 input cases. A changed status literal yields a SAT counterexample to the original status assertion. Selected terminal transfers are captured separately from the 154 modeled instructions. Ordinary helper returns are explicit cuts rather than native execution.

| Assumption | Dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| QF-A1: Only the pinned original collection and normalized kext are covered | QF1-QF7 | Complete containing-function hash, dual kext/bank recapture, original pointers and three kernel function hashes; recapture for another image |
| QF-A2: Modeled AArch64 u32/u64 semantics and decoded instruction operands apply | QF1-QF7 | Reconstructed nonvacuous formulas, arbitrary flags/status/size, exact addresses, 768 bank cases and altered-literal negative control |
| QF-A3: Selected frame/context/workspace/node/data extents are valid, nonwrapping and separate where declared | QF1-QF7 | Interval constraints and exact modeled accesses; native extent/identity is not inferred |
| QF-A4: Same frame/context epoch, stable F+0x9ec and predecessor phase cuts apply | QF1-QF5 | Original producer, 48 literal accesses and one literal store; inspect indirect aliases and intervening native writes separately |
| QF-A5: Selected node/data helper-return values and nominal pointer branches apply | QF2-QF4 | All three original constructors, optional-data split, saved descriptor and callback arguments; native helper outcomes remain unknown |
| QF-A6: Ordinary free-call cuts preserve callee-saved registers, SP and surviving private context/frame storage | QF2-QF4 | Havoc caller-saved registers; check post-return raw status, next targets and C+0x58 without reading retired-node data; inspect native effects and synchronization separately |
| QF-A7: Lower allocator block-entry/runtime-state cuts and cleanup node-validity premise are explicit | QF5-QF7 | Stop before unsupported node read; separate runtime zone/statistics alternatives, raw flag mask, heap/size forwarding and omitted native backend; no native failure guarantee follows |

## Bounded continuation and quality gates

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Lower zone/size allocator return and nonreturn contracts in this exact image | Determine which node/data outcomes are natively possible; raw flags alone do not answer this |
| High | Observed daemon/provider request and response tied to image, selector and endpoint | Correlate internal saved status/records with public transaction behavior |
| High | Native descriptor identity, allocation/free effects and ownership/synchronization | Discharge remaining retirement and pending-cell lifetime premises |
| Medium | Indirect F+0x9ec writes and full frame/context epoch retention | Strengthen the saved-error producer-to-consumer argument |
| Medium | Later C+0x58 consumers after cleanup and status handling beyond third callback | Establish final lifetime and externally visible error behavior |
| Low | Other callers of the shared cleanup and descriptor adapters | Identify independent ABI reuse and environmental constraints |

Extraction requires O(B+I+256R) time/space for consumed image bytes B, instructions I and R=3 bank rules. Formula construction requires O(instruction instances+query DAG); SMT search is separate, with30 s/query limits. Extents use B; sizes and pointer widths are explicit. The source analyses do not execute target code or modify an IDA database.

- **QG1**: All claims concern factual source, data, control or ABI properties.
- **QG2**: QF-A1-QF-A7 identify assumptions, dependent results and falsification probes.
- **QG3**: Error producer, both valid-node data cases, original retirement requests, all three saved callbacks, node-validity boundary and selected lower allocation ABI are covered. The full interface goal remains active.
- **QG4**: u32 status/flags, u64 size/pointers, 24-bit typed size mask, 32/14 B extents, instruction/formula counts and complexity are explicit and reproducible.
- **QG5**: Literal inventory versus indirect aliases, source capture versus modeled blocks, return cuts versus native allocation, context-cell retention versus ownership, and internal error versus public status remain distinct.
- **QG6**: Original images, original pointer metadata, exact source PCs, 30 reconstructed source obligations, five predecessor rechecks, 768 bank cases and a changed-literal SAT control support the stated scope.
- **QG7**: Ranked continuation preserves native allocator outcomes, transaction pairing, descriptor identity, synchronization, indirect frame aliases and public error handling as unresolved evidence frontiers.
