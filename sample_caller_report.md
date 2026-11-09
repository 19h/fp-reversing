# Sample descriptor setup: caller records, task provenance and unwind contracts

The original function at `0xfffffe000a6247a4` coordinates sample-size descriptor creation/preparation and, on the inspected continuation, hardware initialization followed by samples descriptor creation/preparation. Its source return paths store an encoded status at record `+0x08`. Two original builder slices marshal the same record and conditionally select this function through distinct byte banks. These findings connect the [descriptor helpers](sample_descriptor_report.md), [hardware initializer](kext_buffer_report.md) and [dispatch contexts](kext_aes_dispatch_report.md).

The role is established for declared selector `0x507` paths. Other selectors, complete successful processing, producer-frame reachability, native descriptor lifetime and the task's ultimate identity remain unknown. No additional Mach message, port-right event or native hardware operation is observed.

[Original contracts](triage_evidence/sample_caller_contracts.json), [113 caller profiles](triage_evidence/sample_caller_profiles.json), [48 builder profiles](triage_evidence/sample_caller_builder_profiles.json), [distinct fresh replays](triage_evidence/sample_caller_replays.json), [independent checks](triage_evidence/sample_caller_checks.json) and [12 local proofs](triage_evidence/sample_caller_proofs.json) retain the evidence. All addresses are unslid. Sizes and offsets are bytes; u32/u64 arithmetic uses the indicated modulus.

```
builder 1: saved context -> context +0x10 --+
                                        +--> record +0x38: task operand
builder 2: entry record +0x48 -> frame ---+

record +0x18, decoded N*4, task
  -> sample-size create -> prepare
       create fails --------> store status
       prepare fails -------> release -> store status
       secondary word != 0 -> complete -> release -> store status
       secondary word == 0 -> initKernelAESHW
            init fails ----> complete -> release -> store status
            init succeeds -> samples create -> prepare -> later memory helper
```

The diagram describes conditional original source paths under SR1-SR8. It does not establish an accepted native request or execution from a public entry point.

## Source identities and boundaries

| Source | Verified coverage |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Coordinator | Compiler bounds `0xfffffe000a6247a4..0xfffffe000a626648`, 7844 bytes; complete original/normalized equality |
| First builder parent | Compiler bounds `0xfffffe000a635208..0xfffffe000a666930`; selected fragment `0xfffffe000a64b284..0xfffffe000a64b5b4` |
| Second builder parent | Compiler bounds `0xfffffe000a6890dc..0xfffffe000a69ecf8`; selected fragment `0xfffffe000a68f448..0xfffffe000a68f770` |
| Additional source | Two parent entry prefixes, nine literal SP-store records, original bounds helper, 13 exhaustive byte-bank identities and four state routes |

The original pointer at slot `0xfffffe000847aa38` is authenticated format 8, target `0xfffffe000a6247a4`, diversity `0x6353`, with verified chain membership. The sample-size release call also uses modifier `0x6353` but selects a different slot and target. A modifier alone does not identify a routine.

Private caller runs abstract authenticated branches and declared helper results. The original bounds helper executes only in Unicorn; a source BRK stops before execution. The two builder runs begin after a record-initializer call and stop before calling the coordinator. No record initializer, descriptor helper, task access, memory-copy API, crypto operation, native target or IDB mutation executes. SR2-SR5 qualify all modeled paths.

## Record and width contracts

Let P be the record address. The original address expression and its full-width multiplication recover:

```
K64 = ((P XOR 0x0f6f4af997099bc0) * 0xef54ff65) mod 2^64
K32 = low32(K64)
selector32 = (u32[P+0x40] + K32) mod 2^32
N32 = (u32[P+0x50] - K32 + 0x8899d805) mod 2^32
sample_size_length64 = 4 * zero_extend64(N32)
samples_length64 = (u64[P+0x10] + K64 + 0xecb67a32353f2154) mod 2^64
```

The low32 key also equals `(low32(P) XOR 0x97099bc0) * 0xef54ff65 mod 2^32`. The full64 constant is source- and solver-verified independently; equality of low32 expressions alone would not validate a full64 length.

| Record offset | Width | Source-established role on inspected paths |
| --- | --- | --- |
| `+0x00` | u64 | Object operand for the first bounds comparison |
| `+0x08` | u32 | Encoded output status on return paths |
| `+0x10` | u64 | Encoded samples byte length |
| `+0x18` | u64 | Address passed to sample-size descriptor creation |
| `+0x20` | u64 | Secondary record pointer; its u32 `+0x2c` word affects continuation |
| `+0x28`, `+0x30` | u64 each | Saved operands; later complete roles unresolved |
| `+0x38` | u64 | Kernel `task *` operand forwarded to both descriptor groups |
| `+0x40` | u32 | Encoded selector |
| `+0x48` | u64 | Unsigned guard limit |
| `+0x50` | u32 | Encoded count word used for the four-byte-element extent |
| `+0x58` | u64 | Address passed to samples descriptor creation |

These accesses require a record extent of at least `0x60 = 96` bytes for the inspected setup prefix. This is an internal record contract, not an established serialized Mach/IOKit request layout. Padding and a complete allocation type remain unknown. SR6 applies to semantic provenance.

At `0xfffffe000a624b24`, `UBFIZ X1, X8, #2, #0x20` zero-extends the low32 count before shifting. Thus the mathematical maximum is `4 * (2^32 - 1) = 17179869180` bytes, hexadecimal `0x3fffffffc`. The multiplication does not wrap to u32. This describes argument formation; the factory's native acceptance, backing memory and later access checks are unproved.

## Calls, targets and source routes

All addresses below have prefix `0xfffffe000`.

| Call site | Selected target | Interface |
| --- | --- | --- |
| `a6249a4` | `a687ecc` | Original unsigned bounds helper |
| `a624b44` | `a509948` | Sample-size creation: address64, `4*N32` in X1, task64 |
| `a624be4` | `a5099b8` | Sample-size preparation |
| `a6250c8` | `a508030` | `initKernelAESHW` |
| `a625190` | `a509980` | Samples creation: address64, decoded length64, task64 |
| `a625254` | `a509a0c` | Samples preparation |
| `a6257e8` | `a509c08` | Sample-size completion |
| `a625840` | `a509bd4` | Sample-size release, void helper |
| `a6252dc` | `a687d64` | Later memory helper boundary; complete role and continuation unresolved |

Each of the first eight target bindings is supported by original instructions and exhaustive constant byte-bank selection, rather than modifier matching alone. The final target is observed before its call in the three declared successful-initialization continuations; its prefix contains byte stores, but this increment does not execute it or assign a complete semantic name. SR3/SR7 apply.

For selector `0x507`, creation's W0 test selects table index `0x507` for zero, entering preparation at `a624b78`; nonzero selects `0x50b`, entering the status-store epilogue at `a625850`. Preparation compares W0 with source-derived zero. Equality selects index `0x92a`, entering `a624c18`; inequality selects `0x739`, entering release routing at `a625804`. Four original chained slots corroborate these state destinations.

The first guard receives `((u64[P] + 0x140) mod 2^64, u64[P+0x48])`. It returns when the first value is unsigned <= the second; otherwise it selects `BRK #1`. It does not itself establish a valid object, nonwrapping extent or pointer ownership. Private boundary fixtures verify both comparison outcomes and the modular addition; they do not demonstrate native fault reachability.

## Status carrier and conditional cleanup

The epilogue at `a625854..a625858` loads a saved u32 and stores it at record `+0x08`. It does not normalize the incidental X0 register left by the last callee. In particular, `OSObject::release()` has void semantics, as established in the preceding descriptor report.

| Declared path | Ordered helper suffix | Stored record `+0x08` | XOR with `0x31ae0066` |
| --- | --- | --- | --- |
| Creation nonzero | No preparation or release | `0xce515bb2` | `0xffff5bd4` |
| Preparation nonzero | Release | `0xce515bb2` | `0xffff5bd4` |
| Preparation zero; secondary `+0x2c` nonzero | Complete, release | `0x31ae0066` | 0 |
| Initialization returns `0xffffffd8` | Complete, release | `0xce51ffbe` | `0xffffffd8` |
| Initialization returns `0xffffffea` | Complete, release | `0xce51ff8c` | `0xffffffea` |
| Samples creation nonzero | Sample-size complete, release | `0xce515bb2` | `0xffff5bd4` |

Initialization's local source fold is `(R + 0x31ae0066) - ((R << 1) & 0x635c00cc) mod 2^32`, equivalent to `R XOR 0x31ae0066` for every u32 R. The current paths' preserved state supplies the stated additive base. The first builder independently loads record `+0x08` into W26 at `a64b49c`, calls another helper, then compares W26 with literal `0x31ae0066` at `a64b594`. This establishes the source consumer's marker comparison. Retention of the loaded value across that helper requires callee-saved register preservation, which is not separately executed here. A complete business error vocabulary remains unknown.

Six secondary-word cases vary modeled completion results, including nonzero low32 and high-X0/zero-W0 values; the same marker is stored. Release leaves an explicitly arbitrary X0 fixture, while the saved record word remains stable. These are conditional local status/ordering observations, not proof of native prepare/complete pairing or reference-count effects. SR3/SR8 apply.

## Two builder interfaces and task lineage

| Property | First builder | Second builder |
| --- | --- | --- |
| Coordinator emission | `a64b498` | `a68f6b0` |
| Original selected bank rule | Family A, key `0x73`, add `0xf1c` | Family C, key `0x32`, add `0xe6a` |
| Common selection | Index `0xf63`, slot `0xfffffe000847aa38` | Same |
| Record pointer in declared frame | `[SP+0x998]`, held in X25 | `[SP+0x3b8]`, held in X27 |
| State producing selector `0x507` | W24 = `0x510`; field40 decoder yields W24 - 9 | W21 = `0x753`; decoder yields W21 - `0x24c` |
| Task operand written at record `+0x38` | `*(*(SP+0x738) + 0x10)` | `[SP+0x2d8]` |
| Earlier literal task-carrier store | `a63524c`: post-prologue X2 -> `[SP+0x738]` | `a6892e8..a6892ec`: qword `[X2+0x48]` -> `[SP+0x2d8]`; source sets X2 = entry X0 |
| Sample-size address source | qword `[frame_object+0x6f8]`, frame object from `[SP+0xa28]` | `*(*(SP+0x258))` |
| Samples address source | qword `[frame_object+0x5e0]` | `*(*(SP+0x2a8))` |
| Decoded samples length | u32 loaded through `[SP+0x530]`, zero-extended | Full64 value in `[SP+0x460]` |
| Decoded size count | Original u32 through `[SP+0x528]` | Separate mixed-word expression through `[SP+0x250]`; not identified as the literal original count |

Twenty-four fresh cases per builder verify both null and nonnull task forwarding, 48 length roundtrips, 24 first-builder count roundtrips, and 24 second-builder count-expression checks. Original record writes establish 80 bytes per case, totaling `48 * 80 = 3840` source-defined bytes. Record fields are checked against those writes, not merely against zero-filled fixture memory.

The first builder's key operand at `[SP+0x3a8]` is declared to correspond to the record pointer in these slices; its complete reaching definition is not proved. The second builder computes the matching full64 address key within its inspected slice, with a separate universal proof. Nine literal SP-store records identify useful earlier definitions, but exclude dynamic addressing, frame-pointer aliases, indirect writes and callee alias effects. They are a bounded census, not full reaching-definition analysis. SR4-SR6 qualify the builder links.

A kernel task pointer at these interfaces is not a Mach port name. Neither builder establishes which task that pointer denotes, whether it is the UserClient owner, or how a public incoming request reaches the selected frame. No guest/host port-name correspondence follows from these record fields.

## Verification, assumptions and continuation

| Check | Result |
| --- | --- |
| Fresh caller cases / source instruction visits | 113 / 39019 |
| Fresh builder cases / source instruction visits | 48 / 4512 |
| Local proofs | 12 unsatisfiable negated identities |
| Exhaustive bank checks | 13 rules, 3328 byte inputs |
| Original context | 1 coordinator, 2 builder parents, 4 selected builder spans, 25 coordinator instruction facts |
| Frame/record provenance | 119 task stack epochs, 3840 builder-written bytes, 224 output-status bytes |
| Conditional return paths | 21 creation errors; 18 preparation errors; 6 secondary-word unwinds; 6 initialization errors; 5 samples-creation errors |
| Call/bounds stops | 55 before unmodeled calls; 2 before source BRK |
| Undefined private-stack reads | 0 |

The verifier re-reads original bytes, compiler bounds, original chained pointers, proofs, source-defined record writes and task/length stack epochs, then creates distinct fresh caller/builder runs. Time is O(C*(B+V)+I+E) and retained space O(B+C*V+I+E), for C cases, mapped bytes B, bounded visits V, source census I and retained events E, plus solver-dependent fixed-word work. Each caller has a 20000-instruction cap; each builder has a 256-instruction cap. An observation at a call boundary is distinct from executing its target.

The command used before publication follows. Published files remain frozen; independent reproduction requires a separate copy with distinct output paths.

```
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_sample_caller.py
```

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| SR1 | Pinned original KC and normalized image identify this build | All address, byte and ABI claims | Rehash both files; compare compiler spans and exact chain membership |
| SR2 | Private records, file-initialized globals and source-written stack state are declared fixtures | 113 caller cases, not native entry reachability | Recheck every original instruction and record/task epoch; undefined private reads stop |
| SR3 | Helpers return declared modeled results; authentication is abstracted | Conditional branches and unwind order | Canonical failures, upper-X0 width cases, caller-saved clobber cases and source/fixup pins; native effects remain unknown |
| SR4 | Builder slices start after an unexecuted initializer and use declared frame values/state words | Two conditional builder mappings | Retain original prefixes/stores; establish full predecessors, alias effects and actual initializer behavior separately |
| SR5 | The first builder's saved key corresponds to its record pointer | First-builder roundtrips | Trace `[SP+0x3a8]` and `[SP+0x998]` together through all predecessors; second-builder key is independently source-derived |
| SR6 | Context fields carry task operands, but context types/ultimate identity are unknown | Partial incoming task provenance | Trace earlier argument producers and task reference ownership; do not infer UserClient ownership or a task-port name |
| SR7 | Selector `0x507` and stopping boundaries delimit recovered behavior | Setup-role attribution and successful continuation prefix | Recover other selectors and the later memory helper without treating a boundary as successful completion |
| SR8 | Stored words and consumer comparison identify a local status carrier | Conditional status mapping | Preserve void-release semantics; verify intervening callee-saved register preservation and remaining consumers before assigning business meanings |

| Impact | Further work | Interface question resolved |
| --- | --- | --- |
| High | Prove both builder frame predecessors and first-builder key/record correspondence | Whether the recovered setup path is reachable from actual command records |
| High | Trace the two task-carrier producers and reference acquisition/retirement | Which task's address space backs each descriptor, and who owns its reference |
| High | Recover sample-size iteration, later memory helper and all success/unwind edges | Actual data flow, complete/prepare pairing and eventual retirement |
| High | Recover serialization around the four global descriptors | Whether distinct calls can share/replace the same descriptor state |
| Medium | Simplify the second builder's count expression and trace its source | Relationship between its input word and the four-byte-element extent |
| Medium | Recover other selector partitions and status consumers | Complete coordinator role and propagation across the parent interfaces |

QG1: factual technical analysis requires no normative conclusion. QG2: SR1-SR8 list dependent results and falsification probes. QG3: this increment covers record fields, target/call sites, task lineage, widths and conditional control flow; the full interface objective remains active. QG4: widths, byte extents, modular arithmetic and complexity are explicit and reproducible. QG5: stored status/incidental return register, partial/full lifetime, full64/low32 keys and fixture/native reachability are distinguished. QG6: original source, chained slots, 12 proofs, 161 fresh cases and write epochs support the stated scope. QG7: the impact-labeled continuation table bounds remaining work.

[Source identity](triage_evidence/sample_caller_source_identity.json), [prior-artifact preservation](triage_evidence/sample_caller_preservation.json) and [delivery quality gates](triage_evidence/sample_caller_quality_gates.json) record final readback.
