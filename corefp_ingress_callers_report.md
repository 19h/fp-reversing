# CoreFP ingress callers, metadata construction and VM boundary

Current extension: the [caller-to-cold report](corefp_caller_cold_report.md) now composes this actual caller with the complete cold constructor prefix. Five profiles preserve source-produced metadata, VM and nonzero-mode root records through seed construction and both predicates, stopping before0x8eba44. Native admission, successful processing and lifetime remain unknown.

Subsequent evidence: the [VM lifecycle report](corefp_vm_lifecycle_report.md) continues this original entry through declared VM results. Four complete nonzero-mode ingress/root calls and two VM-failure controls reach the outer return; source cleanup overwrites the buffer and metadata before deallocation/free calls. This supersedes the VM frontier as the current source-continuity limit, while native lifetime and successful protected processing remain unknown.

Three original local caller paths select ingress routine `0x5f4584`, conditional on their original cached bank roots and dispatch base. Their common mode preimage is `0x2d2a8321`, which decodes to root mode `0x114e4318`. Five scalar preimages decode to five distinct nonzero root words. The earlier [ingress report](corefp_root_ingress_report.md) deliberately selected mode zero; its complete failure executions do not establish the behavior of these caller-produced inputs.

A separate coherent execution starts at original caller `0x2e4280`, initializes two output cells, checks its two input pointers, constructs a 32 B metadata object and traverses three original helper functions to `_vm_allocate` at callsite `0x1ca598`. Five profiles stop at that API boundary before any VM effect. Four early-return controls complete the original caller. None reaches the later ingress call. Native caller admission, VM allocation, port/right identity, successful protected processing and daemon/kext pairing remain unknown. The full investigation remains active.

## Provenance and assumption register

The [producer](triage_evidence/recover_corefp_ingress_callers.py), [checks](triage_evidence/corefp_ingress_callers_checks.json), [independent auditor](triage_evidence/audit_corefp_ingress_callers.py), [audit receipt](triage_evidence/corefp_ingress_callers_audit.json) and [publication verifier](triage_evidence/verify_corefp_ingress_callers_publication.py) retain the evidence. JSON links resolve logically to `.json.zst`. Original CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; supplied daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Offsets are CoreFP preferred-base-zero addresses. Record offsets below are hexadecimal; sizes use bytes (B). No new IDA readback is needed for the retained original-file claims or asserted as live corroboration.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IC1 | Hash-pinned originals, compiler bounds and format12 fixups identify the analyzed source. All source results depend on them. | Independently compare ten complete function spans totaling 20876 B, all retained pointer rows and dependency hashes. A changed image invalidates the corresponding results. |
| IC2 | Each local caller slice receives its stated symbolic frame, current phase tag, pointer and byte/cache inputs. Record equations depend on these bindings. | Lift all 113 original record-producing instructions, reject undeclared loads/opcodes and prove the field equations. Whole caller reachability is not inferred from a local slice. |
| IC3 | The `0x4bae24` caller record has an even address. Its canonical address key depends on this domain. | An unrestricted SAT control finds an odd-address mismatch. The other two keys are proved for every u64 record address. Ordinary aligned frame assumptions imply the required domain. |
| IC4 | Four bank results assume original A/B pointer roots and dispatch base `0x1c81940`. Their local targets depend on these conditions. | Exhaust 256 low-byte inputs per pair and lift 71 original bank instructions. Prove actual A/B indices and final pointer slots while retaining all 32 seed bits symbolically. Native cached-pointer epochs remain unknown. |
| IC5 | Coherent entry uses a declared encoded tag `0x9744`, two private referents, one encoded scalar, backed stack and frozen PAC/ordinary-return models. Prefix and early-return results depend on this fixture. | Independently reconstruct complete CPU/touched RAM; test each null pointer, both null, scalar 0/4096 and caller-register clobber. No source PC gap or restored parent frame occurs. Native admission is unknown. |
| IC6 | The sole new API effect is a bounded private `_malloc(32)` model returning null or the declared metadata backing. Metadata construction depends on this effect. | Check arguments, return CPU and absence of model memory writes. Source defines the object and output pointer. Compare zero/A5 initial metadata bytes; native allocator ownership and lifetime remain unknown. |
| IC7 | `_mach_task_self_` contains declared name `0x4201` or zero. The VM task argument depends on that input. | Independently trace pointer slot `0x1d14310` to the imported data cell and its four-byte load into W0. Stop before `_vm_allocate`; no API result, native right or message delivery is inferred. |
| IC8 | Literal caller census covers aligned `MOV X17,#0x6073` immediately followed by `BRAA/BLRAA` in complete original `__text`. Completeness is restricted to this pattern. | Independently rescan original words and compiler bounds. Other modifier constructions and computed references are excluded. Same diversity does not identify a callee. |

## Conditional local ingress callers [IC1-IC4,IC8]

The original bank composition is `x XOR B[A[x] XOR c]`, for `x` in `[0,255]`. Each listed composition is constant over that complete domain. The source lift checks that these are the actual table indices and that the final index discards the upper seed bits. Target identities remain conditional local statements, not completed caller executions.

| Callsite | A / B original pointer slots and adjustments | XOR c | Constant byte | Index | Selected slot -> callee |
| --- | --- | --- | --- | --- | --- |
| `0x22438c` | `0x1d08e18` / `0x1d077d0 - 8 B` | `0xe4` | `0xec` | `0x10464` | `0x1d03c60 -> 0x5f4584` |
| `0x2e490c` | `0x1d146f0` / `0x1d09f68 - 8 B` | `0xc8` | `0xc0` | `0x10464` | `0x1d03c60 -> 0x5f4584` |
| `0x4bae24` | `0x1d146f0` / `0x1d09f68 - 8 B` | `0xc8` | `0xc0` | `0x10464` | `0x1d03c60 -> 0x5f4584` |
| `0x14f2720` | `0x1d09500` / `0x1d0b590 - 12 B` | `0x20` | `0x94` | `0x104a4` | `0x1d03e60 -> 0x2233c8` |

Here pointer-slot adjustments apply to the pointer's decoded target, not the slot address. The original slots sharing IA diversity `0x6073` are:

| Original slot | Decoded callee |
| --- | --- |
| `0x1d03a98` | `0x656654` |
| `0x1d03c60` | `0x5f4584` |
| `0x1d03e60` | `0x2233c8` |
| `0x1d03f20` | `0x1561f64` |

The 20 literal callsites are `0x210b08`, `0x22438c`, `0x27ba08`, `0x2e490c`, `0x4b8308`, `0x4bae24`, `0x4c31a0`, `0x5dbc90`, `0x976814`, `0x9f3d90`, `0x9f48d8`, `0xa2b1b0`, `0xad3fb0`, `0xbd1c18`, `0xc564c0`, `0xc8ff00`, `0xca2d0c`, `0x1093538`, `0x1093888` and `0x14f2720`. Four have local target classifications above; sixteen remain unclassified in this census. This is not a complete call graph.

## Input encodings and root transfer [IC1-IC4]

Let `I` be the source-created ingress record and `Ki = (low32(I) XOR 0xd914ae5d) * 0x08c5d407`. All scalar equations here are modulo `2^32`. Let `t` be the caller's current u32 phase tag, not an assumed public operation number. Each caller writes:

```text
I+0x00 := t - Ki + operation_bias
I+0x08 := supplied_pointer
I+0x10 := Ki + 0x2d2a8321
I+0x14 := scalar_preimage - Ki
I+0x18 := local_output_pointer
```

The original ingress transformation is rechecked through eleven frozen UNSAT certificates. It supplies decoded root operation `t + operation_bias + 0x513c5990`, mode `0x114e4318`, and word `F(scalar_preimage)` at root offset `+0x10`. `F` is the exact five-term u32 mixer from the preceding ingress report; its higher-level meaning remains unknown. Ingress pointers map to root offsets `+0x20` and `+0x08`, respectively.

| Caller / local record | Current tag | Operation bias | Decoded root operation | Tag selecting `0xc1f7` | Supplied pointer / local output pointer |
| --- | --- | --- | --- | --- | --- |
| `0x223d10`; `I=FP-0x88=SP+0x98` | W20 | `0xaec41bfa` | `t+0x758a` | `0x4c6d` | `[SP+0x80]` / `SP+0x78` |
| `0x2e4280`; `I=SP+0x78` | W21 | `0xaec43b6b` | `t+0x94fb` | `0x2cfc` | `[SP+0x50]` / `SP+0x68` |
| `0x4ba7e4`; `I=SP+0x50` | W27 | `0xaec40ec5` | `t+0x6855` | `0x59a2` | `[SP+0x40]` / `SP+0x30` |

The first row's key is universal despite its unusual OR/shift arithmetic. The third row's key requires an even `I`: the retained SAT counterexample `I=0x06a7e4cf` produces original key `0x9f3265f4` versus canonical key `0x8a01f1fe`. Neither key family nor equal operation/mode encodings prove native object identity.

| Local byte condition | Scalar preimage | Decoded root word `F(v)` |
| --- | --- | --- |
| Caller `0x223d10`: `(byte[J+0x34] + low32(cache)) mod256 == 0x0b` | `0x72ceb203` | `0x7c9bb44b` |
| Same caller, condition false | `0x2a3b089e` | `0xe0dd53c8` |
| Caller `0x2e4280`, fixed preimage | `0x1f03fdec` | `0x0484c46a` |
| Caller `0x4ba7e4`: `byte[J+0x10] XOR low8(cache) == 0x47` | `0xbfb18293` | `0x5994b43b` |
| Same caller, condition false | `0xf2c062ba` | `0x290d078c` |

Here `J` and `cache` are the explicit local slice bindings. The cache is `[SP+0x30]` for the first caller and `[SP+0x10]` for the third. These conditions recover byte-dependent source selection; they do not establish external control of those bytes or native validity. All three source mode preimages differ from the previous zero-mode fixture preimage `0x27da4849`.

## Coherent original entry and metadata object [IC1,IC5-IC6]

For caller `0x2e4280`, the original input key is `Kj = (low32(J) XOR 0xca39defa) * 0x01266167`. Entry tag is `u32[J] XOR Kj`; the second decoded scalar is `u32[J+0x1c] XOR Kj`. Original source loads the two pointers at `J+0x08/+0x10` and eventually writes a raw result at `J+0x18`. The 64 B retained snapshot is diagnostic backing, not an inferred structure size.

```text
0x2e4280 original entry, declared decoded tag 0x9744
  +-- 0x2e44f0 and 0x2e45a8 -> 0x63cf64
  |     clear the pointed output cell; write raw record+0x10 marker
  +-- input pointer gate at 0x2e45ac..0x2e45d8
  |     either null -> raw J+0x18 = 0x45e2a202 -> ordinary return
  +-- 0x2e469c -> 0x1ae0a4
  |     0x1ae260: declared malloc(32), null or private backing
  |     null -> raw J+0x18 = 0x45e2a20f -> ordinary return
  |     source initializes 28 B and stores metadata pointer to output cell
  +-- 0x2e47e4 -> 0x43c4d8
        +-- 0x43cb10 -> 0x47e434
              +-- 0x47e6e0 -> 0x1c9fac
                    +-- internal route 0x1ca424
                    +-- 0x1ca598 -> _vm_allocate [STOP before API]

Later local call 0x2e490c -> 0x5f4584 is not reached here.
```

Routine `0x63cf64..0x63cf7c` is six original instructions: it loads record `+8`, stores a zero u64 through that pointer, writes raw `0x2811d86d` at record `+0x10` and returns. Routine `0x1ae0a4..0x1ae2f4` requests 32 B and initializes the following metadata view on the modeled success branch:

| Metadata offset | Size | Source value | Defining instruction |
| --- | --- | --- | --- |
| `0x00` | 8 B | zero | `0x1ae29c` |
| `0x08` | 4 B | `0x49741372` | `0x1ae2a8`, first store |
| `0x0c` | 4 B | `0x49741372` | `0x1ae2a8`, second store |
| `0x10` | 4 B | `0x574de777` | `0x1ae2bc`, first store |
| `0x14` | 4 B | `0x71349589` | `0x1ae2bc`, second store |
| `0x18` | 4 B | `0xba1df9db` | `0x1ae2c8` |
| `0x1c` | 4 B | retained initial private fill | No defining source write in the constructor |

Source `0x1ae2cc` stores the new pointer through the output-cell pointer at its input record `+8`; `0x1ae2dc` writes the input record's raw result. These use separate pointer and marker channels. The A5 control changes only the otherwise retained metadata tail. Allocation size 32 B is an actual source API argument; the metadata role is descriptive, and native ownership/retirement remains unknown.

## VM interface and port provenance [IC1,IC5-IC7]

| Interface element | Source evidence | Checked value / boundary |
| --- | --- | --- |
| Task-global pointer | Eight-byte load at `0x1ca540`, slot `0x1d14310` | Original bind to libSystem `_mach_task_self_` |
| Task-name value | Four-byte load through that pointer at `0x1ca548` | Declared private `0x4201`, or zero in control |
| VM function pointer | Slot `0x1d04758`, IA diversity `0x6764` | Original authenticated bind to `_vm_allocate` |
| API callsite | `0x1ca598` | Original `BLRAA X8,X17`; modeled target transfer only |
| X0 task argument | Source global load | Same declared u32 name |
| X1 address-output pointer | `0x1ca58c`: `SP+0x10` | `0x62017d70` in these prefixes; initial eight bytes A5 |
| X2 requested extent | `0x1ca578`: zero-extending W2 write | 4096 B in all five VM-frontier profiles |
| X3 flags | `0x1ca590`: W3=1 | Raw value 1 |
| VM return / allocation / port rights | API not executed or modeled | unknown |

The input scalar controls 0 and 4096 both reach this same 4096 B request. This finite observation does not prove that every possible input requests the same extent. The task-name control proves input propagation, not an extant native send right. There is no native Mach message, port creation/deallocation, OOL transfer or daemon/kext transaction in this increment. The exact emission boundary established here is the source VM API call, not a reconstructed `_mach_msg` site.

## Independent validation and continuation

Fresh independent replay checks nine initial CPU frames, 1196032 B of initial touched RAM and the same final RAM extent; 6939 original instruction visits, 1265 reads, 712 writes, 109 PAC models, six allocator-model returns and 72 checkpoints. Four original early returns and five stopped VM prefixes pass. Source proofs include 44 new UNSAT obligations, one SAT alignment control, 113 record-producing and 71 bank instructions, 56 additional exact instructions, 1024 exhaustive bank inputs, five scalar oracles and eleven rechecked ingress obligations. Semantic annotations are not used as proof. Original input files remain preserved.

The replay/enumeration algorithm has conservative upper bound `O(C*(B+P*F+V*L+R)+T+4*256)` time and space, including per-page fixup reconstruction and frozen reaching-load searches. Here C is profile count, B mapped source bytes, P touched pages, F fixups, V visits, L retained loads, R retained state and T complete text size. Symbolic solver cost is separate; queries have a 30 s limit and no polynomial solver bound is claimed. Source execution is limited to 30000 visits per profile.

| Impact | Remaining question | Discriminating next evidence |
| --- | --- | --- |
| High | Can the original entry reach the nonzero-mode ingress call after VM return? | Recover the source VM result, buffer initialization and cleanup branches; retain failure/success environmental contracts and source-produced record lineage. |
| High | What do mode `0x114e4318` and the five scalar words select in the protected root? | Follow original root consumers with caller-produced fields; compare with the diagnostic zero-mode paths without assigning semantic types from constants alone. |
| High | Which upstream caller/admission path supplies J, its pointers, byte and phase tag? | Resolve original caller bank/record producers and actual input epochs. A local target theorem does not establish public reachability. |
| Medium | How are the 32 B metadata object and VM allocation paired and retired? | Check pointer publication, allocation extent, all release paths and ownership state in original helper source. |
| Medium | What are the remaining sixteen literal targets and nonliteral references? | Resolve each original bank with explicit cache/dispatch assumptions or coherent entry execution. |
| High | Does this chain correspond to a native daemon/kext exchange? | Establish endpoint/right and request/result lineage in a matched epoch; neither private task fixtures nor source VM calls supply it. |

**QG1** passes: factual technical claims. **QG2** passes: IC1-IC8 delimit assumptions and probes. **QG3** passes for this increment; the full goal remains incomplete. **QG4** passes: modular widths, B extents, limits and solver/replay costs are explicit. **QG5** passes: conditional local calls, early returns, VM frontier and prior zero-mode fixtures remain distinct. **QG6** passes: original bytes/fixups, independent replay and source obligations support the stated scope; no new native/IDA corroboration is claimed. **QG7** passes: impact-ranked continuation questions cover input production, environmental state, lifetime and cross-level pairing.
