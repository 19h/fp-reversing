# AES-related dispatch contexts, cleanup call chain and record classifiers

The five previously unresolved `0xed6d` sites now have target selections under explicit saved-frame values recovered from original source setup. They select a CBC helper, a record classifier, and a record dispatcher; none of those five selects `cleanupKernelAESHW` under the recovered contexts. A separate `0xd939` site at `0xfffffe000a6080ac` selects the cleanup adapter at `0xfffffe000a62259c`, establishing a source-context chain into the already recovered cleanup call at `0xfffffe000a6227b4`.

These are **conditional source-context mappings**. Actual reaching frame values, preservation across aliases/callees, complete function paths and native reachability remain unproved. Fresh executions stop before every authenticated call; no authentication bypass or target routine execution is used to resolve the dispatch slices. A separate call-free classifier leaf is executed on declared record fields.

Evidence: [original contracts](triage_evidence/kext_aes_dispatch_contracts.json), [dispatch profiles](triage_evidence/kext_aes_dispatch_profiles.json), [fresh dispatch replays](triage_evidence/kext_aes_dispatch_replays.json), [classifier profiles](triage_evidence/kext_record_classifier_profiles.json), [fresh classifier replays](triage_evidence/kext_record_classifier_replays.json), [independent checks](triage_evidence/kext_aes_dispatch_checks.json), and [six local proofs](triage_evidence/kext_aes_dispatch_proofs.json). This extends the [AES handoff report](kext_aes_handoff_report.md). Source addresses are unslid; modeled record/frame addresses are private fixtures. Offsets and extents are bytes.

```
core function 0xfffffe000a606728
  block 0xfffffe000a60802c builds a cleanup-adapter record
  -- call 0xfffffe000a6080ac, under recovered frame context -->
     adapter 0xfffffe000a62259c
       -> unsigned bounds assertion must return
       -- call 0xfffffe000a6227b4 --> cleanupKernelAESHW
                                      0xfffffe000a5085e0
```

This chain establishes two intended source transfers and a partial record contract. It does not establish an actual cleanup event, successful initialization, complete session finalization or any Mach-right lifetime change.

## Source provenance and context boundary

| Source or readback | Coverage |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Original compiler catalog | 450 FairPlayIOKit function starts |
| Compiler envelopes | 8 envelopes, 168692 bytes; original KC/normalized bytes match |
| Explicit source spans | 14 spans, 9716 bytes, with original instruction decoding |
| Bank evidence | 5 left/right families, 2560 source bytes; 8 base-selection rules and 11 site-selection rules |
| Pointer lineages | 18 literal pool-pointer loads/adjustments, with source instruction spans |
| Frame-store census | 33 direct literal-SP overlap records for tracked qwords; no indexed-SP stores found in that census |

The frame census is deliberately narrower than full data-flow proof. It enumerates direct literal-SP stores in the compiler envelopes and retains competing stores. It does not normalize every prologue SP epoch, trace FP aliases, rule out writes through other pointers, establish all reaching definitions, or prove that callees preserve the saved values. All mappings dependent on inherited frame/register values carry R2-R3 below. A static pointer lineage is not an observed native frame.

No target binary, provider implementation, allocator, crypto operation, reference operation, Mach operation or IDB mutation executes natively. [Fresh source readback](triage_evidence/kext_aes_dispatch_source_identity.json) and [prior-artifact preservation](triage_evidence/kext_aes_dispatch_preservation.json) cover delivery.

## Local selection mechanism

Each recovered selector uses a low byte b, two original 256-byte arrays L/R and a source literal k:

```
c = b XOR R[L[b] XOR k]
index = additive + c
target = load_u64(table_base + 8 * index)
```

For the listed source arrays, c is constant over all 256 b values. Mutable inputs used to generate b therefore cancel from these local selections when the bank pointers have the recovered values. This does not imply that payload-dependent dispatch elsewhere is constant.

The eight context rules independently select pool index `0x33`, slot `0xfffffe0008472098`. Subtracting 12 from that slot's loaded value yields table base `0xfffffe0008472f20`. The contexts use different bank keys/additives; identical final table bases do not prove their original paths were reached.

| Bank family | L address | R address |
| --- | --- | --- |
| A | `0xfffffe0007949dd0` | `0xfffffe000792fbc0` |
| B | `0xfffffe0007949fd0` | `0xfffffe000792ffc0` |
| C | `0xfffffe0007949ed0` | `0xfffffe000792fec0` |
| D | `0xfffffe000792fcc0` | `0xfffffe00079391f0` |
| E | `0xfffffe0007941f60` | `0xfffffe000794a0d0` |

## Six `0xed6d` call sites

All rows assume the source-derived bank/table context described in the contracts. Original authenticated slot metadata matches the call diversity. Authenticated calls themselves are not executed.

| Call PC | Family / key | Constant c / additive | Selected slot | Target and established role |
| --- | --- | --- | --- | --- |
| `0xfffffe000a60db50` | E / `0x98` | `0x95` / `0xed5` | `0xfffffe000847aa70` | `0xfffffe000a5086a0`, exact `_performAESCBCDecryption` label |
| `0xfffffe000a6227b4` | C / `0x32` | `0xf9` / `0xe88` | `0xfffffe000847ab28` | `0xfffffe000a5085e0`, exact `_cleanupKernelAESHW` label |
| `0xfffffe000a6825d0` | A / `0x73` | `0x47` / `0xf2f` | `0xfffffe000847aad0` | `0xfffffe000a5a962c`, address-keyed record classifier |
| `0xfffffe000a6968f4` | B / `0xac` | `0x06` / `0xf65` | `0xfffffe000847aa78` | `0xfffffe000a6674d0`, record control dispatcher |
| `0xfffffe000a698168` | A / `0x5c` | `0xd2` / `0xe99` | `0xfffffe000847aa78` | Same dispatcher |
| `0xfffffe000a698258` | D / `0x87` | `0xdf` / `0xe8c` | `0xfffffe000847aa78` | Same dispatcher |

The two obfuscated targets have no exact source nlist name in the retained symbol readback. Their roles below come from original machine instructions and the associated supplied C, rather than from assigning an AES role based on the shared diversity value.

## Five `0xd939` call sites and incoming cleanup context

| Call PC | Family / key | Constant c / additive | Selected slot | Target |
| --- | --- | --- | --- | --- |
| `0xfffffe000a6080ac` | D / `0x87` | `0xdf` / `0xeb8` | `0xfffffe000847abd8` | `0xfffffe000a62259c`, cleanup adapter |
| `0xfffffe000a623680` | A / `0x5c` | `0xd2` / `0xec3` | `0xfffffe000847abc8` | `0xfffffe000a5c22b8`, further record adapter; complete role unknown |
| `0xfffffe000a6257e8` | C / `0x32` | `0xf9` / `0xeaf` | `0xfffffe000847ac60` | `0xfffffe000a509c08`, exact `_completeSampleSizesIOMD` label |
| `0xfffffe000a6869f0` | A / `0xb4` | `0x6e` / `0xf27` | `0xfffffe000847abc8` | Same further adapter |
| `0xfffffe000a686c44` | A / `0x73` | `0x47` / `0xf59` | `0xfffffe000847ac20` | `0xfffffe000a508b8c`, exact `_getSupportedAESOptions` label |

The whole executable-word census finds six immediate `0xed6d` and five immediate `0xd939` modifier sites, each followed by `BLRAA X8, X17`. This census covers those exact instruction forms; it does not recover every way of constructing a modifier or every indirect transfer. Five recovered `0xd939` contexts select four distinct targets, reinforcing that diversity is not a unique callee identifier.

## Partial cleanup-adapter record

Let P be the record pointer held in caller X24 at block `0xfffffe000a60802c`. The producer writes at least 40 bytes of record extent. The following are source register/value relationships; actual objects, limits and enclosing state are unknown.

| Record offset | Width | Producer value | Established consumer use |
| --- | --- | --- | --- |
| +0x00 | u64 | Caller X22 | Complete meaning unknown |
| +0x08 | u64 | Caller X27 | Adapter loads as object operand |
| +0x10 | u64 | Caller X26 | Adapter loads as comparison limit |
| +0x18 | u32 | Address-mixed control expression below | Adapter decodes into W28 |
| +0x20 | u64 | Caller `[SP+0x1a0]` | Complete meaning unknown |

All arithmetic in the control encoding is modulo 2^32:

```
A(P) = (low32(P) XOR 0x908154a5) * 0x51a7c57b
record_u32[P+0x18] = A(P) + caller_W19 + 0x451
decoded_W28 = record_u32[P+0x18] - A(P)
            = caller_W19 + 0x451
```

The original adapter computes A through an OR/ORN/add/sub/XOR identity before multiplication. Separate local proofs establish that address identity and the producer/consumer roundtrip. These prove a word contract, not that the record is native-valid or that the resulting state index is reachable.

The adapter loads the object and limit, then calls the original five-instruction bounds helper with `(object + 0x40) mod 2^64` and limit. That helper returns for unsigned X0 <= X1 and executes `BRK #1` otherwise. On the returning path, the recovered cleanup call selects `0xfffffe000a5085e0`. The rest of the adapter's branches and its complete object semantics remain unknown. No native bound failure or native cleanup event is reproduced.

## Obfuscated target `0xfffffe000a5a962c`: record classifier

This entire compiler-bounded function is 124 bytes, 31 instructions, and contains no calls or authenticated transfer. For record pointer P it computes:

```
K = (low32(P) XOR 0x0e12cee6) * 0x91c952ff mod 2^32
first  = (record_u32[P+0x10] - K) mod 2^32 == 0x1baf36fd
second = (record_u32[P+0x30] XOR K) == 0x16941447
record_u32[P+0x24] = 0xce51e4ec if (not first and second)
                     else 0x31ae0066
return P
```

The machine implementation uses `CCMP` and `CSEL`; the address arithmetic is another locally proved mixed-Boolean identity. Only record fields +0x30 and +0x10 are read; only +0x24 is written. Minimum accessed extent is 52 bytes. Thirty-two original/fresh cases cross all four predicate combinations with eight declared full64 record addresses, including low32 rollover. Eight cases produce `0xce51e4ec`; twenty-four produce `0x31ae0066`. The business meaning of either marker and the validity of those records in an original caller are unknown.

## Obfuscated target `0xfffffe000a6674d0`: record dispatcher

The original prefix updates two mutable u64 globals at `0xfffffe000ccc77e0` and `0xfffffe000ccc32f8`, using existing values and a stack-relative address. Randomness or cryptographic nonce properties are not established. It then consumes two encoded record words:

```
K2 = (low32(P) XOR 0x841cb645) * 0x440e0fe1 mod 2^32
selector = record_u32[P+0x08] XOR K2
tag      = record_u32[P+0x28] XOR K2
index32  = selector XOR (11 * (tag == 0x0253b9f6))
target   = load_u64(table_base + 8 * sign_extend32(index32))
```

A local proof establishes the original OR/AND/ORN/XOR address identity; another establishes the tag equality after the source constant addition. The target uses signed32 table indexing and modifier `0x9fd7` at the first tail transfer. Its record-controlled selector is not reduced to a constant by the byte-bank proof for table-base selection. The full dispatcher, selector domain, further branches and eventual operation remain unproved; this prefix is inspected statically and is not entered with fabricated selector records.

## Verification and reproduction

| Check | Result |
| --- | --- |
| Recovered contexts / sites / targets | 8 / 11 / 8 distinct target addresses |
| Base/site bank inputs | 2048 / 2816 checks across 8 / 11 rules |
| Fresh dispatch slices | 11264; 158720 original instruction visits |
| Input variation | All 256 low bytes times four upper-word patterns per site |
| Target pointer reads | 11264 original source qword reads |
| Slice data reads / stack writes | 57344 / 1024 events |
| Authenticated calls executed | 0; all slices stop immediately before `BLRAA` |
| Fresh classifier cases | 32; 992 original instruction visits |
| Local proofs | 6 unsatisfiable counterexample queries |
| Native reachability / complete lifetime | Unknown / unproved |

The byte-index proof quantifies over arbitrary upper input bits and arbitrary byte arrays; it proves that equal low bytes select equally. The other proofs cover the cleanup address identity/roundtrip, classifier address identity, and dispatcher address/tag identities. None establishes complete execution or object validity.

The command used before publication is below. Published outputs remain frozen; independent reproduction requires a separate copy of the source/evidence tree.

```
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_aes_dispatch.py
```

The verifier re-reads original envelopes, instruction spans, pool loads, pointer chains and banks, rechecks the word proofs, and creates distinct fresh slice/classifier replays. Complexity is O(B + I + C*J + E) time and retained space for source bytes B, decoded instructions I, cases C, bounded per-case visits J and events E, plus solver-dependent fixed-word work. The classifier cap is 40 instructions; the dispatch-slice cap is 64 instructions.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| R1 | Pinned normalized source, KC and original compiler catalogs identify this build | All source/slot/address mappings | Rehash originals; compare envelopes, selected bytes, instruction decoding and chained pointer membership |
| R2 | Slice seeds reproduce the listed literal source pointer definitions | Eleven conditional target selections | Preserve exact pool loads/adjustments; reject changed bank bytes; compare all low-byte inputs |
| R3 | Actual reaching frame values and alias/callee preservation remain unknown | No unconditional native call-graph claim | Retain competing direct store census; trace full predecessors, frame epochs, FP aliases and intervening callees |
| R4 | Slice input word is declared, with four tested upper patterns | Local machine-code target observations | All 256 low bytes; universal upper-bit independence proof; stop before authentication |
| R5 | Classifier records and fields are explicit fixtures | Marker truth table and pointer-width cases | All four predicate combinations, eight record addresses, guarded field reads and single +0x24 write |
| R6 | Local source lifts preserve 32-bit arithmetic and conditional flags | Six local proof conclusions | Pin relevant machine operations; independently check original classifier cases and emitted SMT |
| R7 | Core record registers/limit are not established native objects | Partial cleanup record and source chain only | Recover entry producers and full branch prerequisites; do not infer legitimate extent or session retirement |
| R8 | Target roles are bounded to inspected instructions | Classifier/dispatcher roles and named target distinctions | Keep unnamed nlist targets explicit; inspect downstream branches/callers before assigning business semantics |

## Bounded continuation

| Impact | Next investigation | Contract resolved |
| --- | --- | --- |
| High | Establish full reaching definitions and branch conditions for the core cleanup record | Actual entry-to-cleanup path prerequisites |
| High | Recover the record dispatcher selector domains from its three source callers | Payload-dependent operation routing beyond the constant bank selectors |
| High | Trace adapter `0xfffffe000a5c22b8` and sample-size descriptor completion | Additional descriptor/object lifetime interfaces |
| Medium | Recover caller use of the classifier's +0x24 marker | Business/control meaning of the two exact marker values |
| Medium | Bind source context cleanup to the close registry and session interfaces | Whether AES cleanup participates in a complete session finalization path |

## Scoped quality gates

QG1 passes for factual analysis. QG2 passes with R1-R8, dependencies and falsification probes. QG3 passes for conditional dispatch mappings, the partial cleanup record and two obfuscated routine roles; native paths and the broad goal remain incomplete. QG4 passes for exact widths, byte extents, source visits, exhaustive byte domains and complexity. QG5 passes with frame definitions/reaching state, constant/payload-dependent selectors, local/native execution and markers/business meaning separated. QG6 passes through original source, compiler bounds, pointer chains, source lineages, fresh slices/classifier cases and six local proofs. QG7 passes with impact-labeled continuation. [Machine-readable gates](triage_evidence/kext_aes_dispatch_quality_gates.json) cover this delivery.

The adapter suffix after the known hardware cleanup call now has a selected source correspondence through auxiliary retirement, the cached lock operand and the parent return store. [AES initialization and cleanup](aes_cleanup_epoch_report.md).
