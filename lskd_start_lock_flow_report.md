# LSKD start initialization, seed publication and RW construction handoff

Subsequent source evidence: [Vector origin and typed element initialization](lskd_vector_origin_report.md) establishes the source publication into `0xfffffe000ccc78d0`, the 8192 B `site.KDDecryptParamsArray_t` descriptor, a 512 B `site.KDDecryptParams` element descriptor, first-slot/tag writes and the conditional vector-failure release/result suffix. Sixteen UNSAT queries, five exhaustive banks and thirteen reconstructed start frames pass. Native allocator outcomes, completed population, lock ownership and matched reader epochs remain unknown.

The start operation supplies the parent phase left conditional in the [construction report](lskd_lock_origin_report.md). Under its retained handler state `0x3be`, the source caller at `0xfffffe000a56e83c` constructs parent phase `0xc2b1dbf2` and invokes `0xfffffe000a52ea1c`. That preparer selects child phase `0x90d` and the recovered `IORWLockAlloc` publication into LSKD cell `0xfffffe000ccc78a8`. Original instructions, pointer banks and thirteen retained start-frame snapshots establish this source composition. Native execution and one matched live pointer epoch remain **unknown**. [SL1-SL5]

The preceding source makes 128 four-byte entropy requests and writes a 512 B static seed table before checking its seed-pointer cell. On the null-cell branch, it publishes the table address, stores flag 255, edits sixteen words and constructs the RW lock. A null allocation result reaches the raw-status return without undoing that seed publication or flag store on the inspected suffix. Successful construction prepares the previously recovered null-explicit-pointer acquisition adapter. The continuation after acquisition remains outside this report. [SL3-SL7]

The [source capture and checks](triage_evidence/lskd_start_lock_flow_checks.json.zst) retain eight spans, 283 original instructions occupying 1,132 B, four exhaustive banks covering 1,024 inputs, six authenticated continuation slots and exact original start/read_random symbols. Eighteen UNSAT queries include 98 source-lifted instruction instances and a separate sixteen-step array composition over all 128 final words. The [extractor](triage_evidence/recover_lskd_start_lock_flow.py) supports exact recapture. The [publication audit](triage_evidence/verify_lskd_start_lock_flow_publication.py) checks the owned delta, original inputs and path scrub. No new target execution, random generation, synchronization or IDA access occurred.

```text
named LSKDKext_start -> operation 1B59 -> retained start handler state
  -> 128 x read_random(scratch, 4 B)
       -> seed[iteration] = scratch_u32
  -> inspect seed-pointer cell CCC78B8
       nonnull -> raw 5E5571AE -> result store and return
       null    -> CCC78B8 = seed-table address CCC78F4
                  CCC78E0 = u32 255
                  edit seed[0], seed[4], ..., seed[60]
                  prepare parent phase C2B1DBF2
                  -> child phase 90D -> IORWLockAlloc
                       null -> raw 5E5571AD -> result store and return
                       nonnull -> CCC78A8 = returned pointer
                                  -> null-explicit acquisition record, phase 2D2
                                  -> acquisition adapter A54E220 [STATIC FRONTIER]
```

Addresses in the diagram abbreviate the common prefix `0xfffffe000`. These are source-ordered effects under returning-call and memory premises. They do not establish native concurrency, initialization success or a daemon reply.

## Entry and retained frame provenance

Exact original nlist entry `__Z14LSKDKext_startv` is at `0xfffffe000a5053f4`. It constructs an operation `0x1b59` request with zero field count and zero payload budget at `0xfffffe000a505420`. Subject to its existing status-helper gate, it calls the execution wrapper at `0xfffffe000a50544c`. Its later source frees the request and any output pointer, then forwards its saved result. No new completed named-method execution is claimed. Operation `0x1b59` is an internal request value here, with no newly established Mach message-ID or port-right meaning. [SL1-SL2]

The thirteen retained cases stop before entropy call `0xfffffe000a50fd10`. Twelve originate in the named start caller and one is a standalone operation fixture. They share X19=0, W22=`0x3be`, W26=`0x1ee`, X23=the legacy dispatch table and the same two byte-bank roots. The new checker independently reconstructs seventeen frame fields per case from ordered byte writes and checks the original instruction bytes at their last producers. Together with the executed handler-prefix bytes, this checks 44 distinct source PCs. These are retained finite cases, not thirteen new target runs.

Let W denote the workspace base and A the actual auxiliary base. Offsets and extents are bytes. The frame slots have these meanings at the entropy boundary. Earlier uses of the same offsets are separate epochs. [SL2,SL4]

| SP offset | Source-written value | Use in this continuation |
| --- | --- | --- |
| `+0x78` | `0xfffffe000ccc78e0` | Destination of the u32 flag store |
| `+0x80` | `0xfffffe000ccc78b8` | Seed-pointer gate and publication cell |
| `+0xf8` | u32 `0x1ee` | Entropy-loop dispatch state |
| `+0x100` | `0xfffffe000846c420` | Legacy dispatch table |
| `+0x120` | W`+0x80` | Base of the repeated entropy scratch request |
| `+0x128` | W`+0xa8` | Parent record, later reused for acquisition |
| `+0x130` | W`+0x4000` | Workspace limit passed to construction preparer |
| `+0x138` | W`+0x1c0` | Child construction-record address |
| `+0x140` | A`+0x1000` | Auxiliary limit copied to parent `+0x18` |
| `+0x148` | A`+0xc0` | Auxiliary work address copied to parent `+0` |
| `+0x198` | W`+0x40` | Receiver of the raw result at `+0x38` |

The workspace limit stays W`+0x4000` in both adjacent and separated auxiliary cases. It must not be relabeled as A. In all thirteen frames, the child bounds argument W`+0x1c0+0x40` is below that workspace limit. These finite relationships do not prove arbitrary native backing validity or an allocation's runtime capacity.

## Entropy loop and static seed extent

The call at `0xfffffe000a50fd10` selects wrapper `0xfffffe000a508d6c`, then original import slot `0xfffffe000847c4f8` and exact `_read_random` at `0xfffffe000be57d68`. X0 is W`+0x9c` and W1 is 4 on every iteration under the callee-saved-register premise. The [deeper entropy ABI](lskd_input_buffers_report.md) retains the original kernel callback/context contract. No callback or random backend executes in this increment. [SL3-SL4]

After each returning call, source `0xfffffe000a50fd64..0xfffffe000a50fd6c` reads the scratch u32 and writes it to `T+4*i`, where T=`0xfffffe000ccc78f4`. The bank selects original pool slot `0xfffffe0008471858`, whose decoded target is T`+12`. Original subtraction by 12 supplies T. The subsequent source increments X19 by one and selects one of two original continuation slots.

| Current iteration i | Source index after the store | Target |
| --- | --- | --- |
| `0 <= i < 127` | `0x222`, diversity `0xfac7` | `0xfffffe000a50fc90`, next entropy request |
| `i = 127` | `0x1ee`, diversity `0xfac7` | `0xfffffe000a56e6f0`, seed-pointer gate |

X19 begins at zero in every retained start boundary. The source relation `next=i+1` and these branches give exactly 128 returning requests before the gate. The total requested and subsequently copied extent is `128 * 4 B = 512 B`. The last copied word begins at T`+508`, and its four bytes end at T`+512`. This is a source-written static extent, with no heap allocation or C object-size inference. The original 512 file bytes are zero, while the later source values are opaque entropy words. No actual entropy values or cryptographic role are asserted.

The original kernel contract processes a four-byte request with one nominal generate-callback chunk if its refresh and generate paths return. Applying that previous source contract gives 128 nominal refresh operations and 128 four-byte generate chunks for this loop. Those are conditional source counts, with no observed native callback or timing evidence.

## Seed-pointer gate and sixteen-word transformation

Only after all 128 copies does `0xfffffe000a56e6fc` read the seed-pointer cell. A nonzero value selects raw status `0x5e5571ae` and the common result return. It does not bypass the preceding seed-table writes. The null branch stores T to the cell at `0xfffffe000a56e714`, then stores u32 255 to `0xfffffe000ccc78e0` at `0xfffffe000a56e720`. Neither cell is a Mach port. The flag's broader meaning remains unknown. [SL3-SL7]

Under W22=`0x3be`, the source derives W19=`0x1fb` and loop limit `0x3b`. It begins the loop counter at u64 `-4`, increments by 4 after each word update, and continues while the updated unsigned counter is below `0x3b`. Updated counters are 0, 4, ..., 60, giving sixteen iterations. The post-indexed store advances its destination by 16 B each time.

For an array of 128 opaque u32 seed words, the recovered transformation is

```text
for j in 0..15:
    v = seed[4*j]
    q = seed[v & 0x3e]
    seed[4*j] = u32(v | (u32(~q) << 16))
```

The selected read index is even and lies in `[0,62]`. Its byte offset is at most 248 B, so the read ends at offset 252 B, within the already populated 512 B extent. Writes affect word indices 0, 4, ..., 60, with 64 unique bytes updated. Each update preserves its destination's low sixteen bits. Every selected index depends only on preserved low bits, and only the selected word's low sixteen bits survive the left shift. Consequently, the final result equals the same formula evaluated against the original array snapshot. A separate sixteen-store SMT array composition checks all 128 final words, including words untouched by this loop. It handles aliasing between a selected source word and an earlier destination. [SL4,SL6]

The seed table remains distinct from the 1024-entry lookup table at `0xfffffe000ccc7b08` and the previously recovered vector-presence cell `0xfffffe000ccc78d0`. This continuation establishes no writer to either of those two locations. Its seed-pointer cell and RW-lock cell are also distinct.

## Construction caller, statuses and acquisition frontier

The caller's address expression reduces to `low32(R) XOR 0xc410a4c0`, where R=W`+0xa8`. Its encoded parent control is

```text
key32 = (low32(R) XOR C410A4C0) * AED3B63B
parent_word20 = key32 XOR (W19 + C2B1D9F7)
W19 = 1FB
decoded parent phase = C2B1DBF2
decoded child phase  = u32(C2B1DBF2 + 3D4E2D1B) = 90D
```

The caller also stores the child record address at parent `+8` and the workspace limit at `+0x28`. Four exhaustive banks verify the entropy wrapper, seed table, construction preparer and later acquisition adapter. At `0xfffffe000a56e83c`, original slot `0xfffffe0008471220` supplies target `0xfffffe000a52ea1c`, diversity `0x709c`. The preceding report's remaining parent-phase premise is therefore sourced for this returning-entropy continuation. Native reachability and hardware authentication remain separate. [SL1-SL5]

The construction preparer returns raw status in parent `+0x10`. The caller compares it with `0x5e561849`. Equality selects index `0x243` and target `0xfffffe000a54a214`; other values select index `0x1fb` and the common result return. Both original slots have diversity `0x2984`. The failure branch preserves the raw value in W8. The return block stores it at receiver `+0x38` at `0xfffffe000a52e4b8` and restores the shared caller frame.

| Local condition | Raw result reaching the return | Source effects already performed |
| --- | --- | --- |
| Seed-pointer cell nonzero | `0x5e5571ae` | 128 entropy requests and 512 B of seed copies under the returning-call premise |
| Seed-pointer cell zero, RW allocation returns null | `0x5e5571ad` | Seed copies, seed-pointer publication, flag 255 and sixteen word updates |
| Seed-pointer cell zero, RW allocation returns nonnull | `0x5e561849` at the construction gate | The above effects plus RW-pointer publication; continues to acquisition preparation |

On the inspected null-allocation suffix, there is no source clear of the seed-pointer cell or flag before the raw result store. The selected constructor also does not write a new RW pointer on its null-result arm. Any original RW-cell contents and actual object lifetime remain unknown. If an outer status consumer applies the previously recovered `u32(raw-0x5e561849)` translation, the first two raw words become `0xffff5965` and `0xffff5964`, respectively. That arithmetic correspondence does not establish a new completed method return or external response.

Successful construction selects the shared preparation fragment at `0xfffffe000a531ca0`. The source restores phase `0x3be`, writes a null explicit lock pointer and encoded selector `0x2d2` to the reused record, then calls `0xfffffe000a54e220` at `0xfffffe000a531d60`. The [existing LSKD lock adapter](lskd_continuations_report.md) loads cell `0xfffffe000ccc78a8` when that explicit pointer is null and selects `IORWLockWrite` if the cached value is nonzero. A stable pointer epoch would join the new construction to that acquisition. Competing writes, native ownership and subsequent unlock/free remain unproved. This report stops at the source acquisition handoff. [SL5,SL7-SL8]

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SL1 | The original KC and normalized kext identify this build. Addresses, names and branch slots depend on that identity. | Rehash both, compare every selected instruction and decode the original chained slots. |
| SL2 | Retained start prefixes describe the declared finite constructor and operation fixtures. Frame and initial phase joins depend on those prefixes. | Reconstruct byte epochs, check producer PCs and boundary values, then establish an actual native caller and backing objects separately. |
| SL3 | Every entropy request returns normally and supplies four writable scratch bytes, preserving callee-saved registers. Loop completion and later stores depend on this. | Verify the actual backend contract and all 128 call/return events. This increment executes none. |
| SL4 | Source banks remain the original byte tables and the stated memory extents are accessible without undeclared aliases. Source array and record compositions depend on this. | Exhaust all byte-bank inputs, verify frame limits and source read/write extents, then inspect concrete native aliases and runtime mappings. |
| SL5 | Bounds and allocation return normally with the construction report's stated contracts. The start-to-construction join depends on this. | Recover actual bounds outcomes, X20 preservation, allocator result and hardware authentication in one matching build. |
| SL6 | The seed transformation follows the decoded post-indexed store and unsigned loop branch. Its snapshot identity depends on those exact semantics. | Compare the original operands and solve the local low-bit, index, counter and sixteen-step array mismatch queries. |
| SL7 | Statements about retained publications concern the inspected sequential suffix. They do not assume native serialization. | Enumerate intervening writers, actual failure cleanup and concurrent consumers before assigning a live readiness or ownership meaning. |
| SL8 | The prior acquisition adapter's phase `0x2d2` applies to the new source-produced record. A matched native acquire requires a stable cached pointer. | Recheck the encoded record and exact adapter bank, then identify the last reaching cell write and actual lock object. |

## Bounded continuation

| Impact | Further question | Evidence needed |
| --- | --- | --- |
| High | Does native startup complete the entropy, construction and acquire chain? | Matching runtime image, returns, bounds, actual lock identity and pointer epochs. |
| High | What are the seed-pointer and flag consumers and retry semantics? | Their complete original read/write census and native scheduling. The source failure suffix leaves them published. |
| High | What does start do after the acquisition adapter returns? | Source continuation at `0xfffffe000a51162c`, downstream record fields, vector publication and eventual release. |
| Medium | How do the returned raw fields reach an outer status or daemon response? | Original forwarding, outer cleanup and transport-field correspondence beyond the inspected receiver return. |
| Medium | How are the separate lookup table and vector-presence cell initialized? | Original stores and their ownership/control-flow connection to this start path. |

## Verification and scoped quality gates

Run `recover_lskd_start_lock_flow.py --verify` with the evidence directory on Python's module path and Z3 available. It re-extracts the original bytes, reconstructs the thirteen retained frames, exhausts the banks, re-lifts the selected slices and compares the complete retained artifact. The publication audit independently reparses and checks every serialized SMT query. The prior profiles and original three supplied inputs remain unchanged.

Source capture and retained-byte reconstruction cost O(B+I+E+256R), plus original pointer-chain work, for bytes B, selected instructions I, retained write epochs E and bank rules R. The fixed loop relation covers 128 iterations, and array composition uses sixteen updates and 128 final-word comparisons. Solver cost is separate with a 10 s limit per query. No native timing or resource-capacity bound is inferred.

- **QG1** passes for factual source and interface analysis.
- **QG2** passes with SL1-SL8 and their dependent results and falsification probes.
- **QG3** passes for the start caller phase, entropy-copy loop, seed publication, local failure return and acquisition handoff in this increment. The full objective remains active.
- **QG4** passes with 32-/64-bit widths, explicit byte extents, fixed loop counts and modular status arithmetic.
- **QG5** passes with distinct frame epochs, workspace and auxiliary limits, four separate global roles, source order and unknown native lifetimes.
- **QG6** passes with original bytes, exact symbols, chained slots, retained-case byte epochs and eighteen checked queries.
- **QG7** passes with impact-ranked runtime, seed-consumer, continuation and transport questions.

[Element population and representation](lskd_element_population_report.md) recovers the conditional 1024-slot loop, 32 sixteen-byte rewrites and 63 distinct-word swaps per nonnull body, transformed-slot publication, completion-record phase `0x1c8ff7c8`, returning-helper raw-success handoff, cached-lock release and the separate presence gate. Twenty-two UNSAT queries cover 154 lifted instruction instances, including the complete 42-instruction SIMD body. Full pointer-codec/helper semantics, native ownership/population and a daemon reply remain unknown.
