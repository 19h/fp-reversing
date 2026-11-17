# Conditional zero-tag core completion through the selector26 caller

The original provider directly calls the analyzed core at `a5052fc -> a635208`, with nominal return at `a505300`. When the retained zero-tag core theorem applies and the core returns normally with X0=0x00000000ffff5bbc, the provider requests copy-out before completing and releasing both descriptors. The handler logs this nonzero result, skips its output descriptor stores and carries the same 64-bit value to its RETAB boundary. This is a conditional source-level caller contract. Native byte transfers, authenticated returns, public status naming and a matched daemon transaction remain unknown.

The earlier adapter model required a forwarded client-state value to be nonzero. All 30 retained core-entry records use X2=0; six have the selected extent 14 B. The new caller model removes only the two pointer-domain restrictions on this by-value lane. Source load addresses and branch/address-check expressions do not depend on that value. It remains distinct from the core's separately allocated 4096 B private context C. The former model's null exclusion is an abstraction restriction, not evidence of a native fault.

## Primary evidence and scope

The source image SHA256 remains `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`; the original kernel collection SHA256 remains `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses below use the common 0xfffffe0000000000 prefix. Original collection words, authenticated pointer records and source-store journals are the primary evidence. No IDA query or native execution was necessary for this bounded increment.

| Evidence | Content |
| --- | --- |
| [Extractor](triage_evidence/recover_userclient_zero_tag_provider.py) | Rebuilds the original adapter capture, core-entry source and 90 argument cells from original store/provenance journals. |
| [Checks](triage_evidence/userclient_zero_tag_provider_checks.json.zst) | Decoded SHA256 `82c5b5be5bfd6dc4924c321fd8483051667fbf7c38cf989e6e7170a16bbc46f0`. |
| [Auditor](triage_evidence/audit_userclient_zero_tag_provider.py) | Lifts caller paths, records actual call registers, checks nullable state and composes source interfaces. |
| [Audit](triage_evidence/userclient_zero_tag_provider_audit.json.zst) | Decoded SHA256 `47c915473442e57cf3bb37f3ef242353c525ceafcf15bc261d3ad010e6497a80`. |
| [Delivery verifier](triage_evidence/verify_userclient_zero_tag_provider_delivery.py) | Fresh extraction/audit, canonical query comparison, manifest delta and publication hygiene. |
| [Core return](userclient_zero_tag_return_report.md) | Retained selected-path theorem, four ordinary retirement returns, explicit frame/guard separation, normal local result and opaque RETAB boundary. |
| [Adapter boundary](userclient_transfer_boundary_report.md) | All five provider classes and four handler cases; transfer counts and native copy effects remain opaque. |

The new audit re-solves all 44 core-return source proofs and 23 adapter proofs. It consumes the named `normal_return_exact_u32_result_and_restored_frame` theorem under that theorem's selected-path/storage/guard premises. A normal authenticated transfer from the core RETAB boundary to its nominal caller is an additional premise. This increment does not execute the entire daemon-to-core path or establish that the selected symbolic predicate is produced by a native request.

## Exact route and argument custody

| Result | Original interface / source effect |
| --- | --- |
| ZP1 | Selector26 index25 slot 846b838 names record 846b710: flags3, input16 B, output16 B; record+8 at 846b718 names handler a504034. |
| ZP2 | Nominal provider vtable symbol 846b8c0 has address point 846b8d0. Offset 0xa20 gives original slot 846c2f0 -> a505198, diversity 0x3499. Handler BLRAA is a50408c. The live object's nominal vtable and successful authentication are premises. |
| ZP3 | Handler obtains provider from UserClient+0xd8, task from +0xe0 and state P from +0xe8. Packet address is u64 at +0; packet extent is u32 at +8. MOV W2 zero-extends the provider's extent argument. |
| ZP4 | Provider moves K to X0 at a5052f0, its incoming extent64 to X1 at a5052f4 and P to X2 at a5052f8; direct BL a5052fc targets a635208. Here K is the buffer-address query result, distinct from user address A. |
| ZP5 | Original core stores X2 at F+0x738 at a63524c, X1 at F+0x878 at a635250 and X0 at F+0x8f8 at a635254. The new proof substitutes the actual provider call registers into this original prologue and checks all import/probe address obligations. |
| ZP6 | Core return X0 is saved in provider X21 at a505300. Copy-out a505344 is requested without testing this status or either copy count. Four later completion/release requests preserve X21 under ordinary-return premises. |
| ZP7 | Provider a5053d8 moves X21 to X0; a5053f0 reaches RETAB. Handler a504090 saves it in X21; a504094 tests W0. For 0xffff5bbc, the error-log call a5040a4 is selected, with the saved 64-bit value placed at handler SP. Stores a5040b0 and a5040b8 are skipped. |
| ZP8 | Handler a5040bc moves X21 back to X0, restores its original SP and X19..X29, and reaches RETAB a5040d0. Native return, transport reply identity and public error-domain assignment remain unknown. |

The 30 original entry witnesses reconstruct three complete 8 B cells each: 90 cells and 720 B. Each cell has exactly one overlapping original source store, matches the saved snapshot and contains eight known/provenance-marked bytes. X0 also matches the retained original-input root; low32(X1) matches the retained extent; X2 is zero. Exactly predecessor cases 5,15,25,35,45,55 have X1=14. The other 24 records support general argument/frame custody, not the selected 14 B execution predicate. Recorded fixture addresses do not establish native allocation or input-byte identity.

## Transfer, lifetime and output channels

For the nominal handler, let A be the packet's user address, N its u32 extent, P the by-value client state, D the task descriptor, B the buffer descriptor and K the queried buffer address. The provider's direct ABI can forward a wider X2 size parameter to the core while using only low32 for transfers; this handler supplies ZE64(N), so the selected path has N=14 and the full core size argument is 14.

| Call site | Role | Relevant argument contract |
| --- | --- | --- |
| a5051d4 | Task descriptor factory | (A, ZE64(N), 3, task), veneer a69f1e4 -> original import 847c420 -> c53a934. |
| a50520c | Task prepare | (D,0), virtual offset 0x218; low32 return zero is selected. |
| a505250 | Buffer factory | (kernel_task,0x13,ZE64(N),SE64(1u32 << (PAGE_SHIFT & 31))), veneer a69f1f4 -> 847c428 -> c526070. |
| a505288 | Buffer prepare | (B,0), virtual offset 0x218; low32 return zero is selected. |
| a5052bc | Buffer address | Receiver B, virtual offset 0x308; opaque result K. |
| a5052ec | Copy-in request | (D,0,K,ZE64(N)), virtual offset 0x208. Reported count is arbitrary. |
| a5052fc | Actual core call | (K,ZE64(N),P) on the nominal handler route. |
| a505344 | Copy-out request | (D,0,K,ZE64(N)), virtual offset 0x210; requested even for the selected nonzero core result and short counts. |
| a505380 | Buffer complete | (B,0), virtual offset 0x220. |
| a505398 | Buffer release | Receiver B, virtual offset 0x28. |
| a5053bc | Task complete | (D,0), virtual offset 0x220. |
| a5053d4 | Task release | Receiver D, virtual offset 0x28. |
| a5040a4 | Nonzero handler log | Veneer a69f0d4 -> original import 847c398 -> c4babac; saved status at handler SP. Native logging effects remain opaque. |

```text
packet(A,N), UserClient(P,task,provider)
  -> handler -> provider -> copy-in request(D,0,K,N)
                            -> core(K,N,P)
                               [selected theorem + ordinary authenticated return]
                            <- X0 = 0x00000000ffff5bbc
                            -> copy-out request(D,0,K,N)
                            -> buffer complete/release -> task complete/release
  <- same status <- provider RETAB [ordinary authenticated return assumed]
  -> error-log request -> skip output descriptor stores -> handler RETAB
```

Payload transfer and output descriptor publication are separate channels. Skipping the handler's 8 B address and 4 B extent stores does not suppress the earlier copy-out request. Conversely a request is not proof that N bytes were transferred. This report proves no concrete payload delivered to A, including under short copy-in/out counts. The selected core's original-input restoration concerns K and the original observations retained by that theorem; establishing copy-in contents or physical memory identity remains a separate requirement. No additional Mach endpoint, port direction or emission site is established by these kernel-local calls.

## Frame interface and source verification

Let H0 be the handler entry SP. Under the captured source prologues:

| Frame | Half-open byte range | Size |
| --- | --- | --- |
| Core | [H0-0x1180,H0-0x90) | 4336 B |
| Provider | [H0-0x90,H0-0x40) | 80 B |
| Handler | [H0-0x40,H0) | 64 B |
| Combined | [H0-0x1180,H0) | 4480 B = 4336 B + 80 B + 64 B |

The actual core incoming SP is H0-0x90, incoming FP is H0-0x50 and nominal incoming link is a505300. Core body F=H0-0x1180 and FP=F+0x10e0=H0-0xa0. The new source queries establish these equations and nonwrapping adjacency. Core return restores its caller FP; it does not retain the core body FP. Accessible/stable outer frames and their preservation against opaque callees and aliases are explicit composition premises; the adjacency proof is not an inventory of native alias writers.

The audit establishes 20 new nonvacuous UNSAT source obligations and re-solves 67 retained obligations. Six separate SAT admissions cover state=0 and state=2^64-1 for the provider, separate-packet handler and exactly aliased-packet handler. In all three models, state-dependent load addresses and branch/address checks number zero. The full by-value state lane therefore has no pointer-domain restriction in this caller model; this does not prove that the core accepts every possible state value on every path.

An additional UNSAT query confirms that the former nonnull state premise excludes state=0. Two changed-source controls produce SAT violations: replacing the core's forwarded-state move at a5052f8 with zero breaks state custody for P=1; replacing the copy-out extent move at a505338 with zero breaks the 14 B request contract. No target bytes are changed. The selected paths cover 177 distinct caller words from the 191-word capture; early factory/prepare failures, the handler zero-status branch and two authentication traps are outside this increment's selected path and remain covered or excluded as documented by the earlier adapter report.

Extraction is O(B+I+C*W) time/space for image bytes B, decoded words I, prefixes C and stores W. Caller lifting is O(I) time/space; argument-cell reconstruction uses O(C*W) scan time and O(C) fixed-cell storage. Symbolic query construction scales with the resulting expression DAG; SMT search is separate, with 60 s limits for new queries and 120 s for retained queries. Source arithmetic is u32 or u64 as specified; all extents and offsets are in bytes.

## Assumption register

| Assumption | Dependent results / stress test or falsification probe |
| --- | --- |
| ZP-A1: Pinned source, original collection and retained receipt identities | ZP1-ZP8. Rehash dependencies, recapture all original caller words/pointers and rebuild 90 argument cells. |
| ZP-A2: Live handler/provider objects, packets and vtables are accessible, stable and nominal | ZP1-ZP4, ZP6-ZP8. Check exact slots/diversity, separate and exact-alias packet cases and authenticated dispatch in a pinned native environment. Partial packet overlap and concurrent mutation remain unknown. |
| ZP-A3: Descriptor factories are nonnull and both prepare calls return low32 zero | ZP4-ZP8. Retain the selected event sequence; compare earlier four failure classes separately. Factory identities and native ownership remain unknown. |
| ZP-A4: Named selected zero-tag core theorem applies to the actual argument epoch | ZP5-ZP8. Retain N14/L4/type/tag/byte-observation/storage premises; re-solve 44 source proofs and check caller-to-prologue roots. Six N14 records do not establish native path reachability. |
| ZP-A5: Ordinary authenticated core/provider returns and opaque adapter calls preserve callee-saved registers, SP and surviving caller frame storage | ZP6-ZP8. Check nominal links, all source save/restore equations and nonwrapping frame adjacency. Exclusion of external alias writers and native PAC effects remain unknown. |
| ZP-A6: Transfer counts/results are independent opaque observations | ZP6-ZP8. Admit arbitrary short counts and retain the exact status/copy-request contracts; inspect actual descriptor implementations/transaction bytes before claiming transfer completion. |
| ZP-A7: Forwarded state is a by-value lane with no adapter dereference | ZP3-ZP5. Inventory all source read addresses and control/address predicates, admit zero and maximum u64, expose the former null exclusion and reject the changed-state source control. Do not identify P with private context C. |
| ZP-A8: Local source status and skipped descriptor stores keep their stated boundary | ZP7-ZP8. Check W0 nonzero gate, saved full64 status, copy-out-before-log sequence and separate payload/descriptor channels; identify a matched external completion before assigning public semantics. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Identify a daemon producer and matched selector26 transaction satisfying the selected core predicate; bind actual copy-in contents and client-state epoch to these argument roots. |
| High | Recover nonzero-tag node/body construction at a642454; retain length, original-byte and ownership interfaces. |
| Medium | Establish why UserClient+0xe8 can be zero at this call epoch, using its source writers and lifecycle rather than treating it as the private core context. |
| Medium | Compare selected nonzero completion with oversized-body and allocation/prepare failures, preserving separate payload-copy, descriptor-output and status channels. |
| Low | Inspect native descriptor copy counts, outer-frame alias exclusion and PAC return effects for a pinned execution context if runtime evidence becomes available. |

## Quality gates

- **QG1**: Pass. Factual source/interface analysis requires no normative judgment.
- **QG2**: Pass. ZP-A1 through ZP-A8 identify dependencies and falsification probes.
- **QG3**: Pass. The bounded increment covers actual call/argument identities, nullable state, frame interfaces, copy/lifecycle requests, status and handler output control. The wider investigation remains active.
- **QG4**: Pass. u32/u64 lanes, zero/sign extension, byte extents, frame arithmetic and complexity are explicit.
- **QG5**: Pass. Forwarded state/private context, source/native return, copy request/bytes, payload/descriptor output and retained/selected prefix populations remain distinct.
- **QG6**: Pass. Original source/pointer/store provenance, rebuilt queries, retained proofs and mutation controls provide primary evidence.
- **QG7**: Pass. Continuations address matched transport, construction, state lifecycle and separate completion channels with bounded impact labels.

The forwarded state at UserClient+0xe8 is the `site.IOUCCtx` pointer cell. Start zeros it before construction and ignores the constructor's ordinary returned status. The earlier lifecycle work distinguishes this object from private core context C and leaves native null allocation and transaction reachability unknown. [Context lifecycle](userclient_context_lifecycle_report.md). The corresponding nonzero-tag core route now reaches first-record publication and its cursor gate. [Nonzero-tag continuation](userclient_nonzero_tag_record_report.md).
