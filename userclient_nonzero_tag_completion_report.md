# Completion after first-record publication

In the pinned FairPlayIOKit image, a 14 B protected fallback input leaves two continuations after the first nonzero-tag record is appended. If the record consumes all 14 B, `_PRnut72j9` publishes the populated container to its caller. If 1–4 B remain, the parser rejects the next header, sends three retirement requests for the allocations it just connected, and resumes the caller with a null output and raw status `0xce515bb8`.

The model starts with the [first-record construction and serialization](userclient_nonzero_tag_record_report.md) and carries its registers and byte-versioned memory through the two continuations. It joins that state to the [parser cleanup](userclient_parser_cleanup_report.md) and [command dispatcher](userclient_command_dispatch_report.md). The exact command lookup result, native allocator effects, hardware pointer authentication, external return and daemon transaction identity remain unknown.

## Parser-to-caller contract

B denotes the retained 14 B input, T the 16 B container, J its 32 B node, and Z the record buffer. F, C and S denote the frame, private context and workspace. The first record has a 10 B header and a body of length L in 0–4 B. Hence its committed cursor is 10 + L B, and the remaining extent is 14 B − (10 + L) B = 4 − L B. PCs below omit the common `0xfffffe0000000000` prefix.

| Result | Condition | Source contract |
| --- | --- | --- |
| NC1 | L = 4 B | The exhausted branch at `a642180` loads T from C+0x228. The success arm stores `0x31ae0066` at S+0xc10. At `a660ad0`, the parser writes T through the saved output pointer to C+0x600. It resumes at `a656c08` with W23 = `0x31ae0066` and F+0xa80 = 14. |
| NC2 | L = 4 B | The caller reloads that same T, clears the result at C+0x1f8, and branches at `a656cf8` to `a662ab4` with X22 = T, W9 = `0x45e5918e` and X10 = C+0x1f8. T still contains J in both list slots and J still holds Z with a 14 B extent. |
| NC3 | L = 0–3 B | The input gate at `a6421dc` restages B. The header gate at `a642248` rejects the 1–4 B suffix against the 10 B requirement. The continuation accesses no bytes of the retained input, original input, or record buffer. The cursor stays at 10 + L. |
| NC4 | L = 0–3 B | At `a662454`, the parser saves raw W23 = `0xce515bb8` at S+0xc10. It puts T in the cleanup cell C+0x4e8. The destructor reads J from T and saves J's zero successor at `a66075c` before the first retirement request. |
| NC5 | L = 0–3 B | After the three ordinary callee returns, the source clears C+0x4e8 and C+0x228, publishes zero at C+0x600, restores W23 = `0xce515bb8`, and resumes at `a656c08`. The caller's branch at `a656c40` selects `a65f358` with the cursor still at 10 + L. |

| Request PC | Target | X0 | X1 | Nominal return |
| --- | --- | --- | --- | --- |
| `a6607e8` | `_IOFreeData` at `c4ba84c` | Z | Zero-extended u32 extent 10 + L B | `a6607ec` |
| `a660708` | `_IOFreeTypeImpl` at `c4ba368` | `site.FPTTLVNode` descriptor `847be20` | J | `a66070c` |
| `a6605c4` | `_IOFreeTypeImpl` at `c4ba368` | `site.FPTTLV` descriptor `847bde0` | T | `a6605c8` |

After the first return, the source clears J+0x18 at `a660804`. After the second, it tests the saved zero successor and advances to container retirement. These transfers are kernel-local calls and branches. Mach rights and the originating external method are tracked in the separate [Mach port inventory](mach_ports_report.md) and [ABI inventory](interface_abi_report.md).

## Evidence and verification

| Artifact | Decoded SHA-256 |
| --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| [Source capture](triage_evidence/userclient_nonzero_tag_completion_checks.json.zst) | `8b51a1f9dc4f8e30c2f4fcd979f83e0c68aaff71b858359ef51cb4fde70fb81f` |
| [Proof and access receipts](triage_evidence/userclient_nonzero_tag_completion_audit.json.zst) | `97699e2be54c9d3ec8f74ce6c47d353fe57680d7ef5f8e5fb2c7d790978cb673` |

The [extractor](triage_evidence/recover_userclient_nonzero_tag_completion.py) checks 452 instruction words in 24 continuation spans against both image representations, together with 31 branch-table observations, 1,280 bank-composition cases and two original typed descriptors. Seven saved frame values per state are reconstructed from 30 original-entry journals, totaling 210 cells and 1,680 B. The covered instructions suffice for this increment.

The [auditor](triage_evidence/audit_userclient_nonzero_tag_completion.py) verifies six live-context equations across the two predecessor modes and five composed length cases. Each query first establishes satisfiable premises and then rejects a violation of the contract. An in-memory omitted-store control for publication and another for clearing the cleanup cell each produce a satisfiable violation. Across the five cases the continuation inventories 326 accesses, checks the three retirement returns on each short-suffix path, and admits no accesses to a modeled retired object after its request returns. The [delivery verifier](triage_evidence/verify_userclient_nonzero_tag_completion_delivery.py) rebuilds the receipts and validates the published file set and path scrub.

These singleton continuations take O(1) time and O(1) auxiliary space, excluding external callee costs and the command lookup after the audited endpoint. Extraction scales linearly with source bytes, captured instructions and scanned journal stores, plus 256 checks per selected bank rule. Symbolic lifting scales with lifted instruction instances and their expression representation. Solver search is separately bounded to 60 s per query.

## Assumption register

| Assumption | Dependent results and falsification probe |
| --- | --- |
| NC-A1. Original and normalized kext images and captured table epochs are pinned. | NC1–NC5. Rehash both images, read the original words and chained pointers, and exhaust the five bank compositions. |
| NC-A2. The incoming state is the previously recovered 14 B nonzero-tag type-0x6685 first-record path. | NC1–NC5. Re-lift the predecessor with all five admitted body lengths and compare its node, extent, buffer and cursor contracts as part of the same query. |
| NC-A3. Live frame and context roots have their reconstructed values. | NC1–NC5. Check both original predecessor modes for the three added context dependencies and compare prefix stores, known bytes and provenance for the seven saved frame cells across all 30 journals. |
| NC-A4. Allocation returns are nonnull and the active allocations and scratch regions are valid and disjoint. | NC1–NC5. Admit each bounded case, check owned extents and classify every selected access. The original allocation-null arms require their own cleanup join. |
| NC-A5. The retirement calls return ordinarily and preserve callee-saved registers, SP and surviving storage. | NC5. Replace volatile state at each return, then verify the reloads, cursor, status and clears. Native callee effects and object lifetime outside the model remain unknown. |

## Bounded continuation

| Impact | Open evidence |
| --- | --- |
| High | Follow the command lookup on the populated container and verify the caller's result handling. |
| High | Match a pinned daemon request to the actual IOKit copy-in, selector, client-state epoch and reply. |
| Medium | Join both allocation-null branches to their cleanup and carry the short-suffix caller failure through the external return boundary. |

## Quality gates

- **QG1** passed. The report states source behavior and ABI observations.
- **QG2** passed. NC-A1–NC-A5 state the premises, dependencies and falsification probes.
- **QG3** passed for both cursor outcomes after first-record publication.
- **QG4** passed. Field widths, byte extents, arithmetic and complexity are explicit.
- **QG5** passed. Parser output, raw status, allocator request arguments and modeled lifetimes have separate checks.
- **QG6** passed. Source bytes, pointer records, journals and solver receipts support the scoped claims.
- **QG7** passed. The remaining caller, allocator and native cross-layer joins are ranked by impact.
