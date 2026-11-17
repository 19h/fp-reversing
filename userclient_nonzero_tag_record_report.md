# First record construction from the protected fallback input

The selected nonzero-tag path in `_PRnut72j9` carries the protected fallback input through the first record's allocation requests, serialization and publication. The original 14 B input extent bounds this record's body length to 0–4 B. After two ordinary nonnull allocation returns, the writer reproduces the first `10 + L2` observed bytes under the new buffer's address-dependent representation. The list code installs the same node as both head and tail. The cursor gate selects another iteration when a suffix remains and the input-exhausted branch when all 14 B have been consumed.

The [fallback metadata report](userclient_fallback_metadata_report.md) establishes the header and bounds at the incoming cut. This increment joins that cut to the [node constructor](userclient_record_nodes_report.md), [protected writer](userclient_record_writer_report.md) and [record publication](userclient_record_publication_report.md) on a single source-derived state. It checks both retained parent modes. Native allocator effects, authenticated execution, subsequent parser completion and daemon transaction identity remain unknown.

## Source and evidence

| Artifact | Decoded SHA-256 |
| --- | --- |
| Normalized kext image | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| [Source capture](triage_evidence/userclient_nonzero_tag_record_checks.json.zst) | `223f7d1a4c5a6e8cbcf753bc25bda6321c4c4d56b4cdcbf7cf1bf0c517996d32` |
| [Solver and access receipts](triage_evidence/userclient_nonzero_tag_record_audit.json.zst) | `dde94415f58eeed7893cae1dd19b7aa9ac0f296440cd447ba5288f2eb9c04eee` |

The [extractor](triage_evidence/recover_userclient_nonzero_tag_record.py) compares selected words against both pinned images and recaptures original pointer records, bank bytes and the typed node descriptor. The [auditor](triage_evidence/audit_userclient_nonzero_tag_record.py) checks the source equations and parent-state projection. The [delivery verifier](triage_evidence/verify_userclient_nonzero_tag_record_delivery.py) rebuilds the receipts and checks the publication delta. The retained files supplied the source evidence for this increment without a new IDA query.

## Allocation, serialization and publication

Let B be the 14 B protected fallback buffer, T the empty 16 B container, J the new 32 B node and Z its new record buffer. F, C and S retain their frame, private context and workspace roles from the parent report. L2 is the header's BE32 body length, separate from the earlier record length L=4. Addresses in the table omit the common `0xfffffe0000000000` prefix.

| Result | Source effect |
| --- | --- |
| NZ1 | The kind gate at `a642450` selects `a642454` for nonzero decoded tag D and transformed type 0x6685. The latter corresponds to wire type 0x50db. The previous header phase has committed `F+0xa80 = 10 + L2` and the body view starts at B+10. |
| NZ2 | `a6425cc` requests `_IOMallocTypeImpl` at `c4ba154`, with descriptor `847c020`, modifier 0xd0c8 and nominal return `a6425d0`. The descriptor contains name `site.FPTTLVNode`, signature `1121`, flags 0x64 and size 32 B. |
| NZ3 | For nonnull J, the initializer zeros both 8 B links and sets the u32 extent at J+0x10 to `10 + L2`. `a6427c0` requests `_IOMallocData` at `c4ba60c` with that u64 extent, modifier 0xca0c and nominal return `a6427c4`. It stores the returned pointer at J+0x18. |
| NZ4 | A null node or null buffer result selects `a6622bc` with raw W23=0xce515bb2. The saved node at F+0x50 is zero on the first arm and J on the second. The second arm has already stored zero at J+0x18. These proofs stop at the cleanup boundary. |
| NZ5 | Two word-writer visits and the type-writer visit write exactly ten header bytes to Z. For nonzero L2, source load `a655e58` and store `a655ecc` visit the remaining offsets in descending order. A zero body length bypasses body loads and stores. Every one of the `10 + L2` destination bytes comes from the corresponding retained input observation with Z's protection mask. |
| NZ6 | The post-copy request at `a655f6c` uses T, the encoded value of D, and output C+0x628. The empty head selects raw MISS 0xce515bda and leaves a zero lookup result. At `a662878`, STP installs J in both T fields. J's links remain zero and its extent and buffer pointer retain their constructor values. |
| NZ7 | The publication returns to `a642138` with the same cursor. The gate selects `a6421dc` if L2<4 and `a642180` if L2=4. The outer publication cell C+0x600 is still zero at this boundary. |

```text
protected input B (14 B)
  -> nonzero tag and bounded type-0x6685 header
     -> request J (32 B) -> request Z (10 + L2 B)
        -> serialize first record -> empty-list lookup -> publish J in T
           +-- L2 = 0..3 -> next iteration, 4 - L2 B remain
           +-- L2 = 4    -> input-exhausted branch
     null J or Z -> common cleanup entry
```

The selected requests total `42 + L2` B, or 42–46 B. This excludes the existing B and T, allocator overhead and cleanup. The writer touches every byte of Z exactly once. J+0x14 through J+0x17 receive no stores on the modeled path. The model retains the earlier input observations as symbolic values. No concrete input fixture or allocation address is required to establish the byte correspondence.

All new calls and transfers are kernel-local. This increment establishes no additional Mach port or emission site. The IOKit ingress and task/context channels retain their separate evidence. [ABI inventory](interface_abi_report.md) and [Mach port inventory](mach_ports_report.md).

## Verification

The audit checks 15 source profiles for five lengths and three allocation cases. It establishes 22 continuation and setup obligations, 148 live-state projection obligations, two parent-domain obligations and ten range obligations. It re-solves 205 earlier source and interface queries. Thirty SAT admissions cover both parent modes for every length and allocation case under the applicable storage and pointer-guard premises.

The projection joins 19 register views, 35 disjoint initial cells and all 14 protected observations to the actual parent. In all 30 prefix journals, one original store supplies each of the additional cells F+0x350, F+0x570 and F+0x60c. The audit reconstructs 90 cells totaling 600 B and checks the original producer instructions. Eight scratch channels bind to the corresponding parent values. Eleven pointer conditions follow from the earlier cut and eleven depend on the new allocation cases.

Across the 15 cases, the access inventory classifies 1,645 accesses and 90 distinct runtime cells. The single partial-width overlap is resolved using source-ordered byte versions. The selected source covers 724 of 730 captured continuation words, 282 carried words and 14 prefix words. Six alternate pointer retags remain outside the selected source routes. Three changed-source controls invalidate the type byte, body byte and tail publication claims, respectively.

For a body length L2 in the admitted range, serialization takes O(10 + L2) time and O(1) auxiliary state, excluding allocated output and allocator costs. Lookup and first-node publication take O(1) time for this empty container. Evidence extraction takes O(Bin + I + Cw + 256R) time for inspected bytes Bin, instructions I, total scanned prefix stores Cw and bank rules R. Lifting scales with instruction instances and the expression DAG. The pairwise footprint check takes O(A^2) time for A distinct cells. SMT search is separate, with limits of 60 s per new query and 120 s per retained query.

## Assumption register

| Assumption | Dependent results and falsification probe |
| --- | --- |
| NZ-A1. Pinned original and normalized images and branch-table epochs | NZ1–NZ7. Rehash images and receipts, re-read source words and original pointers, and exhaust all 768 bank-input cases. |
| NZ-A2. Selected parent state and protected bytes survive the incoming cut | NZ1–NZ7. Reconstruct the three added prefix cells, compare the complete finite live-state projection and bind each protected byte to the original parent store. |
| NZ-A3. D is nonzero, transformed type is 0x6685 and L2 is within 0–4 | NZ1–NZ7. Check the original kind gate and five BE32 length specializations. Compare the zero-tag path and alternate types using their own evidence. |
| NZ-A4. Allocation calls return ordinarily and preserve callee-saved registers, SP and surviving storage | NZ3–NZ7. Forget volatile state at each modeled return and check null and nonnull partitions. Verify native effects separately. |
| NZ-A5. Live storage is valid and disjoint, with sufficient writable extents for J and Z | NZ3–NZ7. Classify source accesses, check nonwrapping bounds and admit every finite case. Native alias exclusion and allocation placement remain unknown. |
| NZ-A6. Selected pointer guards hold and captured indirect targets retain their stated meaning | NZ1–NZ7. Check pointer load addresses, call arguments and targets, then use instruction mutations to test output sensitivity. Hardware authentication remains unknown. |
| NZ-A7. The caller has an empty stable container at this first publication | NZ6–NZ7. Check initial head and tail against the parent, follow empty-list MISS and reject a changed tail store. Populated-list workflows have separate evidence. |

## Bounded continuation

| Impact | Evidence to establish |
| --- | --- |
| High | Follow the exhausted branch through container publication, the saved command lookup and outer completion. |
| High | Follow the 1–4 B suffix through the next header gate and identify rollback and status behavior. |
| High | Correlate a pinned daemon request with the actual descriptor copy-in and client-state epoch. |
| Medium | Join both allocation-null exits to cleanup and reconcile node/buffer ownership with the existing retirement interfaces. |
| Low | Compare ordinary type variants and quantify their distinct writer and cursor requirements. |

## Quality gates

- **QG1** passed. The results concern source behavior and ABI contracts.
- **QG2** passed. NZ-A1 through NZ-A7 identify dependencies and falsification probes.
- **QG3** passed for the fixed-extent first-record scope, including both allocation gates and the cursor split.
- **QG4** passed. Widths, byte extents, arithmetic bounds and complexity are explicit.
- **QG5** passed. L and L2, the inner list update and outer publication, and the source and native boundaries are tracked separately.
- **QG6** passed. The pinned images, pointer records, prefix journals and reproduced solver obligations support the stated results.
- **QG7** passed. The continuation ranks parser completion, rollback, native transport and type coverage.

The cursor split is now composed with populated-container publication, the command lookup request and short-suffix retirement. [First-record completion](userclient_nonzero_tag_completion_report.md).
