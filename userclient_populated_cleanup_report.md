# Populated singleton cleanup and selector 26 return

The exhausted 14 B singleton has two source-proven results at the nominal selector 26 handler. A command-tag miss returns `0xffff5bbc`. A match whose transformed type fails the scalar-type gate returns `0xffff5a87`. Both results require the normal allocator returns, nominal pointer guards and equal stack canaries described below. The result in the native IOKit Mach reply remains unknown. [Preceding command lookup](userclient_populated_command_lookup_report.md)

## Status and control flow

PCs omit the common `0xfffffe0000000000` prefix. C is the private context, S the workspace, F the core frame, I the original input address, B its protected copy, T the returned container, J its only node, and Z the node's record buffer. I is the provider staging address when the core runs through this provider.

| Command outcome | Raw u32 at S+0xde4 | X0 at core RETAB, provider return and nominal handler return |
| --- | --- | --- |
| PC1. Tag miss | `0xce515bda` | `0x00000000ffff5bbc` |
| PC2. Tag match followed by type rejection | `0xce515ae1` | `0x00000000ffff5a87` |

After the common entry at `a656f4c`, the destructor follows the published T to J and requests retirement of the same Z, J and T. It retains the null successor and clears C+0x600 at `a6605e0` before branching to the original callback `a665e90`. The u32 in S+0xde4 survives. With C+0x3c0 null, the callback selects the primary-buffer path. It reads B and writes I one byte at a time, from offset 13 B through offset 0 B. The byte read at `a6660d4` consumes the protected value from the preceding writer and the store at `a6660f4` restores that byte's original value.

## Retirement calls

| Order | Object and extent | Call PC | Original target | Arguments X0, X1 | Nominal link |
| --- | --- | --- | --- | --- | --- |
| 1 | Z, 14 B | `a6607e8` | `c4ba84c` | Z, 14 | `a6607ec` |
| 2 | J, 32 B | `a660708` | `c4ba368` | descriptor `847be20`, J | `a66070c` |
| 3 | T, 16 B | `a6605c4` | `c4ba368` | descriptor `847bde0`, T | `a6605c8` |
| 4 | B, 14 B | `a666188` | `c4ba84c` | B, 14 | `a66618c` |
| 5 | C, 4096 B | `a666260` | `c4ba368` | descriptor `847ba60`, C | `a666264` |
| 6 | S, 16 384 B | `a6662b0` | `c4b9a24` | S, 16 384 | `a6662b4` |

Calls 1 through 3 precede the destructor callback and calls 4 through 6 follow copy-back. The callback reads the saved status before retiring S and carries it in W26 at the S release. Equal canaries select `X0 = zero_extend_64(W26 XOR 0x31ae0066)` and RETAB at `a6662f8`, with the saved SP, X19–X29, D8–D11 low 64 bits and signed link restored. Unequal canaries instead select `a66692c`, which calls veneer `a69f294` and requests the original `___stack_chk_fail` target `c629694`. The native allocator effects, PAC outcomes and failure callee behavior remain unknown. [Original frame and canary analysis](userclient_zero_tag_return_report.md)

## Selector 26 forwarding

| Boundary | Location | Observed in the source model |
| --- | --- | --- |
| Handler to provider | `a50408c` | Nominal target `a505198`. The handler zero-extends the packet's u32 extent. |
| Provider to core | `a5052fc` | Direct target `a635208`, nominal link `a505300`. X0 is staging, X1 is 14 B and X2 is forwarded state. |
| Copy requests | `a5052ec`, `a505344` | Copy-in and copy-out each use the task descriptor, offset 0 B, the same staging address and extent 14 B. Both statuses permit the copy-out request and the buffer and task completion/release requests. |
| Handler result | `a5040a4` | Issues the logging call with the nonzero status in its stack argument area. Preserves that status in X0 and skips the descriptor stores at `a5040b0` and `a5040b8` for both separate and aliased input/output storage. |

The provider and handler checks use the two proved core statuses as return values of opaque calls. The retained caller ABI binds the nominal call sites and frames. The audited 14 B is the extent forwarded from the packet's inner field at offset 8 B. The legacy selector-26 admission checks the outer input and output structures at 16 B each. Native copy counts and bytes, the public error domain, Mach reply serialization and fairplayd transaction identity remain unknown. [Provider call and frame mapping](userclient_zero_tag_provider_report.md) · [Legacy structure arguments](iokit_structure_arguments_report.md)

For an admitted singleton, the destructor performs one node iteration. For input extent n, copy-back takes O(n) time and O(1) auxiliary space. The audited n is 14 B. The audit compares preceding store intervals with the fixed set of live roots. For W stores and R root intervals, that step costs O(W × R) time and O(W + R) space, apart from the separately bounded solver queries.

## Evidence and verification

| Artifact | Decoded SHA-256 |
| --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| [Source and solver receipts](triage_evidence/userclient_populated_cleanup_audit.json.zst) | `ac81a9529f2bffbb6a4dd7a521307d897c1c7c4056bdbbc00cdfa970e0bb5d63` |

The [auditor](triage_evidence/audit_userclient_populated_cleanup.py) recaptures 239 words in the destructor request and caller continuation, checks 11 branch-slot observations and exhausts all 256 byte values in each of four pointer banks. It rereads the retained frame-return and provider words and verifies the associated original pointers. Twelve satisfiable premise checks and twelve unsatisfiable violation queries cover the retained entry modes, both lookup results, both canary outcomes and caller forwarding. Omitting the C+0x600 clear at `a6605e0` yields a satisfiable violation. The protected-byte equations are verified against 14 original write events in each retained predecessor mode.

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| PC-A1. The kext, kernel collection and chained pointer representation are the pinned images. | PC1–PC2 and the call tables. Compare the captured words and original pointer records with both images and exhaust the four banks. |
| PC-A2. The selected fallback is the exhausted, nonzero-tag 14 B singleton with transformed type `0x6685`. Its frame and allocation spans are valid and disjoint. | PC1–PC2 and six retirements. Replay the predecessor and lookup obligations. Check the eight additional root cells against both predecessor modes and verify that no intervening store changes them or B before copy-back. |
| PC-A3. The nominal pointer guards hold and each selected callee returns normally while preserving callee-saved registers and surviving storage. | PC1–PC2 and post-call effects. Check the nominal target, modifier and available argument/return pairs. The clear-store omission tests the storage postcondition. Native confirmation requires matching the call and resume addresses and observing surviving objects across the release calls. |
| PC-A4. The core's original saved frame is intact, the guard global is separate and its comparison selects the specified arm. | PC1–PC2 on equal guards and the failure request on unequal guards. Test both relations separately, check continued store bounds and use original saved-frame provenance. |
| PC-A5. The handler takes the nominal provider slot and preparation succeeds on the 14 B route. | Provider and handler forwarding. Check both input/output arrangements and the call ABI. Native confirmation requires a paired provider invocation, descriptor transfer and handler return. |

## Bounded continuation

| Impact | Open evidence |
| --- | --- |
| High | Follow both handler results through the synchronous IOKit method implementation and the MIG 2865 stub at `be386b4`. Establish how it constructs reply 2965 and correlate one request and reply to fairplayd. [Connection lifecycle and MIG entries](iokit_connection_lifecycle_report.md) |
| Medium | Follow the allocation-failure and short-suffix routes through the shared caller and compare their observed status translations. |

## Quality gates

- **QG1** passed. Claims concern image evidence and ABI behavior.
- **QG2** passed. PC-A1–PC-A5 state dependencies and falsification probes.
- **QG3** passed for both populated lookup outcomes through the conditional selector 26 handler, with the external join marked open.
- **QG4** passed. Widths, byte extents, offsets, status arithmetic and complexity are explicit.
- **QG5** passed. The two lookup outcomes, two guard arms and distinct transfer effects are accounted for.
- **QG6** passed. Captured instructions, original pointers, source stores and solver results support the scoped claims.
- **QG7** passed. The remaining transport and alternate-path work is ranked by impact.
