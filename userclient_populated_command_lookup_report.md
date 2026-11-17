# Command lookup after singleton parser completion

In the pinned FairPlayIOKit image, the exhausted 14 B fallback record can satisfy the caller's command-tag lookup. A match returns the node that the parser appended. The caller then rejects the node's transformed type `0x6685` at the final scalar-type gate and enters cleanup without reading the scalar. A miss follows the node's null successor and enters cleanup without reopening the header.

This increment starts at the [exhausted parser handoff](userclient_nonzero_tag_completion_report.md) and follows the actual singleton through the [command dispatcher](userclient_command_dispatch_report.md). All transfers here are within the kernel image. The native external-method return, Mach reply and originating daemon transaction remain unknown.

The next report follows both saved statuses through the destructor, copy-back and conditional selector 26 handler return. [Populated cleanup and selector 26 return](userclient_populated_cleanup_report.md)

## Lookup and caller contracts

C is the private context, F the frame, S the workspace, T the returned list, J its only node and Z the node's record buffer. PCs omit the common `0xfffffe0000000000` prefix. The initial search reads the four protected tag bytes at Z+0 through Z+3. The branch at `a63d67c` distinguishes equality from inequality with the requested encoded tag.

| Case | Search outcome | Caller continuation | Cleanup status |
| --- | --- | --- | --- |
| CL1. Tag misses | The branch selects `a63d680`; the next iteration reads J's null successor. At `a662c4c` the search writes zero to C+0x1f8. It returns W23 = `0xce515bda` at the callback `a656cfc`. | The status gate goes directly to `a656f00`. Record reads in this case are offsets 0–3 B. | `0xce515bda` |
| CL2. Tag matches | The branch selects `a662c44`. At `a662c4c` the search writes J to C+0x1f8. It returns W23 = `0x31ae0066` at the same callback. | At `a656d5c` and `a656d60`, the caller rereads Z at J+0x18 and the u32 extent at J+0x10. It retains Z in C+0x770 and reads the 10 B header. The extent is 14 B and the decoded body length is 4 B. | `0xce515ae1` |
| CL3. Common handoff | In both cases C+0x600 still contains T at `a656f00`. | At `a656f24` cleanup saves W23 to S+0xde4, then branches to `a656f4c` with W24 = `0x1a`. | Same raw W23 as on entry |

For CL2, the header and body bounds admit the candidate cursor, 10 B + 4 B = 14 B. The branch at `a637524` leaves the `0xa129` scalar path. The `0x6685` comparison at `a63a61c` joins the final type test at `a63acf4`. That test commits 14 B to F+0xa78 and reaches cleanup at `a656f00`. Record reads in CL2 are offsets 0–3 B for the search and offsets 0–9 B for the caller. The scalar cell S+0xcf0 retains its initial encoded-zero value. A status can describe a private phase or transfer. Its translation to a native external-method result remains unknown.

The general search takes O(n) time for n visited nodes and O(1) auxiliary space. This increment visits one nonempty node on either outcome. The post-lookup caller work has O(1) time and auxiliary space through the reported endpoint.

## Evidence and verification

| Artifact | Decoded SHA-256 |
| --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| [Byte, table, access and solver receipts](triage_evidence/userclient_populated_command_lookup_audit.json.zst) | `bca21d34085796e87b0a8bf154b4ff17894e22b4acbe25fa627fd72af815f28b` |

The [auditor](triage_evidence/audit_userclient_populated_command_lookup.py) checks 544 instruction words in 24 spans against the original and normalized images. It verifies 35 branch-slot observations and all 256 byte inputs of the callback bank. The saved F+0x8e8 pointer originates at `a635c68` and is corroborated by 30 entry journals. The byte decoder reads the actual byte versions produced by the earlier writer at Z. Two satisfiable premise checks and two unsatisfiable violation queries verify the match and miss. Omitting the result store in the in-memory model produces a satisfiable contract violation. The access receipts contain 40 entries for the miss and 80 for the match, including pointer-table and bank reads.

## Assumption register

| Assumption | Dependent results and falsification probe |
| --- | --- |
| CL-A1. The images and pointer-table epoch are pinned. | CL1–CL3. Re-read captured words and chained pointer slots in both representations and exhaust the callback bank's 256 possible byte values. |
| CL-A2. The predecessor is the exhausted, nonzero-tag, 14 B singleton with transformed type `0x6685` and valid, disjoint storage. | CL1–CL3. Compose the parser and predecessor checks with each lookup case. Verify J's null successor, 14 B extent and the decoder's access offsets in the composed state. |
| CL-A3. The nominal pointer guards and recovered entry-frame roots apply. | CL1–CL3. Verify the original store of the caller's saved buffer-cell address across the entry journals. Check computed branch targets and modifiers under the nominal guards. Native pointer authentication remains unknown. |

## Bounded continuation

| Impact | Open evidence |
| --- | --- |
| High | Follow both raw statuses through the caller-specific destructor continuation and external-method status translation. |
| High | Correlate a daemon request with the IOKit connection, copied input and reply in one trace. |
| Medium | Join the alternative allocation outcomes and separate them from the populated singleton path. |

## Quality gates

- **QG1** passed. Claims concern source behavior and ABI observations.
- **QG2** passed. CL-A1–CL-A3 state dependencies and probes.
- **QG3** passed for both tag outcomes of the exhausted singleton.
- **QG4** passed. Field widths, extents, offsets, cursor arithmetic and complexity are explicit.
- **QG5** passed. The lookup result, type decision and cleanup status have distinct checks.
- **QG6** passed. Original bytes, chained pointers, entry journals and queries support the scoped claims.
- **QG7** passed. The remaining ABI and native joins are ranked by impact.
