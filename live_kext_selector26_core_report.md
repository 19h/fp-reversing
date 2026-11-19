# Current selector 26 core correspondence

The current provider calls `_PRnut72j9` at `0xfffffe000a676398`. The pinned routine begins at `0xfffffe000a635208`. Across the 202,536 B extent established for the pinned routine, 50,542 of 50,634 words match at the same offsets and all 50,634 decode to the same instruction mnemonic. The 92 changed words consist of 45 ADRP, 41 ADD and six LDR instructions. This positional comparison locates candidate counterparts for the prior proofs. Data targets, indirect dispatch, reached paths and native buffer contents require their own evidence. [Provider transfer](live_kext_selector26_transfer_report.md) [Pinned parser](userclient_early_header_report.md)

The provider supplies the staging pointer in X0, nested extent in X1 and provider context in X2. The current callee saves them to SP+0x8f8, SP+0x878 and SP+0x738. The staging pointer refers to storage owned by the kernel buffer descriptor. Its contents depend on the preceding task-descriptor copy-in. [Provider transfer](live_kext_selector26_transfer_report.md)

## Compiler bounds and parser branches

| Collection | Compiler start | Next compiler start | Core SHA-256 |
| --- | --- | --- | --- |
| Pinned | `0xfffffe000a635208` | `0xfffffe000a666930` | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Current | `0xfffffe000a676398` | `0xfffffe000a6a7ac0` | `f6e14d3993bdc8ff46e4dfe9ac6b00f71d04ca2a8902d40d6ca06e23a1fd9220` |

Both entries occupy index 421 of the 450-entry kext `LC_FUNCTION_STARTS` sequence. The instruction delta is `0x41190` B. On every changed word, the bitwise XOR falls entirely within the immediate field. Operand registers and all words in the selected parser ranges match.

The early path reads the four big-endian length bytes at current PCs `0xfffffe000a6a1f5c`, `0xfffffe000a6a1f68`, `0xfffffe000a6a1f70` and `0xfffffe000a6a1f80`. These loads read offsets +6 through +9 relative to the current record cursor, under the earlier header-path premises. The same unsigned gate at `0xfffffe000a6a1fc4` through `0xfffffe000a6a2020` compares cursor + 10 B + decoded length against the retained extent before reading the tag and type. The seven selected table slots in each collection have identical format-8 authentication metadata and each current target is exactly `0x41190` B above its pinned target. The table addresses are `0xfffffe0008472f20` and `0xfffffe00084899c0`. [Pinned predicates and fixture premises](userclient_early_header_report.md)

| Index | Current destination | Selection documented in the pinned proof |
| --- | --- | --- |
| `0x7c6` | `0xfffffe000a6a2024` | Body fits, continue to tag and type |
| `0x82d` | `0xfffffe000a6a2d8c` | Body exceeds declared extent |
| `0x386` | `0xfffffe000a6a2d00` | Retained span with nonzero tag |
| `0x5a1` | `0xfffffe000a6a2ad8` | Retained span with zero tag |

These are local conditional branch correspondences. The availability and provenance of the current runtime input are unknown. The outer 16 B result belongs to the separate handler and Mach-reply path. Its final four bytes still require a reply-backing initialization trace. [Transfer and reply geometry](live_kext_selector26_transfer_report.md)

## Assumption register

| Premise | Dependent result | Falsification probe |
| --- | --- | --- |
| Both inputs are the identified original collections | Compiler and word comparisons | Recompute whole-image hashes and embedded UUIDs |
| The selected parser path receives the same frame roles and table base as the pinned proof | Extent and dispatch interpretation | Check buffer and cursor provenance at the load and X7 at the authenticated branch |
| The bytes stay readable and stable across the selected loads | Decoded values from one logical record | Compare the retained window with the loads from a correlated transaction |

Current reachability and record contents have high impact on daemon/kext attribution. The inline reply backing has medium impact on interpretation of the returned outer structure. The static audit performs one linear word comparison and seven fixed slot checks after loading the collections. [Audit](triage_evidence/audit_live_kext_selector26_core.py) [Compressed evidence](triage_evidence/live_kext_selector26_core_audit.json.zst)
