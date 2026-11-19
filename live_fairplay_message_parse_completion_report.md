# Installed FairPlayIOKit second FPMessage parse completion

The installed FairPlayIOKit parser completes the second parse for the two retained 14 B scalar fixtures in both attribute modes. It rereads the original input, builds a new node and record buffer under the second container, and publishes that container at `FPMessage+0x00`. It reaches the mode branch using registers produced by the parser itself. The existing independent completion cut yields the same instruction sequence, publication stores, and transfers in these runs. [Previous parser audit](live_fairplay_message_parser_report.md) [Continuous replay auditor](triage_evidence/audit_live_fairplay_message_parse_completion.py) [Replay receipt](triage_evidence/live_fairplay_message_parse_completion_audit.json.zst)

```text
retained 14 B input
  |
  v
decode length, tag/type, scalar -> allocate node and record buffer
  -> write address-masked record -> append node to new container
  -> cursor equals extent -> publish container at FPMessage+0x00
  -> read FPMessage+0x60 -> mode-specific continuation
```

## Data and control interfaces

The addresses below are unslid VAs for build `26C5035r`. I denotes the retained input, N the u32 extent, M the 128 B message, H2 the second 16 B container, J2 its 32 B node and Z2 its 14 B record buffer. C and S retain caller storage and workspace. The model assigns H2, J2 and Z2 disjoint writable regions. The first pass's container, node reference and serialized bytes are preserved.

| Contract | Installed site | Result |
| --- | --- | --- |
| C1 | `0xfffffe000a6a1f5c` onward | Read I+6 through I+9 for the 4 B big-endian length, then I+0 through I+5 for the tag and type, then I+10 through I+13 for the u32 scalar. Both passes read the same unchanged fixture bytes in this order. |
| C2 | `0xfffffe000a6a27f4` | BLRAA to `_IOMallocTypeImpl` at `0xfffffe000c509774` with modifier `0xd0c8`. X0 carries the 32 B `site.FPTTLVNode` descriptor at `0xfffffe0008491f40`. The parser has already advanced the cursor to 14 and stored H2 at C+0x20. |
| C3 | `0xfffffe000a6a29d8` | BLRAA to `_IOMallocData` at `0xfffffe000c509c2c` with modifier `0xca0c` and X0=14 B. C+0x58 already holds J2. J2+0x00 and J2+0x08 are zero, and J2+0x10 holds the u32 extent 14. The returned Z2 is stored at J2+0x18. |
| C4 | `0xfffffe000a6a2a78` through `0xfffffe000a696e44` | The writer follows J2+0x18 and writes every byte of Z2 once. Separate byte arithmetic confirms that removing the mask for Z2's address yields exactly the original fixture. |
| C5 | `0xfffffe000a6a3ddc`, `0xfffffe000a6a3d58` | The lookup returns an empty result at C+0x50. The append stores J2 in both u64 links of H2. J2's own links remain zero. |
| C6 | `0xfffffe000a6a53bc`, `0xfffffe000a6a1cb8` | The saved callback at `0xfffffe000a6a2d30` receives `0x31ae0066`. Cursor 14 equals N. The parser selects the exhausted-input entry `0xfffffe000a6a1cbc` via modifier `0x2f10`. |
| C7 | `0xfffffe000a6a1cdc`, `0xfffffe000a6a1d00` | Write raw status `0x31ae0066` at S+0xc94 and H2 at M+0x00 through the retained output address C+0x170. All message positions from M+0x08 onwards retain their pre-parse values or unwritten state. |
| C8 | `0xfffffe000a6a2330`, `0xfffffe000a6a2370` | Read M+0x60 and transfer with modifier `0xeeda`. The zero byte selects `0xfffffe000a6a2374`. Byte value 1 selects `0xfffffe000a6a4e2c`. |

Both writer destinations hold a 4 B tag, 2 B type, 4 B length and 4 B scalar, with the established address mask applied to each byte. The stored images differ because their destinations differ. The audit independently applies the archived mask formula at each address, then compares all 14 bytes with the first pass's retained image and the second pass's actual writes. The record type is `0x9777` in both fixtures. This establishes the relationship between the two internal encodings. Native input custody and matched daemon transport remain unknown. [Writer header proof](userclient_early_writer_report.md) [Writer payload proof and mask](userclient_early_payload_report.md)

At the exhausted-input entry the actual X22 carries node descriptor `0xfffffe0008492780`. The earlier cut seeded W22 with `0x7795e3ce`. The publication block assigns W22 that value before the status gate consumes it. The other nine register premises match the continuous run at entry. Both versions produce the same completion instructions, stores, transfer targets and modifiers. [Independent completion premises](live_fairplay_message_parser_report.md)

## Verification and assumptions

The audit pins the collection SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`, and kext UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. It compares the four successful predecessor prefixes to decoded SHA-256 `58499ee3d551c128a09b05c252f24855b1c90b119f950cdd84c8d0def3c320ce`. It checks original instruction envelopes, installed branch and descriptor fixups, and the selected byte banks. The archived writer's 14 header and 15 payload proof partitions reproduce UNSAT. [Installed writer](live_fairplay_early_writer_report.md) [Installed append and callback](live_fairplay_early_publication_report.md)

The eight second-pass suffixes cover 989 distinct installed words over 9,352 visits, with 1,040 loads, 352 stores and 288 nominal transfers. They account for 112 original-input byte loads and 112 serialized output bytes. The decoded receipt SHA-256 is `5d0c609727072fe5fe69ba6857068b9aa6e49de2d8b44762bc8f4c142d058643`. [Verified replay receipt](triage_evidence/live_fairplay_message_parse_completion_audit.json.zst)

The two fixtures and two modes each run twice, with zero bytes or an address-derived pattern supplied only when the shared writer reads its eight undefined scratch cells. These cells total 46 B. The patterns change some scratch values. The recorded sites, load and store addresses, transfer targets, and serialized result agree for each pair. The earlier source proof establishes arbitrary-value independence for the corresponding header projection. Modeled allocation returns provide addresses and replace volatile register state at the call boundaries. The replay carries the local PC, frame and state continuously from re-entry to the mode target. Native allocation effects, authentication, ownership and matching Mach emission remain unknown. [Scratch-cell proof scope](userclient_early_writer_report.md) [Mach ports and emitters](mach_ports_report.md)

The checked path parses one fixed-width scalar record and appends to an empty container. Its local work and additional scratch space are O(1) in the constrained input domain, excluding modeled allocation and proof verification. Reproduce the receipt with `python3 triage_evidence/audit_live_fairplay_message_parse_completion.py COLLECTION` using the pinned decompressed Mach-O.

| Assumption | Dependent contracts and falsification probe |
| --- | --- |
| A1. Pinned installed image and continued predecessor state | C1–C8. Rehash the collection and match the entry replay with the prior receipt. Check branch-slot translation and descriptor content. |
| A2. The fixture remains readable at I with extent N=14 across both parses | C1, C4, C6. Compare every actual read address and value across both epochs. Native custody requires matching the actual user-client staging range to the original request. |
| A3. H2, J2 and Z2 are distinct nonnull modeled returns and retain their declared extents | C2–C8. Verify call arguments, modifiers, fresh addresses, per-object writes and preserved first-pass references. Native ownership requires observing corresponding allocation and retirement in the same transaction. |
| A4. Eight scratch reads receive the declared values | C4–C8. Compare both patterns, check all 14 serialized bytes independently, and re-solve the archived arbitrary-value header and payload queries within their scope. |
| A5. Modeled branch authentication and success status | C5–C8. Check chained fixups and compare the complete last-transfer sequence with the prior completion cut. A native trace must establish matching status, relative targets and pointer validity. |

| Impact | Open interface |
| --- | --- |
| High | Follow both mode continuations to establish the published container's next consumer, retirement, and any caller-facing output. |
| High | Join the two reads of I to a single daemon request and verify input lifetime across the intervening helper and allocator calls. |
| Medium | Trace null node and record-buffer returns on the second invocation and track their callback status and cleanup. |

QG1 factual scope, QG2 assumptions and probes, QG3 both fixture modes from input load to completion, QG4 byte widths and exact counts, QG5 continuity and native evidence boundaries, QG6 pinned provenance, and QG7 impact-ranked open interfaces pass for this increment.
