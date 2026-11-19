# Installed FPMessage parser re-entry and completion interface

The second FairPlayIOKit parser invocation changes its output destination to the first word of the newly initialized `FPMessage`. It reuses the original input pointer and encoded extent. A modeled nonnull `site.FPTTLV` return reaches the pending byte load at input plus 6 B. A modeled null return reaches the message caller's failure continuation with raw status `0xce515bb2`. A separate completion cut writes the parser container into the message and takes one of two continuations based on the byte at message offset `0x60`. [Initialization handoff](live_fairplay_message_initialization_report.md) [Installed auditor](triage_evidence/audit_live_fairplay_message_parser.py) [Replay receipt](triage_evidence/live_fairplay_message_parser_audit.json.zst)

```text
new FPMessage + retained input
  |
  v
alias first message word as parser output -> request typed 16 B container
  |-- nonnull -> zero 16 B -> pending byte load at input + 6
  `-- null -> caller tag gate -> raw status gate -> failure continuation

independent completion entry -> publish container pointer at message + 0
  -> caller tag gate -> raw status gate -> read message + 0x60
                                          |-- 0 -> mode-zero continuation
                                          `-- 1 -> mode-nonzero continuation
```

## Installed transfers and data flow

Addresses are unslid VAs for build `26C5035r`. M is the new 128 B message, H2 is the second parser's 16 B container, I is the original input pointer, N is the u32 extent in bytes, C is caller storage, and S is the workspace. The constructor carries the same I and N into both attribute modes within each fixture. The parser sees N=14 in the four predecessor states. The earlier parser set its output pointer to C+0x418. At re-entry, the caller discriminator `0xfbb3f478` and the restored message establish a distinct invocation of the same parser. [Earlier parser](live_fairplay_early_header_report.md) [Historical parser contracts](userclient_message_parser_report.md)

| Contract | Installed site | Recovered effect |
| --- | --- | --- |
| P1 | `0xfffffe000a6774c8` | Common entry reads M from C+0x718 and stores it at C+0x170 at `0xfffffe000a6774d8`. C+0x170 now contains the address of the message's first word. |
| P2 | `0xfffffe000a6774e4`, `0xfffffe000a6774e8` | Copy encoded N from S+0xc8 to S+0xb5c and I from C+0x18 to C+0x98. The extent encoding is u32 N XOR `0x31ae0066`. |
| P3 | `0xfffffe000a6774ec`, `0xfffffe000a6774f0`, `0xfffffe000a677504`, `0xfffffe000a677508` | Reset cursor S+0xa10 and C+0x690 to zero, set raw phase S+4 to `0x31ae0066` and S+0xc60 to `0x8f98c6acce5848ca`. |
| P4 | `0xfffffe000a677594` | BLRAA to `_IOMallocTypeImpl` at `0xfffffe000c509774`, modifier `0xd0c8`, nominal return `0xfffffe000a677598`. X0 is descriptor `0xfffffe0008492600`, named `site.FPTTLV`, signature `11`, flags32 `0xe4`, extent 16 B. |
| P5 | `0xfffffe000a6775b8`, `0xfffffe000a677838` | Store X0 at C+0xb0. BRAA with modifier `0x1fcb` selects `0xfffffe000a67783c` for H2 nonnull or `0xfffffe000a6a1d18` for null. |
| P6 | `0xfffffe000a677858`, `0xfffffe000a6a1f5c` | The nonnull path clears both u64 words of H2. It carries I through C+0x670 and reaches pending `LDRB W11, [X10, X9]` with X10=I, X9=6, cursor zero and W23=`0xce515bb8`. The replay stops before the load. |
| P7 | `0xfffffe000a6a1d44`, `0xfffffe000a6a1d54`, `0xfffffe000a6a1d64` | Ordered tag tests recognize `0x89f25623`, `0xfbb3f478` and `0x1830b7ce`, respectively. The second test transfers this caller to `0xfffffe000a6a22d4`. |
| P8 | `0xfffffe000a6a230c` | Raw status `0x31ae0066` selects `0xfffffe000a6a2310`. The re-entered null allocation instead carries `0xce515bb2` and selects `0xfffffe000a6a6234` with modifier `0xcb79`. |
| P9 | `0xfffffe000a6a1cbc` through `0xfffffe000a6a1d00` | In the independent completion replay, the code writes `0x31ae0066` to S+0xc94 and stores H2 through C+0x170 to M+0x00. The rest of M, including M+0x08 and the five unwritten byte positions, retains its constructor state. |
| P10 | `0xfffffe000a6a2330`, `0xfffffe000a6a2370` | The success continuation reads M+0x60 via the earlier message slot C+0x788. BRAA with modifier `0xeeda` targets `0xfffffe000a6a2374` for the composed zero byte and `0xfffffe000a6a4e2c` for the composed byte value 1. |

The two allocation outcomes preserve all 128 positions of M through their endpoints. The same allocation call site and descriptor served the first parser invocation. In the model, H2 occupies a fresh 16 B region distinct from the earlier parser objects and M. The branch discriminator is internal to the parser caller. The recorded scope establishes the deeper typed-allocation interface and private control transfers. The Mach endpoint, right and emitter inventory is covered separately. [Mach ports](mach_ports_report.md)

## Evidence and verification

| Evidence | Identity or coverage |
| --- | --- |
| Installed decompressed collection SHA-256 | `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126` |
| Installed kernel and kext UUIDs | `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc` |
| Historical parser checks and audit, decoded SHA-256 | `565b2803433729d335ac4535e01be67c5e340e9dd889c3884ce12dc9aee3b6af` and `fbec01eac93c22b1ef2c6ca299ea7a5544e05ff75d0627e6179e16eb920b1ffb` |
| Installed predecessor receipt, decoded SHA-256 | `ae5aab202fce8e6b237025505854703f6ce71c25a18b73cc5fffd730288560d6` |
| New replay receipt, decoded SHA-256 | `58499ee3d551c128a09b05c252f24855b1c90b119f950cdd84c8d0def3c320ce` |
| Selected code and data | 14 spans, 436 words, 2 pool-address relocation words, 13 authenticated branch slots, 19 literal loads, 8 byte banks |
| Byte-bank verification | Equal bank bytes across images and 11 source relations exhaustively checked on 256 inputs each, for 2,816 relation cases |
| Installed replay | 4 reproduced predecessor states, 8 allocation prefixes, 4 independent completion cuts, 2,736 instruction visits covering 432 installed words, 532 loads, 228 stores and 52 logical transfers |
| Archived symbolic checks | 209 UNSAT partitions across 17 historical semantic contracts, including all u32 status and caller-tag values and the conditional null-I path |

The completion cut starts at `0xfffffe000a6a1cbc` with X2=C, X4=S, X7=`0xfffffe00084899c0`, X28=`0xfffffe0007954090`, W1=`0x7795e642`, W3=`0x886a1ca3`, W12=`0x69c`, W22=`0x7795e3ce`, and W23=W30=`0x31ae0066`. It retains memory and SP from the nonnull prefix and initializes only the stated general-purpose registers. The receipt records the discontinuity at the pending load. No original input byte is read in either added replay. Input lifetime, completion of the second parse, native allocation and PAC acceptance, and a paired daemon-to-kext transaction remain unknown. The original input fixture was read in the preceding invocation. [Historical completion premises](userclient_message_parser_report.md) [Predecessor receipt](triage_evidence/live_fairplay_message_initialization_audit.json.zst)

The four unvisited words implement the third caller-tag test. Those words match the archived image and the ordered-dispatch proof covers their condition for all u32 tag values. The existing references supply the needed instruction and fixup evidence. [Archived parser proofs](triage_evidence/userclient_message_parser_audit.json.zst)

The selected installed prefix and the fixed completion cut have O(1) runtime and memory use with respect to N. Checking the selected code and bank relations takes O(W+256R) time for W selected words and R relations, excluding collection verification, retained predecessor construction and SMT query solving. Reproduce the audit with `python3 triage_evidence/audit_live_fairplay_message_parser.py COLLECTION`, where COLLECTION is the pinned decompressed Mach-O. Compare its JSON output with the decoded receipt. [Historical checks](triage_evidence/userclient_message_parser_checks.json.zst) [Archived proof queries](triage_evidence/userclient_message_parser_audit.json.zst)

| Assumption | Dependent contracts and falsification probe |
| --- | --- |
| A1. Image custody and relocation | P1–P10. Rehash the collection, compare instruction bytes except the two pinned relocation words and resolve each selected bank, literal, dispatch slot and descriptor in the installed collection. |
| A2. Distinct parser invocation with retained constructor state | P1–P10. Rebuild each constructor state and compare the full case record to the installed predecessor receipt. Check the aliases, extent encoding and caller discriminator at the new entry. |
| A3. Ordinary allocator return and separate modeled storage | P5–P10. Check the original target, modifier and nominal link, vary the modeled return across both outcomes, require a fresh H2 region, and verify the two zero stores and message preservation. For native ownership, establish allocation and retirement of the corresponding pointers in the same transaction. |
| A4. Independent completion registers and caller storage | P9–P10. Record the exact premises and verify the two stores and message flag load. Compare the premises and output pointer with an independently observed parser completion before composing an end-to-end claim. |
| A5. Input, timing and transport scope | P2, P6, P9–P10. Reject any added replay load overlapping the 14 B retained extent, preserve the unknown mapping and lifetime, and require matching native transaction evidence for daemon custody. |

| Impact | Open interface |
| --- | --- |
| High | Establish the retained input's custody at the pending byte load and follow a complete second parse to the publication path. |
| High | Follow the installed null exit through message and attribute teardown, original-container retirement and status propagation. |
| Medium | Trace the first consumers of the message's published pointer and mode-selected continuations. |
| Medium | Identify where a corresponding daemon transaction acquires and releases the matching kernel-visible byte range. |

QG1 factual scope, QG2 assumptions and falsification probes, QG3 both allocation outcomes and independent completion, QG4 widths and reproducibility, QG5 evidence boundaries, QG6 pinned provenance, and QG7 impact-ranked open interfaces pass for this increment.
