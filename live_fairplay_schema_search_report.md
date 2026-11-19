# Installed selector 26 schema lookup and reader handoff

The installed FairPlayIOKit lookup reads four bytes from the published node's record buffer and compares the recovered tag against `0xfa834112`. The 24 retained one-node cases all miss and return `0xce515bda` to the saved schema caller. A separate synthetic replay using the archived 14 B ADID field reaches the match arm, publishes the same node, and requests a header read from the original buffer. The evidence consists of installed-code replays using archived serializer outputs. [Audit script](triage_evidence/audit_live_fairplay_schema_search.py) [Audit receipt](triage_evidence/live_fairplay_schema_search_audit.json.zst)

```text
H.head -> J -> J.buffer -> read four protected tag bytes
   |-- other tag   -> J.next = 0 -> publish zero -> saved caller with MISS
   `-- matching tag -> publish J -> expose buffer and extent
                         -> request header word at offset 0
```

## Node, tag and result

F is the frame base, C the auxiliary region, S the workspace, H the published container, J its only node, Z the node's record buffer and M its u32 extent. The preceding callback saves the encoded requested key `0xcb2d4174` at S+0, the result address C+0x710 at C+0x758, and the schema return PC at C+0xc8. [Installed exhaustion and schema request](live_fairplay_early_schema_report.md)

| Installed site | Input and result |
| --- | --- |
| `0xfffffe000a6a3da4` and `0xfffffe000a6a3da8` | Load H.head=J and retain the candidate at C+0x2b0. |
| `0xfffffe000a6a3e0c` | Load Z from J+0x18. |
| `0xfffffe000a69808c` | The bridge executes `BRAA X11,X17`. Its selected target is the word decoder at `0xfffffe000a6782c8`, with modifier `0xf930`. This terminal instruction sits immediately after the archived bridge span. |
| `0xfffffe000a6782e8`, `0xfffffe000a678320`, `0xfffffe000a678364`, `0xfffffe000a6783a4` | Read original stored bytes at Z+0, Z+1, Z+2 and Z+3. |
| `0xfffffe000a6783d4` and `0xfffffe000a67e7e0` | Produce W22=raw tag XOR `0x31ae0066` and compare it with the encoded key from S+0. |
| `0xfffffe000a67e80c` | Modifier `0xde40` selects result publication at `0xfffffe000a6a3dd4` for a match and successor preparation at `0xfffffe000a67e810` otherwise. |
| `0xfffffe000a6a3ddc` and `0xfffffe000a6a3cf0` | Store J or zero through C+0x758 into C+0x710, then use the saved callback at `0xfffffe000a6a2dc4`, modifier `0x8d28`. |

A mismatch resumes the node test with J as the link source. Its source-zero next link leads to zero in C+0x2b0 and C+0x710. W23 is `0xce515bda`. A match stores J in C+0x710 and supplies W23=`0x31ae0066` at the schema callback. The callback bank selects the same node-type descriptor as the first-publication lookup. The audit checks both arrays against the archived bytes and exhausts all 256 byte inputs. The selected search uses O(1) work and storage for this sole-node list. [Installed callback bank and descriptor](live_fairplay_early_publication_report.md) [Historical all-tag source proofs](userclient_schema_search_report.md)

## Schema callback and next header

| Condition | Installed target and modifier | Effect |
| --- | --- | --- |
| Raw success at the schema callback | `0xfffffe000a6a2e18`, `0x3751` | Dereference the published node, load Z and M, and store Z through F+0x898 into C+0x560 at `0xfffffe000a6a2e48`. |
| Raw miss at the schema callback | `0xfffffe000a6a2fd0`, `0x3751` | Select the saved caller. The branch at `0xfffffe000a6a2fdc` uses modifier `0x415f` and returns the miss status to `0xfffffe000a6778b8`. |
| Null node buffer, independent source cut | `0xfffffe000a6a2fd0`, `0xd784` | Publish zero at C+0x560 and select status `0xce515bbf`. |
| Nonnull node buffer | `0xfffffe000a6a2e7c`, `0xd784` | Encode M at S+0x260 and retain the reader cursor at F+0xbd0. |
| Header fit under the bounded-cursor premise | `0xfffffe000a6a2f30`, `0x3751` | Prepare the header-word request. The alternative uses the saved caller path with status `0xce515bb8`. |

The extent proof requires a reader cursor c with `0 <= c <= M`. It selects the header path exactly when `c+10 <= M`. For the synthetic match M=14 B and c=0. The branch at `0xfffffe000a6a2fcc` requests the bridge at `0xfffffe000a698080` with modifier `0x5e04`, X8=Z, W11=`0xe07`, and the sum X10+X1 equal to zero modulo 2^64. W9=`0x1a2` selects the next decoder return at `0xfffffe000a679ff8`. W23=`0xce515bb8` at this cut is the pending value before the header read. The caller scalar result at S+0xbc4 stays zero through the observed suffix. [Historical header-fit and callback proofs](userclient_schema_search_report.md)

## Evidence scope

The audit compares 268 captured search words and 57 inherited lookup words against build `26C5035r`. The search words match byte for byte. The inherited lookup has a relocated pool-base pair. The audit decodes the additional bridge branch from installed code, verifies 51 chained slots, and checks four normal-address branch destinations. All 22 archived proof queries reproduce within the configured 115 s limit per query.

The 24 retained fixtures reproduce the installed schema prelude. The synthetic fixture changes the raw input to the archived ADID field in the same 14 B u32 placement and replays that prelude again. Each suffix uses the prior source-derived serialized buffer at its archived Z address. There are 5,756 instruction visits, 300 logical transfers, and exactly four record-byte loads per suffix. The observed search writes preserve the container links, node extent, Z and all bytes in its record. Writer execution between the original prefix and publication remains conditional. [Archived serialized fields and synthetic receipt](triage_evidence/userclient_schema_search_audit.json.zst) [ADID byte provenance](adid_avp_packet_report.md)

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| S1 | The pinned image and translated dispatch bindings cover both selected branches. The exact PC and modifier map depends on this. | Compare original words, decode the extra bridge word and resolve each installed fixup. |
| S2 | The retained schema epoch presents H with J as its sole node and a zero next link. The replayed miss terminates after one comparison. | Compare H and J before and after replay and follow the next-link branch with another source-proven node. |
| S3 | The archived serializer projection is bound at the same Z and declared extent. The tag comparison depends on those stored bytes. | Check the source receipt, Z, the four exact addresses and encoded word before the comparison. |
| S4 | The synthetic 14 B match uses the same allocated region and the archived ADID field bytes. Header fit depends on the nonnull buffer and bounded reader cursor. | Compare the synthetic prefix, node extent and reader arguments. Check the distinct nullable and short-header cuts against their own source premises. |
| S5 | The model uses logical authenticated transfers and stable captured tables. Native lookup and transport pairing depend on additional runtime evidence. | Compare a correlated native transaction, table roots and callback execution with the recorded ABI. |

High impact applies to the exact source record-to-search ABI and match-to-reader boundary. Medium impact applies to the candidate ADID representation match and the untraced nonempty successor cases. Low impact applies to the application meaning of the requested key without its consumer. The exact staging subview, native lifetime, and matched daemon transaction remain unknown. The selected suffix contains no additional Mach transfer. [Mach ports and emission sites](mach_ports_report.md)

QG1 covers the factual claims. QG2 identifies premises and probes. QG3 covers tag, result, callback and reader handoff. QG4 checks widths, extents and counts. QG5 bounds synthetic, symbolic and installed evidence. QG6 ties the conclusions to pinned bytes, fixups, replay and proof queries. QG7 records the remaining field, lifecycle and transport joins.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_schema_search.py "$CURRENT_COLLECTION"
```
