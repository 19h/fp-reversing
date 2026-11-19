# Installed selector 26 schema scalar output

The installed FairPlayIOKit schema reader accepts a matching record with raw type `0x9777` and body length 4 B. It reads the 4 B body, commits cursor 14 B, stores the raw u32 through C+0x5f0 into S+0xbc4, and returns `0x31ae0066` to the saved caller. The synthetic ADID field writes zero. A second u32 fixture writes `0x01234567`. The u64 and span fixtures commit their cursors and return a distinct type error without a scalar store. [Audit script](triage_evidence/audit_live_fairplay_schema_scalar.py) [Audit receipt](triage_evidence/live_fairplay_schema_scalar_audit.json.zst)

```text
found J -> protected header -> candidate cursor and body-fit gate
  |-- fit, u32 L=4     -> decode body -> commit -> write u32 -> SUCCESS
  |-- fit, u64 or span -> commit -> type error
  `-- rejected header  -> short/type error before commitment (source proof)
                                      |
                                  saved caller
```

## Header, bounds and output channels

F is the frame base, C the auxiliary region, S the workspace, J the published node and Z its buffer. The reader inherits C+0x560=Z, C+0x5f0=S+0xbc4, the saved return at C+0x4d0, and zero reader cursor at F+0xbd0. It starts from the bridge at `0xfffffe000a698080`. The installed replay carries registers and storage forward from the matching lookup without a new seed at the scalar entry. [Installed matching lookup](live_fairplay_schema_search_report.md)

| Installed site | Effect |
| --- | --- |
| `0xfffffe000a679ff8` | Return from the tag decoder and request the type decoder. |
| `0xfffffe000a67a4d8`, `0xfffffe000a67a510` | Read protected type bytes at Z+c+4 and Z+c+5. |
| `0xfffffe000a67b464` | Store the u16 type XOR `0x365e` at S+0xc70. |
| Shared word decoder at `0xfffffe000a6782c8` | Read the tag at c+0 through c+3, length at c+6 through c+9, and u32 body at c+10 through c+13 on their respective calls. W22 contains the raw word XOR the success token. |
| `0xfffffe000a679d3c` | Store the u64 candidate cursor at S+0xad8 before testing the body extent. |
| `0xfffffe000a679da4`, `0xfffffe000a679ddc` | Select the type path and require L=4 for u32. |
| `0xfffffe000a67bdb4`, `0xfffffe000a67bde8` | Save the encoded u32 body at S+0xb64 when read, and commit the candidate cursor at F+0xaa8. |
| `0xfffffe000a67be48` | Store the raw u32 through C+0x5f0 into S+0xbc4. |
| `0xfffffe000a6a2fdc`, `0xfffffe000a677908` | Return via C+0x4d0 to `0xfffffe000a6778b8` with modifier `0x415f`. The saved caller tests raw status and transfers with modifier `0x0d4c`. |

The independent source cut gives the exact unsigned body test for u32 node extent M, u32 body length L and u64 cursor c with `0 <= c <= M`. It computes `candidate = c + 10 + zero_extend32(L)` and accepts the body when `candidate <= zero_extend32(M)`. The maximum possible candidate under the premise is 8,589,934,600 B, within u64. Under the archived source obligations, a body outside M, a u32 length other than 4, or an otherwise unsupported type returns `0xce515bb8` before writing the committed cursor or the scalar output. A fitting u64 or span commits the candidate and returns `0xce515ae1`. [Historical exact gates and arithmetic proofs](userclient_schema_scalar_report.md)

## Replayed outcomes

| Fixture | Type | Body | Committed cursor | Scalar store | W23 and selected caller target |
| --- | --- | ---: | ---: | --- | --- |
| Synthetic ADID field | `0x9777` | 4 B | 14 B | `0x00000000` | `0x31ae0066`, `0xfffffe000a67790c` |
| Derived nonzero u32 | `0x9777` | 4 B | 14 B | `0x01234567` | `0x31ae0066`, `0xfffffe000a67790c` |
| Derived u64 | `0x8485` | 8 B | 18 B | No event | `0xce515ae1`, `0xfffffe000a682dac` |
| Derived zero-length span | `0x50db` | 0 B | 10 B | No event | `0xce515ae1`, `0xfffffe000a682dac` |
| Derived nonzero span | `0x50db` | 8 B | 18 B | No event | `0xce515ae1`, `0xfffffe000a682dac` |

Each u32 replay reads 14 B and checks five ordered stores, including the exact four-byte output event even when the old and new scalar both equal zero. Each other replay reads the 10 B header and checks three stores, including cursor commitment and preservation of the original zero output. The reader stores are disjoint from the record. They preserve the container links, node links, extent and original record bytes. The selected caller targets are the stopping points. The action after the success target depends on the shared-holder state. [Historical shared-holder consumer](userclient_schema_registry_report.md)

## Provenance and scope

The audit pins build `26C5035r`, verifies the entire installed `_PRnut72j9` function hash, and checks exact equality of 267 new source words and 77 inherited reader words at their translated addresses. It resolves 63 authenticated table slots and five direct branch targets. The audit reproduces 15 archived UNSAT results within a 115 s per-query limit. The five new suffixes cover 1,907 instruction visits, 67 logical transfers and 58 record-byte loads.

The ADID case reuses its complete archived 14 B record and reproduces the prior installed lookup exactly. The other four cases retain their archived type, length and body, with the matching tag's four archived bytes taken from the same buffer address. The earlier composition proves the tag protection at those addresses independently of the other fields. The replay uses the actual installed header and body reader against those stored byte snapshots. Source composition covers the intervening writer. The evidence establishes representation compatibility through scalar output, while the native container lineage and transport between Avp method 100 and the primary selector 26 staging buffer remain unknown. [Archived field and storage proof](userclient_schema_search_report.md) [ADID packet and installed staging extents](live_fairplay_early_schema_report.md)

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| U1 | Captured words, dispatch bindings and installed image identity agree. Exact reader and caller routes depend on this. | Rehash the full function, compare bytes and decode each direct branch and chained slot. |
| U2 | The lookup preserves buffer Z, node extent M, original output alias and saved caller. Scalar output depends on those epochs. | Compare the prior installed matching receipt, exact read offsets and output store address. |
| U3 | Archived tag bytes belong to the same Z in all derived cases, and the other bytes retain the chosen fixture's fields. Decoded values depend on this. | Check Z equality and the archived certificate, then compare recovered tag, type, length and body against the raw fixture. |
| U4 | Cursor c is bounded by M and the captured extent encoding remains live. The general body test and no-wrap bound depend on this. | Re-solve the source query across u32 lengths and both fit outcomes, and compare candidate and committed stores. |
| U5 | Native ownership, PAC and the Avp/primary staging join require separate runtime evidence. | Correlate the admitted buffer range, connection epoch and callback with one native request and reply. |

High impact applies to the exact output store, caller success/error targets and the pending shared-holder consumer. Medium impact applies to the cursor-committing type error and its later cleanup. Low impact applies to interpreting zero as a business value. The selected reader uses O(1) work and auxiliary storage. The checked suffix has no Mach emission site. [Mach ports and emission sites](mach_ports_report.md)

QG1 covers factual scope. QG2 identifies dependent premises and tests. QG3 covers the header, gates, scalar, cursor and status. QG4 checks widths, capacity and cursor arithmetic. QG5 distinguishes derived and installed evidence and the two error classes. QG6 pins the source bytes, graph edges and proof queries. QG7 bounds the remaining consumer, ownership and IPC joins.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_schema_scalar.py "$CURRENT_COLLECTION"
```
