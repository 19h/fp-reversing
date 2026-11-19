# Selector 26 aggregate publication and zero-tag retirement

The installed FairPlayIOKit first parser publishes three nodes from each reconstructed `fairplayd` selector 26 aggregate. The zero-tag trailer then takes the parser's success arm, which retires all three record buffers, their nodes and the container before requesting another data buffer. The replay reaches that fallback allocation before the command lookup. The command scalar and copying-reader tag established previously are both present in the first container until its retirement. [Daemon request bytes](daemon_selector26_request_bytes_report.md) [Conditional command dispatch](daemon_selector26_command_report.md)

## Staging and publication

The four daemon aggregates reproduce the recorded hashes. The audit supplies each complete buffer as immutable staging at the installed `PRnut72j9` entry `0xfffffe000a676398`. It follows original instructions from entry through the first length read at `0xfffffe000a6a1f5c`, supplies isolated allocation returns and continues through all records with the same cursor and container. The current provider's corresponding staging call is `0xfffffe000a54648c`, after the task-buffer read at `0xfffffe000a54647c`. The replay begins at the core and uses the earlier source-verified task-transfer contract. [Installed provider ABI](live_kext_selector26_transfer_report.md)

| Raw tag | Header offset in 272 B | Header offset in 288 B | Result at first-container retirement |
| --- | ---: | ---: | --- |
| `0x744b91e8` | 0 B | 0 B | Head, protected 14 B record with scalar `0x88594abe` |
| `0x812b9aed` | 14 B | 14 B | Second node, protected 218 B or 234 B record |
| `0x172ba3a8` | 232 B | 248 B | Tail, protected 29 B record including the 19 B body |
| `0x00000000` | 261 B | 277 B | Zero-tag span path with one-byte body |

Each nonzero tag requests a 32 B typed node at `0xfffffe000a6a27f4` and a data allocation for its full record at `0xfffffe000a6a29d8`. Immediately before the first retirement request, the audit reads the head and tail and checks both link directions. Reversing the previously verified address-dependent byte mask on each source-written record gives its exact staging slice. The audit checks the entire span records, including the `0x812b9aed` body. Their contents are copied into record storage at this stage. [Installed record writer](live_fairplay_early_writer_report.md)

## Trailer, retirement and fallback

The zero-tag trailer commits the cursor to 272 B or 288 B. The parser reads all preceding offsets exactly once, including the trailer's ten header bytes. Its sole unread byte is the trailer body at offset 271 B or 287 B. The installed zero-tag branch selects `0xfffffe000a6a2ad8` under discriminator `0xd34`; the parser status saved at S+0xc94 B is `0x31ae0066`. The command caller's C+0x600 B cell receives no write through the fallback boundary. [Earlier zero-tag contract](live_fairplay_early_header_report.md)

| Order | Installed call PC | Request |
| --- | --- | --- |
| Each node in list order, first | `0xfffffe000a6a1978` | `_IOFreeData` with that node's record buffer and full serialized extent |
| Each node in list order, second | `0xfffffe000a6a1898` | `_IOFreeTypeImpl` with descriptor `0xfffffe00084928c0` and that node |
| After the third pair | `0xfffffe000a6a1754` | `_IOFreeTypeImpl` with descriptor `0xfffffe0008492880` and the 16 B container |
| Pending endpoint | `0xfffffe000a682e88` | `_IOMallocData` with X0 equal to the full original staging extent and discriminator `0xca0c` |

With ordinary register-only retirement returns, the cleanup clears C+0x418 B and reaches the pending request with W23 zero. The emulator checks that there is no access to a retired object after its modeled return. Staging bytes are unchanged through the pending request. A subsequent replay follows this boundary through a fresh container, its command node and the copying reader's output. [Fallback and reader continuation](live_fairplay_selector26_fallback_report.md)

The source-checked transport still uses request 2865 on the existing connection right and a distinct reply right for 2965. The supplied RAX trace ends at failed open 2862/2962. Its last returned connection is null. The new observations concern the core's private staging, parsing and memory-management interfaces. [Mach request and reply boundaries](live_iokit_mach_transport_report.md) [Supplied trace](zut_trace_report.md)

## Verification

Sixteen cases cover the four aggregates, two provider values and two scratch fills. Across 227,552 dynamic visits, 3,123 unique installed instruction words are compared with the normalized original. Thirty words differ at relocated sites. The replay checks the raw words and resolved targets for 103 loaded chained-pointer slots. The replay uses one archived stack placement and the original controller fixture. It varies the saved provider between zero and a modeled nonzero value and runs both zero and patterned fills for the previously identified unavailable writer scratch bytes. The receipt records the source words that differ at relocated addresses, installed chained-pointer reads, parser and cleanup edges, exact input-offset journals, masked and decoded record hashes, and the two final status channels. [Replay script](triage_evidence/audit_live_fairplay_selector26_parse.py) [Compressed receipt](triage_evidence/live_fairplay_selector26_parse_audit.json.zst)

```sh
uv run --offline --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_live_fairplay_selector26_parse.py "$COLLECTION" "$RECEIPT"
```

Parsing visits O(B) bytes for the observed B-byte framing. The linked lookups can visit the preceding nodes for each record. For R records this yields O(B + R^2) source work in the selected workflow, excluding allocator execution. The replay stores O(I + B) evidence for I instruction visits and B staged bytes.

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The four modeled daemon aggregates supply the bytes at core entry. Byte custody begins at modeled staging. | Compare a passive provider copy and the original task bytes in the same admitted native transaction. |
| A2 | Allocation returns are nonnull and disjoint. Retirement calls return ordinarily and revoke model access. The publication and fallback results depend on those returns. | Test allocation outcomes separately and observe the actual owner and release order in a correlated trace. |
| A3 | Original controller values, the selected frame and two scratch fills represent the scoped executions. | Vary controller and stack placement and compare the record hashes, ordered reads and exit. |
| A4 | Installed image instructions and fixups define logical execution. Hardware authentication and external method completion remain unknown. | Resolve source-word differences and original slots, then check the core entry and result in the same native transaction. |

| Impact | Open evidence |
| --- | --- |
| High | Downstream consumption of the copying reader's 19 B output for these aggregates. |
| High | A native transaction joining descriptor, provider copy and reply. |
| Medium | Controller and frame-placement dependence of the observed publication and retirement. |

QG1–QG3 cover the factual scope, assumptions, publication, trailer and pending fallback. QG4–QG5 cover byte sizes, cursor coverage, linked layout and ordered retirement. QG6–QG7 cover original source provenance and the open boundaries above.
