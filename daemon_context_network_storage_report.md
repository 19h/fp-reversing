# fairplayd: network-data storage, zero tail and saved context-base alias

State-file continuation: [The state-file base-lineage report](daemon_saved_base_statefile_lineage_report.md) closes the conditional route from the family-case-0 SP+0x7f38 alias to all 76 retained constructor base reloads/count-pointer stores. It joins this report's earlier saved-base endpoint by exact interval/write identity. The larger whole-machine/native caller and object lifetime remains unknown.

Original constructor stores clear a 20 B context region at +32. Four retained successful path-publication controls subsequently replace its first six bytes with network-record data and leave its final 14 bytes unchanged at zero. Two controls use nonzero data, excluding an inference based only on zero-valued samples. The later 24 B container snapshot copies the preceding four-byte count and the whole 20 B region. This resolves the local initialization and write-coverage roles of the previously unexplained 14 snapshot bytes; their application meaning remains unknown. Constructor/publication/snapshot native epoch continuity is not established. [NS1-NS6; NS-A1-NS-A5]

The earlier saved context-base input also has a local producer: `0x1004cf268` stores X22 at outer SP+0x9b8. In all 16 retained pathname-family cases, those eight bytes survive to the `0x1005d0f74/0x1005d0f78` copy into SP+0x7f38. The state-file follow-up subsequently closes the conditional earlier-base-to-count-producer route; whole-machine/native lifetime remains unknown. [NS2-NS4; NS-A4]

| Evidence | Primary provenance and scope |
| --- | --- |
| NS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original zeroing, count/data publication and saved-base stores. |
| NS2 | [Context publication](daemon_context_state_publish_report.md), [pathname family](daemon_state_path_family_report.md), [pointer lineage](daemon_count_pointer_lineage_report.md), [snapshot construction](daemon_count_pointer_origin_report.md), and nine frozen parent artifacts pinned in NS3. Prior class admissions, fixtures, declared API returns, owner and root premises remain dependencies. |
| NS3 | [Extractor](triage_evidence/recover_daemon_context_network_storage.py), [checks](triage_evidence/daemon_context_network_storage_checks.json.zst): selected original constructor instructions, four successful raw publications, 16 saved-base routes and later snapshot layout/value correspondences. |
| NS4 | [Independent auditor](triage_evidence/audit_daemon_context_network_storage.py), [audit](triage_evidence/daemon_context_network_storage_audit.json.zst): ordered fixture overlays, exact tail write exclusion, byte transfers, PC/API links, selected source replay and three nonvacuous source obligations. |
| NS5 | [Publication verifier](triage_evidence/verify_daemon_context_network_storage_publication.py): fresh receipts, reconstructed/re-solved queries, manifest delta, original-input custody and path hygiene. |
| NS6 | [Network helper](daemon_network_identity_report.md) and [network-record adapter](daemon_network_record_report.md) qualify upstream `IOMACAddress`/cache and count/data production. They do not establish a native property read for these local controls. |

Decoded checks SHA-256: 3e28325a3ea3c23e8074002d933686c6f9f29998b9a744363aa28067bc136e06. Decoded audit SHA-256: 30cb2ad9fb16deb06e70e52fd101f6fcc08aa7a589e496a2e50f0b873a9f6ede. NS3-NS4 retain parent/dependency hashes. Associated source and retained receipts sufficed; no additional IDA data was required. [NS1-NS5]

All addresses below are retained private-model addresses. Context J=`0x6500115b20` occupies 552 B; outer SP=`0x6800060100`. B denotes bytes. Ranges are half-open. Earlier constructor and later consumer models retain separate epoch/admission premises. [NS2-NS4; NS-A2]

| Context range | Constructor source | Successful publication source | Later 24 B snapshot destination |
| --- | --- | --- | --- |
| J+[28,32), 4 B | Adjacent initial count storage; current count provenance is the network record | `0x100597974..0x100597980`, u32 count 6 | Container+[24,28) |
| J+[32,38), 6 B | First part of the explicit 20 B zeroed region | `0x10059ccd4/0x10059ccd8`, reverse copy of record data indices 5..0 | Container+[28,34) |
| J+[38,52), 14 B | Remainder of that same zeroed region | No source write in the 20 inspected raw-success intervals | Container+[34,48) |

The initial count store is separate from the selected new zeroing theorem; it is not inferred from the 20 B clear. The new zeroing instructions are `0x10032197c: stp xzr,xzr,[x8,#0x20]` and `0x100321980: str wzr,[x8,#0x30]`, with X8=J in the retained constructor. They write 8 B at J+32, 8 B at J+40 and 4 B at J+48: `8 B + 8 B + 4 B = 20 B`. Their values are independent of prior contents. These bytes overwrite earlier constructor-generated values rather than merely retaining initial emulator zeros. [NS1-NS4; NS-A1]

The four publication controls are parent cases 1/2/4/5, covering two declared API-clobber patterns. Cases 2/5 supply only the six network-record bytes `01 32 45 67 89 ab`; the count remains source-established 6. Their final 20 B region is that six-byte sequence followed by 14 zero bytes. Cases 1/4 use six zero data bytes and retain 20 zeros. The extractor/auditor check each copy read and write, not only the final image. [NS2-NS4; NS-A2]

```text
constructor:
    context+[32,52) <- 20 explicit zero bytes

raw publication success:
    context+[28,32) <- u32 count 6
    context+[32,38) <- six network-record bytes
    context+[38,52) <- unchanged 14-byte zero tail

separate later constructor snapshot:
    count4 || data6 || tail14 -> fixed 24 B container copy
```

The copy-source count and six-byte publication do not prove that 20 is a general input bound or native array capacity. The established source facts are the zeroed extent, the six actual indexed stores and the later fixed-copy extent. No application label such as padding, digest, address family or reserved field is assigned to the remaining 14 bytes. [NS2-NS4; NS-A3]

NULL-allocation publication branches are excluded from this raw-success invariant. They later reseal all 552 context bytes, including this region; their final encoded bytes are not expected to equal raw zeros. Similarly, early encoded context fixtures in the success receipts are historical overlays. Parent restore/audit semantics apply fixtures in order, and later raw-context definitions replace them. NS4 checks the last applicable fixture for each byte and separately counts earlier conflicting overlays. [NS2-NS4; NS-A2,NS-A5]

The saved-base producer follows the retained return from the pathname-family call at `0x1004cf260`. The preceding inner epilogue restores X22 and the outer SP. The next instruction computes context+0x128; `0x1004cf268` then saves X22. This is local caller attribution: the complete origin and lifetime of the restored X22 are unknown. Stack offsets are reused in other epochs, so this is not a unique global writer claim. [NS1-NS4; NS-A4]

| Saved-base operation | Original source | Retained value/location |
| --- | --- | --- |
| Save caller context base | `0x1004cf268: str x22,[sp,#0x9b8]` | J to `0x6800060ab8`, 8 B |
| Reload saved base | `0x1005d0f74: ldr x10,[sp,#0x9b8]` | J from the same cell |
| Publish second stack alias | `0x1005d0f78: str x10,[sp,#0x7f38]` | J to `0x6800068038`, 8 B |

For each of 16 cases, NS4 checks pathname-family intervals 8..27, ending just after the alias store. The 20 stages have 19 links: 18 declared API returns and one direct PC link. Across cases this gives 320 stages, 304 links, 288 API returns and `304 * 8 B = 2,432 B` of boundary comparisons. All 304 declared API memory spans are disjoint from the saved cell. The first stage contains its original store; subsequent stages contain no overlapping source write before the cut. These checks close this local saved-base route. The state-file follow-up closes the selected intervening component route to the later count-pointer producer. [NS2-NS4; NS-A4]

| Validation | Checked scope/result |
| --- | --- |
| Original constructor clear | 2 instructions / 3 stores / 20 B |
| Raw publication coverage | 4 controls / 20 intervals / 24 byte transfers; 2 nonzero controls |
| Ordered tail fixtures | 280 byte queries; all 280 have a conflicting earlier overlay, with latest value zero |
| Final raw-success tail | 56 B checked across four controls |
| Saved-base route | 16 input stores, 320 stages, 304 PC links, 2,432 boundary byte comparisons, 16 alias stores |
| Existing saved-base journals inspected | 196,000 recorded visits and 9,600 write events |
| Later snapshot correspondence | 76 retained fixed 24 B snapshots; separate epoch premises |
| New selected scalar replay | 61 chunks / 110 visits; 5,472 GP/SP values, 171 NZCV frames, 48 reads, 63 writes |
| Source obligations | 3 nonvacuous UNSAT results: arbitrary prior-value zeroing, six-index copy exclusion of the tail, saved-base input store |
| New target intervals/root bytes/API return premises | 0 / 0 / 0 |

The 196,000 recorded visits are inspected for writes and boundary evidence; fresh scalar replay covers the 110 selected original instructions. The copy obligation quantifies arbitrary source bytes and indices 0..5, with tail indices 6..19; it does not infer a general count admission rule. NS5 reconstructs and re-solves all three obligations against the pinned source. No native API, Mach operation, hardware authentication or IDB edit occurred. [NS3-NS5]

Extraction uses O(parent bytes+selected visits+effect bytes) time and O(parent receipts+largest interval+selected chunks) space. The independent audit adds O(32C+proof DAG) frame/proof construction, where C is the selected frame count; its fixed-width byte queries scan ordered fixtures. Solver search is capped at 30 s/query. [NS3-NS5]

| Assumption register | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| NS-A1: Pinned image bytes identify the original AArch64 instructions | Zeroing, indexed copies and saved-base store semantics | Rehash source and nine parents; replay selected opcodes and reconstruct all three obligations. |
| NS-A2: Ordered fixtures and declared API effects apply only to their recorded models | Raw-success tail and local byte continuity | Reverse conflicting overlays or introduce an overlapping API/source write and require audit failure; native effects require separate observation. |
| NS-A3: The six observed indices and count 6 describe these admitted controls | Six-byte overwrite and tail exclusion only | Audit count producers/admission and other source indices before assigning a general capacity or structure type. |
| NS-A4: Every selected saved-base stage and PC/API boundary is retained, without an asserted native epoch join | Local SP+0x9b8 to SP+0x7f38 route | Remove a stage, change an incoming byte or overlap the cell and require rejection; extend through every state-file boundary before claiming the later producer join. |
| NS-A5: Raw, encoded and later snapshot epochs remain distinct; API success alone does not prove fresh network identity | Scope of initialization/snapshot and network-data interpretation | Check resealing paths separately; observe native property type, length, cache freshness and object lifetime before extending the claim. |

| Bounded continuation | Impact | Unresolved evidence |
| --- | --- | --- |
| Join private owners to native transport | High | Same transaction's buffer, selector, Mach right and emission/receive sites |
| Recover whole-machine base-pointer lifetime | Medium | Conditional state-file joins established by the follow-up; caller X22 lifetime remains unknown |
| Establish remaining field semantics | Medium | Independent native producers/consumers of the 14-byte tail; no semantic type established here |
| Establish network-field validity | Medium | Native property length/type, cache freshness and count admission beyond these six-index controls |

**QG1** passes: source and provenance claims require no normative premise. **QG2** passes: NS-A1..NS-A5 give dependencies and falsification probes. **QG3** passes for this increment: local routines, data/control flow, API premises and unresolved transport scope are covered; no new Mach port/right or emission site is established. **QG4** passes: byte widths, half-open ranges, counts and reproduction complexity are explicit. **QG5** passes: raw/encoded/snapshot epochs and local/full/native continuity are distinguished. **QG6** passes: pinned original bytes, retained primary receipts, independent replay and reconstructed obligations supply provenance. **QG7** passes: continuation is bounded and impact-ranked above. The full investigation remains active. [NS1-NS6]
