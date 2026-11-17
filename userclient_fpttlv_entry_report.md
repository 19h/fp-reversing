# Original-entry FPTTLV initialization and first-input boundary

Subsequent exhausted-input evidence: The [early schema-key report](userclient_early_schema_report.md) follows successful first-record exhaustion through C+0x418 container publication, source-fixed action selection and the caller-specific shared lookup request for raw key `0xfa834112`. Thirteen source proofs, four prior rechecks, 30 partial-state evaluations, 270 additional prefix-cell reconstructions, 390 resulting fields and three mutation controls pass. Independent parsing locates the same key in twelve identical retained ADID packet fixtures. Kernel field decoding/meaning, Avp selector 100 to primary selector 26 transport, native transaction identity and new Mach emission remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent early-publication evidence: The [first early record publication report](userclient_early_publication_report.md) composes all four scalar/span variants through empty-container lookup, exact first-node head/tail stores, saved callback and parser cursor selection. Eighteen source proofs, four payload rechecks, 30 partial-state evaluations, 480 reconstructed prefix cells, 270 resulting fields and three rejected mutations pass. The certified bank leaves controller values arbitrary. All retained fixtures select exhausted input; the universal cursor gate also covers a remaining suffix. Continuous guest extension, native ownership/PAC, nonempty early replacement and matched daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent original-entry evidence: The [early header report](userclient_early_header_report.md) continues through declared input bytes in 72 private cases, with 48 exact predecessor prefixes, ten fresh source proofs and two rejected source mutations. It establishes the early BE header and scalar/span domains, conditional wire-field correspondence to staged decoding, zero-tag span success with an unread suffix, and the earlier 32 B FPTTLVNode request. Input custody and allocator returns are fixtures; node allocation/free bodies and matched native daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

The earlier 16 B `site.FPTTLV` request in `_PRnut72j9` now has a continuous, independently replayed allocation-return continuation. Original instructions retain the result, zero both object words when non-NULL, distinguish empty and short input, and select the first input-content read only after a ten-byte header-fit check. The first selected byte is input+6, before the later staging-allocation request. These are private source executions with three declared allocator register returns, zero model RAM writes and logical PAC transfers. No input-content load, native allocation/free or Mach transaction executes. [FE1-FE8]

This extends the [entry report](userclient_entry_execution_report.md), whose non-NULL cases ended before the earlier allocation. It also places a new boundary before the conditional [staging](userclient_container_staging_report.md), [later metadata parser](userclient_record_metadata_report.md) and [cleanup](userclient_parser_cleanup_report.md) analyses. Matching descriptor metadata or shared cleanup code does not equate the earlier and later object instances.

## Primary evidence

| Artifact | Decoded SHA-256 | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instruction/data image |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, symbols, descriptors and chained pointers |
| Complete original routine | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` | 202536 B, 50634 words; entry `0xfffffe000a635208`, end `0xfffffe000a666930` exclusive |
| [Checks](triage_evidence/userclient_fpttlv_entry_checks.json.zst) | `e45e1feb725aa40d54c43c510686adbd9e46f0c7dc67eca15147b168f7f5a62a` | 84 continuous cases; 11 newly selected spans / 725 words; three 256-input bank rules |
| [Audit](triage_evidence/userclient_fpttlv_entry_audit.json.zst) | `e51c00cdb63ed65e1b92fae161de8d7189f0cd27d0f2359c7d11c3bf9080030b` | Independent replay, predecessor preservation, six source obligations and two rejected source mutations |

The [extractor](triage_evidence/recover_userclient_fpttlv_entry.py) compares selected words with both pinned images and rehashes the complete routine. The [producer](triage_evidence/probe_userclient_fpttlv_entry.py) extends original-entry execution without repairing CPU or RAM mid-function. The [independent interpreter](triage_evidence/replay_userclient_fpttlv_entry.py) imports neither that producer nor Unicorn; it computes and checks every visited integer instruction, register/NZCV epoch, memory event and logical edge. Its additional CMN implementation computes 32/64-bit carry and overflow explicitly. The [audit](triage_evidence/audit_userclient_fpttlv_entry.py) adds separate byte/phase/frontier oracles and freshly lifted source proofs. The [delivery verifier](triage_evidence/verify_userclient_fpttlv_entry_delivery.py) rebuilds those receipts and checks publication custody.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| FE1 | Original predecessor prefix and exact earlier allocation request retained | FE-A1-FE-A4 |
| FE2 | Returned H retained at C+0xb0; original source zeroes H[0..15] when non-NULL | FE-A1-FE-A5 |
| FE3 | Exact nullable-result and unsigned cursor/size dispatch | FE-A1-FE-A5 |
| FE4 | Ten-byte header-fit predicate and selected first byte at I+c+6 | FE-A1-FE-A5 |
| FE5 | Empty/short status, publication and distinct cleanup-cell lineage | FE-A1-FE-A5 |
| FE6 | Typed-retirement, staging-allocation and unread-input frontiers | FE-A1-FE-A5 |
| FE7 | Independent replay, source proofs and rejected source-removal controls | FE-A1-FE-A6 |
| FE8 | Environmental limits, interface consequences and bounded continuation | FE-A1-FE-A7 |

## Continuity and result initialization

I, A and Q are entry X0, X1 and X2; N=low32(A). F is source-produced SP, S the 16384 B workspace and C the 4096 B typed region. H is the earlier FPTTLV allocation result. F/S/C retain their predecessor epochs. H is declared before entry as NULL or a separate 16 B private extent. Its initial bytes are poison with an all-zero defined-byte mask. Three API cuts change registers only; allocator bodies are unexecuted. [FE1,FE2]

```text
original core entry -> original predecessor prefix (1162 visits)
    |
typed allocation request, declared result H
    |
C+0xb0 = H; frame raw default = 0xce515bb2
    +--- H == 0 ----------------------> before IOMallocData(N)
    |
    +--- H != 0 -> original STP zeros H[0..15]
                   |
                   +--- N == 0 ------> publish H through C+0x170
                   |                   cleanup cell C+0x418
                   |                   before typed free(H)
                   |
                   +--- 0 < N < 10 --> short-header status
                   |                   cleanup cell C+0x3d0
                   |                   before typed free(H)
                   |
                   +--- N >= 10 -----> before first byte read at I+6
```

All 72 extensions of existing cases preserve their first 1162 visits, CPU frames, reads, writes, logical edges, first two API cuts and original third-call CPU state exactly. Twelve additional N=9/N=10 cases use the same entry construction with changed declared input size. The matrix varies three controller fixtures, two stack placements, six existing non-NULL I/A profiles, two H returns, and those twelve boundary cases. These are finite private states, not exhaustive native admission. [FE1,FE7]

| Source site | Width | Established effect |
| --- | --- | --- |
| `0xfffffe000a636404` | X0 pointer64 | Request `_IOMallocTypeImpl` at `0xfffffe000c4ba154` with descriptor `0xfffffe000847bb60`; declared H return |
| `0xfffffe000a636428` | 8 B | C+0xb0 = H |
| `0xfffffe000a636690` | 4 B | F+0x9ec = 0xce515bb2, a saved raw default; its external error interpretation is unknown |
| `0xfffffe000a6366a8` | Branch | Index0x68e for H!=0 to `0xfffffe000a6366ac`; index0x693 for H==0 to `0xfffffe000a660b88`; original modifier0x1fcb |
| `0xfffffe000a6366c8` | 16 B | `STP XZR,XZR,[X0]` defines both H words as zero |

The zeroing is an executed original instruction, rather than an allocator-zeroing assumption. H==0 skips that store and reaches the staging request without accessing H storage. The large intervening bank-root envelope executes unchanged. Its phase values derive from original entry: W19=0x4a2/W20=0x68e before the request, and W30=0x4a2 at the zeroing block. The local proofs state those phase premises; complete replay checks their production in every delivered case. [FE2,FE3]

## Length gate and original input lineage

Original source initializes cursor c at S+0xa10 to zero and retains encoded N XOR0x31ae0066 at S+0xb5c. At `0xfffffe000a660af8` through `0xfffffe000a660b20` exclusive, the recovered unsigned decision is:

```text
index32 = (c >= zero_extend64(N)) ? 0xcd0 : 0xc89
0xcd0 -> 0xfffffe000a660b2c       empty/exhausted
0xc89 -> 0xfffffe000a660c28       inspect header availability
```

The header path copies retained I from C+0x98 to C+0x670. Under its source phase W11=0x6a2 and c<N, the 52 original instructions at `0xfffffe000a660c84` through `0xfffffe000a660d54` exclusive select index0x6bb exactly when N-c>=10, otherwise0x6a2. The obfuscated arithmetic feeds `CMN X9,#10`; carry-clear selects the fitting-header index. The fresh proof covers all u32 N/u64 c satisfying c<N, not only sampled sizes. [FE3,FE4]

| Predicate | Index / modifier | Original target | Selected effect |
| --- | --- | --- | --- |
| Remaining extent <10 B | 0x6a2 / 0x5e1c | `0xfffffe000a661bfc` | Publish short-header raw status before cleanup |
| Remaining extent >=10 B | 0x6bb / 0x5e1c | `0xfffffe000a660d68` | Form first input-byte address |

The 17 original instructions at `0xfffffe000a660d88` through `0xfffffe000a660dcc` exclusive universally simplify to offset c+6 modulo2^64. The next instruction is `LDRB W11,[X10,X9]` at `0xfffffe000a660dcc`, with X10=I. In these initial loops c=0; all fitting-header cases stop before that load. A non-NULL test alone does not establish readability. The all-one I fixture selects address5 after modular addition and stops before an unbacked read; private I selects an undefined byte at I+6. No fault or input-content value is inferred. [FE4,FE6]

This early header checks original I before staging. The later metadata parser's similar header width is separately established under its own staged-pointer epoch. Header contents, complete early parse, a common serialized object instance and a native caller-provided extent remain unknown.

## Publication, cleanup and lower interfaces

| Case | Raw parser status at S+0xc94 | Object/publication state | Exact unexecuted frontier | Cases / visits each |
| --- | --- | --- | --- | --- |
| H==0 | Undefined in this prefix | C+0xb0=0; C+0x418=0; H storage untouched | `0xfffffe000a641cf8` -> `_IOMallocData` / `_IOMallocData_external` at `0xfffffe000c4ba60c`, X0=zero_extend64(N) | 36 / 1479 |
| H!=0, N==0 | 0x31ae0066 | H words zero; C+0x418=H; cleanup X19=C+0x418 | `0xfffffe000a6605c4` -> `_IOFreeTypeImpl` at `0xfffffe000c4ba368`, X0=retirement descriptor, X1=H | 6 / 1720 |
| H!=0, 0<N<10 | 0xce515bb8 | H words zero; C+0x418=0; C+0x3d0=H; cleanup X19=C+0x3d0 | Same typed-free request | 12 / 1548 |
| H!=0, N>=10 | Undefined in this prefix | H words zero; C+0x418=0 | Before byte load at `0xfffffe000a660dcc` | 30 / 1464 |

Empty input stores status at `0xfffffe000a660b4c`. Instructions `...b68`, `...b6c`, `...b70` load H from C+0xb0, load the previously retained alias C+0x418 from C+0x170, and store H through that alias. Original empty lookup and shared cleanup then reach typed retirement. Short input instead stores status at `0xfffffe000a661c00` and H at C+0x3d0 at `0xfffffe000a661c18`. The shared destructor receives that different cleanup-cell address. W23 is reused for the zero head pointer by the free frontier; its value there is not the saved parser status. Neither retirement body, pointer clearing after retirement, nor overall function return executes. [FE5,FE6]

| Bank rule | 256-input constant | Selected index / bias | Original target |
| --- | --- | --- | --- |
| Container typed retirement | 0xa2 | 0xf2b / 0 | `0xfffffe000c4ba368` |
| Retirement descriptor | 0xa2 | 0x4d / -4 B | `0xfffffe000847bde0` |
| Staging allocation | 0x88 | 0xf10 / 0 | `0xfffffe000c4ba60c` |

The three rules retain both complete 256 B arrays and original selected chained pointer words. Allocation descriptor `0xfffffe000847bb60` and retirement descriptor `0xfffffe000847bde0` have identical normalized 64 B contents, name `site.FPTTLV`, signature `11`, flags0xe4 and declared size16 B. Their addresses are distinct. Matching metadata plus X1=H establishes the source request contract, not successful native allocation/retirement or lifetime correctness. Original symbols retain both aliases for the staging target.

S+0x20..+0x23 remains unknown and unread in every current prefix. Its tunnel-marker producer remains open; there is no alias-complete absence claim. Q remains an opaque retained 64-bit argument. This increment establishes no new incoming Mach port, outgoing message, right transfer, message identifier or emission site. Allocation and typed-retirement requests are memory interfaces. Confirmed transport evidence remains in the [Mach-port report](mach_ports_report.md); a matched daemon/kext transaction remains unknown. [FE6,FE8]

## Independent validation and controls

| Check | Verified count |
| --- | --- |
| Continuous cases / exactly preserved predecessor prefixes | 84 / 72 |
| Source visits / distinct visited PCs | 126060 / 1880 |
| Reads / read bytes checked | 11070 / 58176 B |
| Writes / write bytes checked | 31110 / 233220 B |
| GPR values / NZCV epochs | 3910464 / 126144 |
| Final D-register values / logical edges | 2688 / 1326 |
| Frame/workspace/typed snapshot bytes | 2084544 B |
| Additional H snapshot bytes | 1344 B |
| Register-only API returns | 252; three per case, zero RAM writes |
| New bank-array input checks | 768 |
| Fresh satisfiable-premise UNSAT proofs | 6 / 97 lifted instruction instances |

The six obligations cover result retention/nullable dispatch, two-word source zeroing, unsigned cursor dispatch, exact ten-byte fit, first-byte offset and empty publication alias. Eleven selected new spans contain725 words:722 visited continuation PCs plus the three unexecuted frontier instructions. Source custody includes those frontier words; execution coverage excludes them. [FE7]

Two single-word controls replace original stores with NOP while keeping entry and return fixtures unchanged. Removing the H zeroing at `0xfffffe000a6366c8` stops before the dependent head load at `0xfffffe000a662c14`. Removing C+0xb0 retention at `0xfffffe000a636428` stops before its publication load at `0xfffffe000a660b68`. Independent replay verifies both altered prefixes, both fail the normal semantic oracle, and neither consumes an undefined value. These controls falsify initialization dependencies rather than only checking receipt hashes.

Production uses O(B+I+256R+C*(B+V+E)) time/retained space for image bytes B, captured instructions I, bank rules R, cases C, visits V and byte events E. Independent replay uses O(V+E+M) time/space per case, M the snapshots. Each producer case is bounded at30000 visits. Symbolic lifting costs O(I) DAG construction/space; solver search is separate with a30 s/query limit. No case reaches the visit bound. No native host operation or IDB mutation executes.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FE-A1: The two pinned images and original chained-pointer interpretation apply. | FE1-FE8 | Rehash images/container; compare every selected word and original pointer, descriptor and symbol. Any mismatch invalidates reuse. |
| FE-A2: Declared original-entry registers, private separated arenas and retained F/S/C epochs apply. | FE1-FE8 | Rebuild84 cases, vary controllers/placement/size/result; compare all epochs and72 exact predecessor prefixes. Native admission remains unknown. |
| FE-A3: PAC/AUT and authenticated branches have logical transfer semantics here. | FE1-FE8 | Recheck original words, target slots/modifiers and complete logical edge journals. Native authentication needs independently established machine state. |
| FE-A4: Three declared register-return cuts preserve the specified storage/other registers and write no RAM. | FE1-FE8 | Check request PCs/arguments, caller clobbers, both H outcomes and source-only defined-byte provenance. Authentic allocator effects may change boundaries. |
| FE-A5: Local proof phase values and stable nonwrapping object extents hold where required. | FE2-FE8 | Re-solve all six nonvacuous obligations; replay original production and intervening writes. Test9/10 and high32 size projection; do not extend into unexecuted input or call bodies. |
| FE-A6: The explicit independently interpreted integer/NZCV/memory/D-register subset matches visited words. | FE7 | Compare every epoch/event and two altered-source prefixes; unsupported instructions or differing results fail closed. No complete ISA equivalence is asserted. |
| FE-A7: Static/private evidence applies only to the reported prefixes and pinned images. | FE8 | Establish authentic input ownership, caller admission, subsequent body/call effects and shared transaction identity before native composition. |

## Bounded continuation

| Impact | Discriminating next work | Result sought |
| --- | --- | --- |
| High | Provide separately justified input-byte provenance at the first early header load and continue original decoding. | Recover early record fields and the first nonempty-parse frontier without substituting the later staged parser. |
| High | Continue original retirement return under a declared lower contract, preserving the distinct C+0x418/C+0x3d0 aliases. | Establish post-retirement clearing, callback and staging reachability without equating the two cleanup epochs. |
| High | Follow original S+0x20 writers and source aliases beyond these frontiers. | Locate the tunnel-marker producer before the established insertion read. |
| High | Join original selector26 admission and fairplayd request custody to these retained arguments. | Establish incoming buffer/object/transaction identity; pointer-value control alone is insufficient. |
| Medium | Establish native allocator, input ownership, controller observation and PAC contracts. | Replace declared return/storage and logical-authentication assumptions. |
| Low | Seek an original type/schema name corroborated by this early header's actual decoded fields. | Improve naming without promoting descriptor similarity to ABI identity. |

## Quality gates

**QG1** Pass: factual technical analysis. **QG2** Pass: FE-A1-FE-A7 register dependencies and falsification probes. **QG3** Pass for this increment: routine purpose, original-entry control/data flow, lower ABI cuts, environmental limits and Mach-interface consequences covered; the full goal remains active. **QG4** Pass: u32/u64 arithmetic, byte widths/extents, exact counts and complexity are reproducible. **QG5** Pass: earlier/later object epochs, raw status versus reused W23, empty/short cleanup aliases, selected versus executed reads and private unknown bytes versus native behavior are distinguished. **QG6** Pass: pinned original/normalized source, chained pointers/descriptors/symbols, fresh proofs, independent replay and controls support the claims. **QG7** Pass: impact-ranked continuation above. `full_goal_complete=false`.
