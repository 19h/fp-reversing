# Earlier data return and shared writer input provenance

The original `_PRnut72j9` entry now continues through a declared return from the early `L+10` B data request. Source stores that result at node+0x18. NULL data selects a typed-node retirement request; non-NULL data reaches the shared writer entry but stops before its first undefined required-cell load. The writer setup consumes five retained pointer roots and seven metadata cells. Only 18 of those 64 input bytes are source-defined in this private prefix; 46 remain unknown. No buffer byte is written. [ED1-ED8]

This is a provenance boundary, not a native failure claim. The allocator returns and pre-entry input bytes are fixtures. The investigation locates source stores that could supply the missing pointer roots under their stated frame/context premises; it does not insert those values or establish their runtime epochs. The previous [node return](userclient_early_node_report.md), [later constructor](userclient_record_nodes_report.md) and [protected writer](userclient_record_writer_report.md) retain their separate scopes.

## Evidence and claim mapping

| Artifact | Decoded SHA-256 | Coverage |
| --- | --- | --- |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, allocation-site metadata, symbols and chained pointers |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Independent comparison of selected words/data |
| Complete `_PRnut72j9` | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` | 202536 B /50634 words, starting `0xfffffe000a635208` |
| [Checks](triage_evidence/userclient_early_data_checks.json.zst) | `1528647bc86b5a33d1da3bb156346aa0b30b46e5f8cc44437f3b00a61b8bd7bb` | 60 continuous cases, 164 captured words, 512 bank inputs, 12 writer inputs and 69 syntactic inventory sites |
| [Audit](triage_evidence/userclient_early_data_audit.json.zst) | `c2a584dacc8d8d909b28406d10179bb05f649ddf1169264026b9554da299fb3d` | Independent replay, nine nonvacuous source obligations and two rejected source mutations |

The [extractor](triage_evidence/recover_userclient_early_data.py), [producer](triage_evidence/probe_userclient_early_data.py), [independent interpreter](triage_evidence/replay_userclient_early_data.py), [auditor](triage_evidence/audit_userclient_early_data.py) and [delivery verifier](triage_evidence/verify_userclient_early_data_delivery.py) preserve reproducible custody. The interpreter imports neither the producer nor Unicorn. It independently derives the twelve required-cell snapshots from the original load instructions.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| ED1 | Original-entry continuation and 60 exact predecessor prefixes | ED-A1-ED-A4 |
| ED2 | Data-result retention, 28 source-defined node bytes and 4 unknown padding bytes | ED-A1-ED-A5 |
| ED3 | NULL-data typed-node retirement request and matching normalized type metadata | ED-A1-ED-A5 |
| ED4 | Non-NULL-data shared writer handoff and pointer-cell ABI | ED-A1-ED-A5 |
| ED5 | Conditional five-root/seven-metadata setup and actual definedness boundary | ED-A1-ED-A5, ED-A7 |
| ED6 | Five conditional call-return stores and scoped syntactic inventory | ED-A1, ED-A5, ED-A7 |
| ED7 | Independent replay, source proofs and falsification controls | ED-A1-ED-A6 |
| ED8 | Native, transport and continuation limits | ED-A1-ED-A7 |

## Continuous return and node bytes

I, N, F, S, C, H and J retain the previous entry/header/node meanings. J is the declared non-NULL 32 B early node. Z is the fifth allocator return, selected as either NULL or a separate private data extent. Five accepted wire profiles cross three controller fixtures, two stack placements and two Z selections:5*3*2*2=60 cases. Every case exactly preserves its predecessor visits, CPU frames, memory events, logical edges, four API cuts and frontier CPU state. The previous NULL-node cases are not duplicated. [ED1]

At `0xfffffe000a661848`, the model returns Z for `_IOMallocData` at `0xfffffe000c4ba60c`. It changes the declared volatile register/NZCV state and writes no RAM. The private data snapshot covers 64 B for auditing; that extent is not a native allocation-capacity claim. The source request remains `L+10` B (10,14 or18 B in this matrix).

The sole additional source memory store before either frontier is `STR X0,[X22,#0x18]` at `0xfffffe000a66184c`. It defines J+0x18..+0x1f as Z. Together with the earlier explicit 16 B clear and 4 B extent store, J has 28 source-defined bytes. J+0x14..+0x17 remain 4 unknown padding/other bytes. Every private data byte remains unknown, and all parent frame/workspace/context/H/input snapshots remain unchanged. [ED2]

```text
original entry -> early node J -> IOMallocData(L+10)
                                      |
                          declared register result Z
                                      |
                            source J+0x18 = Z
                             /              \
                        Z == 0             Z != 0
                           |                  |
                   typed-node free       shared writer entry
                   request for J              |
                                      before undefined C+0x768 load
                                      no data byte written
```

The source gate at `0xfffffe000a661850` through `...1864` exclusive selects index 0x871 for Z==0 and0x87c otherwise. Original chained slots target `0xfffffe000a664074` and `0xfffffe000a661880`, respectively, with modifier 0x3769. The universal proof quantifies over the full 64-bit return value; it does not restrict success to the sampled private address.

## NULL data: typed-node retirement interface

The shared retirement-selection block loads J+0x18 and selects index 0xa71 when that value is zero, or0xa94 otherwise, under the stated source-phase constants. The NULL fixture takes0xa71 to `0xfffffe000a66414c`. It stops before `0xfffffe000a6641e4`, which requests `_IOFreeTypeImpl` at `0xfffffe000c4ba368`, modifier 0x4d6a, X0=`0xfffffe000847bfa0`, X1=J. No data-free call or node-free body executes in this prefix. [ED3]

| Metadata / bank role | Established source contract |
| --- | --- |
| Early allocation descriptor | `0xfffffe000847b4a0`, `site.FPTTLVNode`, signature 1121, flags 0x64, size 32 B |
| Retirement descriptor | `0xfffffe000847bfa0`, identical normalized 64 B metadata; separate address |
| Retirement function bank | Arrays `0xfffffe0007949dd0` / `0xfffffe000792fbc0`; key 0xb4, constant 0x6e, add 0xebd, index 0xf2b; slot `0xfffffe000847a878` -> `_IOFreeTypeImpl` |
| Retirement descriptor bank | Arrays `0xfffffe0007949fd0` / `0xfffffe000792ffc0`; key 0x37, constant 0x3a, add 0xaa, index 0xe4; slot `0xfffffe0008472620` -> retirement descriptor |

All 256 byte inputs per bank rule and both original array copies are checked. Matching descriptor metadata supports the typed request correspondence. It does not prove native retirement effects, lifetime completion, clearing of retained aliases or any returned API status. The previous synthetic NULL-node boundary and this NULL-data retirement request concern different allocation results.

## Non-NULL data: writer handoff and required state

The non-NULL preparation at `0xfffffe000a661884` through `...18e8` exclusive supplies the following ABI before the authenticated transfer to `0xfffffe000a654ad4`, index 0x543, modifier 0xdfc5. [ED4]

| Register | Value at transfer |
| --- | --- |
| X0 | 0x02e859d27e491464 |
| W1 | SUCCESS=0x31ae0066 |
| X3 / X11 | S / C |
| X16 | J+0x18: address of the buffer-pointer cell, not Z |
| W23 | raw tag D XOR0x2502309f |
| W14 / W25 | 0x7795e642 /0x886a1ca3 |

The same entry is reached by the separately analyzed later constructor. That correspondence establishes a shared code entry and compatible selected fields; it does not establish that their current nodes or storage epochs are identical. In particular, early J is retained at C+0x58, while the later constructor's analyzed J is retained at C+0x6b8.

The writer setup reads the following cells in order. Definedness is measured from original source provenance in all 60 current cases, not from the poison bytes' numeric values. Snapshots of unexecuted inputs are post-prefix observations, not source reads or repairs. [ED5]

| Cell | Width | Load PC | Current source-defined bytes |
| --- | --- | --- | --- |
| C+0x768 | 8 B | `0xfffffe000a654ae4` | 0 |
| S+0xd30 | 4 B | `0xfffffe000a654af0` | 0 |
| C+0x458 | 8 B | `0xfffffe000a654b04` | 0 |
| C+0x140 | 8 B | `0xfffffe000a654b0c` | 0 |
| C+0x6b8 | 8 B | `0xfffffe000a654b14` | 0 |
| S+0xe28 | 4 B | `0xfffffe000a654b20` | 0 |
| S+0xdf8 | 4 B | `0xfffffe000a654b2c` | 0 |
| C+0x58 | 8 B | `0xfffffe000a654b38` | 8; J |
| S+0x94 | 4 B | `0xfffffe000a654b40` | 4; early encoded length |
| S+0x110 | 4 B | `0xfffffe000a654b48` | 4; early encoded scalar channel |
| S+0xb90 | 2 B | `0xfffffe000a654b54` | 0 |
| S+0x1b2 | 2 B | `0xfffffe000a654b68` | 2; early type Ue |
| Total | 64 B | Twelve loads | 18 defined /46 unknown |

The first eight-byte load has no source-defined value. Each non-NULL case therefore stops before `0xfffffe000a654ae4`. That instruction executes neither a read nor a store. Native allocator zeroing, authentic incoming state and complete initialization epochs remain outside this model; an undefined model cell is not evidence of native uninitialized memory.

For conditional analysis only, a fresh original-word lift supplies arbitrary symbolic values for all twelve cells. Under disjoint stable F/C/S epochs, it establishes:

| Setup result | Exact source value |
| --- | --- |
| X9 / X13 / X15 | contents(C+0x768/0x458/0x140)+0x18, respectively |
| X10 and saved F+0x50 | contents(C+0x6b8)+0x18; contents(C+0x6b8), respectively |
| X22 / X8 | contents(C+0x58); contents(C+0x58)+0x18 |
| X16 | Incoming pointer-cell address preserved |
| F+0x9e0 / F+0x9d0 / F+0x480 | S+0xd30 / S+0xdf8 / S+0x110 values XOR0x14ac30f9 |
| W7 / W6 | S+0xe28 / S+0x94 values XOR0x14ac30f9 |
| low8(W19) / low8(W30) | high8(Ul) XOR0x36 / low8(Ul) XOR0x5e, with Ul=contents16(S+0xb90) |
| low8(W11) / low8(W3) | high8(Ue) XOR0xa2 / low8(Ue) XOR0xe3, with Ue=contents16(S+0x1b2) |
| W17 | 0x439, selecting the previously analyzed first word-writer entry |

X3 and X11 are input roots only until their last setup uses; later W3/W11 writes replace them with type-byte channels. The early header already proves Ue=raw_type XOR0xa2e3, so its last pair recovers raw type high/low bytes. The other pair similarly corresponds to raw_type XOR0x365e only if that later type field's provenance is independently joined. No missing cell is populated in the continuous execution to obtain this conditional proof.

The setup thus prepares several retained roots and metadata channels together. Treating it as a single-node serializer hides actual mandatory inputs. Earlier protected-header/copy proofs remain conditional on their stated inputs; this entry continuation does not yet satisfy all of them.

## Located source return stores and bounded inventory

Five local post-call sequences reload C from F+0xa28, reload the table root from F+0xa60 and store the returned X0 into a retained cell. The fresh obligations prove each store for an arbitrary 64-bit return under those explicit frame/context premises. [ED6]

| Retained cell | Three-word post-call sequence start | Return store PC | Executed in current prefix |
| --- | --- | --- | --- |
| C+0x768 | `0xfffffe000a6547a4` | `0xfffffe000a6547ac` | No |
| C+0x458 | `0xfffffe000a65c46c` | `0xfffffe000a65c474` | No |
| C+0x140 | `0xfffffe000a65ccbc` | `0xfffffe000a65ccc4` | No |
| C+0x6b8 | `0xfffffe000a6425d0` | `0xfffffe000a6425d8` | No |
| C+0x58 | `0xfffffe000a661668` | `0xfffffe000a661670` | Yes |

These are concrete provenance joins to investigate. Their local store contracts do not establish which earlier control path admits each call, which descriptor/return applies in a native epoch, or that all five values coexist at this writer entry.

The full 50634-word container additionally yields 69 syntactic memory-access sites with a non-SP base and one of the twelve exact displacements. Their original bytes and disassembly are retained. This is not an alias-complete writer inventory: other-base identity, indexed/overlapping accesses, paired accesses starting elsewhere, calls and SP epochs require separate analysis. The five local sequences are not declared the only possible writers.

## Independent checks and falsification

| Check | Verified count |
| --- | --- |
| Continuous cases / exact predecessor prefixes | 60 /60 |
| NULL / non-NULL data-return fixtures | 30 /30 |
| Source visits / GPR values | 118782 /3684102 |
| NZCV epochs / final D-register values | 118842 /1920 |
| Reads / checked read bytes | 10950 /56028 B |
| Writes / checked write bytes | 23100 /172452 B |
| Logical edges / register-only models | 1332 /300 |
| Frame/workspace/context snapshot bytes | 1488960 B |
| H / input / J snapshot bytes | 960 B /936 B /1920 B |
| Data / writer-input snapshot bytes | 3840 B /3840 B |
| Captured source spans / words | 9 /164 |
| Bank inputs / syntactic inventory sites | 512 /69 |
| Source obligations / lifted instruction instances | 9 /104 |

The nine nonvacuous obligations cover data retention/selection, early writer ABI, common retirement selection, five post-call stores and conditional writer setup. Two copied-source NOP controls remove the buffer-field store or the X16 pointer-cell preparation. The first stops before the undefined J+0x18 cleanup read. The second retains the normal undefined-C+0x768 frontier but fails the handoff ABI oracle. Independent replay checks both; neither executes an undefined/unbacked value load. [ED7]

Production costs O(B+I+512+C*(B+V+E)) time/retained space for image bytes B, captured instructions I, cases C, visits V and byte events E. Independent replay costs O(V+E+M) per case for snapshot extent M. No case reaches its 30000-visit cap. Symbolic DAG construction is linear in lifted instructions; solver search is separate, limited to 30 s/query. No native target or IDB is executed or modified.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ED-A1: Pinned images, container, original pointer format and predecessor receipts apply. | ED1-ED8 | Rehash images/container/dependencies; compare words, bank arrays, original slots, metadata and symbols. |
| ED-A2: Original-entry fixtures and separated F/S/C/H/J/I/data extents apply. | ED1-ED8 | Rebuild 60 cases across profiles/controllers/placements and compare every epoch and exact predecessor prefix. Native admission is unknown. |
| ED-A3: PAC/AUT and authenticated transfers are logical in the private model. | ED1-ED8 | Check original words, slots, modifiers and edge journals; native authentication requires independent machine state. |
| ED-A4: Five register-only allocator returns preserve the declared other state and have no RAM effects. | ED1-ED8 | Verify each call, clobber epoch and byte provenance. Native zeroing, outcome and ownership need separate contracts. |
| ED-A5: Explicit phase constants, stable cells and disjoint nonwrapping storage premises hold at each symbolic cut. | ED2-ED8 | Re-solve nine satisfiable-premise obligations; retain the distinction between continuous defined bytes and arbitrary conditional inputs. |
| ED-A6: The independent interpreted instruction subset matches visited effects. | ED7 | Compare all CPU/memory/control epochs, independently decode the twelve input snapshots and reject both source mutations. |
| ED-A7: Shared entry and local store identities do not establish temporal coexistence, complete aliases or native object identity. | ED5-ED6, ED8 | Join actual incoming control paths, source writes, intervening effects and native allocation/caller state before composing a complete serializer or transaction. |

## Bounded continuation and interface limits

| Impact | Discriminating next work | Result sought |
| --- | --- | --- |
| High | Trace incoming control and allocation contracts for C+0x768/0x458/0x140/0x6b8 and the four missing metadata cells. | Establish the writer's required state without repairing the continuous prefix. |
| High | Establish exact-target allocator memory effects and original caller admission. | Distinguish private unknown bytes from actual native initialization and data ownership. |
| High | Join the admitted daemon request and original kext input/protected staging epochs. | Establish matched transport and buffer/object identity. |
| Medium | Continue the typed-node retirement return under an explicit lower contract. | Establish alias clearing, outer container cleanup and returned operation status. |
| Medium | Locate S+0x20 writers along the newly identified provenance/control paths. | Establish the tunnel-marker producer; C+0x20 remains the distinct H cell. |
| Low | Refine retained-root/tag roles from original type/name metadata. | Improve names without assigning unsupported business semantics. |

S+0x20 remains unknown/unread and Q remains opaque. No new incoming Mach port, outgoing message, transferred right, message identifier or emission site is established. Existing transport evidence remains in the [Mach-port report](mach_ports_report.md). Complete serialization, native lifetime/PAC and matched daemon/kext identity remain unknown; the full goal is active. [ED8]

## Quality gates

**QG1** Pass: factual technical analysis. **QG2** Pass: ED-A1-ED-A7 state dependencies and falsification probes. **QG3** Pass for this increment: obfuscated routine continuation, pointer-cell ABI, data/control flow, required-state provenance, allocator/retirement interfaces and transport limits covered; full goal active. **QG4** Pass: widths, byte totals, modular domains, exact counts and complexity are reproducible. **QG5** Pass: native effects versus private unknowns, data versus node NULL results, conditional writer proofs versus continuous execution, and store identities versus temporal/alias completeness are distinguished. **QG6** Pass: pinned original/normalized words, pointers, arrays, metadata, independent replay, source proofs and rejected mutations support the claims. **QG7** Pass: impact-ranked continuation above. `full_goal_complete=false`.
