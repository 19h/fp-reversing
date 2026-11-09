# A70 output publication and the encoded extent interface

The source component at 0x100582808 publishes an unchanged u64 pointer and a decoded u32 extent into the two borrowed output cells, then assigns raw success marker 0x8b3dc651. The 64-bit mixed Boolean/arithmetic expression for the extent is exactly `zero_extend64(encoded_u32 XOR 0x8b3dc651)`. Its upper 32 bits are zero for every input. This establishes the successful-result publication component; allocator provenance, buffer contents, readable extent, full construction and native reachability remain unknown. [OP1-OP3,OP8]

The incoming gate at 0x10059c7d0 selects this publisher only when its saved raw result equals the marker. Other values bypass publication. Both routes enter 0x1004de1d4, which stages the raw result and selects an internal cleanup owner. That block has a common result-staging role; its earlier allocation-failure use is a narrower instance of that role. [OP2,OP6]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid VAs; offsets/constants are hexadecimal; byte counts are decimal. Evidence: [original source and census](triage_evidence/daemon_output_publication_source.json), [static proofs and checks](triage_evidence/daemon_output_publication_checks.json), [preservation](triage_evidence/daemon_output_publication_delivery.json), [quality gates](triage_evidence/daemon_output_publication_quality_gates.json).

## Gate, publication and shared staging

K denotes the core frame SP. The following component assumes original tag/phase u32[K+0x9d0]=0x6cf4 and the original dispatch table at K+0x9d8. The raw input to this gate is s=u32[K+0x8c54]; its complete producer is not established here. [OP2,OP3]

```text
0x10059c7d0
  W8 := 0x6cf4 - 0x2427 = 0x48cd
  local cursor K+0x16d0 := cursor - 48 B
  |
  +-- s == 0x8b3dc651 --> table[0xc268] -> 0x100582808
  |    D := u64[K+0x70c8]
  |    N := u32[K+0x3928]
  |    *borrowed_pointer_cell := D                  8 B
  |    *borrowed_extent_cell := zero_extend64(N XOR 0x8b3dc651)
  |                                                8 B
  |    W6 := 0x8b3dc651
  |    -> table[0x48cd] ------------------------+
  |                                           |
  +-- s != 0x8b3dc651 --> table[0x4146] -------+
                                              v
                                      0x1004de1d4
                                      u32[K+0x44a4] := W6
                                      X20 := u64[K+0x1360]
                                      u64[K+0x5f68] := X20
                                      -> table[0x39b4]
                                      -> 0x1005aa740
```

| Source site | Contract | Width |
| --- | --- | --- |
| 0x10059c7dc | Read raw inner result from K+0x8c54 | 4 B |
| 0x10059c7f8 | Restore the local cursor by 48 B | 8 B modular value |
| 0x100582818 / 0x100582820 | Read K+0x70c8; publish through address at K+0x1a30 | 8 B |
| 0x100582824 | Read encoded extent N from K+0x3928 | 4 B; zero extension into X9 |
| 0x1005828bc | Publish decoded extent through address at K+0x7098 | 8 B; upper half zero |
| 0x1005828c8..0x1005828cc | Assign W6=0x8b3dc651 after both output stores | u32 marker |
| 0x1004de1e0 | Stage W6 in K+0x44a4 | 4 B |

| Edge | Original slot | Target | IA diversity |
| --- | --- | --- | --- |
| Inner marker | 0x10109b230 | 0x100582808 | 0x0248 |
| Inner nonmarker | 0x10105a920 | 0x1004de1d4 | 0x0248 |
| Outputs published | 0x10105e558 | 0x1004de1d4 | 0x173b |
| Result staged | 0x101056c90 | 0x1005aa740 | 0x814f |

Each selected original pointer uses IA and address diversity zero. The caller's raw result is preserved by the two-way composition: the marker branch writes the same marker, and the nonmarker branch retains s in W6. Subsequent cleanup and terminal consumption still require preservation of K+0x44a4 and normal returns. The [terminal-output report](daemon_xpc_error_outputs_report.md) supplies the later marker/nonmarker gate, protected-result publication and canary boundary. This report does not substitute a successful cleanup run for that missing continuous path. [OP2,OP6]

The cursor decrement is an original XOR identity: `zero_extend64(0x48cd) XOR 0xffffffffffffb71d = 0xffffffffffffffd0`, i.e. -48 modulo 2^64. K+0x16d0 is a local frame cursor used by the helper setup below. It is a different cell from the adapter's budget/output word. This decrement does not establish that the caller's returned SP delta is zero. [OP2,OP7]

## Exact extent codec and pointer limits

For z=zero_extend64(N), the original expression is:

```text
a = (z XOR 0x327d5b04c58c3b05) + 0xcd82a4fb3a73c4fb
b = (z XOR 0xa835841070e0199b) + 0x57ca7bef8f1fe665
c = (z XOR 0x9a48df143e51e4cf) + 0x65b720ebc1ae1b31
L = (a XOR b XOR c) + (zero_extend64(W19) XOR 0x8b3daaa5)
```

All additions are modulo 2^64. The source computes W19=`((0x48cd+0x1f63) OR 0x4c4)=0x6cf4`. Translating all 46 original instructions before the post-publication table load into 44 SMT SSA definitions proves, for every N and arbitrary u64 pointer D, that the two emitted stores are D and `zero_extend64(N XOR 0x8b3dc651)`. No sampled arithmetic identity is substituted for this all-input proof. [OP1-OP3]

Consequently `0 <= L <= 4,294,967,295 B`. N=0x8b3dc651 yields L=0; N=0x74c239ae yields L=4,294,967,295 B. These are arithmetic cases, not observed requests or allocations. A separate byte-array proof checks the two exact 8 B stores and preservation of all other caller-frame bytes at the known output offsets. [OP3]

The publisher neither checks D for NULL nor establishes its readable extent. Assigning the marker here does not prove allocation success, initialized output bytes or unique ownership. Those properties must come from earlier producers. No buffer content schema or semantic error name is assigned. [OP8]

## Preceding helper output cells

The source exposes another output interface with an 8 B pointer and a 4 B encoded extent. This is a conditional same-frame data-flow composition, not a recovered complete call/return path. [OP3-OP5]

| Stage/site | Source-defined interface |
| --- | --- |
| 0x10058d5f0..0x10058d5f4 | X11 := &u32[K+0x3928] |
| 0x10058d5f8..0x10058d5fc | X9 := &u64[K+0x70c8] |
| 0x1005db640 | Save X11 in K+0x2988 |
| 0x1005db6c8 | Save X9 in K+0x2d20 |
| 0x1007518b4..0x1007518bc | Read u64[K+0x8378], then store it through u64[K+0x2d20] |
| 0x1007518c0..0x1007518c8 | Read u32[K+0x1210], then store it through u64[K+0x2988] |
| 0x100847980..0x100847984 | Further nested component supplies X19 := &u32[K+0x1210] |
| 0x100847988..0x10084798c | Further nested component supplies X8 := &u64[K+0x8378] |

At 0x10058d604 the selected helper edge is table[0x1997], slot0x101046ba8, target0x1005db618, IA diversity0x8bfa. This target applies when the incoming state selects index0x1997; the incoming state is not replaced with 0x6cf4. The original index expression is `(W8 XOR 0x607b) XOR (W8+0x66dc)`. The nested component at 0x100847960 has a further state-dependent target; that target and the writers behind the nested cells remain unknown in the established contract. [OP4,OP5]

Under preserved saved addresses and one K epoch, the helper-return stores supply exactly the outer publisher's K+0x70c8/K+0x3928 inputs. A byte-array proof checks all pointer/extent bits, exact 8 B versus 4 B writes, preservation of the source cells K+0x8378/K+0x1210 and preservation of every other byte. It does not prove that the helper components execute consecutively or that the nested pointer is allocated. [OP3,OP5]

The setup forms a local 48 B view at R=K+0xc070+cursor. Calls at 0x1005db6e8 and 0x1005db73c select the existing internal byte-fill body 0x10046faf8 through slot0x1010a03c8, IA diversity0xac7d. They pass value0 and extents16 B at R, then32 B at R+16 B. Their half-open extents are disjoint and cover [R,R+48 B). The [frame-entry report](daemon_frame_entry_report.md) already establishes this internal fill body's role. Its original 356 B body is freshly recaptured here; the new coverage proof concerns the two extents, not a new all-input proof of the entire fill routine. [OP3,OP4]

The two 256-input bank checks resolve both fill selections. Original pool pointers plus biases supply the F-bank bases saved at K+0x5d0/K+0x5d8; the second call uses the inherited B-bank frame cuts. Preservation of those frame values is explicit. No malloc, native API or IPC is executed by this analysis. [OP1,OP4]

## XPC and transport consequence

The [XPC bridge](daemon_xpc_core_bridge_report.md) produces the borrowed addresses as pre-call SP+0x408 and SP+0x6e8. The [reply lifecycle](daemon_xpc_reply_lifecycle_report.md) attaches data only on marker0x8b3dc651, then writes decoded status and sends through the saved peer. For this component, with normal returns, preserved cells, matching frame epochs and caller delta zero, the attached extent is the decoded u32 value widened to u64. The existing `_xpc_dictionary_set_data` site is 0x100bd6a5c; send is 0x100bb4d08. [OP6-OP8]

The output publisher itself performs local stores and an internal branch; it emits no Mach message. It establishes no numeric port/right identity, actual libxpc scheduling/delivery or daemon/kext exchange. Data validity and successful transport remain separate from the marker and size codec.

## Locator census and evidence limits

The original __text section is scanned at all 3,712,490 aligned instruction words for each exact encoding. Register Rt is ignored; the base is literal SP and the addressing form is unsigned immediate.

| Exact encoding class | Matches | Interpretation limit |
| --- | --- | --- |
| LDR Xn,[SP,#0x1a30] | 10 | Terminal clear and nonzero publication identified; eight other frame/epoch roles unresolved |
| LDR Xn,[SP,#0x7098] | 2 | Clear and decoded-extent publication |
| STR Xn,[SP,#0x70c8] | 1 | Initial zero; escaped-address writers are separate |
| STR Wn,[SP,#0x3928] | 0 | Does not exclude alias/pair/vector/other-encoding stores |

All 13 matched contexts and the complete text hash are retained. Equal stack offsets are locators, not frame-identity evidence. In particular, zero literal stores do not imply an unwritten field: the helper-return aliases above provide a concrete indirect store component. [OP1,OP3,OP5]

## Validation and reproduction

Eleven source ranges retain369 instructions/1476 B. Forty-nine prior ranges are freshly compared over7692 B. The eight selected pointers and all61737 fixup memberships are checked. Independent validation passes67 instruction assertions, the46-instruction/44-definition publication translation, six complete SMT queries,32 arithmetic boundary cases, five gate cases and eight altered-evidence controls. No target code is run or emulated; the SMT translation is a static component certificate.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_output_publication.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_output_publication.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_daemon_output_publication.py
```

Capture/check complexity is O(image bytes + fixups + retained source bytes + text words), with space O(image + largest prior JSON + matched contexts). Publication is O(1) time/space; solver resources are additional. Values are little-endian u32/u64; mathematical addresses use modulo 2^64. Applying them to real storage requires the explicit valid/nonwrapping-owner premises.

## Assumption register

| ID | Premise | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| OP1 | Pinned original image/fixups and retained source are authoritative | PCs, operations, banks, edges, census | Rehash and recapture; compare selected words and fresh fixup membership |
| OP2 | Core phase at K+0x9d0 is0x6cf4 and table at K+0x9d8 is original | Inner marker partition, -48 B cursor and publisher phase | Recover actual incoming epoch/phase; do not substitute arbitrary phases |
| OP3 | Relevant owners are valid, distinct where required, writable/readable and nonwrapping | Store effects, local R48, helper and caller byte projections | Establish actual frame roots, alias writes and lifetimes before native application |
| OP4 | Helper-input index0x1997 and inherited bank-frame cuts apply; fill calls return normally | Selected helper interface and two fill calls | Establish incoming state and bank writers; compare original body and call arguments |
| OP5 | Saved output addresses and one K epoch survive between helper components | K+8378/1210 -> K+70c8/3928 -> caller outputs | Recover full logical continuation and every intervening writer; no synthetic relocation supplies this proof |
| OP6 | Cleanup/core/adapter return normally and retain status/output cells, guards and logical saved links | Later protected result and possible XPC data reply | Recover continuous source/native return; guard/PAC and full cleanup remain separate |
| OP7 | Caller returned delta=0 with no later output-cell overwrite | Post-return SP-relative loads consume these pre-call cells | Recover full adapter budget write history and actual before/after SP |
| OP8 | D allocation, contents, readable extent and unique ownership are unknown | Limits on data attachment, copying, freeing and success | Recover nested output writers and allocator/size/content consumers; marker alone is insufficient |

## Bounded continuation targets

| Impact | Next evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Writers behind K+0x8378 and K+0x1210, starting from the nested output-address producer | Actual allocation and encoded extent provenance |
| High | Saved continuations between helper-input, setup, return and core status gate | Continuous construction/return path and frame identity |
| High | Full adapter budget escape/write history | Delta-zero same-cell join at XPC reply preparation |
| High | Native selector26/RPC502/700 pairing and successful exchange | Actual endpoint/right identity and daemon/kext processing |
| Medium | Buffer content writers and format/length consumers | Serialization schema and initialized extent |
| Medium | Eight other literal SP+0x1a30 load sites | Additional frame roles without cross-epoch conflation |

QG1: Pass; factual source/interface analysis.
QG2: Pass; OP1-OP8 identify premises, dependent results and falsification probes.
QG3: Pass for this increment; output roles, helper/core/XPC data flow, conditional control and existing emission touchpoints are reported. The full interface goal remains active and incomplete.
QG4: Pass; exact byte widths/extents, modular equations, all-input queries, census bounds and complexity are explicit.
QG5: Pass within scope; publication versus allocation, component joins versus continuous execution, frame cursor versus budget, widened u32 versus general u64 size and local stores versus emission remain distinct.
QG6: Pass; original bytes/fixups, source recapture, explicit instruction-to-SMT translation and complete queries provide provenance.
QG7: Pass; remaining interfaces and opportunities are bounded by impact above.
