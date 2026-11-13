# Cached path, network-record fields and entropy interfaces in the arena context

Original source at `0x1004b4580` stores the second allocation return in raw context C+0x10 before testing NULL or filling the allocation. Success decodes `/var/db/fpsd/SC Info\0` into that 21-byte allocation, copies the network-record count into C+0x1c and its six data bytes into C+0x20, then initializes further context fields. The successful route enters two nested helpers and reaches `arc4random`; declared random returns seed a 624-word image state and reach `gettimeofday`. These are local context, representation and environmental-input interfaces. Native synchronization, filesystem use and daemon-kext delivery remain unknown. [CSP1-CSP5]

A NULL second allocation instead reaches `free` for the first encoded temporary allocation. Under explicit void-return and pthread-return premises, the original failure suffix reaches context-token unlock and fallback write-lock calls, reseals all552 context bytes and republishes the encoded reference at `0x1009a2014`. Its final context/reference bytes match the constructor codec. Source order is established; native lock ownership and inter-thread visibility are not established. [CSP2,CSP4-CSP5]

```text
second malloc(21) return
  -> C+0x10 = returned pointer, before NULL test
  |
  +-- NULL -> pending free(encoded temporary)
  |            + declared free return and owner retirement
  |         -> context-token unlock -> fallback write-lock
  |         -> seal 552 bytes -> encode reference -> fallback unlock
  |         -> STOP at undefined caller pointer S+0x12a0
  |
  +-- non-NULL -> decode 20 bytes + NUL into second allocation
               -> C+0x1c=count6, C+0x20=data6
               -> initialize additional descriptor-shaped fields
               + four separate caller roots and metadata premises
               -> pending arc4random()
                    + declared random u32
               -> seed 624 u32 words -> pending gettimeofday(out,NULL)
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CSP1 | Original thin-image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_context_state_publish.py) retains source regions, every visited instruction word, effects, frames, owners and logical fixups. |
| CSP2 | Frozen [lock-use checks](triage_evidence/daemon_context_lock_use_checks.json.zst), decoded SHA-256 `ce8d539c6aa4f83cb5130a7f3351fbe30f29c0f5a41b23efeceb33424240e44f`; this increment continues its two successful first-allocation component controls. |
| CSP3 | [Initializer receipts](triage_evidence/daemon_return_bank_origins_checks.json.zst) and [constructor snapshot](triage_evidence/daemon_context_lock_snapshot.json.zst); twelve root-writer ledgers, fresh initializer replay and separately transferred metadata bytes qualify the success continuation. |
| CSP4 | [New checks](triage_evidence/daemon_context_state_publish_checks.json.zst): six allocation/data controls and eight random-return controls; complete GP/Q/NZCV state, separate return/root/image/input premises and owner retirement. |
| CSP5 | [Independent auditor](triage_evidence/audit_daemon_context_state_publish.py) and [audit receipts](triage_evidence/daemon_context_state_publish_audit.json.zst): scalar/AdvSIMD replay, byte/state joins, exact reseal comparison, six nonvacuous UNSAT obligations, initializer replay and compile-only current arm64e ABI checks. |
| CSP6 | [Publication verifier](triage_evidence/verify_daemon_context_state_publish_publication.py): hashes, original-input preservation, manifest delta, compressed archives and raw/typed/decoded path hygiene. |

## Raw context and allocation contracts

| Source | Destination or interface | Established width and operation |
| --- | --- | --- |
| `0x1004b4580` | C+0x10 | Store full u64 second malloc return before the NULL test |
| `0x1004d4ca0..0x1004d4cac` | Encoded temporary A -> second allocation B | Twenty one-byte reads/writes; decode each byte with XOR `0x98` |
| `0x1005c3d98`, `0x100597960` | B+20 | Two one-byte zero stores to the same terminator location |
| `0x100597974..0x10059797c` | Network record prefix -> C+0x1c | Copy u32 count6 without conversion |
| `0x10059ccd4`, `0x10059ccd8` | Record+4+i -> C+0x20+i | Reverse-index copy, i=5..0; all six bytes preserved |
| `0x100836124` | Pending `free(A)` on NULL second allocation | X0=`0x6600003000`; native free remains unexecuted |
| `0x1009a2014` | Reference cell `0x1010c9298` | Store encoded reference after complete context resealing |

C=`0x6500115b20` owns552 B; A=`0x6600003000` and B=`0x6600004000` each own21 B under explicit allocation premises. B begins entirely undefined. Source fills21 unique bytes using22 one-byte writes and performs no B-content read in this increment. C+0x10 is a cached decoded-path pointer on the checked success route. Its early pointer publication does not prove initialization visibility or exclusion. [CSP2,CSP4-CSP5]

The carried record at `0x1010c5764` contains u32 count6 followed by six zero-valued bytes. A separately labeled control replaces only those six data bytes with `01 32 45 67 89 ab`; source count and all other caller state remain joined. Exact source reads at record+9..record+4 match writes at C+0x25..C+0x20. The nonzero control and arbitrary-byte source theorem establish copying rather than merely observing zero output. Native MAC-address validity and delivery are not inferred from these local inputs. The [network-identity report](daemon_network_identity_report.md) separately covers the upstream IOKit MAC-property helper. [CSP2,CSP4-CSP5]

Success also writes two repeated layouts at C+0x158 and C+0x198, with stride0x40. The source-defined fields are listed below; the gaps remain inherited context bytes, not new zero initialization. A native structure name or decoded descriptor meaning is unknown. Both layouts remain inside the declared552-byte owner. [CSP1,CSP4-CSP5]

| Offset relative to either layout | Width | Source-established initial value |
| --- | --- | --- |
| +0x00 | u64 | `0xe3b88695c0d52dbc` |
| +0x08 | 8 B | No write by this initializer |
| +0x10 | u32 | `0x0912f04b` |
| +0x14 | 4 B | No write by this initializer |
| +0x18,+0x20,+0x28,+0x30 | Four u64 | Zero |
| +0x38 | u64 | `0xfffffffffffffffb` |

Source `0x1005d22bc` separately writes u32 zero at C+0x1d8. The complete success continuation performs23 context write events totaling126 B: pointer8 B, count4 B, network data6 B, two layouts52 B each and marker4 B. The repeated layouts are not the constructor's separate twenty48-byte global slots. The sentinel also occurs in other recovered local representations; shared bits alone do not prove shared type or ownership. [CSP4-CSP5]

## Metadata roots, nested calls and environmental inputs

| Separate caller root | Pointee | Original initializer writer |
| --- | --- | --- |
| S+0x3f8 | u32 index at `0x1010c6830` | `0x1004c2f18` |
| S+0x408 | Word-array base `0x1010b5d70` | `0x1004c2854` |
| S+0x400 | Byte flag at `0x1010c6818` | `0x1004c2ea4` |
| S+0x410 | u64 controller at `0x1010b8d78` | `0x1004c354c` |

Each root has one u64 writer and no later overlap in each of twelve preserved initializer profiles. Each is supplied only after its original undefined-read stop. The separate constructor-compatible image transfer contains index0, seven preserved u32 array words, flag0 and one u64 controller: 4+28+1+8=41 B. Exact source updates include the selected array word at `0x1005d2278` and index0 -> 1 at `0x1005d22b0`. This is an explicit state premise, not an observed native epoch join or silent substitution of writable file bytes. [CSP3-CSP5]

| Source call | Target/interface | Established touchpoint |
| --- | --- | --- |
| `0x100605f18` | `0x100add594`, IA modifier `0x22a0` | X0=record S+0x10cb8, X1=scratch S+0xbbc8 |
| `0x100add7d4` | `0x100acd9c4`, IA `0x7c25` | Same X0 record; X1 equals the nested caller's current SP |
| `0x100b33030` | Shared record helper `0x10041a5e0`, IA `0xec9d` | X0=current SP+0x290, X1=0, X2=0x20 |
| `0x100a8c0c0` | Pending `arc4random`, IA `0x2692` | Current SDK prototype returns u32 and takes no parameters; incoming GP contents are not API arguments |
| `0x100b4db4c` | Pending `gettimeofday`, IA `0x9298` | X0=current SP+0x230, X1=NULL |

Under declared random return s, source `0x100a8c0c4` stores S[0]=s at `0x1010c784c`. Original loop `0x100ab7598..0x100ab75c8` stores indices1..623:

```text
S[0] = random_return_u32
S[i] = u32(1812433253 * (S[i-1] XOR (S[i-1] >> 30)) + i)
       for i = 1..623
```

Every one of624 stores is checked against this independent recurrence for both return controls0 and `0xffffffff`. The state occupies2496 B, ending at exclusive address `0x1010c820c`; the last word is at `0x1010c8208`. The [return-bank report](daemon_return_bank_origins_report.md) covers a separate reader/update of that same state region. This increment establishes seeding, not a cryptographic role or native randomness quality. [CSP4-CSP5]

The current arm64e SDK compile check establishes a16-byte `struct timeval`, alignment8 B, seconds field at offset0 with width8 B, and microseconds field at offset8 with width4 B. Its final4 padding bytes are not a time value. The clock call is pending: no clock return, output bytes, padding contents or subsequent use is modeled. Historical SDK/runtime identity remains unknown. No source-level context unlock occurs on the checked success route before these entropy/clock boundaries; native lock ownership remains unknown. [CSP4-CSP5]

## Failure representation cycle and provenance checks

The NULL branch passes A to pending free at `0x100836124`. A declared void return retires that21-byte owner; no later source read or write touches it. Historical fixture bytes remain recorded as evidence of prior state, not proof of live ownership. The subsequent import sequence is once, context-token unlock, once, fallback wrlock, once and fallback unlock. In these component controls the context-token argument is `0x6600001000`; the fallback argument is `0x1010b7478`. Native calls remain unexecuted. [CSP4-CSP5]

The resealing interval writes2184 B across the552-byte context: the byte transform and repeated in-place word swaps create more write traffic than unique owner bytes. The final context equals the independent constructor codec `encode(raw_context,0x78396e8d)` byte for byte. The encoded reference equals the earlier codec with fold `0xc41c69cd`, yielding `0xe5f6a0000600f0c1`. All context stores precede the reference publication at `0x1009a2014`. After fallback cleanup, source stops before an undefined u64 caller pointer at S+0x12a0, PC `0x1006a6a08`. No caller-pointer value or final externally visible failure is supplied. [CSP2,CSP4-CSP5]

The independent audit derives saved-continuation addresses from replayed current SP at the visited return sites: six origin checks across the two failure controls. An interval can begin inside the112-byte adapter frame and later restore SP; using interval-entry SP throughout would inspect the wrong slots. A separate X5 origin chain checks the original table load at `0x10051c01c`, source store, intervening register reuse, reload at `0x1005da0a0` and branch at `0x1006eab3c`. Overlapping writes invalidate retained memory provenance. These checks preserve the original fixup target and authenticated-branch modifier constraints; hardware PAC is not executed. [CSP1,CSP5]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CSP-A1: Pinned thin image and logical fixups identify the source | All operations and call targets | Verify source SHA-256, every visited opcode, used fixups and original branch modifiers. |
| CSP-A2: Frozen successful first-allocation component states apply | Second allocation and context writes | Exact bytes, GP/Q/SP/NZCV and owner joins to parent cases1 and3; native reachability and shared constructor/caller epoch remain unknown. |
| CSP-A3: Declared pointer/import returns and ABI preservation admit each suffix | Allocation branches, cleanup and seeded state | Check exact return joins; preserve low64 Q8..Q15 and X18..X29; carry two joint status/clobber fixtures. No native API outcomes are inferred. |
| CSP-A4: A/B ownership and declared free retirement apply | Byte initialization and lifetime boundaries | B starts undefined; verify22 stores to21 bytes, no B-content read, no post-retirement A access and exact owner lists. Native allocation/free behavior remains unknown. |
| CSP-A5: Four initializer-compatible roots and41 metadata bytes apply separately | Metadata and nested helper route | Preserve undefined stops; check twelve writer ledgers, no overlap, fresh initializer replay and exact snapshot bytes. Native epoch linkage remains unknown. |
| CSP-A6: Separate nonzero data and random-return fixtures qualify local flow | Six-byte copy and state recurrence | Retain carried-zero controls; label data replacement; compare all bytes and624 words for each declared seed. Neither control is an observed native input. |
| CSP-A7: Scalar/AdvSIMD and provenance models match source semantics | Replay and algebra | Check every GP/Q/NZCV state and memory effect, current-SP saved slots, X5 store/reload provenance and six nonvacuous source obligations. Unsupported behavior fails closed. |
| CSP-A8: Current arm64e SDK is an ABI comparison, not historical runtime evidence | Pending entropy/clock API interpretation | Compile only, pin header hashes and source; leave clock output and historical version unknown. |
| CSP-A9: Pending clock and undefined caller-pointer stops bound this increment | Remaining native/transport behavior | Continue those actual boundaries separately. Filesystem use, successful-path release/reseal, native synchronization and daemon-kext delivery remain unknown. |

Six main cases use one retained constructor/caller state under two parent clobber fixtures: NULL second allocation with carried data; successful allocation with carried zero data; and successful allocation with a separate nonzero six-byte control. They do not extend allocation coverage to all thirteen constructor profiles or every parent caller. Eight child controls combine each of the four success boundaries with random returns0 and `0xffffffff`. Imported pthread status35 is a synthetic ABI fixture, not a claimed native return. Once completion supplies no additional callback or imported memory effects. [CSP2,CSP4-CSP5]

## Verification and bounded continuation

The receipts contain44 intervals,80,688 original visits,7642 read events,6384 write events,5338 logical edges and18 internal call records. Independent replay checks2,583,424 GP/SP values,2,583,424 full Q-register values,80,732 NZCV states,56,908 read bytes and28,986 written bytes. It verifies5328 authenticated-branch origins/modifiers, six current-SP saved origins, and four complete X5 store/reload/branch chains. Twelve fresh initializer runs cover21,396 source visits and48 new live root cells. [CSP4-CSP6]

Six nonvacuous UNSAT obligations qualify full-u64 pointer publication/NULL selection, arbitrary-byte XOR decoding, an arbitrary reverse-copied byte, arbitrary-u32 count publication, the arbitrary-u32 seeding recurrence, and seed-store independence from unspecified upper32 return bits. Whole-context reseal equality is checked for the two concrete failure controls; no new all-seed theorem for that separate forward source body is claimed. [CSP5]

Extraction and replay use O(receipt bytes + cases*(visits+effects)) time/storage, excluding solver work. The path transform is O(n) time with n=21 B output and O(1) source auxiliary state. Generator seeding is O(N) time with N=624 words and4N=2496 B state. Context resealing is O(m) time, m=552 B, with O(1) in-place auxiliary storage. Each solver query has a30 s limit. Integer widths, counts and address extents are exact under the stated premises. [CSP4-CSP6]

| Impact | Next evidence | Purpose and current limit |
| --- | --- | --- |
| High | Follow the pending gettimeofday return and output consumers | Establish how time joins seeded state and the nested helper; no clock output is supplied here. |
| High | Follow the decoded path and repeated context layouts through actual filesystem, IOKit or Mach call sites | Identify downstream architectural consumers; current allocation and stores prove local state only. |
| High | Recover successful-path unlock/reseal and continuous constructor/caller admission | Determine representation-validity and synchronization lifetimes; the success boundary still has raw context/reference state. |
| Medium | Recover semantic encodings/readers of the two repeated layouts | Distinguish shared sentinel bits from shared descriptor meaning; gaps and native types remain unknown. |
| Medium | Establish the missing S+0x12a0 pointer producer on the failure route | Complete caller result flow; no value is substituted at the current stop. |
| Low | Correlate later transport emission with the existing daemon/kext port and method mappings | This suffix adds no source-established Mach port emission, right disposition or daemon-kext transaction. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: CSP-A1-CSP-A9 identify dependencies and falsification probes. **QG3** passes for this increment: path publication/decode, network fields, repeated layouts, failure resealing and entropy/clock boundaries are covered; the broader goal remains active. **QG4** passes: modular widths, field gaps, owner extents, byte/event counts and complexity are explicit. **QG5** passes: raw/encoded phases, declaration versus native behavior, concrete versus universal checks and incomplete continuations remain distinct. **QG6** passes after original-byte, independent replay, provenance, initializer, solver, SDK, receipt and publication checks. **QG7** passes: the impact-ranked continuation and present transport/native limits are bounded above.

Decoded checks SHA-256: `a0c631dcec58e837f66de9a1222f9789d8058b98d89b79c685393a5fcbbfa74e`. Decoded audit SHA-256: `157858700ca7dd19ca2651c78ffebce0a502953fbb5599059a8ffc7c47dcec53`.
