# Mode471C registry scans, head unlink and object-field interfaces

Mode471C searches a 16-byte key-record array using the low32 bits of an unmasked eight-byte query. On a tag hit, it reads the selected record's full64 key and header/token word, then searches a separate 32-byte payload-record array. A payload hit supplies an object pointer at+0x10. When the object's first u32 equals the selected key-record header/token, source `0x100A264E0` replaces that payload head pointer with the object's+0x360 link. The retained sequence then inspects further fields of the removed object. This establishes conditional search and head-unlink behavior; native registration, object allocation, complete cleanup and transport linkage remain unknown [RK1-RK14].

The 64 continuous source cases and256 independent A64 replays cover explicit private registry-state inputs. They do not establish native population of those registries. Forty-four cases return raw result `0x74C29F00`, free the eight-byte query input, and stop before the earlier unresolved caller-frame dereference. Twenty stop within object processing at genuine unknown-dependent comparisons. No additional original Mach or IOKit emission is established. The full daemon/kext/deeper-interface investigation remains active.

Evidence: [original source and bounded censuses](triage_evidence/daemon_registry_lookup_source.json), [54 array-state paths](triage_evidence/daemon_registry_lookup_profiles.json), [ten object-state paths](triage_evidence/daemon_registry_lookup_payloads.json), [contracts](triage_evidence/daemon_registry_lookup_contracts.json), [21 proof pairs](triage_evidence/daemon_registry_lookup_proofs.json), [216 array A64 replays](triage_evidence/daemon_registry_lookup_replays.json), [40 object A64 replays](triage_evidence/daemon_registry_lookup_payload_replays.json), [independent checks](triage_evidence/daemon_registry_lookup_checks.json), [source/predicate IDB bytes](triage_evidence/daemon_registry_lookup_live_ida.json), [word/initializer/object IDB bytes](triage_evidence/daemon_registry_lookup_more_ida.json), [unlink IDB bytes](triage_evidence/daemon_registry_lookup_unlink_ida.json), [direct-xref query](triage_evidence/daemon_registry_lookup_ida_refs.json), [preservation](triage_evidence/daemon_registry_lookup_preservation.json), and [scoped gates](triage_evidence/daemon_registry_lookup_quality_gates.json).

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| RK1 | Addresses identify thin arm64e SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. | Rehash source; compare27 spans,116 original fixups,every replayed opcode and1,472 fresh IDB raw bytes. |
| RK2 | The preceding caller/frame/bank/controller premises apply to entry39C894. Native incoming reachability remains unknown. | Run the original prefix and continuation with no fixture PC transitions; use two placements and controller pairs. |
| RK3 | The outer/inner bound words and array pointers are explicit initial-state inputs. | Retain every override; exercise outer bounds1/2/3/10 and inner bounds0/1/2/3/10. Native publishers and allocation continuity remain unknown. |
| RK4 | Private key/payload owners are disjoint and cover all accessed records. | Check each read/write against16*N or32*M bytes and prove unsigned index/extent bounds. Native owners and address validity remain unknown. |
| RK5 | The query points to eight initially specified bytes. | Independently derive both stack-word representations, preserve their source order and check all64 new concrete cases plus28 earlier arbitrary-byte cases. |
| RK6 | Imported synchronization/free operations return through the established ABI models; once is completed in these cases. | Verify every target/modifier/argument and preserved register; vary primitive status0/22 and volatile state. Native primitive effects and lock ownership remain unknown. |
| RK7 | Unspecified private/API bytes retain their identities, including object links and fields. | Use symbolic byte expressions and four independent physical backings; stop before unknown-dependent control/address effects. No arbitrary continuation target is supplied. |
| RK8 | Non-NULL object fixtures provide an872-byte private owner with a specified first u32; optional state at offsets+0x310/+0x360. | Verify all actual object reads at+0,+0xD8,+0x310,+0x360 and their widths. Only explicitly declared NULL fields become defined; native type/extent remain unknown. |
| RK9 | Raw key/tag/header values have only the proved transformations and comparisons. | Prove tag XOR decoding and full64 equality; retain the header comparison as raw-u32 equality. Header meaning and cryptographic purpose remain unknown. |
| RK10 | Candidate allocation/initializer blocks are inspected under declared frame/register roots. | Exhaust both256-byte bank domains and verify original slots. Incoming candidate phases and continuous allocation-to-publication paths remain unknown. |
| RK11 | Literal frame-slot,constant-construction and ADRP censuses are syntactically bounded. | Reproduce52 frame-slot matches,three bias constructions and227 page candidates. Aliases,paired/unscaled accesses,other constant constructions and frame changes remain excluded. |
| RK12 | Hardware PAC is abstracted as logical control transfers. | Verify original authenticated slots,modifiers,register targets and source return/frame behavior. Native authentication remains unknown. |
| RK13 | IDB raw bytes and displayed decoding have separate coverage. | Compare12 raw ranges; retain four undecoded byte rows and partial macro rows explicitly. A zero-result direct-xref query does not prove absence of obfuscated references. |
| RK14 | Old source artifacts remain frozen; two report narratives require correction. | Preserve old producers/proofs/journals and prove28 old intermediate-to-later-word relations, then hash the corrected reports in the new manifest. No native observation is retroactively claimed. |

## Correction: the two query-word representations

The earlier reports correctly established the word stored at callee SP+2A70, but described its later transfer to SP+3630 as a copy. Source `0x1009F016C` performs an additional XOR. The corrected sequence is:

```text
input bytes b[0..7]
  |
  +--9D0304: E = BE64(b) XOR9898989898989898 XORE3B88695C0D52DBC
  |             store E at SP+2A70
  |
  +--9F0168: read E
  +--9F016C: U = E XORE3B88695C0D52DBC
  +--975790: store U at SP+3630
  |             U = BE64(b) XOR9898989898989898
  |
  +--972914 on creator path: overwrite low32(SP+2A70) with471C
```

For this selected mode, source9F0120..9F012C produces phase `((0x471C-0x3F0C)|7)=0x817`. The constant constructed at9F0154..9F0164 plus that phase is exactly `0xE3B88695C0D52DBC`. The new source proof covers arbitrary u64 E; independent checks prove the E-to-U relation in all28 preceding symbolic journals. The earlier writer-to-reader check covered975790 toB353B4, so it did not validate the omitted relation from9D0304. The [producer report](daemon_descriptor_producers_report.md) and [lifecycle report](daemon_mode471c_lifecycle_report.md) now describe the additional transform; their original source proof files are unchanged [RK5,RK14].

The outer predicate consumes `low32(U) = BE32(b[4..7]) XOR0x98989898`. Its source identity holds for an arbitrary64-bit query. This is a statement about that predicate; later unknown interfaces are not assigned a query-width contract.

## Globals and record layouts

| Address | Source-established role | Width/stride | Native provenance |
|---|---|---|---|
| `0x1010C67C0` | Selected lock storage-pointer cell | u64 | Lazy lifecycle previously recovered |
| `0x1010C67D0` | Outer scan bound N; inspected initializer writes10 | u32 | Native publisher phase unknown |
| `0x1010C67A8` | Key-array base-pointer cell | u64;16-byte records | Native allocation/population unknown |
| `0x1010CA2B0` | Independent inner scan bound M | u32 | Native publisher phase unknown |
| `0x1010C9288` | Payload-array base-pointer cell | u64;32-byte records | Candidate allocation/publication blocks inspected |
| `0x1010C5754` | Separate counter addressed by the retained SP+21A8 value; candidate initializer writes0 | u32 | Full counter meaning unknown |

No common C structure follows from these addresses. N and M are independent source bounds. The earlier descriptor G=`0x1010C8218`, with48-byte records, remains distinct [RK1-RK4,RK10].

| Record | Offset | Accessed value | Established operation |
|---|---|---|---|
| Key,16-byte stride | +0 | u64 key representation | Loaded on a tag hit; encoded-zero sentinel isE3B88695C0D52DBC |
| Key | +8 | u32 tag representation | `raw_tag XOR8B3DC651 == low32(U)` |
| Key | +0x0C | Raw u32 header/token | Copied to SP+326C, then compared with the object's first u32 |
| Payload,32-byte stride | +0 | u64 key representation | Equality against selected key-record+0 |
| Payload | +0x10 | Object/head pointer,8 bytes | NULL test; source may replace it with object+0x360 |
| Payload | Other offsets | Unknown | No complete native C layout is inferred |

The inspected key initializer writes ten records: u64E3B88695C0D52DBC at+0 and u32 8B3DC651 at+8/+0x0C, a160-byte footprint. It also writes N=10 and the separate counter=0. The tag transform proves its initial tag represents0. The header/token's semantic decoding remains unknown.

## Search and mutation sequence

```text
query U -> outer tag scan, bound N
             |
             +-- no equal tag -> returning raw result74C29F00
             |
             +-- first equal tag
                   +-- load raw64 key and raw32 header/token
                   +-- read independent bound M
                   +-- initialize output index toFFFFFFFF
                   +-- scan payload records,32-byte stride
                         |
                         +-- full64 key hit -> store selected index
                               +-- read payload+10 object/head
                                     +-- NULL -> returning path
                                     +-- non-NULL -> compare object.u32[0]
                                           |
                                           +-- equal header/token
                                           |     head = object.u64[360]
                                           |     retain removed object locally
                                           |     inspect fields310 / D8
                                           |
                                           +-- unequal
                                                 read link at360
                                                 NULL closes retained branch;
                                                 arbitrary link remains unresolved
```

Offsets10/360/310/D8 in this diagram are hexadecimal. Outer source entry8BF64C and predicateBB01E8 select tag-hit targetB0C638 or miss/advance target96928C. On a miss the index increases by1; equality with N ends the scan. A tag hit enters the independent M gate at963CC0. Before the full-key comparison, source95E938 tests the selected raw key against the encoded-zero sentinelE3B88695C0D52DBC. The inner equality compares complete u64 representations at8BB518. Its index increases by1 and stops at M. The selected index is stored as u32 atB328C8; M is sourced from a u32, so the retained in-range index fits that store [RK3-RK5,RK9].

Under valid owners and returning primitive calls, these scan phases use O(N+M) time and O(1) scan state. The source breaks out of the outer scan at the first equal tag. Subsequent object-chain processing is incomplete, so no whole-routine complexity or termination bound is assigned.

The header-equal block is an observable state change: A264DC reads object+0x360; A264E0 stores the same eight-byte value to payload+0x10. Four retained traces execute this replacement, including two with an arbitrary link and two with a declared NULL link. No other key/payload/object-owner writes occur before the retained boundaries in these64 cases. Source behavior therefore supports a head-unlink role in this phase. The full routine name, native object ownership transfer and eventual release remain unknown.

## Partial object interface and exact boundaries

| Object-relative offset | Width | Established use | Remaining unknown |
|---|---|---|---|
| +0 | 4 bytes | Raw equality against key-record header/token | Semantic tag/generation/type |
| +0xD8 | 8 bytes | Loaded to X0 atC70CA8, followed by a NULL comparison | Field type and downstream consumer |
| +0x310 | 8 bytes | Loaded to X0 atB31CEC, followed by a NULL comparison | Field type and downstream consumer |
| +0x360 | 8 bytes | Read during head replacement and unequal-header continuation | Native chain allocation/lifetime |

The maximum accessed end is `0x360+8=0x368=872 bytes`. This is a minimum accessed extent under valid-object premises, not a recovered sizeof. Equating this object with the earlier standalone552-byte context would require an enclosing allocation or a different pointer/extent interpretation; neither is established.

| Frontier | Cases | Source fact at stop |
|---|---|---|
| `0x10039C998` | 44 | Raw result74C29F00 stored; cleanup and input free requested; caller SP restored; unknown frame-derived address |
| `0x100C744C4` | 14 | Matched payload+0x10 word remains arbitrary; stop before its comparison |
| `0x100B31CF0` | 2 | Header equality and head replacement completed; object+0x310 remains arbitrary |
| `0x100C70CAC` | 2 | Header equality, head replacement and declared NULL+0x310/+0x360; object+0xD8 remains arbitrary |
| `0x100A2AE30` | 2 | Unequal header; object+0x360 remains arbitrary |

Incomplete paths stop before cleanup/free, so they do not establish a native leak or an unbalanced completed lock lifecycle. The models request64 acquisitions,44 unlocks,108 once calls and44 input frees. Their native effects and concurrent pointer stability remain unknown [RK6-RK8,RK12].

## Candidate publishers, external context and IPC boundary

The original-byte census finds11 literal LDRs for SP+26D0,13 for SP+24A8 and28 for SP+26B0. These are candidates because identical offsets can belong to different frames or phases. Two candidate payload publishers store X0 through the saved payload cell: AC7D60 after a literal320-byte request atAC7D44, and ACECAC after a variable request. Under the recorded bank-root premises, both call slots resolve to malloc at10109FF58, IA modifier6AA4. Those candidate allocator calls do not execute in the new journals. The sizes satisfy160=10*16 and320=10*32 bytes; a common construction remains unproved without continuous allocation/publication evidence. The variable request's complete allocation-size contract and the key-array allocator remain unknown [RK10-RK11].

The source contains one adjacent MOVN/MOVK construction for each of the three original global-address biases. The227 ADRPs to the searched C6000/C9000 pages all immediately add800, referring to another global. This bounded search therefore supplies no direct publisher for the requested globals. The saved pool-site annotation file has4,920 entries and no exact target match for the three requested addresses. The current IDA direct-xref query also scans zero candidates. None of these negative results proves absence of obfuscated references.

No new Mach send/receive, message ID, right disposition or IOKit emission site is established by these local operations. The source-retired import models are synchronization/free operations; their internals and unresolved successors are outside this conclusion. The unchanged [RAX packet audit](triage_evidence/zut_trap_argument_audit.json) remains separate evidence. The object/link words and local controls are not assigned a Mach-port role.

## Validation and bounded continuation

| Check | Verified coverage |
|---|---|
| Continuous source inputs | 54 array-state plus10 object-state cases;94,308 continuation visits |
| Independent A64 | 256 cases;490,896 source visits;all read/write/register/edge checks pass |
| Fresh checker execution | Two additional source compositions |
| Source identities | 21 proof pairs,42 persisted UNSAT queries,236 lifted instructions;three satisfiable premise witnesses |
| Word correction | 28 additional quantified relations in preceding symbolic journals;128 concrete representation checks in the64 new cases |
| Original provenance | 27 spans,116 fixups,two exhaustive byte-bank rules (512 inputs),18 dispatch slots |
| Live IDB | 12 ranges,1,472 raw bytes;324 displayed rows,three partial macro rows,four undecoded byte rows kept separate from instruction decoding |
| Unique continuation opcodes | 1,722 retired plus two additional inspected/unretired opcodes |

Private backings are execution witnesses, not definitions of unspecified bytes. Source-producer/executor complexity is linear in retained visits/events/expression construction apart from solver work; each query has a30 s limit. Mapped owners and the largest trace bound replay RAM. No native target or IDB mutation executes.

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_registry_lookup.py
```

| Impact | Next investigation | Discriminating evidence |
|---|---|---|
| High | Follow the removed object's+0x310/+0xD8 consumers and the+0x360 chain. | Source-defined owners/fields can resolve the current boundaries and establish release or subsystem calls. |
| High | Establish continuous native registry constructors and callers. | Allocation/publication paths can replace candidate bank/frame premises with source-order evidence. |
| High | Connect the eight-byte query producer and object consumers to retained Mach/IOKit request handlers. | Record-to-message provenance and exact payload offsets can establish cross-layer meaning. |
| Medium | Characterize an unequal head followed by a matching owned node. | Establish interior unlink versus head unlink and predecessor update locations. |
| Medium | Recover object allocation/type and concurrent ownership discipline. | Distinguish this minimum872-byte interface from earlier context/descriptor owners. |
| Low | Expand syntactic writer coverage beyond the current literal patterns. | Additional aliases and frame-relative definitions may identify publishers; a larger census alone does not prove reachability. |

## Scoped quality gates

QG1 passes for factual technical analysis. QG2 is covered by RK1-RK14 and falsification probes. QG3 passes for this registry/unlink increment; the full objective remains incomplete. QG4 covers bit widths,byte extents,loop bounds and algorithm/solver limits. QG5 resolves the word-representation error and separates two bounds,raw header equality,lookup from mutation,partial paths and native ownership. QG6 covers original source/fixups,independent A64,solver files,saved annotation hashes and fresh IDB bytes with undecoded rows explicit. QG7 is covered by the impact-bounded continuation table.
