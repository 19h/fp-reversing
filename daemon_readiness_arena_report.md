# Daemon readiness admission and arena descriptor interfaces

The source distinguishes cold initialization from an existing-arena path by testing whether byte `0x1010c5798` equals exactly 1. The earlier clock/entropy route follows the cold partition, saves a zero pointer and releases an admission gate before entropy initialization. A separately retained constructor snapshot has readiness 1, a valid source-model arena link and different arena-header metadata. These observations bound the earlier address-4 demand to its stated cold-path premises. Native reachability and a continuous constructor-to-caller epoch remain unknown. [RA1-RA4]

```text
CAS gate: expected 0x5d96, desired 0xa94ef
  old != expected -> retry setup (stop before another attempt)
  old == expected -> acquired -> X16 = 0 -> read readiness byte
    byte != 1 -> save zero -> gate = 0x5d96 -> pending arc4random
    byte == 1 -> read descriptor link at D+72
      link == D+48 -> pending malloc(5000 B)
      link != D+48 -> pending read of node+8
        + separate arena header -> pending decoded marker read
```

| Evidence | Primary artifact and boundary |
| --- | --- |
| RA1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_readiness_arena.py) retains original opcodes, complete states, byte events and logical fixups. |
| RA2 | [Context-state checks](triage_evidence/daemon_context_state_publish_checks.json.zst) and [clock report](daemon_clock_record_report.md): four successful parent boundaries, inherited constructor-compatible context/table views and the conditional cold-path zero-pointer demand. |
| RA3 | [New checks](triage_evidence/daemon_readiness_arena_checks.json.zst): 60 bounded intervals; each runtime metadata substitution and added owner is explicit. |
| RA4 | [Startup profiles](triage_evidence/daemon_arena_storage_profiles.json), [constructor snapshot](triage_evidence/daemon_context_lock_snapshot.json) and [constructor success journal](triage_evidence/daemon_context_lock_success.json): distinct source-model epochs, not native observations. |
| RA5 | [Independent auditor](triage_evidence/audit_daemon_readiness_arena.py) and [audit receipts](triage_evidence/daemon_readiness_arena_audit.json.zst): complete GP/Q/NZCV replay, exact joins, retained dispatch origin and eight nonvacuous source obligations. |
| RA6 | [Publication verifier](triage_evidence/verify_daemon_readiness_arena_publication.py): pinned dependencies, exact manifest delta, preserved original inputs, decoded archive identity and raw/typed/decoded path hygiene. |

## Gate and readiness operations

Addresses below are preferred-image addresses. H=`0x6500100000` is a private source-model arena placement, not a native pointer. D=`0x1010b5ef0`, sentinel S=D+48=`0x1010b5f20`, link cell L=D+72=`0x1010b5f38`, gate A=`0x1010b5de0`, and readiness F=`0x1010c5798`. Word arithmetic is modulo 2^32 and pointer arithmetic modulo 2^64. All widths and extents are bytes. [RA1,RA3]

| Source operation | Location and width | Established function |
| --- | --- | --- |
| `0x100a6e5b8 CASAL W8,W13,[X9]` | A, 4 B | Compare old word with `0x5d96`; matching value becomes `0xa94ef`; W8 receives old word |
| `0x100b73fa0 MOV X16,#0` | Register, 8 B | Unconditionally zero the later cold-path saved pointer |
| `0x100b74044 LDRB W11,[X11]` | F, 1 B | Compare the entire byte with 1 |
| `0x100a8c054 STR X16,[SP,#0x190]` | Private stack, 8 B | Save zero on the cold partition |
| `0x100a8c078 STR W8,[X9]` | A, 4 B | Restore `0x5d96` on the cold partition before the entropy call |
| `0x100ba7724 LDR X9,[X28,#0x48]` | L, 8 B | Read existing arena/list link |
| `0x100ae2cbc LDR X13,[X9,#8]` | node+8, 8 B | Demand node header on the non-sentinel partition |
| `0x100a7b8d8 BLRAA X8,X17` | Pending `malloc`, IA `0x6aa4` | Source sets X0 to `0x1388`=5000 B before expansion request |

The admission test is proved for every u32 old word. Concrete controls use 0, `0x5d96`, `0xa94ef` and `0xffffffff` for each of four parents. A failed comparison returns to setup at `0x100a6e57c`; the extractor stops before a second attempt. This identifies a compare-exchange admission/retry pattern. Its native lock type, contention behavior, ordering, fairness and lifetime are unknown. Failed-CAS CPU journals contain an identity write event; independent replay checks the unchanged value without interpreting that event as a native hardware write cycle. [RA3,RA5]

| Predicate | Index | Original slot | Target | IA modifier |
| --- | --- | --- | --- | --- |
| old gate == `0x5d96` | `0x62f3` | `0x10106b688` | `0x100b73f98` | `0x504c` |
| old gate != `0x5d96` | `0x177c` | `0x101045ad0` | `0x100a6e57c` | `0x504c` |
| readiness == 1 | `0x4b3a` | `0x10105f8c0` | `0x100ba6f80` | `0x472f` |
| readiness != 1 | `0x82` | `0x10103a300` | `0x100a8c054` | `0x472f` |
| link == S | `0xa059` | `0x10108a1b8` | `0x100a860b8` | `0x98d1` |
| link != S | `0xa057` | `0x10108a1a8` | `0x100ae2cac` | `0x98d1` |

These are decoded original fixup targets/modifiers. Hardware pointer authentication does not execute. The sentinel route later branches through retained X8 to `0x100c190f4`; its producer is the original load at `0x100b9eefc` from slot `0x10103a438`. The audit checks the load and absence of intervening X8/W8 definitions across the readiness/descriptor interval join. [RA1,RA3,RA5]

For each parent, readiness controls 0,1,2,255 establish 69-visit cold suffixes and a 129-visit warm suffix. The all-u8 proof establishes the full equality partition; byte 255 is not treated as ready. Cold controls restore the gate before the pending `arc4random` at `0x100a8c0c0`. The warm suffix stops before reading L; an unspecified mutable link is not replaced with the preferred-image file bytes. [RA3,RA5]

Each warm parent then receives separate link controls 0,S,H. S reaches the pending 5000 B allocation after 52 visits. Zero and H stop before the node-header instruction, with pending addresses 8 and H+8 respectively. No access to address 8 executes, and no allocation return is supplied. The sentinel comparison supports an existing-list/expansion interpretation; a complete allocator structure, deallocator and native ownership remain unknown. [RA3,RA5]

## Arena metadata epochs and encoded marker demand

Startup source stores H into L at `0x10032a56c`, stores M+89976 into H+8 at `0x10032a5d0`, and stores readiness 1 at `0x10046c750`, where M=`0x5e878c613b8123ea`. The descriptor writer uses S+24, which equals D+72 exactly. The source proof establishes writer/reader identity conditional on the same memory epoch. Sharing an address across recorded paths does not establish that epoch. [RA4-RA5]

| Field | Fresh startup profile | Pre-constructor snapshot |
| --- | --- | --- |
| Owner extent | H, 90000 B | Same source-model placement and extent |
| Readiness F | Written as 1 | 1 |
| Descriptor link L | Written as H | H |
| Gate A | Separate caller premise | `0x5d96` |
| H+8 | M+89976 | M+86620 |
| Decoded next marker | H+89976=`0x6500115f78` | H+86620=`0x650011525c` |
| Known 16 B at H+89976 in snapshot | Separate startup evidence | `[M, M XOR 2^63]` |
| Known 16 B at H+86620 in snapshot | Separate later epoch | `[M+86620, M-2220]` |

Snapshot heap masks mark every reported header/marker byte as source-defined. The later successful constructor journal contains 4418 original instruction visits and 523 write events. No write overlaps these protected fields, the gate, readiness or descriptor link. This establishes preservation through that recorded constructor journal. It does not join that journal to the present caller or establish a native transaction. [RA4-RA5]

Eight header controls supply only the 8 B H+8 word, two epochs for each of four H-link parents. Each introduces H..H+90000 as an outer owner view containing the already retained 552 B context and 512 B table views. This is an explicit owner premise, not another allocation event. No snapshot marker byte is imported into these continuations. [RA3,RA5]

Each control executes 2732 original visits and stops before `0x100b6a918 LDR X17,[X15]`. The source block `0x100b6a8e0..0x100b6a918`, with phase W12=`0xb399`, computes:

```text
offset = u64(header - M)
address = u64(node + offset)
```

An arbitrary-u64 node/header obligation proves both equations from the source. Fresh metadata demands the terminal marker at H+90000-24; snapshot metadata demands an earlier marker 3356 B before it. Both 8 B reads lie within the declared owner but remain undefined in these particular continuations, so neither read executes. In-owner does not imply source-defined. The comparison prevents silently combining a fresh free-span header with later context/table allocations. The next bounded step is to continue from one explicitly coherent snapshot epoch and account for its complete metadata lifetime. [RA3-RA5]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| RA-A1: Pinned source and logical fixups identify the specimen | Every source address, target and operation | Check image SHA-256, each visited opcode and every used original fixup; no hardware PAC inference. |
| RA-A2: Four frozen successful parent entry states apply | Caller admission controls | Exact 849-visit parent-prefix replay and GP/Q/SP/NZCV/byte joins; native caller admission is unknown. |
| RA-A3: 24 initial-image metadata bytes apply to these controls | Reproduced prefix and warm routing | Keep two 8 B words and two 4 B words separate from inherited fixtures; retain file-backed versus zero-fill provenance. Reject any native epoch inference. |
| RA-A4: Current gate, readiness and descriptor words are independent premises | Gate/readiness/link partitions | Separate controls, exact-width substitution and all-u32/u8/u64 source proofs; no initializer-to-caller join is assumed. |
| RA-A5: Sequential CAS value semantics apply | Admission and retry targets | Independently check old return, conditional replacement and failed identity value. Native interleavings/order/fairness remain unknown. |
| RA-A6: Startup and constructor snapshot describe distinct evidence epochs | Two header controls and marker addresses | Check known masks, exact startup stores and every later constructor write for overlap. Never combine them into a continuous native state. |
| RA-A7: Outer arena view is supplied independently | Header consumer and owner-relative extent | Preserve nested existing views; define only H+8; stop before the first undefined marker read. No allocator ownership inference. |
| RA-A8: Independent scalar/AdvSIMD lift matches original operations | State/byte/equation checks | Replay all GP/Q/NZCV frames, bytes and logical edges; verify retained X8 provenance; unsupported operations fail closed. |
| RA-A9: Explicit cuts bound the reported semantics | Architectural and IPC conclusions | Stop before repeated CAS, pending imports, unsupplied link/header and undefined marker. Native delivery and daemon-kext pairing remain unknown. |

The 24 metadata bytes comprise `(0x1010b9008,8)`, `(0x1010c4f48,8)`, `(0x1010c67dc,4)` and `(0x1010c8258,4)`. The last field is initial-image zero-fill. They expose an additional runtime-state premise in the earlier reproduced path; original file defaults do not establish current daemon values. Each new gate/flag/link/header effect is listed separately in the receipts. [RA2-RA3]

## Verification, interface scope and continuation

Receipts retain 4 parent prefixes,16 gate controls,4 acquired prefixes,16 readiness controls,12 link controls and8 header controls: 60 intervals,27216 source visits,3440 read events,3044 write events,1376 logical edges and12 internal call records. Eight nonvacuous UNSAT obligations establish CAS value transition, admission indices, readiness equality, descriptor equality, same-epoch link identity, expansion size/modifier, marker arithmetic and cold gate restoration. Independent full-state and byte totals are retained in the audit receipts. [RA3,RA5-RA6]

Extraction/audit cost is O(parent receipt bytes + cases*(visits+state+effects)) time/storage, excluding solver work; each query has a 30 s limit. These bounded source components use O(1) auxiliary algorithm state. Arena ownership covers 90000 B; nested context/table extents are 552 B and512 B. No native API, Mach operation, allocation/free, concurrent execution, hardware PAC or IDB mutation executes. No new incoming/outgoing Mach port, right disposition, send/receive site or UserClient selector is established by this increment. Existing mappings remain in the [port report](mach_ports_report.md) and [ABI report](interface_abi_report.md). [RA1-RA6]

| Impact | Bounded next evidence | Architectural purpose |
| --- | --- | --- |
| High | Restore one coherent constructor snapshot and follow arena metadata mutation through the caller | Resolve warm-path context/arena ownership without mixing initialization epochs |
| High | Recover complete gate acquire/release sites and readiness writers | Establish synchronization boundaries and explain cold versus initialized routing |
| High | Follow actual warm-path consumers to existing Mach/IOKit call sites | Establish source data dependence before claiming daemon-kext request pairing |
| Medium | Recover next-marker readers/writers and expansion result contract | Identify allocation, free-span and link semantics beyond the established local arithmetic |
| Medium | Correlate documented port emissions with the annotated trace under matching call context | Separate modeled syscall observations from native endpoint identity |
| Low | Assign provisional descriptive labels to admission/readiness/header components | Improve navigation while retaining original addresses and confidence limits |

**QG1** passes: factual source/interface analysis. **QG2** passes: RA-A1-RA-A9 list assumptions and falsification probes. **QG3** passes for this bounded increment; the full interface investigation remains active. **QG4** passes: exact widths, extents, modulo arithmetic, counts and complexity are explicit. **QG5** passes: cold/warm partitions, failed-CAS identity events, separate epochs and undefined in-owner bytes remain distinct. **QG6** passes after source, independent replay, solver, input-preservation and publication checks. **QG7** passes: impact-ranked continuation covers synchronization, ownership and cross-layer dependency gaps.

Decoded checks SHA-256: `29145dc0f6a14b9a1676d9c0829d319df9ebe8cd8291194626a2f35ef6da25de`. Decoded audit SHA-256: `82b7ce76a60c37592b1d8393352511f766cf0600abea6d32214e8546391b729f`.

The subsequent [arena split/payload report](daemon_arena_split_report.md) consumes the first 8 B snapshot marker, commits an 88 B reservation, preserves 64 already source-filled payload bytes and restores the gate before entropy. It traces one payload word into the private seed record. The initialized metadata subset remains separate from a continuous caller/native epoch join.
