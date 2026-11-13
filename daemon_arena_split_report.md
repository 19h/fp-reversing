# Daemon arena split and defined payload-to-seed flow

The initialized arena route reserves an 88 B block, returns its 64 B payload at block+24, releases the admission gate and reaches the same entropy/clock sites as the earlier cold route. The payload already has original source provenance: a 156 B descending fill in the parent interval covers every payload byte. Its first retained consumer reads payload+4, updates word 1 of the private 16 B seed record and reaches the next state-mixing iteration. This establishes a local arena-to-seed data dependency. Native ownership, complete generator execution and daemon-kext transaction pairing remain unknown. [AS1-AS5]

```text
parent warm route
  -> descending fill: 156 B ending immediately before old marker
  -> pending marker read
     no marker premise -> stop before read
     + snapshot marker and accounting word
       -> reserve 88 B: metadata 24 B + payload 64 B
       -> save payload pointer -> restore gate -> pending arc4random
       -> declared random/clock/random/random returns
       -> read defined payload word at payload+4
       -> update private seed-record word1
       -> stop before next generator mixing iteration
```

| Evidence | Primary artifact and boundary |
| --- | --- |
| AS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_arena_split.py) retains source regions, original opcodes, complete states, fixups and byte events. |
| AS2 | [Readiness/arena checks](triage_evidence/daemon_readiness_arena_checks.json.zst) and [report](daemon_readiness_arena_report.md): four snapshot-header parents, original descending-fill events, arena owner and strict pending marker boundary. |
| AS3 | [Constructor snapshot](triage_evidence/daemon_context_lock_snapshot.json) and [success journal](triage_evidence/daemon_context_lock_success.json): source-defined header, marker and accounting bytes; later constructor writes do not overlap these fields. No native epoch join is established. |
| AS4 | [New checks](triage_evidence/daemon_arena_split_checks.json.zst): eight marker controls and eight complete seed-prefix controls; no new payload bytes are supplied. |
| AS5 | [Independent auditor](triage_evidence/audit_daemon_arena_split.py) and [audit receipts](triage_evidence/daemon_arena_split_audit.json.zst): complete state/byte replay, source-fill provenance, exact return joins and eight nonvacuous source obligations. |
| AS6 | [Publication verifier](triage_evidence/verify_daemon_arena_split_publication.py): pinned dependencies, exact manifest delta, preserved inputs, decoded compression identity and raw/typed/decoded path hygiene. |

## Arena metadata and byte lifetime

Use source-model owner H=`0x6500100000`, extent 90000 B; M=`0x5e878c613b8123ea`; D=`0x1010b5ef0`; accounting cell D+40=`0x1010b5f18`. The inherited snapshot-header word is M+86620. The marker at T=H+86620=`0x650011525c` contains the same word. Four controls leave T undefined and execute zero instructions before the read cut; four controls supply its source-defined first 8 B. The following 8 B at T+8 are neither supplied nor accessed. [AS2-AS5]

The accounting word is supplied separately from the same snapshot. Its bytes differ from preferred-image file contents, so the file default is not used as current accounting state. The original constructor success journal contains 4418 visits; no write overlaps H+8, T or D+40. This establishes recorded preservation of those three metadata fields, while the caller's controller values, roots, context and API-return premises remain inherited. It does not establish a continuous constructor-to-caller or native memory epoch. [AS2-AS5]

Before this increment, source `0x100be73cc` writes 156 single bytes in descending address order from T-1 through T-156. The current 88 B reservation lies wholly within that filled span. The audit checks every original fill event and all 64 payload-byte origins, rather than treating physical allocator backing as initialization. [AS2,AS5]

For each fill iteration, let a=low32(X14), b=low32(X3), k=low32(X15), d=low32(X2), and n be the remaining count. Source `0x100be73b0..0x100be73d8` performs:

```text
byte[base+n-1] = low8(u32((u32(a+b) XOR 0x88888888) + k)
                          * u32(k XOR d))
remaining = n-1
X15 = u64(X15+1)
```

An arbitrary-u32 input obligation proves the byte equation and one descending-counter transition from the original instructions. The concrete parent journals establish all 156 iterations and complete payload coverage. This is a deterministic source fill under retained inputs; randomness, cryptographic entropy and a native allocation guarantee are not inferred. [AS2,AS5]

## Split layout, accounting and returned pointer

The first marker read is `0x100b6a918 LDR X17,[X15]`; it compares the word with the inherited header. Under phase W12=`0xb399`, equality selects index `0xa7c4`, slot `0x10108dd10`, target `0x100a77d3c`, IA modifier `0x98d1`. Inequality selects index `0xa059`, slot `0x10108a1b8`, target `0x100a860b8`, with the same modifier. The arbitrary-u64 source obligation establishes this partition. The mismatch continuation under its distinct register state is not executed here. [AS1,AS4-AS5]

The retained request total is q=`0x58`=88 B. Source computes block B=T-q=`0x6500115204` and returns payload P=B+24=`0x650011521c`. P+64=T exactly. These are model placements; a native malloc/free operation does not execute. [AS4-AS5]

| Source writer | Destination | Width | Established value/effect |
| --- | --- | --- | --- |
| `0x100a77d9c` | H+8 | 8 B | M+86620-88=M+86532 |
| `0x100a77da4` | B+0 | 8 B | Same reduced header; post-indexed X22 becomes B+24 |
| `0x100a77df4` | B+8 | 8 B | M-88 |
| `0x100a77dfc` | B+16 | 8 B | Copy the existing 8 B word from SP+0x20 |
| `0x100a77e10` | T | 8 B | Reset the old marker's first word to M |
| `0x100a77e70` | D+40 | 8 B | Add 88 modulo 2^64 to snapshot accounting word |
| `0x100a8c054` | SP+0x190 | 8 B | Save P, preserving its source allocation provenance |
| `0x100a8c078` | `0x1010b5de0` | 4 B | Restore admission word `0x5d96` before entropy |

```text
H ... remaining span ... B                 P                  T
                         +0 header         +24 payload64      old marker
                         +8 encoded extent ------------------+
                         +16 copied word
                         |<-- metadata24 -->|<-- payload64 -->|
                         |<------------- total88 ------------>|
```

Eight nonvacuous source obligations cover marker equality, block/header arithmetic, original header stores and payload pointer, encoded extent, copied word/marker reset, accounting, fill and payload decoding. The encoded extent simplifies to M-q for 8 B-aligned u64 q. The observed q=88 satisfies that premise. The universal aligned-extent proof does not establish this simplification for arbitrary unaligned inputs. Accounting addition is proved for arbitrary u64 old words and extents. Complete allocator ownership, boundary-tag meaning, free operation and synchronization lifetime remain unknown. [AS4-AS5]

No write in the split changes P..P+64. The original 156 B fill therefore remains the latest definition of every payload byte. The split commits metadata around an already source-defined region; it does not require a new payload fixture. The warm gate release here extends the previous report's shorter warm prefix, which had stopped before the marker read. [AS2,AS4-AS5]

## Defined payload consumer and private seed record

Each successful marker parent continues under two declared initial random returns, 0 and `0xffffffff`, giving eight seed controls across both retained API clobber profiles and network-data controls. Each then supplies a separate zero-status clock return with zero seconds and microseconds, leaving the 4 B timeval padding undefined, followed by random words 0 and `0xffffffff`. Native APIs and their side effects do not execute. The [clock report](daemon_clock_record_report.md) supplies the separately validated field layout and comparison-leaf contracts. [AS2,AS4-AS5]

The source executes 8140 visits to the clock boundary,22 to random2,19 to random3,273 to the payload consumer and53 through that consumer. Its two private comparison calls retain the earlier decoded unsigned inputs 623<2 and1>3, both false. Their results direct execution to the same load site used by the cold route, with a different saved-pointer provenance. [AS4-AS5]

| Operation | Established value or dependency |
| --- | --- |
| Saved base at SP+0x190 | P, from the original split and save |
| `0x100a075e4..0x100a075ec` | Address P+4*1=`0x6500115220` |
| `0x100a0769c` | Read 4 B `5c902e62`, little-endian u32 `0x622e905c` |
| `0x100a076f0` | Read 4 source-text bytes at `0x100822c84` |
| `0x100a076f8` | Read 4 source-text bytes at `0x100822c86`; 2 B overlap the preceding read |
| `0x100a0770c` | Store u32 `0xb50bf7c4` into private seed record Q+4 |
| Next boundary | `0x1009c46dc`, before the next generator mixing iteration; state index W19=2 |

Q=SP+0x220, the private 16 B record. The payload consumer replaces its word 1, initially the separately supplied microseconds value 0. No payload byte is changed. The retained consumer reads exactly one 4 B payload word; it neither serializes the 64 B region nor establishes a kernel input buffer. [AS4-AS5]

For arbitrary payload word w, old record word r, phase c, flag f, read address A and a shared 48-bit source-text word Z covering the overlapping reads, source `0x100a0769c..0x100a07710` establishes:

```text
new_word = u32(low32(A)*0xc40ba787) XOR w
           XOR (c AND 0xc68e91c5) XOR (f AND 1)
           XOR u32(r - ((r<<1) AND 0x377b9daa) + 0x1bbdced5)
           XOR low32(Z) XOR low32(Z>>16) XOR 0xe2715a91
```

The proof shares the overlapping text bytes rather than assigning independent 32-bit values to the two reads. Source-text bytes match the pinned image. The arithmetic dependency supports a local address/text-dependent record decoder interpretation. Complete routine identity, cryptographic purpose, whole-array state and external transport use remain unknown. [AS1,AS4-AS5]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| AS-A1: Pinned source and fixups identify this specimen | Every operation and target | Check image SHA-256, original opcode at every visit and each used fixup; hardware PAC remains unexecuted. |
| AS-A2: Four frozen warm header boundaries apply | Split admission and later caller path | Exact GP/Q/SP/NZCV/owner/byte joins; inspect parent runtime-controller premises separately. Native admission remains unknown. |
| AS-A3: Three arena metadata fields share the retained snapshot state | Header/marker match and accounting | Check source-known masks, header/marker identity and all later constructor writes for overlap. Do not infer a continuous caller epoch. |
| AS-A4: Parent fill events remain the latest payload definitions | Defined payload and first consumed word | Verify all 156 byte equations,64 payload origins and absence of split/seed writes to payload. Import no new payload bytes. |
| AS-A5: Aligned extents apply to the encoded-extent simplification | B+8=M-q | Retain `(q AND 7)==0` in the nonvacuous proof; verify observed q=88. Unaligned simplification is not claimed. |
| AS-A6: Imported returns and separate clock fields apply | Seed-prefix composition | Verify all 32 return joins, preserved ABI state, unknown clock padding and both clobber profiles; no native outcome inference. |
| AS-A7: Full scalar/AdvSIMD replay and symbolic lift match source semantics | Byte/state/equation claims | Independently check complete GP/Q/NZCV, memory effects, post-indexed store and retained X8 fixup origin; fail closed on unsupported behavior. |
| AS-A8: Overlapping text reads refer to one pinned byte epoch | Private record update | Check 6 unique source bytes and use one symbolic 48-bit word in the source equation. Runtime text mutation is not established. |
| AS-A9: Final cut precedes the next mixing iteration | Remaining generator and cross-layer scope | Preserve the actual source boundary; complete mixing, later context release, filesystem/Mach/IOKit use and native pairing remain unknown. |

## Verification and bounded continuation

The new receipts contain 48 intervals,68592 original instruction visits,5700 read events,5208 write events,5088 logical edges and16 internal calls. Four missing-marker controls stop before the first read. Eight seed controls each execute the original defined payload consumer, without a payload fixture. Independent replay covers complete GP/Q/NZCV states and byte effects; exact totals are retained in the audit receipts. Eight nonvacuous source obligations pass. [AS4-AS6]

Extraction/audit require O(parent receipt bytes + cases*(visits+state+effects)) time/storage, excluding solver work; each solver query has a 30 s limit. The fixed reservation uses O(1) source operations; descending fill costs O(n) time and O(1) auxiliary state for n bytes. The retained array has624 u32 words=2496 B. Word arithmetic is modulo2^32, address/accounting arithmetic modulo2^64, and byte extents/counts are exact. No native API, IPC, allocation/free, concurrent execution, hardware PAC or IDB mutation executes. [AS1-AS6]

| Impact | Next evidence | Architectural purpose and boundary |
| --- | --- | --- |
| High | Recover complete payload-driven record/generator recurrence | Establish how all 64 B affect later material, avoiding trace-only algorithm recovery |
| High | Establish the caller/controller and initializer snapshot epoch join | Current coherent metadata subset does not prove whole-caller coherence or native reachability |
| High | Trace actual completed material to existing Mach/IOKit sites | Source data dependence is required before claiming a paired daemon-kext request |
| Medium | Recover arena reservation/free and accounting lifecycle | Distinguish metadata semantics from unproven native allocation ownership |
| Medium | Relate source-text/address decoding to earlier encoded material paths | Identify shared representation contracts while preserving distinct caller epochs |
| Low | Apply descriptive navigation labels to split/fill/consumer blocks | Preserve exact addresses and provisional role confidence |

This increment establishes no new incoming/outgoing Mach port, right disposition, send/receive emission site or UserClient selector. Existing transport evidence remains in the [port report](mach_ports_report.md) and [ABI report](interface_abi_report.md); the current result supplies a concrete local data-flow predecessor for subsequent correlation. The full interface goal remains active. [AS1-AS6]

**QG1** passes: factual source/interface analysis. **QG2** passes: AS-A1-AS-A9 register assumptions and probes. **QG3** passes for split/fill/payload composition; the full objective remains incomplete. **QG4** passes: exact widths, alignment, arithmetic, extents, counts and complexity. **QG5** passes: inherited source fill, separately supplied metadata, defined consumer and cold zero-pointer route are distinct. **QG6** passes after pinned source, independent replay, solver, original-input and publication checks. **QG7** passes: bounded continuation covers full algorithm, ownership, caller coherence and cross-layer transport gaps.

Decoded checks SHA-256: `ec60b186a8613a1c1e6844cf3a5ea88bb50c8dc272e649d39c7073cfc1ebbd48`. Decoded audit SHA-256: `0266b5139f41536f7005b0e05d05a2e523037ccc14ee22f6426d2c3293359366`.

The subsequent [payload-mixing report](daemon_payload_mix_report.md) completes the first 624-iteration pass for two frozen seed parents. The private record mutates through four repeating XOR masks; three payload words supply the nonwrap inputs and the pointer supplies the wrap input. The original counter exit reaches0x100abba18 before the next stage executes. Full generator completion and transport correlation remain open.
