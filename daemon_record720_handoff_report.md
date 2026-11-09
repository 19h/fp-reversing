# Private record, cursor adapter and control 0x7A3A after the 720-byte initializer

The 720-byte initializer now has a declared source-component continuation through a 32-byte private call record, adapter `0x100536E98`, dispatcher `0x100523894` and handler `0x10062A624`. The private control decodes to **0x7A3A**. A leading u64 and an independently decoded u32 select different observed continuations. The allocated owner is passed in the record, but none of the checked paths reads its bytes or establishes registry publication. Native caller continuity and daemon-to-kext transport linkage remain unknown. [H1-H12]

The preceding [720-byte initializer report](daemon_record720_report.md) and [cache publication report](daemon_cache_publication_report.md) remain frozen. In particular, the earlier registry-derived base+0x238 read still has an unowned scalar base. This increment does not assign the new allocation to that base. The full interface investigation remains active.

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Eleven fresh read-only ranges in IDB `6b117c693e3b` cover 3,440 bytes and match the image. [Original source/banks/fixups](triage_evidence/daemon_record720_handoff_source.json), [source proofs](triage_evidence/daemon_record720_handoff_proofs.json), [input producers and declared cases](triage_evidence/daemon_record720_handoff_profiles.json) and [independent checks](triage_evidence/daemon_record720_handoff_checks.json) retain the evidence. No native process, imported allocator, Mach/IOKit operation or hardware PAC executes.

## Input fields and explicit composition boundary

Let F be the outer SP, P the successful 720-byte allocation, and R=F+0xDE90 the caller's private record. Original input fragments consume a declared 12-byte input B. They produce:

```text
U:u64 = BE64(B[0:8]) XOR 0x9898989898989898
D:u32 = BE32(B[8:12]) XOR 0x98989898
E:u64 = U XOR 0xE3B88695C0D52DBC
V:u32 = D XOR 0x8B3DC651
```

The first input pack at 0x1009D0198 and word store at 0x1009D0304 produce E at F+0x2A70. Under source mode0x471C, the original fragments at 0x10095AF18 and0x10095AF50 produce U at F+0x2DC0 and V at F+0x2FEC. The mode-dependent third-byte mask becomes0x98; a source proof covers the full u32 field decoder, including its mixed Boolean/arithmetic expression. The u32's downstream semantic unit remains unknown; it is not assigned a byte-count or IPC-selector role.

Twenty-four input-fragment executions cover three U values, four D values and two F placements. Their actual output values cross an explicit component boundary into new allocation/initializer cases. Original control flow between these input fragments and the allocation cutpoint is not established. No prior stopped profile is resumed by filling its unknown frame fields.

The continuation uses saved F+0x2970=`0x101031FA0`, F+0x2978=`0x100FC4230`, F+0x2988=`0x101031EA0` and F+0x29A0=`0x101039EF0`, retaining their earlier source-writer evidence. Incoming X25=`0x100FC4130` is a separate phase premise. The preceding isolated initializer cases declared a different F+0x2970 value and stopped before its later use; those cases do not establish this extended call path. Native frame-epoch continuity remains unknown.

## Private record and exact internal calls

The caller and dispatcher compute the same address-derived u32 key:

```text
K(R) = u32((low32(R) XOR 0x7CF28BE0) * 0x83918153)
```

The source caller's retained phase W23=0x5B85 gives decoded control `0x5B85+0x1EB5=0x7A3A`. All u32 arithmetic below wraps modulo2^32. Pointer/value fields retain all64 bits.

| Record field | Width | Caller emission | Dispatcher / caller use |
| --- | --- | --- | --- |
| R+0 | 4 bytes | 0x100B0B8B4: 0x7A3A XOR K | 0x100523A24..0x100523A28: XOR K to W24 |
| R+4..+7 | 4 bytes | Undefined in these cases | No observed read |
| R+8 | 8 bytes | 0x100B0B8B0: U | 0x100523A2C: load X17 |
| R+0x10 | 8 bytes | 0x100B0B8AC: P | Not read by the checked dispatcher header; no P-byte read anywhere in the cohort |
| R+0x18 | 4 bytes | 0x100B0B8A0: V+K | 0x100523A34..0x100523A38: subtract K to W21 |
| R+0x1C | 4 bytes | Initially undefined | 0x10061AABC writes returned status;0x100B0B97C reads it on returning paths |

The combined caller/result interface requires32 bytes. The dispatcher header alone accesses through R+0x1B. The source key identity covers an arbitrary u64 record address; the field-composition proofs additionally use valid, disjoint frame/owner premises.

| Call / transfer site | Original slot | Logical target | IA diversity / address diversity |
| --- | --- | --- | --- |
| 0x100B0B960 | 0x1010A0688 | Adapter0x100536E98 | 0x566A /0 |
| 0x100537100 | 0x1010A0238 | Dispatcher0x100523894 | 0x8489 /0 |
| 0x100523D68, control0x7A3A | 0x1010770C0 | Handler0x10062A624 | 0xEB00 /0 |

The first two are BLRAA calls; the third is a BRAA dispatch. Eleven exhaustive byte-bank contracts retain the biased pool pointers and constant indices. Branch slots and modifiers are checked through their actual load/spill provenance. Control0x7A3A is a private dispatcher value, not an established Mach message ID or IOKit selector.

## Cursor state and nested frames

The caller at0x100B0B904 reads u64 C from global0x1010B7C58 and saves it at F+0x3988. Its bank roots and the adapter's independently decoded pool pointer resolve to the same global cell. The adapter receives X0=R and X1=F+0x3988.

```text
caller:  local cell = C
adapter: global[0x1010B7C58] = u64(C*0x2E9D + 1) = L
         reserve = 16 * (top4(L) + 1) bytes
         temporary cursor = u64(C - 176)
entry:   temporary cursor += 176
         ... handler body ...
return:  local cell = ((low32(temporary)-low32(C)) & 0xFFFF) << 4
caller:  SP += local cell
```

The reserve is universally16..256 bytes and a multiple of16. The adapter prologue separately consumes64 bytes; dispatcher0x100523894 consumes another0xD60=3,424 bytes before its first body load. These stack reservations are distinct from the 720-byte heap allocation. The temporary cursor's initial bias cancels at the dispatcher entry; this does not prove the complete handler returns or preserves that cursor for every input.

Ninety-six returning modeled cases produce a zero output delta and return through both RETAB sites. The other extended cases stop before the handler returns. The delta formula is proved for every u32 returned counter; zero delta is a finite observed result. Source provenance does not establish a native stack randomization or entropy property.

| Runtime cell | Observed source effect | Role established here |
| --- | --- | --- |
| 0x1010B8E78 | u64 write at0x100536FB4 | Adapter address/state-derived arithmetic |
| 0x1010C4670 | u64 writes at0x100536FB8 and0x1005239D8 | Shared runtime-state touchpoint |
| 0x1010B7C58 | Caller u64 load; adapter u64 write at0x100537028 | Cursor input / LCG publication |
| 0x1010B7D70 | u64 write at0x1005239D4 | Dispatcher address/state-derived arithmetic |

The adapter's pair of state-update equations is source-proved for arbitrary u64 inputs. Native writers, synchronization and interleaving remain unknown. These cells are not assigned Mach-port or lock-object roles.

## External-data boundary and observed successors

At0x1005238BC, the dispatcher loads the imported `___stack_chk_guard` pointer through original slot0x1010B1E18. Its first pointed-to u64 read at0x1005238C0 is unavailable in192 cases, which stop before that read. The logical import token used by the emulator is not a native address or Mach-port name.

A separate192-case extension supplies a declared borrowed8-byte guard cell and a declared dispatcher runtime word. Both are explicit environmental premises. It then executes the original dispatcher, including the guard comparison on returning paths. Actual native guard address/value and failure behavior remain unknown.

| Extended finite cohort | Cases | Observed endpoint |
| --- | --- | --- |
| U=0 | 64 | Raw status0x74C29D88 at R+0x1C; adapter returns with delta0; subsequent call stops at0x100435BC4 before u32 global0x1010B6570 |
| U!=0,D=0 | 32 | Raw status0x74C29D8F at R+0x1C; same return/delta/frontier |
| U!=0,D!=0 | 96 | Stop at0x10044DD48 before u64 global0x1010B9278; no status/return is claimed |

The entry gate's zero/nonzero equation is source-proved. The complete endpoint partition above is finite evidence for the tested values, not a universal theorem about every D or runtime state. Raw statuses are not assigned errno, IOReturn or transport-error meanings.

The96 returning paths compare the status against raw0x8B3DC651. They then reuse the record:0x100BE0BE8 writes P at R+8, replacing U, and0x100BE0BF8 writes a u32 at R+0x10, replacing only part of the earlier pointer field. The next call at0x100BE0C50 selects0x100435B9C through slot0x1010A0840, IA0x485B. This is a second record epoch; it is not evidence that the original fields retain their earlier types. No `_free` or allocation-byte read occurs before the new frontier.

The nonzero path calls0x10044DD40 at0x1003E55F4 through slot0x1010A05C0, IA0xB06F. Its inspected prefix mixes runtime state and decodes another private record. Its overall role remains unknown; no synchronization or registry-publication role is established.

```text
12-byte input fragments -> U,V -- explicit value handover --+
                                                          |
malloc(720) -> initializer -> R[control7A3A,U,P,V] ----------+
                                 |
                         adapter536E98: cursor ABI
                                 |
                         dispatcher523894
                                 +-- missing guard cell -> STOP (192)
                                 |
                         declared guard/state extension
                                 |
                         handler62A624 (192)
                                 +-- returning status -> second record -> STOP (96)
                                 +-- nested adapter / runtime word -> STOP (96)

P -> registry entry+8: unknown
registry value+0x238 -> Mach/IOKit emission: unknown
```

## Assumption register

| ID | Premise / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| H1 | Pinned image, original pointer words and current IDB ranges / source identity | Rehash source and every observed opcode; independently decode54 used fixups; compare11 raw IDB ranges |
| H2 | Input fragments and their output-value handover are declared components / U,V provenance | Reexecute24 original106-instruction fragments; prove all-u64/U and all-u32/D equations; retain unavailable native intervening control flow |
| H3 | Incoming allocation phase0x471C, bank roots and saved-frame values apply / allocator, adapter and targets | Exhaust11 byte banks over256 inputs each; preserve distinct preceding initializer fixtures and unknown native root production |
| H4 | The720-byte owner, caller record and nested frames are valid and disjoint / memory and encoding composition | Explicit no-wrap/disjoint symbolic premise; two SP/owner placements; byte-defined masks and outside-owner/undefined-read rejection |
| H5 | Imported malloc returns the declared non-NULL owner and preserves the scalar ABI / new continuation | Two volatile GPR/NZCV patterns; verify720-byte argument, original slot and modifier; prior NULL cases remain in the frozen initializer report |
| H6 | Runtime scalars are declared external state / finite helper and dispatcher execution | Two independent state sets; all-u64 source equations for adapter updates, LCG and reserve; native writers/concurrency remain unknown |
| H7 | Guard-present extension supplies an8-byte imported data owner and dispatcher state /192 extended paths | Keep192 missing-guard paths stopped; vary guard values; execute source guard comparison without extracting a native value |
| H8 | Logical PAC/returns model control transfer only / source-edge identity | Track original slots through loads/spills and compare IA/diversity/address-diversity; no hardware authentication is claimed |
| H9 | Finite replay and universal fragment proofs have different domains / verification scope | Independent instruction-at-a-time replay of all384 cases, exact memory effects and final known GPRs; retain full-handler/native unknowns |
| H10 | The observed endpoint partition covers only the tested U,D,state cases / statuses and successors | Test U=0/nonzero/all ones and D=0/1/20/all ones; distinguish universal entry gate from finite whole-path classification |
| H11 | Each record/global has a source epoch and width / ownership and architecture | Audit the R+8/R+0x10 overwrites after status return; count zero P-byte reads; do not assign global state to a Mach port or lock |
| H12 | No registry publication or transport join is established / goal status | Require actual P store into entry+8 and later byte dependence into a known daemon/kext emission; keep the full goal active |

Whole declared-path results depend on H1-H9. Input decoding uses H2; ownership/record composition additionally uses H4. Endpoint interpretation uses H10-H11. Cross-layer limits use H12. Native original C types, callers, input provenance, guard/state values, publication and driver interaction remain unknown.

## Validation and bounded continuation

The accepted proof set contains17 rebuilt source obligations,34 SMT files and154 lifted source instructions. It includes both independent source key computations. The384 declared cases cover U in{0,0x123456789ABCDEF0,0xFFFFFFFFFFFFFFFF}, D in{0,1,20,0xFFFFFFFF}, two SP placements, two allocated-owner placements, two runtime-state sets, guard absent/present and two volatile/physical fill patterns. All new malloc returns are declared non-NULL; the preceding report retains the NULL-return partition.

The main cohort contains810,560 source visits:769,696 ordinary emulated A64 instructions,39,616 logical indirect transfers/returns,864 modeled PACIBSP heads and384 modeled malloc calls. An independent instruction-at-a-time executor checks all384 cases,120,384 ordered writes and74,656 ordered reads. The source inventory contains1,730 observed opcodes and54 used original fixups. Input-fragment validation adds24 fresh components/2,544 original instruction visits. The three distinct stopped-frontier classes remain explicit.

The fixture mapper initially omitted a private page needed by the second SP placement. The failed unpublished sweep stopped before producing an accepted cohort. After correcting physical mapping while retaining undefined-byte masks, all384 cases were regenerated. The independent replayer separately maps original instruction pages on demand. Neither correction supplies undefined source data or changes target instructions.

Reproduce in the pinned Python/Z3 environment by running [capture/input fragments](triage_evidence/capture_daemon_record720_handoff.py), [source proofs](triage_evidence/prove_daemon_record720_handoff.py), [case producer](triage_evidence/probe_daemon_record720_handoff.py), then [independent validation](triage_evidence/validate_daemon_record720_handoff.py). The [continuous source executor](triage_evidence/daemon_record720_handoff_replay.py) and [independent replayer](triage_evidence/replay_daemon_record720_handoff.py) are separate implementations. [Delivery/preservation checks](triage_evidence/daemon_record720_handoff_delivery.json) and [quality gates](triage_evidence/daemon_record720_handoff_quality_gates.json) seal the artifacts.

Capture/bank verification is O(source bytes+256*bank rules). Execution and replay are O(source visits+effects) time and O(largest mapped case+known-byte sets+decoder cache) space; stored compressed profiles add their output size. Proof construction is O(lifted instructions) plus solver resources, with30 s per query. Byte extents and source counts are exact; u32/u64 operations are modular. No full-handler termination, general runtime distribution or whole-native-path complexity is established.

| Impact | Required continuation evidence | Consequence |
| --- | --- | --- |
| High | Native caller/root continuity from the12-byte input components to control0x7A3A | Would replace explicit handover premises with an actual entry contract |
| High | Producers and consumers of global0x1010B9278 and the private record passed to0x10044DD40 | Would extend the nonzero-input path without assigning an unsupported synchronization role |
| High | Decode the second record consumed by0x100435B9C | Would establish the returned-status path's ownership action; free/retirement is not yet observed |
| High | Source stores publishing P into registry entry+8 | Would join the720-byte candidate to the previously stopped +0x238 read |
| High | Byte flow from a proven registry owner into a known Mach/IOKit emission | Would establish the missing daemon/kext transaction link |
| Medium | Complete runtime-state writers and native interleaving | Would distinguish per-call obfuscation state from persistent shared state |
| Medium | Native imported guard/data binding and ABI context | Would separate model-only continuation from native environmental reachability |

QG1: factual source/ABI scope. QG2: H1-H12 with dependent results and falsification probes. QG3: input fields, private record, cursor adapter, dispatcher and finite successors covered; the full objective remains incomplete. QG4: byte extents, record epochs, widths, instruction/event counts and modular arithmetic are explicit. QG5: missing guard versus modeled extension, partial returns, disjoint frames, undefined bytes and unknown adapter roles are separated. QG6: original source/fixups, current IDB bytes, rebuilt equations and independent A64/memory replay provide scoped provenance. QG7: impact-ranked continuation evidence is listed above.
