# Conditional descriptor readers and shared synchronization adapters

Two previously annotated reader candidates resolve to the global descriptor `G=0x1010C8218` under explicit byte-bank roots. Candidate A at `0x10021ECF4` captures its lock pointer, calls the known acquisition adapter, tests the configured count, and reaches cleanup for count zero. Its nonzero path loads the buffer pointer and reaches a dispatch expression whose incoming W23 phase remains unknown. Candidate B at `0x100A636EC` tests the buffer pointer and combines its NULL predicate with the incoming phase parity. Native entry phases and native control-flow connections to these blocks remain unknown.

The retained evidence comprises 96 staged reader compositions, 96 independent A64 replays with 49,528 source visits, 4,608 isolated guard executions, 16 additional independent guard cases, four exhaustive 256-input bank identities, 41 original fixups and 18 source proof pairs. Four live IDB ranges match 512 original bytes. These are process-local descriptor and synchronization contracts. No additional daemon-level Mach or IOKit call site occurs in the retained paths; imported implementations are unexamined. The broader interface investigation remains active.

Primary evidence: [source contracts](triage_evidence/daemon_descriptor_readers_contracts.json), [reader compositions](triage_evidence/daemon_descriptor_readers_profiles.json), [guard executions](triage_evidence/daemon_descriptor_guard_profiles.json), [proof queries](triage_evidence/daemon_descriptor_readers_proofs.json), [independent A64 replays](triage_evidence/daemon_descriptor_readers_replays.json), [independent checks](triage_evidence/daemon_descriptor_readers_checks.json), [live IDB bytes](triage_evidence/daemon_descriptor_readers_live_ida.json), [incoming IDB references](triage_evidence/daemon_descriptor_readers_ida_retry.json), [preservation](triage_evidence/daemon_descriptor_readers_preservation.json), and [scoped quality gates](triage_evidence/daemon_descriptor_readers_quality_gates.json). The earlier [construction and sealing report](daemon_context_lock_report.md) and [IOKit synchronization report](daemon_iokit_sync_report.md) supply the separately sealed constructor and adapter context.

## Assumption register

| ID | Assumption and dependent results | Stress test or falsification probe |
|---|---|---|
| DR1 | Addresses identify the thin arm64e source with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. All source conclusions depend on this identity. | Rehash source; compare ten retained spans, every replayed opcode, original fixups and bounded live IDB bytes. Equal preferred virtual addresses in another binary are insufficient. |
| DR2 | Candidate A enters with W25=`0x43C9`. Native production of this phase is unknown. Its decoded acquisition mode and count destinations depend on this premise. | Full-width symbolic identities separate phase-dependent expressions from the selected phase; resolve the incoming table/phase producer before claiming native reachability. |
| DR3 | Candidate A uses SP+B30=`0x100E99A00`, SP+B38=`0x100F4E390`, SP+B60=`0x100FC4130`, SP+B68=`0x101031EA0`, SP+B00=`0x100E99700`, SP+B08=`0x100F4E190`. | Verify all 256 inputs of each bank, original fixup and bias. Four constants are published by an original source clip; the two B30/B38 roots are declared X22/X24 parameters stored by another clip. Their upstream native producers remain unknown. |
| DR4 | Root clips and reader are composed through two fixture PC transitions with explicit register setup. Native continuity and common native frame ownership are unknown. | Independently replay the clips, compare all registers at each boundary, and count the 192 fixture transitions separately from original branches. No original branch is asserted at either splice. |
| DR5 | Candidate A's controller addresses SP+B70=`0x1010B66A8`, SP+B78=`0x1010C4670`, X27=`0x1010B66A8`, X28=`0x101039EF0`, W30=`0x0A5CD4CF` are declared entry context. | Check all effective addresses and bank identities. Native producer reachability remains unknown; callback controller updates execute as original instructions. |
| DR6 | The private stack, descriptor values, twenty-record buffer, direct/fallback tokens and once state are fixtures. They are not native addresses or allocation observations. | Vary two placements, four u32 counts, three pointer selections, two once states and two primitive returns. Check complete memory read/write sequences and exact fixture provenance. |
| DR7 | The helper record address R is eight-byte aligned. Acquisition caller prekey is unrestricted; agreement with the callee is proved under this alignment premise. | Check R=FP-0x100 and R&7=0 for every case; save a satisfiable alignment-premise witness. A weaker minimum alignment is not established here. |
| DR8 | Authenticated branches, calls and returns are modeled as logical targets and return tokens. | Verify original opcodes, original slots, modifiers, selected register targets, SP and X19-X29 restoration. Native PAC success remains unknown. |
| DR9 | Imported pthread primitives return with declared integer-register effects; source once callback executes only when the fixture invokes it. Native once scheduling, lock ownership and object contents are unknown. | Check original import bindings, exact arguments, two return values and two physical clobber patterns. All 834 retained source opcodes are integer-only and do not access X18/W18; native imported bodies remain outside this result. |
| DR10 | The descriptor cell remains unchanged by the declared primitive models. Native pointer stability and concurrent publication are unknown. | Verify there are no modeled descriptor writes. Source independently captures G+0 before acquisition and rereads G+0 before cleanup; establish mutation/lifetime rules before inferring identical native lock tokens. |
| DR11 | Candidate A's nonzero W23 semantic phase is unknown. Its physical backing is varied solely to verify the pre-use boundary. | Stop original execution before MUL at `0x10025F0E8`; prove the later index as a formula of arbitrary W23. Do not choose a W23 value to manufacture a successor. |
| DR12 | Candidate B uses SP+48=`0x101031FA0`, SP+50=`0x100FC4230`, X26=`0x1010A1960`, X22=`0x1010C4E18`. Native root/frame provenance and phase reachability are unknown. | Exhaust all 256 bank inputs, vary 768 phases and three pointer values, then execute 16 additional independent cases. Stop before the target load at `0x100A63790`. |
| DR13 | u32/u64 arithmetic is modular and memory is little-endian. Pointer arithmetic identities alone do not establish native address validity. | Save original and simplified solver queries; check all 36 queries UNSAT and three nonempty premise witnesses. Stack/cursor formulas require valid native owner extents for dereferences. |
| DR14 | LC_FUNCTION_STARTS provides enclosing compiler entry intervals, not semantic ownership of flattened blocks. | Decode the original load command and compare intervals with IDB data references. Do not assign Candidate A's fixture frame to Candidate B's enclosing prologue. |
| DR15 | The stack-probe binding identifies `___chkstk_darwin`; its native special register-preservation contract is unknown. | Verify the format-12 original bind, full GOT-address modifier, W9 argument and following stack arithmetic. Recover the actual helper implementation before composing a native entry ABI. |
| DR16 | IDB analysis is bounded and incomplete. Saved semantic comments are candidates, not proof of incoming control flow. | Compare all 512 raw bytes and 113 displayed rows; independently confirm both incoming data-reference slots against original fixups. No IDB mutation occurs. |
| DR17 | This increment establishes local reader and arithmetic contracts, not complete native descriptor use, port traffic or a full daemon/kext protocol. | Continue the unresolved producer, nonzero traversal and downstream interface boundaries below. The full investigation remains active. |

## Descriptor and two record epochs

The earlier constructor initializes a lock cell and a 960-byte allocation of twenty 48-byte records. This increment reads the following fields; it supplies no semantic C type or new array traversal interpretation.

| Location | Access width | Established operation in this increment |
|---|---:|---|
| G+0 | 8 bytes | Lock token captured at `0x10021ED7C`; freshly loaded for cleanup at `0x10025C4E8`. |
| G+8 | 4 bytes | Configured count loaded at `0x10021EE20` and tested for zero. It is not an occupancy or readiness proof. |
| G+12 | 4 bytes | No semantic read or write established; zero is fixture backing in these cases. |
| G+16 | 8 bytes | Buffer token loaded on Candidate A's nonzero path at `0x10025F0C4`, and tested by Candidate B at `0x100A63768`. |

The stack record at R=FP-0x100 has two distinct accessed layouts. Each requires at least 16 addressable bytes; this is an accessed extent, not an allocation or `sizeof` claim.

| Epoch | R+0 | R+4 | R+8 | R+12 |
|---|---|---|---|---|
| Acquisition | u32 encoded control | Unread, source-undefined padding in the fixture | u64 captured lock token spans R+8..R+15 | Included in that u64 token |
| Cleanup | u64 freshly captured token spans R+0..R+7 | Included in that u64 token | u32 encoded control | Retained backing; no cleanup field semantics established |

Let r=low32(R). The acquisition caller computes `K=u32((r XOR 0x987EAC8A)*0x316F29C1)` and stores `(W25+0x1574) XOR K` at R+0. The callee's source prekey agrees under R&7=0; multiplication and record decode are separately proved. Thus the declared W25=`0x43C9` produces decoded control `0x593D`. The caller prekey proof ends at `0x10021ED90`, before multiplication; its proved output supplies the next source-lift cut. The proof manifest records these compositional cuts explicitly.

Cleanup computes `Kc=u32((r XOR 0xEAAE0AC9)*0x7398180B)` and writes `u32(W26+0x1DD1-Kc)` at R+8. With retained W26=`0x84C2`, the known cleanup adapter decodes control `0xA293`. Reusing R does not make the two layouts interchangeable.

## Byte-bank and dispatch mapping

For each bank, `b(i)=i XOR right[left[i] XOR key]` is constant over all 256 possible byte inputs. Consequently controller changes affect intermediate values but do not alter these selected targets while the declared bank roots hold.

| Use | Left / right preferred VA | Key | Constant | Index / original slot | Effective target |
|---|---|---:|---:|---|---|
| A: global | `0x100E99A00` / `0x100F4E390` | 78 | A1 | 6BB / `0x1010A4F38` | G after bias `0xFFFFFFFFD5A43965` |
| A: acquire | `0x100FC4130` / `0x101031EA0` | A3 | 72 | CBF3 / `0x10109FE88` | `0x10043E280` |
| A: cleanup | `0x100E99700` / `0x100F4E190` | 81 | 48 | CBA3 / `0x10109FC08` | `0x1004423F8` |
| B: global | `0x100FC4230` / `0x101031FA0` | 6C | 87 | 6BB / `0x1010A4F38` | G after the same bias |

All bare numerical bank/table values in this table are hexadecimal. The global pool's original decoded rebase `0x12B6848B3` plus the stated u64 bias equals `0x1010C8218` modulo 2^64. Root publication clip `0x100387DF0..0x100387E40` derives the four A acquire/cleanup bank roots from original pool values. Clip `0x100387E68..0x100387E70` stores declared X22/X24 into B30/B38. Neither clip supplies native control-flow continuity to Candidate A.

```text
root-publication clip -- fixture transition --> root-parameter stores
                                             |
                            fixture transition + declared entry registers
                                             v
                         A: capture descriptor lock token
                                             |
                     acquire adapter / once / optional wrlock
                                             |
                              load descriptor count u32
                               /                      \
                           count=0                   count!=0
                              |                         |
                    reread descriptor token      load buffer token
                    cleanup / once / unlock      derive W13=0
                              |                         |
                    stop before next block       stop before W23 use

B: declared roots --> same G --> load buffer token --> phase/parity gate
                                                          |
                                              stop before target load
```

Under DR2, the caller derives W24=`0x7EAF` and W26=`0x84C2`. Its u32 count index is `W25 XOR ((count==0)*u32(W26+W24+0xFFFEFC94))`. The inner constant is 5. Before branching it overwrites W9 with `0x2DB65945`; the previous zero predicate does not survive in W9 into the successor.

| Condition / site | Index | Original slot | Destination / boundary |
|---|---:|---|---|
| count=0, BRAA `0x10021EE90`, modifier 07F3 | 43CC | `0x10105BD50` | `0x10025C4E0` |
| count!=0, same branch | 43C9 | `0x10105BD38` | `0x10025F0BC` |
| Cleanup return then BRAA `0x10025C57C`, modifier 07D7 | 84C2 | `0x10107C500` | Stop before `0x100246B84` |
| Nonzero dispatch at `0x10025F0F8`, modifier 3284 | `u32(125*W23) XOR 7EAF` | Depends on unknown W23 | Original execution stops earlier at `0x10025F0E8`. |

The nonzero prefix establishes X12=buffer token and W13=0, because `u32(0x2DB65945+0xD249A6BB)=0`. No buffer record is dereferenced or modified in the retained compositions. A scan, deletion, reset, occupancy check or eventual external call is unknown.

For Candidate B let s=incoming W24 and p=MEM64[G+16]. The original prefix reduces to:

```text
flag  = (s & 1) XOR (p == 0)
index = u32(s - 0x4C6F) XOR u32(flag * u32(s - 0x8A85))
```

The source uses `61*(s XOR 0x8B28)` before its low-bit mask; 61 is odd and `0x8B28` is even. Full-width source proofs establish parity and the final index for every u32 s and u64 p, conditional on G resolution. This formula leaves the target and native phase unestablished.

## Synchronization and external boundaries

| Original call PC | Selected entry / binding slot | Logical target / arguments | Modifier |
|---|---|---|---:|
| `0x10021EE18` | `0x10109FE88` | Acquisition adapter `0x10043E280`, X0=R | 6AA4 |
| `0x10025C570` | `0x10109FC08` | Cleanup adapter `0x1004423F8`, X0=R | 6AA4 |
| `0x10043E508`, `0x100442650` | `0x10109FE80` | `_pthread_once`, control `0x1010B8CD0`, callback `0x10040EBD4` | 8489 |
| `0x100361DF4` | `0x1010A0A00` | `_pthread_rwlock_wrlock`, captured non-NULL token or fallback | 4C4D |
| `0x100208EFC` | `0x1010A0D78` | `_pthread_rwlock_unlock`, freshly loaded non-NULL token or fallback | 5431 |

These are the same adapter entries, once control, callback and fallback cell `0x1010B9638` used by the previously recovered selected IOKit caller. Its primary cell `0x1010C8240` differs from this descriptor's G+0. If both primary tokens are NULL and the shared fallback is non-NULL and stable, they select that same logical token. This establishes conditional token convergence; native mutual exclusion, recursion, lock validity and scheduling are unknown. If no selected token exists, these retained adapters omit the corresponding lock primitive.

The source record capture precedes the acquisition adapter. The count read follows its return. Zero-count cleanup performs a fresh G+0 read. The declared pthread models do not change G; source publication and native concurrency must be resolved before inferring token identity across that interval. Return values 0 and 22 are finite primitive fixtures. The new caller's count-index theorem is independent of arbitrary incoming W0; native primitive success is not established by reaching the count load.

All 200 retained imported calls are pthread operations. There is no new observed Mach send, receive, port emission, IOKit connection or external method in these local paths. A descriptor lock token is not a Mach port name. Native imported bodies and unresolved successor blocks remain outside the observation.

## Enclosing entry and environmental context

Original LC_FUNCTION_STARTS places Candidate A within `0x100013F0C..0x10040EBD4`, and Candidate B within `0x100A59BB4..0x100ABCA64`. Their extents are 4,173,000 and 405,168 bytes respectively. These sparse compiler entry intervals do not define semantic ownership of flattened blocks or establish shared stack layouts.

At enclosing entry `0x100A59BB4`, the source saves 96 bytes, sets W9=`0xDEF0`, loads `___chkstk_darwin` through original slot `0x1010B1E28`, and calls at `0x100A59BE4` with X17 holding that full slot address. The original authenticated format-12 bind uses IA, diversity zero and address-diversity one. Subsequent instructions reserve `13*4096+3824=57072` local bytes; with the fixed save, `57072+96=57168` bytes. A separate retained prefix at `0x100A59D0C` loads an eight-byte cursor through X1, advances it by `0xA0=160` bytes and stores it through X1. Native owner bounds, complete record decode and the stack-probe helper's special preservation ABI are unknown.

The live IDB reports only incoming data references from `0x10106D6A8` to Candidate A and `0x10107F4C8` to Candidate B. Both match original fixups. They establish table membership, not native incoming phases or branch execution. The initial IDA query failed; the retained retry succeeded. Automatic function analysis remains partial; no database changes were made.

## Validation and reproduction

| Check | Result and limit |
|---|---|
| Original evidence | 10 source spans, 41 fixups and 834 distinct replayed opcodes checked. |
| Bank identities | 4*256=1024 input cases; roots remain stated premises. |
| Source arithmetic | 18 original/simplified proof pairs, all 36 queries UNSAT; 3 satisfiable premise witnesses; 127 source-lift visits. |
| Reader compositions | 4 counts * 3 selections * 2 once states * 2 returns * 2 placements/patterns = 96 cases. |
| Independent reader replay | 96 fresh engines, 49,528 source visits, 10,584 reads, 2,832 writes, 400 logical branches, 200 imported-call models, 96 final boundaries. |
| Fixture separation | 192 declared PC transitions, 120 record epochs; fixture transitions are not original control-flow edges. |
| Isolated B predicate | 768 distinct phases * 3 pointer values * 2 controller pairs = 4,608 cases, 188,928 source visits. |
| Additional independent B execution | 16 cases, including pointer 1 and phase boundary values absent from the original set; 656 source visits. |
| Fresh verifier replay | First and last reader cases replay again; 834 integer-only/X18-free opcodes checked. No universal native caller-clobber result is inferred from finite patterns. |
| Live IDB | 4 ranges, 512 raw bytes, 113 displayed instruction rows, 2 incoming data-reference slots; automatic analysis incomplete. |

Reproduce the new increment, without rerunning sealed older producers:

```sh
cd /Users/___/dev/dylex/extracted
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_descriptor_readers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_descriptor_guard.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_descriptor_readers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_descriptor_readers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/replay_daemon_descriptor_readers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_descriptor_readers.py
```

The scripts require the hash-pinned original image and retained evidence dependencies. Fresh IDB output is a separately captured read-only observation. `recover` verifies those retained bytes rather than silently requesting another live query. Expected final validation has `all_checks_pass=true`; native target execution and IDB mutation remain false.

Source lifting is linear in retained instructions with fixed memory cells and a 30-second solver limit per query. Replay time is O(C*(J*F+V+E)), where C is case count, J mapped source pages, F retained fixups scanned per mapped page, V source visits and E compared effects. Memory is O(F+the largest run and mapped RAM). Report/hash preservation is linear in total artifact bytes. All extents above are bytes and arithmetic widths are explicit; modular pointer identities do not prove address validity.

## Bounded continuation opportunities

| Impact | Unresolved boundary | Discriminating evidence |
|---|---|---|
| High | Native incoming phases for both readers and A's nonzero W23. | Recover the original table-index producers and register state from their actual predecessors; validate continuity without fixture PC transitions. |
| High | Descriptor publication and lock-token stability. | Establish all writers of G+0/G+8/G+16 and fallback, their lifetime and synchronization conditions; distinguish capacity from readiness. |
| High | Nonzero buffer use and connection to downstream daemon/kext work. | Resolve W23 from its producer, follow actual array accesses and preserve sentinel/control-word semantics before assigning traversal purpose. |
| Medium | Shared fallback token across descriptor and IOKit adapters. | Establish simultaneous native selection, non-NULL token validity and fallback initialization/lifetime. Shared once/fallback alone does not establish a common native critical section. |
| Medium | B's stack/frame and cursor ABI. | Recover its root producers and input cursor owner, then inspect the actual stack-probe helper; the enclosing entry's large reservation is insufficient to assign the reader's frame. |
| Low | IDB incoming-reference completeness. | Continue bounded read-only cross-reference and original-table census. Existing data references do not exclude additional computed incoming edges. |

Quality gates QG1-QG7 apply to this increment: factual content; explicit assumptions and falsification probes; local requirement coverage with the broad goal open; reproducible byte/u32/u64 calculations; separated record epochs and unknown phases; source/IDB/solver/replay provenance; and impact-bounded continuation context. The machine-readable gate artifact records the checked counts and hashes.
