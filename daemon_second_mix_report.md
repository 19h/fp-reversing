# Daemon second mixing pass and gate reacquisition

The warm payload-driven initializer completes 623 second-pass updates, forces state word 0 to `0x80000000` and reacquires the same gate released before entropy collection. The second pass has a compact indexed recurrence and one state wrap. The gate's source compare-and-swap replaces `0x5d96` with `0xa94ef`; every other old word selects a self-retry. Both retained executions take success without an additional memory or API premise. Execution stops before `0x100a3881c`, where subsequent readiness/global-state decisions begin. Native synchronization, output use and daemon-kext pairing remain unknown. [SX1-SX5]

```text
inherited first pass: G[624 u32], i=2, remaining=623
  -> G[i] = second_mix(G[i], G[i-1], i)
  -> increment i; if624: copy G[623] to G[0], i=1
  -> decrement remaining; repeat until0
  -> force G[0]=0x80000000
  -> load saved gate pointer
  -> CAS gate: expected0x5d96, desired0xa94ef
     old differs -> self-retry
     old matches -> stop before 0x100a3881c
                     later readiness/state/output: unknown here
```

| Evidence | Primary artifact and boundary |
| --- | --- |
| SX1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_second_mix.py) retains original regions, fixups and complete packed intervals. |
| SX2 | [First-pass report](daemon_payload_mix_report.md), [checks](triage_evidence/daemon_payload_mix_checks.json.zst) and [audit](triage_evidence/daemon_payload_mix_audit.json.zst): complete entry states for two declared seed/caller contexts. |
| SX3 | [New checks](triage_evidence/daemon_second_mix_checks.json.zst): two complete second-pass executions, final counter exits, word forces and gate transitions; zero new input bytes or imported returns. |
| SX4 | [Independent auditor](triage_evidence/audit_daemon_second_mix.py) and [audit receipts](triage_evidence/daemon_second_mix_audit.json.zst): complete source/state/byte replay, every intermediate array/key state and eight nonvacuous original-source obligations. |
| SX5 | [Readiness/arena report](daemon_readiness_arena_report.md) and [arena split report](daemon_arena_split_report.md): earlier admission and gate release. [Seed-material](daemon_seed_material_report.md) and [PRNG-output](daemon_prng_output_report.md) reports retain separately established caller/consumer variants. |
| SX6 | [Publication verifier](triage_evidence/verify_daemon_second_mix_publication.py): pinned source/dependencies, packed interval integrity, exact manifest delta, preserved inputs and raw/typed/decoded path hygiene. |

## Complete second-pass recurrence

G=`0x1010c784c` holds 624 little-endian u32 words:624*4 B=2496 B. The private key at Q=SP+`0x220` and 64 B payload at P=`0x650011521c` retain their inherited definitions. No instruction in the retained second-pass intervals accesses the payload span; all four key words remain unchanged. Parent cases 0 and 1 correspond to prior seed cases 0 and 7. Their expansion returns, caller/API clobber profiles, clock fields, arena metadata and controller premises remain inherited. [SX1-SX4]

For each iteration, using modulo2^32 word arithmetic:

```text
G[i] = u32((G[i] XOR u32((G[i-1] XOR (G[i-1] >> 30))*1566083941)) - i)
i = i+1
if i == 624:
    G[0] = G[623]
    i = 1
remaining = remaining-1
```

The pass starts at i=2,remaining=623, visits destinations2 through 623 and then1, and ends at i=2,remaining=0. The state-wrap copy occurs once. Source `0x100abba18..0x100abba44` establishes the indexed equation and increment for arbitrary u32 state words and i=1..623. The full executions establish the actual index sequence and all 624 intermediate state words after each iteration. The final force is a separate source store. [SX1-SX4]

| Source operation | Address | Established effect |
| --- | --- | --- |
| Load current/preceding words | `0x100abba18`, `0x100abba20` | G[i],G[i-1] |
| Multiply transformed predecessor | `0x100abba30` | u32((previous XOR(previous>>30))*`0x5d588b65`) |
| Second-pass store | `0x100abba3c` | XOR result minus i |
| Increment candidate | `0x100abba40` | W22=i+1 |
| Comparison call | `0x100abbb2c -> 0x100444d6c` | Unsigned incremented i >623 |
| State-wrap copy | `0x1009f04b8` | G[0]=G[623] |
| Wrapped index reset | `0x1009f04d0` | W19=1 |
| Nonwrap index advance | `0x100a6c674` | W19=W22 |
| Remaining decrement | `0x100a0773c` | W25=u32(W25-1) under established phase |
| Counter transfer | `0x100a07764` | Continue or final force |
| Final force | `0x100b2a20c` | G[0]=`0x80000000` |

Descriptive roles are second-pass state mixer, state wrap, remaining-counter dispatch, final state-word force and gate reacquisition. These labels establish block behavior with exact addresses; whole-function boundaries and native entry reachability remain unknown. [SX1-SX4]

## Comparison and exit contracts

Each iteration builds a private 40 B record at `0x680005ff70` and calls the existing equality/unsigned-greater leaf. The new auditor reconstructs every record at call time using original byte definitions. A=zero-extended(i+1),B=623,mode=1. Each execution has one true comparison at i=623 and 622 false comparisons. The source result store selects the original fixups below. [SX3-SX5]

| Predicate | Index | Fixup slot | Target | IA modifier |
| --- | --- | --- | --- | --- |
| i+1 >623 | `0x1770` | `0x101045a70` | `0x1009f0478` | `0xc044` |
| i+1 <=623 | `0x17bd` | `0x101045cd8` | `0x100a6c638` | `0xc044` |

The nonwrap and wrap blocks independently establish W9=1,W10=1 at the common counter entry. The proofs retain source-defined private fields SP+`0x148`=`0xa73ca7a3`, SP+`0x150`=`0xd831fa4f` and SP+`0x1cc`=`0xb399` as applicable. These fields are inherited, rather than supplied by this continuation. This phase relation is necessary for the obfuscated arithmetic to simplify to decrement by 1. [SX1-SX4]

| Remaining before decrement | Counter after decrement | Index | Slot | Target |
| --- | --- | --- | --- | --- |
| n!=1 | u32(n-1) | `0x1c60` | `0x1010481f0` | `0x100abba18` |
| n=1 | 0 | `0x1cdc` | `0x1010485d0` | `0x100b2a200` |

Both counter targets use IA modifier`0x0d73`. Source `0x100a0775c` loads X9; `0x100a07764 BRAA X9,X17` emits the transfer. The arbitrary-u32 counter proof includes n=0, whose result is`0xffffffff` and continuation. Concrete retained execution reaches n=1 and exits. No arbitrary-input termination claim follows from the partition. [SX1-SX4]

## Final word force and same-gate transition

The force block writes `0x80000000` to G[0] before its gate operation. Source `0x100b2a240` loads the 8 B pointer from SP+`0xc0`; it equals gate address `0x1010b5de0`. Source `0x100b2a244` separately loads SP+`0x128`=`0x1010b5f20` into X4; its later role is not established here. The block selects gate entry`0x100b3a848` through slot`0x1010672b0`, index`0x5a78`, IA modifier`0x04f3`. Its transfer is emitted at`0x100b2a24c`. [SX1-SX4]

At`0x100b3a84c CASAL W8,W12,[X5]`, source sequential value semantics are:

```text
old = gate32
gate32 = (old == 0x5d96) ? 0x000a94ef : old
W8 = old
```

| Old gate word | Stored gate word | Index | Slot | Target |
| --- | --- | --- | --- | --- |
| `0x00005d96` | `0x000a94ef` | `0x8106` | `0x10107a720` | `0x100a3881c` |
| Every other u32 | old word | `0x5a78` | `0x1010672b0` | `0x100b3a848` |

Both use IA modifier`0x04f3`; source`0x100b3a864` loads X8 and`0x100b3a86c BRAA X8,X17` emits the transfer. The retry target reloads the expected available word before trying CAS again. The arbitrary-old-word source obligations prove replacement/return semantics and both index choices. Failed hardware write cycles, contention, fairness, native atomic ordering and eventual admission are not observed. [SX1-SX4]

```text
earlier source acquisition     gate=0xa94ef
  -> arena decision/reservation
  -> 0x100a8c078 release        gate=0x5d96
  -> entropy/clock + expansion + first 624 + second 623
  -> force G[0]=0x80000000
  -> 0x100b3a84c reacquire      gate=0xa94ef
  -> next readiness/state decisions [not executed here]
```

The source intervals place state initialization between release and reacquisition of the same 4 B gate. Their byte-level joins preserve the released value through mixing; both CAS reads see `0x5d96`. This is a sequential source-order result under inherited caller premises. It does not establish a native critical-section ownership protocol, a race, a publication guarantee or an absence of other writers. [SX2-SX5]

## Resulting state and related caller evidence

| Parent case | Seed parent | Second-pass array before force: SHA-256 | Final array after force: SHA-256 |
| --- | --- | --- | --- |
| 0 | 0 | `9ae85df6ce8e60296ebe456435731d268f89cb8fb5a069d63a0e45324135764b` | `c590f718f4e4c6d98064bdc33a9b7dbb1478114f75ceacb1753dbcf9d15b978b` |
| 1 | 7 | `5b3bb41bc7078261dcd253617f11478bedabc6c70690db6f8578ff1c6ae151a2` | `b8b35dfc90a18fdf90bc99b001069c38ef6c3fb3c8ba3bfcd94b5d64ac19378b` |

The force changes only G[0]; G[623] is respectively`0x894f07ca` and`0x18743e6f`. Final key words remain`[0xffffffff,0,0,0]`; the64 B source-filled payload is unchanged. The final cut is before the first instruction at`0x100a3881c`. The current path has not executed a twist, tempering step, generated-output store or IPC emission in this increment. [SX2-SX4]

| Property | Earlier seed-material caller | Current warm caller |
| --- | --- | --- |
| Global state | G=`0x1010c784c`,624 u32 words | Same address and extent |
| First-pass length/coefficient | 624 /1664525 | 624 /1664525 |
| Key representation | Four words XOR-encoded by`0x5cf7672b` | Four raw words |
| Nonwrap key mutation | low32(P+1) | Payload/address/text-dependent masks, distinct per j |
| Second-pass length/coefficient | 623 /1566083941 | 623 /1566083941 |
| Second-pass equation | XOR transformed predecessor, subtract i | Same local recurrence, proved at current source |
| Final word 0 | `0x80000000` | `0x80000000` |
| Subsequent evidence | Separate full twist/tempering and buffer-XOR caller | Cut before 0x100a3881c; output use unresolved here |

The [earlier seed-material](daemon_seed_material_report.md) and [PRNG-output](daemon_prng_output_report.md) artifacts provide these separate source contracts. Matching array dimensions, coefficients and local equations support a common initialization pattern. The differing key mutations prevent transferring complete routine equivalence, generator-stream identity, caller lifetimes or output-buffer identity to the current route. The current source was recovered independently. [SX1-SX5]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| SX-A1: Pinned image and fixups identify this specimen | Operations and transfer destinations | Rehash image, every visited opcode and used fixup; distinguish logical transfers from hardware PAC. |
| SX-A2: Two frozen first-pass boundaries apply | Current entry and caller reachability | Exact GP/Q/SP/NZCV/known-byte/owner joins; native caller/controller epoch remains unknown. |
| SX-A3: Inherited API/clock/arena premises apply | Initial state/key/payload and gate value | Retain existing return/field controls and unknown clock padding; introduce zero new input bytes or returns. |
| SX-A4: Fixture compaction preserves source-known byte maps | Complete resumed execution | Check every parent/intermediate/exit byte map and owner extent; physical backing is not initialization evidence. |
| SX-A5: Index and private phase fields satisfy their declared domains | State wrap and common-counter simplification | Prove i=1..623 recurrence, i=1..622 nonwrap phase, exact wrap fields and all-u32 remaining partition. |
| SX-A6: Scalar/vector/CAS lift matches original source semantics | Independent replay and equations | Check full GP/Q/NZCV and byte effects; model CAS as a conditional sequential value transition. |
| SX-A7: Saved pointer identifies the earlier gate | Same-gate lifecycle | Verify the original SP+0xc0 load, exact address, inherited release and absence of intervening gate writes during mixing. |
| SX-A8: No concurrent actor changes the retained source-model state | Observed gate success | Prove arbitrary-old-word retry/success partition; native ordering, contention and eventual acquisition remain unknown. |
| SX-A9: Separate caller variants do not establish current downstream identity | Pattern comparison and cross-layer use | Preserve current cut and differing key mutations; require actual def-use joins into later output/Mach/IOKit sites. |

## Verification and bounded continuation

The publication verifier compares rebuilt proof DAGs modulo commutative operand order, rejects changed operators/literals/noncommutative ordering, and reruns every retained UNSAT query.

The new receipts contain 1252 intervals,181990 original instruction visits,28672 reads,11220 writes,6234 logical edges and 1246 internal calls. Two complete 623-iteration passes account for 1246 intervals; each case adds 17-,20- and 10-instruction exit/force/gate intervals. Independent replay checks all scalar/vector/flag states and byte effects. The compact model checks 777504 intermediate state words,4984 unchanged key words and 79744 unchanged payload bytes. Eight nonvacuous source obligations cover recurrence, increment, wrap, nonwrap phase, remaining counter, force/setup, CAS replacement and retry/success selection. [SX3-SX4,SX6]

The release-to-reacquisition census checks two original release writers,1260 gate-preserving parent intervals and23724 parent source-write events. No parent write overlaps the gate after release; both retained CAS operations then replace its available word. [SX2-SX6]

The recurrence takes O(K) time for K=623 and O(N) state words for N=624, plus O(1) counters. Complete-array validation costs O(K*N); extraction/replay additionally scales with receipt bytes, source visits and memory effects. JSON decoding retains storage proportional to the receipt collection and largest interval. Each solver query has a 30 s limit. Word arithmetic is modulo2^32, pointer arithmetic is64-bit, all state words are4 B and extents/counts are exact. Native APIs, IPC, allocation/free, concurrent target execution, hardware PAC and IDB mutation do not execute. [SX1-SX6]

| Impact | Next evidence | Architectural purpose and boundary |
| --- | --- | --- |
| High | Follow0x100a3881c readiness/global-state decisions | Establish actual use of the completed state after gate acquisition |
| High | Join current state to twist/tempering and established output consumers | Prior consumer variants do not prove the current route's buffer or transport dependency |
| High | Establish coherent constructor/controller/native writer epochs | Exact sequential joins do not prove native reachability, ownership or synchronization |
| Medium | Census other gate/state writers and their access order | Initialization lies between release and reacquisition; native reader exposure remains unknown |
| Medium | Compare initializer variants with their distinct key codecs | Identify shared contracts while retaining payload/address/text dependence |
| Low | Apply descriptive mixer/wrap/force/gate navigation labels | Preserve source addresses and unknown whole-function boundaries |

This increment adds no incoming/outgoing Mach port, right disposition, message emission site or UserClient selector. Existing [port mappings](mach_ports_report.md) and [ABI mappings](interface_abi_report.md) remain the transport evidence. The result supplies complete local second-pass state and a concrete post-initialization gate boundary for subsequent correlation. The full interface goal remains active. [SX1-SX6]

**QG1** passes: factual source/interface analysis. **QG2** passes: SX-A1-SX-A9 register dependencies and falsification probes. **QG3** passes for second-pass/force/gate recovery; the full objective remains incomplete. **QG4** passes: exact widths, modulo arithmetic, counts, extents and complexity. **QG5** passes: two mixing phases, final force, sequential CAS and native synchronization are distinct. **QG6** passes after pinned-source, independent replay, nonvacuous solver, preserved-input and publication checks. **QG7** passes: bounded continuation covers actual output use, caller epochs, writer order and variant comparison.

Decoded checks SHA-256: `de0faa88143debe0cd696ebe39f86a3e82dc0875233629a4e8f4357ac7c1c69e`. Decoded audit SHA-256: `0ca3ddf3e468e960ca30a972380591b7a488086a7d7ae7437b4b28eebb1fe575`.
