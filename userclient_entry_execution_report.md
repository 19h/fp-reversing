# Continuous `_PRnut72j9` entry and initialization frontiers

Subsequent original-entry evidence: The [earlier FPTTLV entry report](userclient_fpttlv_entry_report.md) continues through the first 16 B allocation return in 84 private cases, preserving 72 predecessor prefixes exactly. Source zeroing, a ten-byte early header-fit gate, the first selected original-input byte at I+6, distinct empty/short cleanup cells and typed-retirement/staging-request frontiers are independently checked. Six source proofs and two rejected store-removal controls pass. No input-content read, native allocation/free or new Mach emission executes. Earlier boundaries below describe their historical increments; later staged objects and matched daemon/kext transactions remain separate open joins.

Original `_PRnut72j9` now executes continuously from its compiler entry to two distinct call frontiers in a private guest. NULL first argument reaches an `_IOFreeTypeImpl` request for the 4096 B typed region. Non-NULL first argument reaches the earlier `site.FPTTLV` 16 B allocation request. Both paths execute the original stack probe, two allocation request sites and two unsigned address-order helpers. The allocation results are declared non-NULL register fixtures; allocator bodies and the frontier calls do not execute. [UE1-UE4]

This replaces the earlier isolated entry and phase-value premises for this prefix with source continuity in 48 cases. It does not establish native UserClient admission, a complete `_PRnut72j9` operation, a successful daemon/kext transaction or the original producer of the tunnel marker. In the non-NULL cases, source stores define exactly 45 B of the 16384 B workspace and 80 B of the 4096 B typed region before the frontier. Workspace+0x20 has no defined byte at that point. This is a temporal boundary in a deliberately uninitialized private allocation model, not evidence of a native undefined read. [UE5-UE8]

## Primary evidence and verification

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instruction/data image |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, symbols, metadata and pointer-format-8 chains |
| `_PRnut72j9` container | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` | 202536 B / 50634 words, `0xfffffe000a635208` through `0xfffffe000a666930` exclusive |
| [Checks](triage_evidence/userclient_entry_execution_checks.json.zst) | `d0975eb53ea85b662d125d43e9a6e05aca48f30307a11d4b94c148d87cd9effe` | 48 continuous cases; five source spans / 1212 words; twelve 256-input bank rules |
| [Audit](triage_evidence/userclient_entry_execution_audit.json.zst) | `4988c70d99866f2bd75ae432e165b81a2f4dc058cb13a7d02059bce87b7fc07b` | Independent integer replay, byte provenance, six fresh source obligations and two source controls |

The [extractor](triage_evidence/recover_userclient_entry_execution.py) rechecks the entire container hash and compares each selected instruction with both images. The [producer](triage_evidence/probe_userclient_entry_execution.py) starts at the compiler entry, without mid-function CPU or memory repair. The [independent interpreter](triage_evidence/replay_userclient_entry_execution.py) does not import that executor or run Unicorn: it decodes original instructions, computes integer registers, NZCV, branches, loads and stores, then compares every recorded epoch. It also verifies the saved D-register values and the visited FMOV. The [audit](triage_evidence/audit_userclient_entry_execution.py) applies separate semantic and initialization oracles. The [delivery verifier](triage_evidence/verify_userclient_entry_execution_delivery.py) rebuilds the cases and audit and checks publication custody.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| UE1 | Compiler-entry frame, original stack-probe execution and exact retention of three arguments | UE-A1-UE-A3 |
| UE2 | Original two allocation requests, descriptor metadata and private return cuts | UE-A1-UE-A4 |
| UE3 | Two actual calls to the unsigned address-order helper; no initialization by that helper | UE-A1-UE-A4 |
| UE4 | Exact local NULL/non-NULL dispatch and the two reached call frontiers | UE-A1-UE-A5 |
| UE5 | Defined-byte maps, pointer/extent clones and saved aliases before the non-NULL frontier | UE-A1-UE-A5 |
| UE6 | No input-content read and no defined workspace+0x20 byte within these prefixes | UE-A1-UE-A5 |
| UE7 | Independent replay, universal local obligations and rejected source controls | UE-A1-UE-A6 |
| UE8 | External-interface limits, remaining joins and bounded continuation | UE-A1-UE-A7 |

## Entry, frame and call sequence

E is entry SP; F is the source-produced frame SP. S is the aligned allocation result and C the typed allocation result. I, A and Q are entry X0, X1 and X2. These symbols describe the observed argument and storage channels; this increment does not identify Q as a Mach name, task or external credential.

```text
compiler entry: I, A, Q
        |
save 128 B; original stack probe for 4208 B; reserve 4208 B
        |
F = E - 4336 B; save I, A, Q
        |
_IOMallocAligned(16384 B, 64 B) -> declared S
_IOMallocTypeImpl(AllocType descriptor, 4096 B) -> declared C
        |
unsigned order(S+0xe40, S+0x4000)
unsigned order(C+0x800, C+0x1000)
        |
source field initialization; test I != 0
        +---- I == 0 ---> before typed free(descriptor, C)
        |
        +---- I != 0 --> original initialization / fixed table transfer
                         ---> before typed allocation(FPTTLV descriptor)
```

The prologue reserves 0x80 B, calls the original probe with X9=0x1070 B, then subtracts 0x1070 B. Thus F=E-0x10f0 B. The probe performs two discarded WZR byte loads in each case; those loads establish access to private mapped pages without importing their poison bytes as values. The audit checks all 30 prologue/probe instruction words for writes to X0/W0, X1/W1 or X2/W2: none writes those argument registers before the saved-argument stores. The source probe returns to its actual caller. A fresh bit-vector obligation checks the exact subsequent frame subtraction and three stores. [UE1,UE7]

| Entry channel / source site | Width | Destination / meaning |
| --- | --- | --- |
| X2 / `0xfffffe000a63524c` | 8 B | F+0x738 retains Q |
| X1 / `0xfffffe000a635250` | 8 B | F+0x878 retains A, including upper 32 bits |
| X0 / `0xfffffe000a635254` | 8 B | F+0x8f8 retains I |
| Guard store / `0xfffffe000a635264` | 8 B | F+0x1060 retains the loaded guard; native guard value is not attested |
| First allocation / `0xfffffe000a6353dc` | X0/X1 | 16384 B, alignment 64 B; exact target `_IOMallocAligned` at `0xfffffe000c4b9a08` |
| Second allocation / `0xfffffe000a635470` | X0 pointer64 | Descriptor `0xfffffe000847bea0`; exact target `_IOMallocTypeImpl` at `0xfffffe000c4ba154` |

The two models supply only X0=S or C, overwrite X1-X17 with recorded caller-clobber fixtures, set recorded NZCV and the return address, and resume after the original call word. They write no memory. Neither fixture is described as native allocator output. The model's other register/vector and storage preservation is explicit; wider allocator effects, zeroing, failure behavior and platform admission remain unknown. Private arenas start with poison bytes and an all-zero defined-byte mask. [UE2]

## Ordering, descriptors and input branch

Both ordering calls select original slot `0xfffffe000847a828`, index0xf21, target `0xfffffe000a687ecc`, modifier0x4d6a. The helper consists of BTI, CMP X0,X1, B.HI to BRK #1, and RET. Its exact original symbol is unknown. It tests unsigned numeric order and performs no store; it does not establish mapped capacity, ownership or allocation initialization. The separate LSKD helper at another address is not substituted here. [UE3]

| Call PC | X0 | X1 | Retained frame cells |
| --- | --- | --- | --- |
| `0xfffffe000a6354dc` | S+0xe40 | S+0x4000 | F+0x968 / F+0x960 |
| `0xfffffe000a635534` | C+0x800 | C+0x1000 | F+0x958 / F+0x950 |

Two source obligations recover those exact additions and prove the comparison succeeds under the stated nonwrapping extent premises. Every continuous case executes both original helper returns. BRK is captured as source but never executed.

| Descriptor / use | Address | Name / signature | flags32 | Declared size |
| --- | --- | --- | --- | --- |
| Second allocation | `0xfffffe000847bea0` | `site.AllocType` / 512 `1` characters | 0xe4 | 4096 B |
| NULL-input release request | `0xfffffe000847ba60` | `site.AllocType` / 512 `1` characters | 0xe4 | 4096 B |
| Non-NULL frontier allocation | `0xfffffe000847bb60` | `site.FPTTLV` / `11` | 0xe4 | 16 B |

Each 64 B descriptor, its original chained name/signature pointers, complete NUL-terminated strings and scalar metadata are separately retained. The allocation and release descriptors occupy different addresses and have identical normalized contents. That establishes matching metadata, not native allocation/free identity or a complete C++ type. The 16 B FPTTLV request is the earlier call discussed in the [replacement bootstrap report](userclient_replacement_bootstrap_report.md), distinct from the later parser allocation described by the [container-staging report](userclient_container_staging_report.md).

At `0xfffffe000a635584` through `0xfffffe000a63559c` exclusive, the source computes:

```text
index32 = 0xc26 XOR (I != 0 ? 10 : 0)
target64 = original_table[index32]
```

The universal local proof covers every 64-bit I. The original transfer occurs at `0xfffffe000a6355b0` with modifier0x8851.

| Predicate | Index | Target | Reached frontier |
| --- | --- | --- | --- |
| I==0 | 0xc26 | `0xfffffe000a6661bc` | Before call `0xfffffe000a666260`, target `_IOFreeTypeImpl` at `0xfffffe000c4ba368`, X0=release descriptor, X1=C |
| I!=0 | 0xc2c | `0xfffffe000a6355b4` | Before call `0xfffffe000a636404`, target `_IOMallocTypeImpl`, X0=FPTTLV descriptor |

The NULL path's release request and eventual function return are different boundaries: release does not execute here and no return status is asserted. The non-NULL prefix loads fixed table slot index0x89b at `0xfffffe000a6362e0` and transfers at `0xfffffe000a63630c` to `0xfffffe000a636338`. Original execution supplies W12=0x5c and W15=0x32 before the FPTTLV request. The alternative source block at `0xfffffe000a636310` through `0xfffffe000a636338` exclusive, including the earlier report's transfer at `...6334`, is not visited in these cases. No inferred jump through that block is needed to reach the frontier. [UE4]

## Data origins and initialization boundary

Define N=low32(A) and R=N XOR0x31ae0066. A remains stored as 64 bits, while the encoded size channel uses W-register arithmetic. A fresh source obligation proves this low32 projection; the two tested sizes 16 and 0x1234567800000010 produce the same R. No input byte is read before either frontier, so the non-NULL test does not establish an admitted payload, length range, serialization schema or termination guarantee. [UE5,UE6]

| Source store / load | Width | Recovered value / next use |
| --- | --- | --- |
| `0xfffffe000a635950` -> C+0x718 | 8 B | C+0x418; loaded at `0xfffffe000a636344`, copied to C+0x170 |
| `0xfffffe000a635954` -> C+0x18 | 8 B | I; loaded at `0xfffffe000a63634c`, copied to C+0x98 |
| `0xfffffe000a635958` -> F+0x524 | 4 B | R |
| `0xfffffe000a63595c` -> S+0xc8 | 4 B | R; loaded at `0xfffffe000a636350`, copied to S+0xb5c |
| F+0x658 / F+0x490 / F+0x628 | 8 B each | Source-produced saved aliases S+0x10 / S+0x14 / S+0x26 |

Those saved aliases are actual values reconstructed from entry in all 36 non-NULL cases. They do not cover every possible alias writer in the complete container or later SP epochs. A separate source obligation checks the pointer/extent clone effects under disjoint nonwrapping frame/C/S storage premises. The full concrete replay checks the earlier definitions and intervening register/memory epochs for each delivered case.

The exact non-NULL workspace-defined map is:

| S offset | Defined extent | Value at frontier |
| --- | --- | --- |
| +0x4 | 4 B | 0x31ae0066 |
| +0x10 | 1 B | 0 |
| +0xc8 | 4 B | R |
| +0x154 | 4 B | 0x31ae0066 |
| +0x1e0 | 4 B | 0x1830b7ce |
| +0xa10 | 8 B | 0 |
| +0xb5c | 4 B | R |
| +0xbc4 | 4 B | 0 |
| +0xc60 | 8 B | 0x8f98c6acce5848ca |
| +0xe00 | 4 B | 0x31ae0066 |

The sum is 45 B. The typed region has ten defined 8 B fields, totaling 80 B: C+0x8=0, +0x18=I, +0x90=0, +0x98=I, +0x170=C+0x418, +0x3e0=0, +0x418=0, +0x440=0, +0x690=0 and +0x718=C+0x418. Contiguous C+0x90/+0x98 appear as one 16 B interval in the audit's byte map. All other arena bytes remain unknown in this model. The NULL prefix defines only S+0x154/S+0xe00, totaling 8 B, and C+0x8/+0x90/+0x3e0, totaling 24 B. [UE5]

In particular, S+0x20..S+0x23 remains undefined in both prefixes. The [discriminator-origin report](userclient_discriminator_origin_report.md) and [secure-tunnel insertion report](secure_tunnel_table_insertion_report.md) locate its later marker read. No read from that cell occurs in the current prefixes. This narrows the missing producer's required temporal position under these private epochs; it does not establish absence of a later writer, alias-complete coverage or a native initialization defect. [UE6]

## Independent checks and falsification controls

The case matrix is three controller fixtures (original file values, zero, declared nonzero noise), two 256 B-separated entry stack placements, and eight I/A combinations. It includes NULL with size0 and size2^64-1; a private non-NULL pointer with sizes0,1,16,65536 and0x1234567800000010; and the all-one 64-bit pointer/size values. Q is separately zero or a private pointer. The all-one pointer is never dereferenced; its inclusion tests only local pointer-value control. These are 48 finite private states, not an exhaustive native input domain. [UE7]

| Check | Verified count |
| --- | --- |
| NULL cases / visits per case | 12 / 297 |
| Non-NULL cases / visits per case | 36 / 1162 |
| Total original instruction visits | 45396 |
| Source reads / read bytes checked | 3324 / 16560 B |
| Source writes / write bytes checked | 12948 / 97044 B |
| GPR values / NZCV epochs checked | 1408764 / 45444 |
| Final D-register values checked | 1536 |
| Logical control edges checked | 372 |
| Whole frame/arena snapshot bytes checked | 1191168 B |
| Register-only API cuts | 96, two per case; zero model memory writes |
| Bank-array inputs checked | 3072 across twelve rules |
| Fresh nonvacuous UNSAT obligations | 6, covering 37 lifted instruction instances |

The five captured spans contain 1212 words; the continuous cases visit 1199 distinct PCs. The 13 remaining words are the ten-word alternative block, the two unexecuted frontier call words and the order helper's BRK. Captured source custody is not described as execution of those words. The 30-word argument-preservation certificate and six source obligations are separate from that execution coverage.

Two controls replace one original store with NOP in the private code image while preserving original entry and the allocation fixtures. Removing the C+0x718 store at `0xfffffe000a635950` stops before the dependent load at `0xfffffe000a636344`. Removing the S+0xc8 store at `0xfffffe000a63595c` stops before the dependent load at `0xfffffe000a636350`. The independent interpreter checks each altered prefix and both fail the ordinary frontier/defined-byte oracle. Neither consumes the undefined value. These controls test semantic initialization dependencies, not only artifact hashes.

Construction and production cost O(B+I+256R+C*(B+V+E)) time/retained space for image bytes B, captured words I, bank rules R, cases C, visits V and byte events E. Independent replay costs O(V+E+M) time/space per case, M the delivered snapshot extents. The producer has a 30000-visit bound per case; neither normal nor altered case reaches that limit. Source lifting is linear in its instruction/DAG representation; solver search cost is separate, with a 30 s per-query limit. No native heap, protected input-content processing, IPC operation or IDB mutation executes.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UE-A1: Both pinned images and original pointer-format-8 interpretation apply. | UE1-UE8 | Rehash images/container, compare selected words, independently decode each selected original pointer and metadata string. A changed word, chain or digest invalidates reuse. |
| UE-A2: The declared private original-entry CPU state and mapped, separated frame/arena extents apply. Native entry admission is unknown. | UE1-UE8 | Rebuild all 48 cases, compare every GPR/NZCV epoch and entire frame/arena maps; vary placement/controller/argument fixtures without mid-function repairs. |
| UE-A3: PAC/AUT and authenticated branches are treated as logical transfers; native authentication, keys and hardware effects are unknown. | UE1-UE8 | Verify original branch words, source pointer slots, modifiers and actual logical targets. Hardware validation would require independently established native state. |
| UE-A4: Two non-NULL allocator register-return cuts preserve the declared storage and other register state and write no RAM. | UE2-UE8 | Check both request PCs, arguments, descriptor sizes, clobbers and source-only byte provenance. Replacing a cut with authentic allocator effects may change the initialization/lifetime boundary. |
| UE-A5: Within each local proof, source frame/C/S epochs are stable, nonwrapping and disjoint where memory effects are composed. | UE4-UE8 | Re-solve the six satisfiable-premise obligations; replay earlier definitions and all intervening writes. Establish later alias/epoch continuity before applying the maps past the frontier. |
| UE-A6: The explicit integer, NZCV, memory and D-register subset used by the independent interpreter matches the visited original instructions. | UE7 | Compare all recorded epochs and both store-removal prefixes; unsupported instructions or differing effects fail closed. No full ISA or native-machine equivalence is asserted. |
| UE-A7: Current memory/source facts apply only to the pinned images and reported prefixes. Native caller, input schema, lifetime and transaction identity remain unknown. | UE8 | Join original caller admission and later producers to the same object/transport epochs before assigning native behavior or extending completion claims. |

## Bounded continuation and interface consequences

| Impact | Next discriminating work | Result sought |
| --- | --- | --- |
| High | Continue the original earlier FPTTLV allocation return at `0xfffffe000a636408`, retaining the source-produced frame/C/S state. | Establish the returned object's initialization, NULL path, retention at C+0xb0 and subsequent frontier without injecting phase values. |
| High | Trace subsequent exact S+0x20 byte writers, including saved aliases, calls and SP changes. | Locate the original tunnel-marker producer and its lifetime before the already recovered insertion read. |
| High | Join the original selector26/provider admission to this entry and later daemon request evidence. | Establish incoming argument/object/transaction identity; a pointer-value branch alone is insufficient. |
| Medium | Continue NULL-input cleanup through original typed/aligned free requests and the epilogue under explicit lower contracts. | Establish source completion/status and retirement ordering while preserving the distinction from native free effects. |
| Medium | Establish native allocator zeroing/capacity, controller observation epochs and PAC admission. | Replace the private no-memory allocator cuts and logical authentication premises. |
| Low | Search for additional original symbols or verified ABI aliases for the five-word order helper. | Improve naming without inferring identity from a similar helper body. |

The new interfaces are argument saving, allocation requests, unsigned ordering, internal table dispatch and private field publication. No new incoming Mach port, outgoing message, transferred right, message identifier or emission site is established. The two frontier targets are typed-memory operations, not IPC endpoints. Existing confirmed endpoint and emission evidence remains in the [Mach-port report](mach_ports_report.md) and [interface ABI report](interface_abi_report.md). Native daemon/kext pairing and the full interface investigation remain open. [UE8]

## Quality gates

**QG1** Pass: factual technical analysis. **QG2** Pass: UE-A1-UE-A7 register dependencies and falsification probes. **QG3** Pass for this increment: original routine entry, CPU/data/control contracts, environmental assumptions and Mach/interface limits covered; the full goal remains active. **QG4** Pass: u32/u64 channels, byte extents, exact offsets, modular arithmetic, counts and complexity bounds are reproducible. **QG5** Pass: numeric order versus initialization, NULL versus non-NULL paths, earlier versus later FPTTLV allocations, private unknown bytes versus native defects and captured versus executed words are distinguished. **QG6** Pass: pinned original/normalized bytes, original metadata/pointers/symbols, fresh obligations, independent replay and source controls support the claims; native gaps remain explicit. **QG7** Pass: impact-ranked bounded continuation above. `full_goal_complete=false`.

## Subsequent failure fallback evidence

The [failure-fallback report](userclient_failure_fallback_report.md) locates later cleanup of the original entry allocations: typed context retirement at `0xfffffe000a666260`, using a descriptor matching the 4096 B allocation descriptor, followed by `_IOFreeAligned` at `0xfffffe000a6662b0` with the original 16384 B workspace extent. These requests occur after the selected message-parser failure and a NULL fallback-buffer result. Native retirement, compiler guard/frame restoration and RETAB remain unknown.
