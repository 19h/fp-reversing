# Capacity-policy caller and ordered zone startup

The original caller invokes the complete capacity policy before dispatching phase6 (`kmem`) and phase7 (`zalloc`). The magazine bootstrap is the unique phase7/rank0 registration; the three recovered IPC-zone specifications have rank3. The original unsigned comparator therefore places that magazine callback before each selected IPC-zone callback, conditional on a sorted, protected table and ordinary callback completion. The policy's formerly unnamed feature word is the high u32 of the original `_sane_size` u64, not an independent Boolean input. Five continuous private caller/policy/dispatcher/observer runs check the policy tail and registration order; all registered callback bodies remain explicit ordinary-return models. Native zone creation, allocation ownership and a matching daemon transaction remain unknown. [BO1-BO6]

```text
original caller 0xfffffe000c634e88
  |
  +-> trace "zone_bootstrap" -> complete policy 0xfffffe000c631f9c
  |      count/capacity -> descriptors -> 689 metadata updates
  |                                      -> two callback objects
  |
  +-> other boot helpers [explicit no-RAM return models]
  |
  +-> dispatcher(6): 13 registrations
  |
  +-> original sizing arithmetic, full _sane_size load
  |
  +-> dispatcher(7): 136 registrations, sorted by unsigned rank
         rank0: unique magazine bootstrap [callback body modeled]
         rank1: two callbacks             [callback bodies modeled]
         rank2: MixedData family builder  [callback body modeled]
         rank3: includes IPC zones        [callback bodies modeled]
         later ranks
```

## Primary provenance and claim register

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Eight complete compiler intervals contain966 instructions/3864 B; seven match prior captures. The new caller interval is `0xfffffe000c634e88..0xfffffe000c6350a4`, end exclusive:135 instructions/540 B. The complete retained policy is `0xfffffe000c631f9c..0xfffffe000c6321a8`:131 instructions/524 B. Function role names below are descriptive or inferred from original trace literals; they are not recovered nlist definitions.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| BO1 | Original caller's policy, phase6 and phase7 call order; original timing literals | BO-A1, BO-A2 |
| BO2 | `_sane_size` alias, exact descriptor/metadata/object writes in the complete policy | BO-A1, BO-A2, BO-A4-BO-A6 |
| BO3 | Pinned registration/fixup custody; unique magazine rank0 precedes selected IPC rank3 | BO-A1, BO-A3 |
| BO4 | Continuous private caller/policy/dispatcher/observer execution, with explicit callback models | BO-A1-BO-A6 |
| BO5 | Source proofs, CFG certificate, semantic oracles, fresh CPU replay and altered-source rejection | BO-A1-BO-A6 |
| BO6 | Architectural boundary and unresolved native producer/consumer join | BO-A1-BO-A6 |

Evidence: [extractor](triage_evidence/recover_kernel_zone_boot_order.py), [private executor and semantic oracle](triage_evidence/probe_kernel_zone_boot_order.py), [independent replay](triage_evidence/replay_kernel_zone_boot_order.py), [source/CFG audit](triage_evidence/audit_kernel_zone_boot_order.py), [delivery verifier](triage_evidence/verify_kernel_zone_boot_order_delivery.py), [capture](triage_evidence/kernel_zone_boot_order_checks.json.zst), [audit receipt](triage_evidence/kernel_zone_boot_order_audit.json.zst). Decoded capture SHA-256: `745cc81c71a9d629db071eb4cd6fc314ac0cdbc566e24627c2e18d25916db152` (271,775 B). Decoded audit SHA-256: `8cb89a598d2aabfc36e587a691a2bd92bde373c8a6552f84b859d69dbcfd3600` (40,330,489 B). Original reference data sufficed; no new IDA access or mutation was required.

## Original caller and naming evidence

| Caller PC | Target / argument | Original evidence and qualification |
| --- | --- | --- |
| 0xfffffe000c634ee4 | 0xfffffe000c637698 | Preceding trace literal `vm_page_bootstrap`; helper body not executed |
| 0xfffffe000c634f1c | 0xfffffe000c631f9c | Preceding trace literal `zone_bootstrap`; complete policy body executed |
| 0xfffffe000c634f54 | 0xfffffe000c636dac | Preceding trace literal `vm_object_bootstrap`; helper body not executed |
| 0xfffffe000c634f58 | 0xfffffe000be2eb88 | Additional intervening helper; exact role unknown |
| 0xfffffe000c634f90 | 0xfffffe000c6365b0 | Preceding trace literal `vm_map_init`; helper body not executed |
| 0xfffffe000c634fc8 | 0xfffffe000c6353e4 | Preceding trace literal `kmem_init`; helper body not executed |
| 0xfffffe000c634fd0 | 0xfffffe000c6302c4, W0=6 | Phase6 dispatch after policy and the listed helpers |
| 0xfffffe000c635054 | 0xfffffe000c6302c4, W0=7 | Phase7 dispatch after `vm_fault_init` trace and sizing arithmetic |

Trace labels describe source timing positions. In particular, the `vm_fault_init` literal does not identify a separately called body at that point: original sizing instructions precede phase7 dispatch. `_kprintf` is an exact original nlist definition at `0xfffffe000c5e73a4`; `___strncpy_chk` is an exact definition at `0xfffffe000be3e790`. Their private calls are explicit no-RAM return models, including the trace-copy helper. Native trace contents/output are not asserted. [BO1]

The complete caller CFG has135 nodes,135 reachable states and135 edges in a may-branch abstraction. Its normal RETAB at `0xfffffe000c63509c` follows the policy call, dispatch6 and dispatch7 in that order. The canary-failure call at `0xfffffe000c6350a0` has an out-of-interval return edge; no normal error-callee return or termination is inferred. Calls are ordinary returning ABI boundaries in this certificate. Their RAM effects and termination are separate premises. [BO1,BO5]

## Shared `_sane_size` input and complete policy tail

| Object | Address / width | Original evidence |
| --- | --- | --- |
| `_sane_size` | 0xfffffe000cb29cb0 / u64 | Exact original `com.apple.kernel` nlist definition; full load at0xfffffe000c63500c |
| Policy high word | 0xfffffe000cb29cb4 / u32 | Load at0xfffffe000c632190, within that same u64 |
| Count N | 0xfffffe0007e66f38 / u32 | Input at0xfffffe0007ef8bf0 plus1 modulo2^32 |
| Capacity K | 0xfffffe0007e6a248 / u16 | Original file default8; conditional stores10/14 |
| Descriptor base | 0xfffffe000cb7f2d0 | Original48 B stride |
| Metadata base | 0xfffffe0007e6a7a0 | Records at4 B stride; low u16 updated for indices1..689 |
| Callback object A | 0xfffffe000cb7f5d0 /128 B | Logical callback0xfffffe000bd79158, flags0x02200001 |
| Callback object B | 0xfffffe000cb7f1f0 /128 B | Logical callback0xfffffe000bd77d00, flags0x02200003 |

For one unchanged little-endian u64 V at `_sane_size`, the policy load equals V[63:32]. Its nonzero test is equivalent to unsigned V>=2^32. This refines the previous report's abstract feature word. It does not establish constancy across unexamined native helpers, or the value supplied by a native machine. The original symbol and VM context support a memory-size interpretation; the proofs use raw integer widths and do not assume native units. If V denotes bytes, the threshold is4 GiB; that unit interpretation is unnecessary for the alias result. [BO2]

The presence-only parser call remains `(boot_structure+0x6c,"zc_mag_size",NULL,0,0)`. For an incoming default8:

```text
N = (u32 maximum_index + 1) mod 2^32
if the original parser reports the key present: preserve K
else if unsigned N >= 10: K = 14
else if high_u32(_sane_size) != 0: K = 10
else: preserve K
```

After capacity selection, the original policy initializes N descriptors when N is nonzero. For descriptor D=base+48*j, it calls either the direct helper `(D,16)` at `0xfffffe000be57bec` or the logical indirect helper with `(context,u16[TPIDR_EL1+0x1b8],16,D)`. The indirect function cell is `0xfffffe0007e6c9a8`, the mode word is `0xfffffe0007e6c9b8`, and the context cell is `0xfffffe000cb88f48`. The BLRAA uses a modifier derived from the function-cell address with top halfword0xedeb. Native helper targets/effects and authentication remain unknown. Direct helper effects are also modeled; the integer16 is a recovered argument, not an established byte count. Source stores set u32[D+0x10]=0, u64[D+0x18]=0, u64[D+0x20]=17. The source's address-tag adjustment is retained; the bounded private descriptor regions do not take it. [BO2]

The next loop calls `0xfffffe000be577f0` exactly689 times, even when N=0. Its original function name and entropy quality are unknown. For each returned u32 r and old u16 s at metadata record j, the source writes:

```text
j = 1..689, address = metadata_base + 4*j
new16 = (s & 0xdf00) | ((r & 1) << 13)
        | ((s + ((r & 6) >> 1)) & 0xff)
```

The upper halfword of each4 B record is untouched by these source stores. Entry0 and guard entry690 remain unchanged in the private cases. The loop advances the u64 index and decrements its u64 remaining counter. One-iteration SMT obligations prove the exact metadata update and next-edge/count relation for all admitted index/counter/return values; finite execution composes all689 iterations under explicit helper noninterference. The deterministic zero/ones/cycling return fixtures do not measure native randomness. [BO2,BO5]

The policy then initializes all128 B of each callback object: zeros except flags at+0x40 and logical callback pointer at+0x58. PACIA uses modifier0x73d8. Source fields+0x60/+0x68/+0x70/+0x78 are zero. This establishes object initialization, not enqueueing, invocation, an original callback-role name, or a Mach message emission. The source restores its80 B stack frame and returns to the original caller; the previous prefix stop is no longer used in these components. [BO2,BO4]

The caller later reads full `_sane_size` and stores a derived u64 at `0xfffffe000cae4dc0`. The independent oracle retains the exact W-register signed comparison/truncation, u64 multiplication wrap, UMULH constant0x28f5c28f5c28f5c3 and shifts. It does not replace this arithmetic with an unrestricted percentage formula. The extreme u64 input exercises that distinction; native units, operational limits and the output's downstream meaning remain unknown. [BO2,BO4]

```text
q32 = low_u32(V >> 30)
factor32 = (35 - q32) mod 2^32, if signed32(q32) < 25
           10, otherwise
product64 = (zero_extend(factor32) * V) mod 2^64
shifted64 = product64 >> 2
output64 = high_u64(shifted64 * 0x28f5c28f5c28f5c3) >> 2
```

## Registration order and IPC-zone boundary

The [startup dispatcher evidence](startup_dispatch_report.md) is reused and rechecked:3519 original24 B records, all6950 logical pointer fixups, the source comparator, sorter, dispatcher and phase-name mapping. The section begins at `0xfffffe000cbea1d0` and ends at `0xfffffe000cbfebb8`, end exclusive:84,456 B. Keys are unsigned `(u32 phase,u32 rank)`. Equal keys compare equal regardless of callback and argument; no stable tie order is inferred. [BO3]

| Original record | Phase / rank | Logical callback | Argument / role | Finite sorted index |
| --- | --- | --- | --- | --- |
| 0xfffffe000cbebec8 | 7 /0 | 0xfffffe000c6324a0 | 0; magazine bootstrap | 1047 |
| 0xfffffe000cbec9f0 | 7 /1 | 0xfffffe000c636524 | 0; role not established here | 1048 |
| 0xfffffe000cbed2a8 | 7 /1 | 0xfffffe000c637f1c | 0; role not established here | 1049 |
| 0xfffffe000cbeaea8 | 7 /2 | 0xfffffe000c62a87c | 0; previously recovered MixedData builder | 1050 |
| 0xfffffe000cbea3f8 | 7 /3 | 0xfffffe000c63222c | 0xfffffe000cbc8370; `ipc port sets`, ID23,56 B | 1075 |
| 0xfffffe000cbea3c8 | 7 /3 | 0xfffffe000c63222c | 0xfffffe000cbc8310; `ipc kmsgs`, ID24,256 B | 1081 |
| 0xfffffe000cbea3e0 | 7 /3 | 0xfffffe000c63222c | 0xfffffe000cbc8340; `ipc ports`, ID22,144 B | 1084 |

The magazine callback's format8 authenticated pointer is at original slot `0xfffffe000cbebed0`, diversity0x2abe; the argument is zero. Chain membership, raw word, target, authentication bit and diversity are freshly compared with the independent fixup parser. Its raw record is `0700000000000000a0e46205be2a30800000000000000000`. Logical bytes are `0700000000000000a024630c00feffff0000000000000000`. [BO3]

Phase7 contains136 registrations: one rank0, two rank1, one rank2,71 rank3,10 rank0x7fffffff and51 rank0xffffffff. The sole rank0 must precede every rank3 in any correctly sorted permutation. The finite sorted indices and the order among the three rank3 IPC entries describe this pinned sorter/input, not a universal tie order. Their original immutable-record addresses differ from the private sorted cursor addresses. [BO3]

The source magazine body and its later publication store were established in the [magazine-bootstrap report](kernel_magazine_bootstrap_report.md); original IPC constructor/cache bodies were established in the [zone startup report](kernel_zone_startup_report.md). This increment establishes their registration/caller order without executing those callback bodies. The rank1/rank2 callbacks also precede selected rank3 entries and may change native allocation state. Therefore the earlier declared dynamic slot40 remains a controlled epoch, not a native identifier derived from this ordering. [BO3,BO6]

## Continuous private execution and independent checks

The original source sorter executes231,961 integer-interpreter visits/4215 source calls. All3519 logical records form an exact permutation, keys are sorted, and128 guard bytes are preserved. Sorted table SHA-256: `59fee911ef4245c47031c68d965e88ca030f22f1876d525aeaaf6d1f83249e2c`. This finite witness is not a universal correctness/stability proof for the sorter. [BO5]

Each private component starts at the complete caller with a declared completed phase1..5 prefix: cursor `0xfffffe000cbf02c0`, phase5 and announced-phase5. No stack reset, register handoff, capacity overlay or state transfer occurs between the policy and either dispatch call. The original dispatcher consumes13 phase6 and136 phase7 registrations, stores each predecessor phase before callback entry, and advances its saved cursor after the modeled callback returns. The original phase observer body executes; its trace/print callees remain models. [BO4]

| N | Raw `_sane_size` V | Boot key | Descriptor helper mode | Result K | Source visits |
| --- | --- | --- | --- | --- | --- |
| 1 | 0x80000000 | absent | direct | 8 | 14831 |
| 2 | 0x600000000 | absent | indirect | 10 | 14863 |
| 10 | 0x640000000 | absent | direct | 14 | 14992 |
| 1 | 0xffffffffffffffff | `zc_mag_size=16` | indirect | 8 | 15143 |
| 0, u32 wrap control | 0x100000000 | absent | direct | 10 | 14808 |

The phase6 return leaves cursor `0xfffffe000cbf03f8`/phase6; phase7 return leaves cursor `0xfffffe000cbf10b8`/phase7. At all149 callback entries per run, count/capacity equal the completed policy's outputs; phase is5 for phase6 entries and6 for phase7 entries. The saved cursor still identifies the current record until return. Modeled callbacks neither modify RAM nor reenter the dispatcher. Native reentrancy and cursor protection remain unestablished. The zero-count case is a source-width control, not a valid native topology claim. [BO4]

Five components pass70 independent semantic checks. Fresh CPU replay, without importing the producer executor, checks74,637 original visits,10,873 writes/63,068 B,15,284 reads/86,766 B,775 reconstructed events,438,622 final global bytes and5,242,880 final private-RAM bytes. It validates4316 declared API models against their explicit contracts and762 logical PAC/BLRAA envelopes; two string leaf inputs/results are independently checked. Native hardware authentication is not executed. [BO5]

Nine new nonvacuous source queries are UNSAT over28 distinct PCs/42 instruction instances/32 linked-edge obligations. Thirteen prior comparator/dispatcher queries are freshly reconstructed, canonically compared and re-solved; two byte-separation lemmas are rechecked. The new blocks require zero read-over-distinct-store rewrites. Across the five components,568 of the966 captured PCs execute; all unexecuted PCs are listed. [BO5]

| Changed-source control | Independent rejection |
| --- | --- |
| NOP metadata STRH at0xfffffe000c632030 | Exact689-record metadata oracle fails |
| NOP descriptor+0x20 store at0xfffffe000c632160 | Descriptor byte/guard oracle fails |
| NOP first callback flags store at0xfffffe000c632084 | Complete128 B callback-object oracle fails |
| NOP phase7 argument MOV at0xfffffe000c635050 | Exact phase6/7 callback-order oracle fails |
| NOP policy BL at0xfffffe000c634f1c in CFG | Normal-return order certificate fails |

Source extraction is O(collection bytes + fixups + records + instructions) time/space. Finite interpretation/replay is O(visits + journals + mapped state), with a200,000-visit limit per caller component and an8,000,000-visit sort limit. SMT construction is O(source + formula DAG), with solver search separate and30 s per query. Each private CPU has1,048,576 B RAM; source image pages and journals are additional storage. Fixed-width arithmetic is little-endian with exact u16/u32/u64 modular rules; no floating-point approximations or measured error bars are used. [BO5]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BO-A1: Pinned collection, normalized kext, compiler intervals and format8 logical targets | BO1-BO6 | Rehash original inputs; compare all3519 raw records/6950 fixups and seven retained bodies; reject any changed byte |
| BO-A2: Ordinary returning call ABI and logical PAC identity, including source BLRAA | BO1, BO2, BO4-BO6 | Pattern-clobber volatile GP/flags; check nonvolatile GP/SP and replay every source envelope; native failed PAC/nonreturning callees invalidate continuation |
| BO-A3: Sorted table, completed phase1..5 prefix, protected cursor/table, no callback reentrancy | BO3-BO6 | Source-sort exact permutation/keys/guards; compare every callback cursor/argument and phase; native table/cursor mutation or reentry invalidates the traversal join |
| BO-A4: Listed boot, descriptor, trace and registered callback bodies have explicit no-RAM return effects; metadata-return values are declared | BO2, BO4-BO6 | Independently check every model contract and whole-state outputs; recover/execute their actual effects before asserting native initialization; source/CFG mutants must fail |
| BO-A5: Bounded descriptor storage, guard records, private thread/context and callback-object input extents | BO2, BO4-BO6 | Whole-byte descriptor/object oracles, upper-halfword/entry guards, N=0/1/2/10 and both helper modes; native bounds, address tags, ownership and helper targets remain unknown |
| BO-A6: Shared `_sane_size` bytes remain in one unchanged private epoch; native units are not presumed | BO2, BO4-BO6 | Prove high-word alias in one byte array; use one u64 fixture for both reads; a native intervening writer breaks value constancy, while the storage alias remains true |

## Architectural scope and bounded continuation

This increment refines the startup environment needed by recovered kernel allocation/retirement paths. IPC-zone IDs and byte extents identify constructor specifications, not process-local Mach names, rights or endpoint emissions. No additional Mach endpoint, right transfer, message emission, daemon request or successful daemon/provider pair is established. The [Mach-port report](mach_ports_report.md) and [ABI report](interface_abi_report.md) retain those separate evidence boundaries. [BO6]

| Impact | Continuation / opportunity | Remaining evidence |
| --- | --- | --- |
| High | Replace the phase6/7 callback models, beginning with unique magazine rank0 and selected IPC constructors | Full magazine prefix/prerequisites, fixed slot1/2 setup callbacks, raw statistics/cache storage and publication effects in the same call stack |
| High | Establish the `_sane_size` producer and stability interval | Actual early VM helper writes and physical-memory unit/bounds; native entry value remains unknown |
| High | Join source-created capacity/view to actual allocation, fill, drain and retirement without new-call ownership overlays | Native backing/identity, initialized metadata, exclusion and object lifetimes |
| Medium | Account for rank1/rank2 effects and dynamic-ID changes before IPC construction | Those actual bodies and phase6 effects; finite registration order alone cannot establish native zone IDs |
| Medium | Identify the two initialized callback objects' consumers and invocation roles | Incoming references, registration operations, scheduling and target bodies; pointer/flags do not prove invocation |
| High | Correlate one daemon request with one kext/provider/kernel epoch | Matched image identities, request bytes, rights, status and timestamp/epoch evidence |

## Quality gates

**QG1** passes: factual source/ABI analysis requires no normative content. **QG2** passes: BO-A1-BO-A6 declare dependent claims and falsification probes. **QG3** passes for this increment: caller order, shared input alias, complete policy tail, registration ordering and boundaries are covered; the full investigation remains active. **QG4** passes: widths, raw units, byte extents, modular arithmetic, limits and complexity are explicit. **QG5** passes: strict rank order, equal-key ambiguity, native/helper effects, private callbacks, zero-count wrap and the error-callee edge are separated. **QG6** passes: original bytes, nlist/fixups, reconstructed source certificates, independent semantic/replay checks and changed-source controls provide provenance. **QG7** passes: bounded, impact-ranked continuation is recorded. `full_goal_complete=false`.


## Memory and logical CPU producer evidence

The [boot-input producer study](kernel_zone_boot_inputs_report.md) supersedes the producer frontier above: the located _sane_size store is0xfffffe000be752c4 inside the ARM/SPTM initializer0xfffffe000be7400c, rather than the VM helper0xfffffe000c637698. It establishes V=M-((A-B) mod2^64) only under the strict unsigned M>delta gate. The CPU input is the exact _ml_get_max_cpu_number storage, maintained by a logical index/count/maximum setter. Native call-chain order, intervening writes, physical units and active CPU count remain unknown; the preceding private boot-order evidence is unchanged.
