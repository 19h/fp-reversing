# Earlier FPTTLVNode return and data allocation interface

Subsequent original-entry evidence: The [early data-return report](userclient_early_data_report.md) preserves 60 predecessor prefixes through a fifth register-only return. NULL data requests typed-node retirement; non-NULL data requests the shared writer and stops before its undefined C+0x768 input. The setup consumes five retained pointer roots and seven metadata cells: 18 of 64 required bytes are source-defined and 46 remain unknown in the private model. Nine source proofs, 118782 independently interpreted visits and two rejected mutations pass. Five call-return stores are located, without inventing their missing current epochs. No data bytes are written; native allocator effects, complete serialization and matched daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

The original `_PRnut72j9` prefix now continues through a declared return from its earlier 32 B `site.FPTTLVNode` request. Source code retains that result, zeroes its first 16 B, stores a u32 total extent at node+0x10 and requests `L+10` B from `_IOMallocData`. The lower typed-allocation wrapper masks incoming flags with 0x7; its caller's 0x8004 value does not, by itself, establish a native non-NULL guarantee. A synthetic NULL result stops before an unbacked load in the private model. Native failure reachability, allocator memory effects and whole-operation completion are unknown. [EN1-EN8]

## Evidence and claim mapping

| Artifact | Decoded SHA-256 | Coverage |
| --- | --- | --- |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, function bounds, symbols, descriptors and chained pointers |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Independent comparison of selected kext words/data |
| Complete `_PRnut72j9` | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` | 202536 B /50634 words, starting `0xfffffe000a635208` |
| [Checks](triage_evidence/userclient_early_node_checks.json.zst) | `3376d0d190a8232484d92074e75335086aabaffe545e590388bcc886a83f79bb` | 60 continuous cases,132 continuation words,83 allocator-wrapper words and 256 bank inputs |
| [Audit](triage_evidence/userclient_early_node_audit.json.zst) | `d6b3b0f4b052311c33d374105c862ac7e21547f524bd327f163186553d292265` | Independent replay, ten nonvacuous source proofs and two rejected source mutations |

The [extractor](triage_evidence/recover_userclient_early_node.py), [producer](triage_evidence/probe_userclient_early_node.py), [independent interpreter](triage_evidence/replay_userclient_early_node.py), [auditor](triage_evidence/audit_userclient_early_node.py) and [delivery verifier](triage_evidence/verify_userclient_early_node_delivery.py) retain reproducible custody. The interpreter imports neither Unicorn nor the producer. Source kernel wrappers are inspected separately; the private continuation does not execute them.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| EN1 | Original-entry continuation and 60 exact predecessor prefixes | EN-A1-EN-A4 |
| EN2 | Retained node result and nullable source dispatch | EN-A1-EN-A5 |
| EN3 | Explicit16 B source clear and 4 B node extent publication | EN-A1-EN-A5 |
| EN4 | Encoded u64 extent channel and next data-allocation request | EN-A1-EN-A5 |
| EN5 | Pinned typed-wrapper flag selection and downstream projection | EN-A1, EN-A5, EN-A7 |
| EN6 | Pinned data-wrapper first backend argument contract | EN-A1, EN-A5 |
| EN7 | Independent byte/CPU/control audit and source falsification controls | EN-A1-EN-A6 |
| EN8 | Native, transport, marker and continuation limits | EN-A1-EN-A7 |

## Continuous private entry and result custody

I, N, F, S, C and H retain their [early-header](userclient_early_header_report.md) meanings: input, low32 size, original frame, 16384 B workspace, 4096 B typed region and 16 B FPTTLV result. The new J fixture is either NULL or a disjoint 32 B private extent. Five accepted profiles (zero-length nonzero-tag span,8 B span,4 B scalar,8 B scalar and the high32 size variant) cross three controller fixtures, two stack placements and two J selections:5*3*2*2=60 cases. All60 preserve complete predecessor visits, frames, memory journals, logical edges, API cuts and frontier CPU state. The42 predecessor cases that never requested a node are not duplicated. [EN1]

At `0xfffffe000a661664`, the fourth register-only model supplies J for `_IOMallocTypeImpl` at `0xfffffe000c4ba154`. Original X0 is descriptor `0xfffffe000847b4a0`: name `site.FPTTLVNode`, signature1121, flags 0x64 and declared size32 B. The model writes no RAM, preserves the defined nonvolatile/vector/storage state and applies the declared volatile-register/NZCV clobbers. Neither NULL nor non-NULL is an observed native allocator outcome.

```text
original entry -> declared input -> earlier node request
                                      |
                       fourth register-only return J
                                      |
                          source store C+0x58 = J
                             /                 \
                       J == 0                 J != 0
                          |                      |
                 private boundary       source zero J+0..+15
                 before unbacked        source extent J+0x10
                 value load                      |
                                      before IOMallocData(L+10)
```

The store at `0xfffffe000a661670` retains J in C+0x58. The following CMP/CSET arithmetic selects index 0xb09 for J==0 and0xaaa otherwise; original table slots lead to `0xfffffe000a66169c` and `0xfffffe000a6616d4`, respectively, modifier 0xbe31. The source proof covers arbitrary 64-bit J under the explicitly seeded original phase constants. [EN2]

For the NULL fixture, the source reloads C+0x58 and follows a second original table edge. The private engine stops before a value load outside its backed extents. No such load executes and no machine exception is observed. A raw internal status register at that boundary is not a returned API status. Lower allocation effects, caller admission and native state must be established before assigning native meaning to this countercase. [EN2, EN8]

## Node bytes and data-buffer request

| Original source site | Cell / interface | Established value |
| --- | --- | --- |
| `0xfffffe000a6616d8` | X22 | J on the non-NULL path |
| `0xfffffe000a6616ec` | J+0..+15, 16 B STP | All zero, from source stores |
| `0xfffffe000a661790` | S+0xca8, 8 B | zero_extend64(L)+0x622f763938943e93 |
| `0xfffffe000a6617f4` | X0 through a W0 write | zero_extend64(L+10) |
| `0xfffffe000a6617f8` | J+0x10, 4 B | u32 L+10 |
| `0xfffffe000a661848` | Authenticated call, modifier 0xca0c | `_IOMallocData` at `0xfffffe000c4ba60c`, X0=L+10 |

The 4 B size and 8 B encoded-channel proofs quantify over arbitrary u32 L. The total-size proof includes L<=0xfffffff5, already selected by the previous count/body gates, so L+10 is representable without u32 wrap. Original mixed Boolean/arithmetic instructions, rather than the finite lengths alone, establish both formulas. The encoded S+0xca8 value is a storage domain, not a byte-address or a wire size. [EN3, EN4]

At the data-request boundary, precisely 20 of J's32 bytes have source provenance:16 zero bytes and 4 extent bytes. J+0x14..+0x1f remain 12 unknown poison bytes in this no-RAM-write model. This does not establish the native contents of that tail. The parent tag/type/length, scalar/span channels, callback, H and committed cursor remain independently checked. No further input bytes are read; input bytes remain unchanged and retain pre-entry provenance. [EN3]

The call bank uses complete 256 B arrays at `0xfffffe0007949dd0` and `0xfffffe000792fbc0`, key 0x3e, collapsed constant 0x54, add 0xebc and index 0xf10. Original chained slot `0xfffffe000847a7a0` resolves to the data allocator. Both array copies match the normalized kext. The first argument is the only argument assigned semantic meaning at this call; other volatile argument registers retain the declared earlier cut's noise. No data allocation return is supplied. [EN4]

## Lower allocation contract and version boundary

| Pinned function | Bytes / words | SHA-256 |
| --- | --- | --- |
| `_IOMallocTypeImpl`, `0xfffffe000c4ba154` | 28 B /7 | `2be5777872d60de5b0513968f8aaaaa1b3947085f183f933b4ba7b7607290029` |
| `_kalloc_type_impl` / external alias, `0xfffffe000bcfeb8c` | 160 B /40 | `c2741f4a72af1e2a358007be4a36398fdc0aab0a092cd4ba85afafb495330892` |
| `_IOMallocData` / external alias, `0xfffffe000c4ba60c` | 144 B /36 | `0bc800f390215db6847c0e74814ad727ac2d56d59c4b8c04eed740b600efd0dd` |

The typed caller reads descriptor flags at+0x28 and selects W1=0x8004 when bit 0x10 is clear, or4 otherwise. The frozen earlier-node descriptor has flags 0x64, selecting0x8004. The external wrapper then computes W10=W1 AND7. Thus0x8004 becomes 4; bit 0x8000 is absent from that projected argument. The wrapper separately adds its own backend flag domains. [EN5]

| Original backend path | Pinned call | W2 with selected incoming0x8004 |
| --- | --- | --- |
| Zone, nonzero statistics selector | `0xfffffe000bcfebdc` -> `0xfffffe000bd75c64` | 0xd1004 |
| Zone, zero statistics selector | Same call | 0xd1044 |
| No zone, heap fallback | `0xfffffe000bcfec20` -> `0xfffffe000bcfe5b8` | 0xd1004 |

These are numeric source projections, not proof that any one runtime descriptor/CPU path occurs. The zone path reads TPIDR_EL1-derived per-CPU state and descriptor context; the fallback selects a heap from descriptor bits and a 24-bit size. Its lower backend memory effects are outside this increment.

For context, Apple's public [allocation flag definitions](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/zalloc.h) identify0x4 with ZERO and0x8000 with NOFAIL, while the public KPI mask excludes NOFAIL. The public [IOLib wrapper](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOLib.cpp) and [external typed wrapper](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/kalloc.c) explain those names and the mask pattern. This immutable public commit is dated 2025-10-16; the pinned binary identifies Darwin 27.2.0 / xnu-13432.41.4~3. Exact source-version equivalence is unestablished and no native guarantee is imported. Retrieved source-byte hashes and sizes are retained in the checks. [EN5]

The data wrapper prepares X0=`0xfffffe0007f8bfb0`, X1=request size, W2=0x31000, X3=0 before its first call to `0xfffffe000bcfe5b8` at `0xfffffe000c4ba638`. A separate arbitrary-size source proof establishes those arguments. Subsequent source branches perform conditional accounting/tracking. The wrapper bytes contain those operations, but their execution, lower memory initialization, allocation success and native ownership are unknown. [EN6]

## Independent checks and falsification

| Check | Verified count |
| --- | --- |
| Continuous cases / exact predecessor prefixes | 60 /60 |
| Non-NULL / NULL register fixtures | 30 /30 |
| Source visits / GPR values | 113172 /3510192 |
| NZCV epochs / final D-register values | 113232 /1920 |
| Reads / checked read bytes | 10110 /51168 B |
| Writes / checked write bytes | 22920 /171132 B |
| Logical edges / register-only models | 1242 /240 |
| Frame/workspace/context snapshot bytes | 1488960 B |
| Additional H / input / J snapshot bytes | 960 B /936 B /1920 B |
| Fresh source obligations / lifted instruction instances | 10 /97 |
| Bank inputs / source mutation controls | 256 /2 |

The ten nonvacuous obligations cover retention/nullable dispatch, explicit node zeroing, encoded64 extent, node/request extent, typed flag selection, external masking, three backend flag projections and data-wrapper arguments. The 132 continuation words occupy two spans; the 83 allocator-wrapper words occupy three separately identified spans. These counts describe captured source custody rather than newly discovered unique instructions. [EN7]

Two NOP mutations operate only on copied private instructions. Removing the C+0x58 store stops the NULL fixture before an undefined private-value load. Removing the J+0x10 store still reaches the data allocator but fails the node-definedness oracle. Independent replay validates both changed prefixes; neither executes an undefined or unbacked load. Matching only a call frontier would miss the second failure.

Production costs O(B+I+256+C*(B+V+E)) time/retained space for image bytes B, captured instructions I, cases C, visits V and byte events E. Independent replay costs O(V+E+M) per case for snapshot extent M. Each case has a 30000-visit cap; none reaches it. Symbolic lifting costs O(I) DAG construction; solver search is separate with 30 s/query limits. No native target or IDB is executed or changed.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EN-A1: Pinned original/normalized images, function boundaries, pointer interpretation and predecessor artifacts apply. | EN1-EN8 | Rehash images/full container/functions/dependencies; compare selected words, arrays, descriptors, symbols and original slots. |
| EN-A2: Original-entry fixtures and separated F/S/C/H/I/J extents apply. | EN1-EN4, EN7-EN8 | Rebuild 60 cases across two placements, three controller selections and five wire profiles; verify every epoch and exact predecessor prefix. Native admission is unknown. |
| EN-A3: Authenticated branches and PAC/AUT are logical transfers in the private model. | EN1-EN4, EN7-EN8 | Check original words, modifiers, pointers and edge journals; native authentication requires independent machine evidence. |
| EN-A4: Four declared allocator register returns have their specified clobbers and zero RAM effects. | EN1-EN4, EN7-EN8 | Verify call arguments, register epochs and all source/provenance bytes. NULL/non-NULL are model selections, not observed outcomes. |
| EN-A5: Stated source-phase, bounded-length and stable-cell premises hold at each local cut. | EN2-EN8 | Re-solve ten satisfiable-premise obligations, check source production and intervening writes; qualify total size by L<=0xfffffff5. |
| EN-A6: The independent interpreted instruction subset matches visited source effects. | EN7 | Check all CPU/memory/control epochs, node masks and two source mutations; unsupported effects fail closed. |
| EN-A7: Older public source supplies terminology/context only. | EN5, EN8 | Retain immutable commit/date and retrieved byte hashes; require exact target-build source or verified lower machine behavior before promoting native guarantees. |

## Bounded continuation and transport limits

| Impact | Discriminating next work | Result sought |
| --- | --- | --- |
| High | Continue the earlier data-allocation return under an explicit contract. | Establish source payload/header writes, J+0x18 population, callback/list publication and the next interface. |
| High | Establish exact-target backend allocation effects and descriptor/per-CPU admission. | Replace register-only storage assumptions and determine native success/failure/initialization contracts. |
| High | Join original caller input ownership to the daemon's actual transmitted bytes and request identity. | Establish an admitted daemon/kext transaction rather than conditional field correspondence. |
| Medium | Trace S+0x20 source writers beyond these boundaries. | Locate the tunnel-marker producer while retaining the distinct C+0x20 H cell. |
| Medium | Continue typed retirement and protected staging with original object epochs. | Establish early-to-later parser continuity and full-operation status. |
| Low | Seek symbol/type metadata for the wire tag's business role. | Refine naming without inferring unsupported semantics. |

The node tail and buffer-return frontier make initialization provenance the next useful discriminator. S+0x20 remains unknown/unread; Q remains opaque. This increment establishes no new incoming Mach port, outgoing message, transferred right, message identifier or emission site. The [Mach-port report](mach_ports_report.md) retains confirmed transport evidence. Native daemon/kext pairing and the full interface goal remain open. [EN8]

## Quality gates

**QG1** Pass: factual technical analysis. **QG2** Pass: EN-A1-EN-A7 state dependencies and falsification probes. **QG3** Pass for this increment: obfuscated routine continuation, data/control flow, allocation ABI, environmental inputs and transport limits covered; full goal active. **QG4** Pass: widths, byte counts, modular domains, bounds, exact counts and complexity are reproducible. **QG5** Pass: synthetic outcomes versus native reachability, source zeroing versus allocator effects, projected flags versus guarantees, and historical parser epochs are distinct. **QG6** Pass: pinned words/pointers/descriptors/functions, independent replay, nonvacuous source proofs, mutations and version-scoped primary-source context support the stated claims. **QG7** Pass: impact-ranked continuation above. `full_goal_complete=false`.
