# Collection entry, copied boot header and physical-root provenance

Original source identifies the bulk copy that supplies the previously unresolved pmap physical-root global. The collection entry preserves external X1/X2, publishes the embedded SPTM record from X2, reaches an opaque selector15 boundary, then has a source continuation that copies1152 B of X1 and856 B of X2 into adjacent kernel destinations. The latter copy supplies0xfffffe0007e6d838 from header+0x1d8 and publishes the same copied header as the device-input structure. Seven private six-component chains now carry that source-produced root/header through the original converters and nested context/pool/CPU initialization into mapping consumers. Actual bootloader inputs, backing ownership, self-relocation, feature-callback effects and opaque receiver behavior remain unknown. [BH1-BH7]

```text
original collection LC_UNIXTHREAD.PC
  original mode dispatch -> mode0 cold body
    save external X1 as bootargs; X2 as header
    declared self-relocator return [original body captured]
    original device-tree bounds and 271 reverse list insertions
    four original authenticated callback slots [explicit leaf contracts]
    original magic check -> original embedded-record publication
    selector15 -> STOP before selected original opaque word
  declared opaque-return epoch, same private RAM and tracked image state
    original tail handoff -> original continuation
      declared registration/helper returns
      original memcpy(bootargs destination, X1, 1152 B)
      original memcpy(header destination, X2, 856 B)
        copied header+0x1d8 supplies physical-root global
        original store publishes copied-header/device pointer
  exact state transfer -> original root converter/source publication cut
    -> original nested context/pool/device-tree/CPU initialization
    -> declared admission call -> source descriptor -> declared backend call
```

Primary target provenance is the pinned collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original load commands, compiler starts, nlist aliases, chained fixups and exact instruction/data bytes. The preserved normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference data sufficed; no IDB was read or modified. [BH1]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| BH1 | Original collection entry and source/fixup custody | BH-A1 |
| BH2 | Full-width entry dispatch, input preservation and selector15 emission boundary | BH-A1,BH-A2,BH-A4 |
| BH3 | Original early device-tree/list/callback ABI | BH-A1-BH-A4 |
| BH4 | Original bulk header copy supplies root and device-input pointer | BH-A1,BH-A3-BH-A5 |
| BH5 | Byte-exact root/header state joins reach original mapping consumers | BH-A1,BH-A3-BH-A6 |
| BH6 | Source proofs, independent field/byte formulas, fresh replay and controls | BH-A1-BH-A7 |
| BH7 | Environmental, Mach and native-ownership boundaries; continuation | BH-A1-BH-A7 |

Artifacts: [extractor](triage_evidence/recover_kernel_boot_header_handoff.py), [private executor and formulas](triage_evidence/probe_kernel_boot_header_handoff.py), [independent replay](triage_evidence/replay_kernel_boot_header_handoff.py), [source audit](triage_evidence/audit_kernel_boot_header_handoff.py), [delivery verifier](triage_evidence/verify_kernel_boot_header_handoff_delivery.py), [source capture](triage_evidence/kernel_boot_header_handoff_checks.json.zst), [audit receipt](triage_evidence/kernel_boot_header_handoff_audit.json.zst). Decoded capture:1020742 B, SHA-256 `18a8d69b9710b595b60fd002b85987349872283530587c4078f7b3e38af284a0`. Decoded audit:73929622 B, SHA-256 `3a4eeaaa1de9db22d19cb2d86ccac17dd194a72594fc05335d38700a196355ed`. [BH6]

## Collection entry and original intervals

The collection's LC_UNIXTHREAD command at file offset0x50 has size288 B, flavor6 and68 u32 state words. Its PC is0xfffffe000c65c000; X16 is0xfffffe000bc98000; other retained general registers, SP and CPSR are zero in this file record. This establishes recorded entry metadata, not the runtime values supplied by a bootloader. The independently checked Apple SDK `mach/arm/thread_status.h` identifies ARM_THREAD_STATE64=6, and `mach/arm/_structs.h` defines29 u64 general registers, FP/LR/SP/PC u64 fields and CPSR/padding u32 fields. Their pinned SHA-256 values are respectively `652760f46ee3b456efdcfcc5b5710a0bbc3aa30e0a1495f45ebdd038b323a693` and `30e201a2bf77b2b09163250db64760f303903590904a3daabd9b96cbcba19b7e`. The state extent is33*8 B+2*4 B=272 B, plus16 B of command/flavor/count header. [BH1]

| New compiler-start interval, end exclusive | Words | Role established here |
| --- | ---: | --- |
| 0xfffffe000c65c000..0xfffffe000c65c034 | 13 | Recorded collection entry and mode4/5 dispatch |
| 0xfffffe000c65c034..0xfffffe000c65c050 | 7 | Thread-register clears and ordinary cold/secondary split |
| 0xfffffe000c65c050..0xfffffe000c65c0c4 | 29 | Cold stacks, input custody, early calls and selector15 boundary |
| 0xfffffe000c65c0c4..0xfffffe000c65c0f8 | 13 | Secondary body; captured, unexecuted |
| 0xfffffe000c66058c..0xfffffe000c660ad4 | 338 | Early self-relocation/fixup routine; captured, leaf contract in execution |
| 0xfffffe000c660ad4..0xfffffe000c660bf8 | 73 | Device-tree bounds, original reverse linking and early callbacks |
| 0xfffffe000c639a40..0xfffffe000c63a3e0 | 616 | Post-transport continuation; executed only through0xfffffe000c639af4 |
| 0xfffffe000c647f10..0xfffffe000c6480c0 | 108 | Exact nlist aliases _memcpy/_memmove; original body executes |
| 0xfffffe000c660058..0xfffffe000c660158 | 64 | Feature setter with list-driven code stores; captured, unexecuted |
| 0xfffffe000c660158..0xfffffe000c6603c8 | 156 | Early boot-text parser; captured, unexecuted |
| Four callback bodies, listed below | 310 | Original callback source; declared no-RAM leaves in execution |
| Twenty byte-identical prior intervals | 4283 | Record/root/context/pool/CPU/converter/mapping source |
| Total,34 intervals | 6010 | 24040 B; seven undecoded words preserved |

The previous last-compiler-start boot interval still uses its explicitly recorded file-backed segment boundary. The continuation also contains an undecoded word at0xfffffe000c63a3c0; it is preserved without assigning an instruction name. Six other undecoded words are the two cold-entry transport words and four prior CPU-wrapper words. None executes. Other captured-but-unexecuted code is not treated as a completed native path. [BH1,BH6]

## Entry modes and lower transport boundary

All mode comparisons use X0's full64 bits. Mode0x100000000 therefore takes the ordinary nonzero/secondary path even though its low32 bits are zero. [BH2,BH6]

| Entry X0 | Original destination | Input transformation / side effect |
| --- | --- | --- |
| 4 | 0xfffffe000c660000 | u8[0xfffffe000ca93df8]=low8(X2); X0=entry X1; stop before diagnostic entry |
| 5 | 0xfffffe000bc9bbdc | X0=entry X1; X1=entry X2; exception/privilege handoff remains unexecuted |
| 0 | 0xfffffe000c65c050 | Clear TPIDR_EL0/TPIDR_EL1/TPIDRRO_EL0; cold path |
| Other values | 0xfffffe000c65c0c4 | Same thread-register clears; secondary body remains unexecuted |

The cold body selects SP_EL1 and loads stack top0xfffffe000cbbc000, then selects SP_EL0 and loads0xfffffe000cbb4000. It saves entry X1/X2 in X26/X27 before the self-relocation call at0xfffffe000c65c078. The device initializer receives saved X1 at0xfffffe000c65c080. VBAR_EL1 receives0xfffffe000bc98000 at0xfffffe000c65c08c, followed by ISB. The magic/record caller receives saved X2 at0xfffffe000c65c098. These stack/system operations use explicit logical envelopes in the private witness; native stack ownership, architectural synchronization and hardware execution remain unproved. [BH2,BH3]

After record publication, source sets X16=0x0f and tests byte0xfffffe0007f8c7c8. Zero selects raw word0x00201420 at0xfffffe000c65c0ac; nonzero selects0xd4e00000 at0xfffffe000c65c0b4. These are emission boundaries, not identified Mach sends or assigned instruction names. The private cold component stops before the selected word. A separate declared opaque-return epoch begins at0xfffffe000c65c0b8, where original instructions restore X0=X26, X1=X27 and tail-branch to0xfffffe000c639a40. Native return behavior, clobbers and RAM effects across that boundary remain unknown. [BH2,BH5,BH7]

## Early environmental initialization and callbacks

The device initializer reads u64[entry X1+0x60] as a tree base and u32[entry X1+0x68] as a byte extent. Carry from their zero-extended sum enters the original diagnostic at0xfffffe000c660bd8 before publication/linking. Otherwise it publishes base/size/end as u64 fields at0xfffffe0007f8b508/+8/+16 and `(base!=0)` as a u32 at+24. This is arithmetic exclusion of unsigned addition overflow; it establishes no object lifetime, readable extent or tree validity. Selected base0/size0 and base0/size0xffffffff paths still proceed. [BH3,BH6]

It then traverses the original16 B records from0xfffffe000cbc50e0 down to0xfffffe000cbc4000, inclusive: `(0x10f0 B)/(16 B)=271` records with92 distinct owners. Each record's qword+8 is an original format-8 fixup containing an owner pointer plus two low tag bits. For each reverse insertion, original source performs the following exact updates. First8 B of every record and other owner bytes remain preserved in this component. [BH3,BH6]

```text
tagged = u64[node+8]; owner = tagged & ~3
u64[node+8] = (tagged & 3) | u64[owner+8]
u64[owner+8] = node
u32[owner+4] = (u32[owner+4] + 1) mod 2^32
```

Four8 B callback slots occupy0xfffffe000cbfebb8..0xfffffe000cbfebd8, immediately after the separately reported startup-entry section. They are not24 B startup-dispatch records. All four original fixups are format8/auth1, key0, diversity0x2abe and address-diversity0. The original loop increments the slot pointer by8, passes `entry X1+0x6c` in X0 and modifier0x2abe in X17 to BLRAA at0xfffffe000c660bac. Source proofs cover argument/slot/modifier production up to this instruction; authentication itself is a logical private envelope. [BH1,BH3,BH6]

| Slot | Exact target | Captured source evidence |
| --- | --- | --- |
| 0xfffffe000cbfebb8 | 0xfffffe000c660014 | Calls parser for original strings validation_disables and serverperfmode |
| 0xfffffe000cbfebc0 | 0xfffffe000c6613cc | Reads architectural feature registers, parser string enable_sme, FPCR tests and feature setters |
| 0xfffffe000cbfebc8 | 0xfffffe000c6611e8 | Reads AIDR_EL1/MIDR_EL1, parser string mdsb and feature setters |
| 0xfffffe000cbfebd0 | 0xfffffe000c661fa4 | Reads system register s3_6_c15_c2_7; selects/stores a small feature value or enters diagnostics |

All four exact nlist names remain unknown. Their full captured bodies establish these operations, not native feature values or final patch results. Captured setter0xfffffe000c660058 follows the linked records and can store code words; consequently actual callback effects may change later instruction bytes. Executed witnesses explicitly replace the self-relocator and four callbacks with no-RAM leaves and verify preserved source bytes. Original cache operations IC IALLUIS/DSB SY/ISB then occur as logical effects before return. Native relocation, code patching, PAC, cache synchronization and CPU-feature results remain outside this witness. [BH3,BH7]

## Original copies and the missing root producer

The continuation preserves its X0/X1 inputs in X21/X20 before two declared registration/helper returns. The two original calls below then execute the complete _memcpy/_memmove implementation. All2008 destination bytes are checked against independent source slices; the routine is not a copy-return model. [BH4,BH6]

| Original call PC | Source | Destination | Extent | Following pointer publication |
| --- | --- | --- | ---: | --- |
| 0xfffffe000c639ab0 | Entry X1 bootargs | 0xfffffe0007e6d1e0 | 0x480=1152 B | 0xfffffe000c639ab8 stores destination at0xfffffe0007ef9168 |
| 0xfffffe000c639ad0 | Entry X2 header | 0xfffffe0007e6d660 | 0x358=856 B | 0xfffffe000c639ad8 stores destination at0xfffffe0007f8b5e0 |

The physical-root relationship follows directly from these exact offsets. [BH4]

```text
0xfffffe0007e6d660 + 0x1d8 = 0xfffffe0007e6d838
header + 0x1a0 [embedded versioned record] + 0x38 = header + 0x1d8
```

Thus the original bulk-copy call at0xfffffe000c639ad0 is a concrete producer of the root global later loaded by the original ARM root-conversion cut. The [earlier boot-input locator](kernel_sptm_boot_inputs_report.md) deliberately excluded bulk copies: its negative direct-store result remains correct within that scope. The root's original file bytes are zero; the new private chain starts with that root absent and checks the copy supplying it before any selected root consumer. [BH4,BH5]

The record publisher also copies input record+0x38 into0xfffffe0007f8c750. Source therefore identifies the same header offset as the root input through the later header copy. Equality of values across publication and copy additionally requires the header to remain unchanged across selector15 and the intervening calls; actual native mutation/ownership is unknown. The private exact-state joins impose and check that preservation explicitly. [BH4,BH5,BH-A3]

The copied header at0xfffffe0007e6d660 also supplies u32 count+0x68 and raw fields+0x330/+0x338/+0x340/+0x348 to the previously recovered context/pool initializers. These now use the original copied structure through the original device-pointer store. The earlier separate device fixture and direct root fixture have been replaced in these new chains. Early tree bounds use entry X1+0x60/+0x68; the pmap count uses entry X2+0x68. The test fixtures deliberately decouple their values. Native meanings for other header fields remain unknown. [BH3-BH5]

## Verification, assumptions and continuation

Nineteen new nonvacuous source queries are UNSAT over82 distinct PCs/instruction instances and63 linked-edge obligations. They cover full-width dispatch, input custody, selector15 selection, both copy requests, pointer/auxiliary publication, tree carry and exact publication, one reverse-link iteration, and the callback slot/argument/modifier ABI. The symbolic model explicitly implements the scalar post-index LDR writeback used by the callback loop. Three prior baseline-record/root/context contracts are re-solved. These are local source contracts, not a universal proof of the whole memcpy implementation or native boot. [BH6]

Sixty-one components pass321 independent semantic checks: six entry modes, five cold environmental/failure cases and nine producer-to-consumer chains. Seven chains contain all six components; two stop after context initialization's small-count diagnostic. There are41 byte-exact state joins, nine original bulk-header-copy components,18 original memcpy entries,3523 reverse list iterations and52 declared callback entries. Four source-NOP controls are rejected: selector15 production at0xfffffe000c65c09c, tagged-link store0xfffffe000c660b5c, second memcpy call0xfffffe000c639ad0 and device-pointer store0xfffffe000c639ad8. Controls are excluded from positive totals. [BH5,BH6]

Fresh independent replay checks99340 source visits/1210 captured PCs,15956 reads/110280 B,15644 writes/109436 B,61 final boundaries,63963136 whole-private-RAM bytes and4588664 tracked-image bytes. It reconstructs18 copy entries,52 callback entries,99 original conversion entries,18 original clears,25 declared transport-return entries and27 nested entries. It checks84 boot leaves plus119 inherited leaf contracts,147 logical boot-system effects,70 logical authentication envelopes,342 logical PAC steps and7389 logical DC ZVA effects. Independent formulas check all nonstack image bytes and all private RAM for new boot components; full recorded stack bytes also match fresh replay. [BH6]

Source extraction costs O(K+F+I+L log L) time and O(K+F+I+L) space in collection bytes K, fixups F, captured source I and link records L; sorting the distinct owner inventory accounts for the logarithmic term. Formula construction is O(I+Q) in source/formula DAG Q; solver search is separate with30 s/query and no polynomial claim. Execution, byte formulas and replay cost O(V+J+R) time/space in visits V, journals J and checked RAM R. Each component has1048576 B private RAM and a60000-instruction execution limit. All arithmetic is exact little-endian u8/u16/u32/u64 or explicitly stated modular arithmetic; there is no statistical uncertainty estimate. Receipts use `zstd --ultra -22 -q -T1`, with decoded roundtrip checks and decoded/nested local-path hygiene. [BH6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BH-A1: Pinned image bytes, compiler starts, fixups and thread-state schema identify this build | BH1-BH7 | Rehash original inputs,34 intervals/20 retained captures,271 record fixups, four callback fixups and both SDK schemas; preserve seven opaque words; no cross-build equivalence |
| BH-A2: Entry mode and stack/system-register fixture select the shown original route | BH2,BH3,BH5-BH7 | Modes0/1/4/5/0xffffffff/0x100000000; exact destinations, thread clears, stack banks and VBAR source; native bootloader registers/admission remain unknown |
| BH-A3: External bootargs/header extents remain readable and unchanged in declared epochs | BH3-BH7 | Complete1152/856 B copy oracles, separate X1 tree/X2 pmap fields, poisoned destination and absent initial root; vary/mutate the header across the opaque boundary before asserting native snapshot equality |
| BH-A4: Self-relocation, feature callbacks, registration/helper and opaque returns obey explicit private contracts | BH2-BH7 | Original bodies/fixups retained;84 independently checked boot leaves, original list execution, cache/PAC logical envelopes and source-byte identity; actual code patches and receiver effects remain unknown |
| BH-A5: Prior backing/range/memory/topology inputs select these converter/context paths | BH4-BH7 | Original memcpy supplies root/device fields; original converters, three CPU records, alignment/count/memory/status variations and region guards; native PA validity/ownership unproved |
| BH-A6: Exact RAM/image transfer permits composition across declared register/thread/call epochs | BH5-BH7 |41 whole-state joins, seven six-component chains and two small-count stops; native startup continuity, thread producer and complete gateway path remain unproved |
| BH-A7: Local proofs, private execution and fresh replay establish only this increment | BH6,BH7 |19 nonvacuous proofs, three prior rechecks, four source controls, full journals/RAM and explicit false native/full-goal flags; native synchronization/progress remains open |

These are boot/pmap/lower-transport contracts. They establish no additional incoming/outgoing Mach right, endpoint, transfer or Mach message-emission site. Selector15 and the callback modifier are not Mach port names. The [Mach inventory](mach_ports_report.md) retains endpoint evidence; direct daemon control of boot inputs and a matched fairplayd/FairPlayIOKit/kernel transaction remain unknown. [BH7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Identify the actual collection caller and entry X1/X2/root/table producers | Runtime input extents, version selection, PA ownership and native boot record snapshots |
| High | Recover selector15 receiver/return effects alongside selectors0x13/0x32/2 | Root/header mutation, register clobbers, identifier/result-record ownership and native mapping effects |
| High | Execute original self-relocation and feature callbacks under measured hardware inputs | Actual code patches, feature controls and source-byte validity after initialization |
| High | Join the copied bootargs/header through the continuation's original thread/CPU initialization | Source-produced thread state, native context inputs, initialization order and visibility |
| Medium | Recover actual conversion-range contents and root backing ownership | Native validity/exclusion of zero, wrapping or unmapped root/table inputs |
| High | Pair daemon/user-client/provider traffic with these kernel effects in one observed transaction | Actual cross-layer payload/right/status/epoch correlation |

**QG1** Pass: factual technical analysis. **QG2** Pass: BH-A1-BH-A7 register dependencies and falsification probes. **QG3** Pass for this increment: routine roles, original entry/callback/copy ABI, root/device data flow, environmental/control context and lower/Mach boundaries covered; full investigation remains active. **QG4** Pass: exact widths, units, offsets, extents, arithmetic and algorithmic bounds stated. **QG5** Pass: direct-store versus bulk-copy discovery, X1 versus X2 fields, source snapshots versus native ownership, original linking versus modeled callbacks and opaque returns separated. **QG6** Pass: pinned primary target metadata/bytes, SDK schema hashes, reconstructed proofs, independent byte oracles/replay and controls; native gaps explicit. **QG7** Pass: impact-ranked bounded continuation above. `full_goal_complete=false`. [BH1-BH7]
