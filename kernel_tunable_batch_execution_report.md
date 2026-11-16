# Continuous kernel tunable execution, SFI registration and UUID formatter ABI

Original main now returns from 368 consecutive phase-one initialization callbacks without resetting the preceding state or injecting callback results. These include all 237 compact boot-option initializers, all 22 tree/option initializers, 87 of 101 registered per-CPU pointer adjustments and all 17 indexed SFI registrations. Callback index 368 is active: its Mach-O identity initializer has published the original UUID-byte pointer and entered `_uuid_unparse_upper`. Execution stops before its BL to `_snprintf` at `0xfffffe000c48ef98`. Formatter output, completion of phase one and native startup remain unknown. [TB1-TB7]

```text
original main -> original platform/topology/thread handoff
  preserved first-callback boundary 0xfffffe000c63037c
  original dispatch, actual callback bodies, actual parser bodies
    368 callbacks returned; cursor 0xfffffe000cbec450
    callback 368: Mach-O load-command traversal
      LC_UUID -> published original byte pointer
      _uuid_unparse_upper -> 16 zero-extended stack arguments
      STOP before BL _snprintf

17 SFI registrations -> 96 B indexed slots
  registered handler thunks -> shared thread-state body
                            -> shared continuation
  registration executed; handler invocation not executed

later phase 14 mach_ipc -> registered MIG hash initializer
  still not reached by this continuous startup run
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| TB1 | Original descriptor/body/label provenance and exact symbol boundary | TB-A1 |
| TB2 | Preserved prior state and 368 continuous callback returns | TB-A1-TB-A4 |
| TB3 | Compact option schema, numeric/string ABI and conditional normalization | TB-A1-TB-A5 |
| TB4 | Per-CPU pointer subtraction and indexed SFI publication | TB-A1-TB-A5 |
| TB5 | Selected timer/chosen/policy/trace/watchdog data flow | TB-A1-TB-A5 |
| TB6 | Original UUID-pointer producer and formatter argument custody | TB-A1-TB-A6 |
| TB7 | Independent validation, Mach limits and remaining interfaces | TB-A1-TB-A7 |

Primary provenance is kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original instruction/data bytes, compiler function-start records, format-8 pointer metadata and original nlists. The preserved normalized FairPlayIOKit source has SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference files suffice for this increment; no IDB is read or modified. Results apply to the pinned image and declared private inputs. [TB1]

Artifacts: [capture producer](triage_evidence/recover_kernel_tunable_batch_execution.py), [private executor](triage_evidence/probe_kernel_tunable_batch_execution.py), [independent contracts and replay](triage_evidence/replay_kernel_tunable_batch_execution.py), [source audit](triage_evidence/audit_kernel_tunable_batch_execution.py), [delivery verifier](triage_evidence/verify_kernel_tunable_batch_execution_delivery.py), [capture](triage_evidence/kernel_tunable_batch_execution_checks.json.zst), [audit](triage_evidence/kernel_tunable_batch_execution_audit.json.zst). The capture retains every compact descriptor/name/destination, every adjustment slot, every SFI descriptor/handler/label and all 29 Mach-O load commands. [TB1,TB7]

## State continuity and execution boundary

The default component preserves the previously published [first callback experiment](kernel_startup_registry_abi_report.md) at `0xfffffe000c63037c`: visits, reads, writes, declared returns, tracked original API entries/returns, logical effects, full private RAM, all 37 preceding mutable regions, logical system registers, GPR31, SP, NZCV and final SIMD values. New storage is declared before original main entry and compared unchanged at this boundary. No later repair, callback-result model or call-frame epoch is introduced. The earlier zero-topology-page failure remains a separate historical experiment; the positive run retains its explicit original initialized-page premise. [TB2]

The batch adds 171 disjoint mutable intervals totaling 4568 B, after subtracting overlaps with the earlier 37 intervals. All 208 intervals total 142012 B per case. Initialization uses original logical image contents. The original platform initializer has already produced flag value 1 at `0xfffffe0007f8b648`; its original image value zero is not substituted for the produced state. Native initialized-section lifetime and authentication remain assumptions. [TB2]

The complete original 3519-record sort and its unsigned phase/rank order remain intact. Original dispatch emits each callback at BLRAA `0xfffffe000c630370`, X8=target, X0=argument, X17=`0x2abe`. Actual callback return reaches `0xfffffe000c630374` with the saved dispatcher SP. Original ADD/STR advance and publish the cursor by 24 B. The final cursor is base `0xfffffe000cbea1d0` + 368 * 24 B = `0xfffffe000cbec450`. All 369 entered records have phase 1; index 368 has rank `0x7fffffff`, target `0xfffffe000c62a0cc`, argument zero. [TB2]

There are 392 phase-one records, so 392 - 368 = 24 have not returned, including the active identity callback. The remaining 14 per-CPU adjustments are among the unreturned records. Equal phase/rank records retain the actual original sort order; no stable ordering or general sorter termination proof is asserted. Phase-two, phase-three and later phase-fourteen `mach_ipc` execution remain unknown. [TB2,TB7]

## Compact boot-option ABI

The 237 compact descriptors are distinct from the previously analyzed 48 B tree/option descriptor. Their common initializer is `0xfffffe000c6306e0..0xfffffe000c630754`, 29 words. [TB3]

| Descriptor offset | Width | Meaning established by source |
| --- | --- | --- |
| +0x00 | 8 B | Boot-option key pointer |
| +0x08 | 8 B | Destination pointer |
| +0x10 | 4 B | Requested destination width |
| +0x14 | 1 B | Bit zero enables conditional numeric low-byte normalization |
| +0x15 | 1 B | Bit zero selects string parsing |
| +0x16 | 2 B | Original reserved bytes retained |

| Width B | Normalize byte | String byte | Descriptors |
| ---: | ---: | ---: | ---: |
| 1 | 0 | 0 | 4 |
| 1 | 1 | 0 | 67 |
| 2 | 0 | 0 | 8 |
| 4 | 0 | 0 | 110 |
| 8 | 0 | 0 | 44 |
| 5 | 0 | 1 | 1 |
| 17 | 0 | 1 | 1 |
| 128 | 0 | 1 | 1 |
| 256 | 0 | 1 | 1 |

Both paths load key, destination and size from the descriptor and the copied bootargs pointer from `0xfffffe0007f8b6e8`. String mode sets X0=bootargs+0x6c, W4=1 and tail-branches at `0xfffffe000c630704` to original parser `0xfffffe000c5e48a4`. It preserves the dispatcher's return LR and has no local frame. Numeric mode saves the descriptor in X19, sets W4=0 and calls the same parser at `0xfffffe000c630724`, returning to `0xfffffe000c630728`. The parser's width and string-capacity behavior are checked independently against its original execution, including 255/256 B callers. [TB3]

Absent numeric input skips normalization. Present numeric input with normalization bit zero set loads only the destination's low byte, maps zero to 0 and nonzero to 1, and stores only that byte at `0xfffffe000c630744`. Other destination bytes retain parser output. String mode bypasses this logic. Descriptor order and overlapping destination effects are evaluated sequentially from the sorted records; no distinctness of all destinations is assumed. [TB3]

| Selected key | Width B | Destination | Role in finite cases |
| --- | ---: | --- | --- |
| memstat_ballast_offset_mb | 4 | 0xfffffe0007f1a340 | First returned compact descriptor, sorted index 2 |
| thid_should_crash | 1 | 0xfffffe0007e63340 | Numeric 2 becomes canonical byte 1 |
| bootprofile_type | 5 | 0xfffffe0007e6c981 | String `xyz` exercises tail parser |
| bootprofile_proc_name | 17 | 0xfffffe0007e6c970 | Original string descriptor; absent input retained |
| ipc_disable_enforcements | 128 | 0xfffffe0007e5c1a1 | Original string descriptor; absent input retained |
| trace_typefilter | 256 | 0xfffffe0007f12504 | Original string descriptor; absent input retained |

The input string in the second case is `thid_should_crash=2 bootprofile_type=xyz nbuf=17`. It is an explicit private bootargs fixture. The experiment does not establish fairplayd control over bootargs or native boot admission. All 22 tree/option callbacks also return; their earlier property-then-option precedence remains checked through their actual original bodies. [TB3,TB-A3]

## Per-CPU pointer adjustment and SFI registration

Initializer `0xfffffe000c62a018..0xfffffe000c62a034` has seven words. It loads a u64 pointer from X0, reads TPIDR_EL1, loads the full u16 ordinal at thread+0x1b8, subtracts ordinal << 14 and stores the result through X0. The exact contract is `(old_pointer - (zero_extend64(ordinal16) << 14)) modulo 2^64`. All 101 registered argument slots and their original pointer records are retained; 87 execute before the formatter boundary. Selected ordinal 1 exercises a 16384 B subtraction, while ordinal 0 preserves each value. Pointer ownership, object lifetime and a general CPU-allocation contract remain unknown. [TB4]

SFI initializer `0xfffffe000c62f2a4..0xfffffe000c62f35c` consumes a 32 B descriptor: u32 selector+0 and three pointers+8,+0x10,+0x18. The original diagnostics identify `sfi.c`, invalid SFI class and duplicate SFI registration. It accepts unsigned selector < 18. Slot address is `0xfffffe000cadce28 + selector * 96 B`; the source also checks signed-index representability and selects a poisoned address on mismatch. For admitted selectors, the index is representable and the ordinary slot is selected. [TB4]

| Registry-slot offset | Width | Registration action |
| --- | --- | --- |
| +0x48 | 8 B | Nonzero existing value selects duplicate diagnostic |
| +0x24 | 4 B | Store zero |
| +0x28 | 4 B | Store one |
| +0x48 | 8 B | Publish descriptor handler pointer |
| +0x50 | 8 B | Publish first label pointer |
| +0x58 | 8 B | Publish second label pointer |
| All other bytes | 64 B | Retain preceding contents |

All 17 registered selectors 1..17 execute successfully in each selected run; selector 0 has no descriptor in this inventory. Handler fixups are format 8, authenticated, diversity `0xd507`, address-diversity zero and key zero; labels use unauthenticated pointer records. These are original fixup metadata and logical pointers, not authenticated runtime bits. Invalid/duplicate branches are source-recovered and are not exercised by the three positive runs. [TB4]

All handler addresses in the following table have prefix `0xfffffe000`; suffixes complete exact addresses. Labels have prefix `SFI_CLASS_`, omitted only in this table. [TB1,TB4]

| Selector | First label | Second label | Handler suffix |
| ---: | --- | --- | --- |
| 1 | DARWIN_BG | DARWIN_BG | bd35e2c |
| 2 | APP_NAP | APP_NAP | bd35e40 |
| 3 | MANAGED_FOCAL | MANAGED | bd35da0 |
| 4 | MANAGED_NONFOCAL | MANAGED | bd35d8c |
| 5 | DEFAULT_FOCAL | DEFAULT | bd35e18 |
| 6 | DEFAULT_NONFOCAL | DEFAULT | bd35e04 |
| 7 | KERNEL | OPTED_OUT | bd35df0 |
| 8 | OPTED_OUT | OPTED_OUT | bd35d78 |
| 9 | UTILITY | UTILITY | bd35c20 |
| 10 | LEGACY_FOCAL | LEGACY | bd35ddc |
| 11 | LEGACY_NONFOCAL | LEGACY | bd35dc8 |
| 12 | USER_INITIATED_FOCAL | USER_INITIATED | bd35d50 |
| 13 | USER_INITIATED_NONFOCAL | USER_INITIATED | bd35d3c |
| 14 | USER_INTERACTIVE_FOCAL | USER_INTERACTIVE | bd35d28 |
| 15 | USER_INTERACTIVE_NONFOCAL | USER_INTERACTIVE | bd35d14 |
| 16 | MAINTENANCE | MAINTENANCE | bd35db4 |
| 17 | RUNAWAY_MITIGATION | RUNAWAY_MITIGATION | bd35d64 |

Each of the 17 handlers is five words: PACIBSP, frame save/setup, BL `0xfffffe000bd35c34`, BL `0xfffffe000be7c70c`. The shared first body is 56 words and reads current-thread TPIDR_EL1. It requires DAIF bit 9 set or enters the original diagnostic path; it masks interrupt bits through DAIFSET #7 when required. Calls at `0xfffffe000bd35c7c` and `0xfffffe000bd35c8c` pass the same object `0xfffffe000cb62de8` around saving and clearing thread u32+0x20c. The exact callee targets are `0xfffffe000bd0bfa4` and `0xfffffe000bd0c2cc`; their full semantics are not newly established here. [TB1,TB4]

When thread u64+0x350 is nonzero, the shared body passes X0=thread u64+0x4e8, W1=the indexed u32 at `0xfffffe0007ef9040 + saved_class*4`, X2=(thread u64+0x270 - thread u64+0x350) modulo 2^64 to `0xfffffe000bd01454`, then clears u64+0x350. Its index conversion has a separate representability/poison selection. The diagnostic names `machine_routines_common.c` and `ml_set_interrupts_enabled_with_debug`; an inlined diagnostic name does not name the entire shared function. [TB1,TB4]

The 22-word continuation reads thread u16+0x1cc. If nonzero and bit zero of byte[`0xfffffe000cb5c400`] is set, it calls `0xfffffe000c26972c` with W0=`0x01030002 | (flags << 2)` and X1-X4=0. It then clears the u16 and thread byte+0x1cf before BL `0xfffffe000bc9bccc`; when the initial u16 is zero it skips its redundant clear. The downstream target has not been followed in this increment. A completed return to EL0, handler runtime invocation and scheduler policy effects are unknown. Registration is the only executed SFI effect. [TB1,TB4,TB7]

## Additional initialized interfaces

| Original initializer | Source-supported selected effect | Boundary of interpretation |
| --- | --- | --- |
| 0xfffffe000c62f458 | u32[0xfffffe000cb62e78]=5000; u64[0xfffffe000cb62e80]=(u32[0xfffffe000ca8c000]*0x51eb851f)>>38 | Exact unsigned product/shift; physical units not established |
| 0xfffffe000c63ad8c | `/chosen` property `kernel-ctrr-to-be-enabled`, admitted at 4 B, sets byte[0xfffffe0007ef8e68]=1 and byte[+1]=(value==0) | Absence retains both bytes; malformed-size behavior not exercised |
| 0xfffffe000c63bb08 | Reads `/chosen/asmb` lp-sip0/lp-sip1, chosen/manifest properties, environment and `-restore`; selected cases publish u32[0xfffffe0007f12c60]=0 | Selected cases do not cover nondefault security-policy branches |
| 0xfffffe000c26498c | `-s`/`-x` contribute bits 2/256; present `nbuf` sets value at 0xfffffe000cb29c18 and presence at +4; copied bootargs revision/bit feed 0xfffffe000cb2a71c | Exact private boot inputs; native observability and downstream use unknown |
| 0xfffffe000c6334fc | Retains values 1..100 at u32[0xfffffe000ca92374], otherwise stores 95; `wdt=-1` without `zet` stores -1 at 0xfffffe0007e66e28 | No native watchdog or timing claim |

The trace configuration also calls the original string parser with capacity 255 for `panic-on-proc-crash`, `panic-on-proc-exit` and `panic-on-proc-spawn-fail`. Buffers follow u32 presence flags at `0xfffffe000cb29df0`, `0xfffffe000cb29ef4` and `0xfffffe000cb29ff8`. A present nonempty parsed string sets its flag to one. Independent sequential formulas compare every declared mutable byte, including unchanged fields and destination aliases. The chosen-property case supplies value 1 as a 4 B property and selects CPU ordinal 1 through the actual preceding enumeration. [TB5]

## Mach-O identity and variadic formatter ABI

Initializer `0xfffffe000c62a0cc..0xfffffe000c62a1e0` walks the original kernel Mach-O header at `0xfffffe000700c000`. All 29 load commands are retained with exact bytes and extent. The first LC_UUID has command 0x1b and size 24 B. Original code publishes command+8 to u64[`0xfffffe000cb51120`] and calls `_uuid_unparse_upper` at `0xfffffe000c62a134`, passing UUID bytes in X0 and destination `0xfffffe000cb2a1a0` in X1. [TB6]

Exact-address original nlists name `_uuid_unparse_upper` at `0xfffffe000c48ef18` and `_snprintf` at `0xfffffe000c3003b0`. Other newly described callbacks and SFI handlers have no exact-address name in the retained query. Behavioral descriptions do not rename the original image. [TB1,TB6]

The 36-word UUID routine loads each of the 16 input bytes into a W register, thereby zero-extending it into X, and places 16 u64 variadic arguments at stack offsets 0..120, an exact 128 B region. Its frame consumes 144 B. Before BL `0xfffffe000c48ef98`, X0=destination, X1=37 B and X2=`0xfffffe00070d7f36`, the original uppercase UUID format. The format has 16 `%02X` conversions separated into 8-4-4-4-12 hexadecimal digits. Expected formatted length is 36 characters plus one NUL byte, matching capacity 37 B. The audit records the original UUID bytes and independently predicted uppercase text. The formatter has not executed; the destination's unchanged original bytes are checked. [TB6]

## Validation receipts

Decoded capture: 2673011 B, SHA-256 `64d81d258a9d33b11b067a168df96a0f7c7d9b393691e21ff448629059a521b0`. Decoded audit: 239193422 B, SHA-256 `b5d76eafcca226e7db156a08598b5266b178f6f106394739eff322ac18788b1a`. The closure retains 176 complete function bodies, 13474 words / 53896 B, including all 156 preceding bodies with matching bytes. The 20 additional functions are the UUID routine, 17 SFI thunks and two shared bodies. Five opaque words remain preserved and unexecuted. Independent static contracts total 1222. [TB1,TB7]

Fourteen new nonvacuous QF_AUFBV queries are UNSAT across 104 distinct source PCs, 116 instruction instances and 102 linked-edge obligations. Fourteen preceding registry queries are rebuilt against the closure. Three positive components pass 16127 independent semantic checks across 1105249 visits and 4176 distinct executed PCs. [TB7]

| Private input | Original visits | Returned callbacks | Earlier declared no-RAM returns |
| --- | ---: | ---: | ---: |
| continuous_default_phase_one_batch | 305828 | 368 | 3 |
| numeric_boolean_and_string_options | 479411 | 368 | 3 |
| selected_CPU_ordinal1_and_chosen_property | 320010 | 368 | 4 |

Independent formulas compare 439608 callback-output/final-global bytes and 3132672 private nonstack bytes. Fresh replay checks 294487 reads / 1735009 B, 164114 writes / 1293802 B, 10272 logical PAC/return steps, 14068 other logical effects and all 10 earlier declared return/clobber contracts. There are no new callback-result models. [TB7]

Original API tracking retains 18535 entries and 18523 returns, with 12 unfinished outer entries across the three formatter boundaries. Fresh replay compares 34603008 private checkpoint bytes; earlier-region, bootstrap-extra, registry-extra and phase-one-extra checkpoint byte totals are 1098240, 86724, 2725704 and 123336 respectively. Eager original page checks total 172032 B. Final comparisons cover 3145728 private bytes, 1798144 mapped-image bytes and 96 SIMD values. Counts overlap across checkpoints and cases; they are not disjoint native object extents. [TB7]

The original UUID is `9b65bd6e027b34d1a22bac03dccffc84`; the independently predicted uppercase text is `9B65BD6E-027B-34D1-A22B-AC03DCCFFC84`. This is an input/format prediction, not observed formatter output. [TB6]

The source obligations include descriptor loads/string branch, tail-call LR/capacity/flag, numeric call/saved descriptor, absence and normalization guards, low-byte normalization, full-u16 pointer subtraction, unsigned SFI bound/96 B address/duplicate gate/publication, timer arithmetic, admitted chosen-property bytes and all 16 zero-extended UUID variadic slots. Each proof checks SAT premises before requiring the negated contract and linked-edge violations to be UNSAT, with a 30 s/query limit. The UUID BL is modeled symbolically to establish its target and LR; the continuous executor stops before that instruction. [TB7]

Fresh replay imports no batch executor and checks the original instruction stream, read/write journals, register boundary, logical transfers, original API calls, checkpoint RAM, all final mapped pages and SIMD values. At the preserved first boundary, replay may have already mapped pages demanded only later by the probe. Existing checkpoint pages match exactly; each additional eagerly mapped page is checked against its original logical image. This declared mapping normalization does not alter bytes or assert native page lifetime. Full final page sets match. Four initial full-page snapshots are published as address-and-SHA-256 references to their exact original logical pages, avoiding embedded incidental target-image path strings. Reconstruction requires the pinned original collection and verifies both collection and page hashes; no executed, read, written or checkpoint byte changes. All four reconstructed pages equal their pre-publication bytes. [TB2,TB7]

Two independently checked controls replace only one original source word with NOP: `0xfffffe000c630744` removes the canonical Boolean store in the option-bearing case; `0xfffffe000c62a02c` removes the pointer-adjustment store in the ordinal-1 case. All declared initial state fields match their corresponding positive cases. Both reach the same formatter boundary and are rejected by independent callback-output contracts. The retained control receipts contain exact patch bytes, initial-equality fields, rejection, final registers and canonical journal SHA-256; full control journals are regenerated by the delivery verifier rather than retained twice. Controls are excluded from positive totals. Shared decoder/emulator defects remain possible; finite controls do not establish universal correctness. [TB7]

## Mach relevance, assumptions and bounded continuation

The initialization callback BLRAA and formatter BL are function transfers. This increment establishes no new incoming/outgoing Mach port, transferred right or Mach-message emission PC. The prior [Mach report](mach_ports_report.md) remains authoritative. Phase-14 `mach_ipc` registration of the MIG hash initializer `0xfffffe000c62a46c` remains established by the prior registry capture, but that phase is not executed here. The new closure and SFI registration are kernel-owned; a FairPlayIOKit-specific downstream effect and a matched daemon/user-client/provider/kernel epoch remain unknown. [TB7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TB-A1: Pinned collection bytes and fixups identify this build | TB1-TB7 | Rebuild original bodies, all descriptors/labels/load commands and exact-symbol queries; reject cross-build reuse |
| TB-A2: Original logical initialized data are explicit pre-entry fixtures | TB2-TB7 | Exact published first-boundary comparison and new-storage unchanged check; native loader/lifetime still unknown |
| TB-A3: Well-formed private trees and copied bootargs define the selected domain | TB2-TB7 | Absent/options/chosen/nonzero-ordinal cases; original parsers plus independent API formulas; malformed/native admission unproved |
| TB-A4: PAC/system operations preserve logical values under the declared envelope | TB2-TB7 | Exact operands, modifiers, callback targets/LR/SP, full replay and retained earlier leaf contracts; native authentication unproved |
| TB-A5: Sequential descriptor formulas cover selected callback effects | TB3-TB5,TB7 | Compare each returned output and all 208 mutable regions; NOP controls; absent/unexecuted policy branches remain limited |
| TB-A6: Original Mach-O bytes and target ABI define formatter inputs | TB6,TB7 | Full header/load-command extent, nlists, 16 symbolic byte slots and actual boundary RAM; no produced formatter output claim |
| TB-A7: Kernel startup registration does not establish a matched FairPlay transaction | TB7 | Continue preceding phases and pair daemon/provider/kernel epochs, payloads, rights and statuses; currently unknown |

Capture is O(K+I+R*E+N) time and O(K+I+R+N) space in collection bytes K, source I, descriptor records R, owner segments E and symbols N. Proof construction is linear in source/formula DAG, with SMT search separate. Execution/replay are O(V+J+M) in visits, journals and mapped bytes; independent API timeline ordering adds O(J log J). Callback formulas are sequential in callbacks plus compared bytes. Full-sort behavior is finite evidence, not a general complexity proof for the original sorter. Widths and extents are exact little-endian bytes; raw timer words carry no inferred physical units. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, exact decoded roundtrips and decoded/nested path checks. [TB7]

| Impact | Next discriminating work | Evidence sought |
| --- | --- | --- |
| High | Follow the original formatter with its actual stack arguments | Produce source-supported UUID output and resume the active callback without synthetic return data |
| High | Complete the remaining phase-one and admitted phase-two/three callbacks | Establish original preceding state before later main and phase-14 MIG registration consumption |
| High | Recover initialized-section producer/fixup lifetime | Replace the private initialized-data premise with an original loader contract |
| High | Pair a daemon/user-client/provider/kernel transaction | Establish observed FairPlay relevance, port rights, message custody and epoch correspondence |
| Medium | Follow SFI slot consumers and registered handler invocation | Establish actual invocation ABI and downstream thread-state/continuation semantics; modifier value alone is insufficient |
| Medium | Follow the new timer/trace/watchdog destinations | Establish downstream units, observability and native control boundaries |

**QG1**: Factual technical analysis; no normative content required. **QG2**: TB-A1-TB-A7 include dependencies and falsification probes. **QG3**: Finite callback batch, descriptors, SFI registration, external inputs, UUID ABI and Mach limits covered; the full interface goal remains active. **QG4**: Exact widths, extents, modular arithmetic, counts and complexity stated. **QG5**: Registration/invocation, original/produced state, symbolic/actual BL, native/private execution and eager mapping are distinguished. **QG6**: Original bytes, independent contracts, source proofs, replay and controls retained. **QG7**: Impact-ranked bounded continuation included. All gates pass for this finite increment; native startup, phase completion and matched FairPlay effects remain unknown.
