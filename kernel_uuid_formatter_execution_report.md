# Original UUID formatting, phase-one completion and per-CPU initialization

Original main now produces `9B65BD6E-027B-34D1-A22B-AC03DCCFFC84` followed by NUL through the original `_snprintf`, returns from all 392 consecutive phase-one callbacks and prepares the first phase-two call. Four private startup cases preserve preceding state without a new callback-result model. Execution stops before BLRAA `0xfffffe000c630370`, with target `0xfffffe000bd12f7c` and argument `0xfffffe000ca94260`; that callback has not executed. Native startup, native PAC and a matched FairPlay transaction remain unknown. [UF1-UF7]

```text
original main -> original platform/topology/thread initialization
  preserved published formatter-call state: 0xfffffe000c48ef98
  original UUID wrapper -> _snprintf -> generic engine
                                      -> original bounded byte callback
    original stack varargs -> 36 attempted characters -> 37-byte UUID string
  actual Mach-O identity callback return
  remaining original phase-one callbacks -> 392 returns total
    final cursor 0xfffffe000cbec690
  original transition -> phase 2, trace label "timeouts"
  STOP before first phase-two BLRAA

four per-CPU objects
  phase 1, rank 0xffffffff -> embedded per-CPU pointer publication: executed
  phase 7, rank 0xffffffff -> zalloc-phase registration: not executed

phase 14 mach_ipc -> registered MIG hash initializer: still not reached
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| UF1 | Original formatter closure, conversion table, digit bytes and symbol provenance | UF-A1 |
| UF2 | Exact preceding formatter boundary and continuous phase-one completion | UF-A1-UF-A4 |
| UF3 | Variadic wrapper, logical output callback, bounded output and attempted count | UF-A1-UF-A4,UF-A6 |
| UF4 | Four embedded per-CPU pointer publications and eight phase registrations | UF-A1-UF-A5 |
| UF5 | Selected stack masks, debugger-option parsing and remaining callback outputs | UF-A1-UF-A5 |
| UF6 | Finite direct formatter cases, source obligations, replay and controls | UF-A1-UF-A6 |
| UF7 | Architectural relevance, Mach boundaries and bounded continuation | UF-A1-UF-A7 |

Primary evidence is kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original instruction/data bytes, compiler function-start records, original nlists and format-8 pointer records. The preserved normalized FairPlayIOKit source has SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The original files suffice; no IDB is read or modified. Exact addresses and results apply to this build and the declared private inputs. [UF1]

Artifacts: [capture producer](triage_evidence/recover_kernel_uuid_formatter_execution.py), [continuous executor](triage_evidence/probe_kernel_uuid_formatter_execution.py), [direct formatter cases](triage_evidence/probe_kernel_uuid_formatter_cases.py), [independent contracts and replay](triage_evidence/replay_kernel_uuid_formatter_execution.py), [source audit](triage_evidence/audit_kernel_uuid_formatter_execution.py), [delivery verifier](triage_evidence/verify_kernel_uuid_formatter_execution_delivery.py), [capture](triage_evidence/kernel_uuid_formatter_execution_checks.json.zst), [audit](triage_evidence/kernel_uuid_formatter_execution_audit.json.zst). [UF1,UF6]

## Continuous state and phase transition

The default component exactly preserves the previously published [formatter-call boundary](kernel_tunable_batch_execution_report.md): visits, reads, writes, declared earlier returns, logical effects, original call/API entries and returns, callback entries and returns, full private RAM, all 208 declared mutable image intervals, page hashes, system state, GPR31, SP, NZCV and SIMD values. The initial first-callback boundary is also retained. This increment adds no initialized mutable interval: the same 208 intervals total 142012 B. No later state repair or call-frame epoch occurs. Earlier declared no-RAM leaf return/clobber contracts remain explicit; continuous execution is conditional on them. [UF2,UF-A2,UF-A4]

The original formatter BL at `0xfffffe000c48ef98` now executes. Its return checkpoint at `0xfffffe000c48ef9c` has X0=36. Original `_uuid_unparse_upper` and the Mach-O identity callback actually return. The remaining 24 callback completions comprise the following exact families. [UF2-UF5]

| Original callback target | Returned in this continuation per case | Established role |
| --- | ---: | --- |
| 0xfffffe000c62a0cc | 1 | Mach-O identity, UUID output, debugger-option presence |
| 0xfffffe000c62a018 | 14 | Remaining registered per-CPU pointer adjustments |
| 0xfffffe000bd3a524 | 1 | Requested kernel stack size and alignment masks |
| 0xfffffe000c629adc | 1 | Optional capability callback/type gate |
| 0xfffffe000c629a70 | 1 | Empty initializer |
| 0xfffffe000c62f35c | 4 | Embedded per-CPU object pointers |
| 0xfffffe000c644d1c | 1 | Produced platform guard and selected mode branch |
| 0xfffffe000c62a0a4 | 1 | Conditional flag OR |

All 101 pointer adjustments, all 237 compact option initializers, all 22 tree/option initializers and all 17 SFI registrations have now returned in each startup case. SFI handler invocation remains unexecuted. All sorted records 0..391 have phase 1; the cursor is `0xfffffe000cbea1d0 + 392 * 24 B = 0xfffffe000cbec690`. The next record is phase 2, rank zero. Source publishes u32[`0xfffffe0007f8b5f0`]=1 and last phase at `0xfffffe000cb62ec8`=2, then produces the third trace record, label `timeouts`, event ID `0x07020010`, counter 3. Its timestamp remains within the earlier logical system-register envelope; no physical time unit is inferred. X8 and X0 hold the next target and argument at the unexecuted dispatch boundary. [UF2]

## Formatter closure and exact ABI

| Original source interval, end exclusive | Words | Naming evidence |
| --- | ---: | --- |
| 0xfffffe000c3003b0..0xfffffe000c300414 | 25 | Exact original nlist `_snprintf` |
| 0xfffffe000c300414..0xfffffe000c300444 | 12 | No exact-address nlist; bounded byte-output behavior |
| 0xfffffe000bd146a0..0xfffffe000bd15408 | 858 | No exact-address nlist; generic conversion engine behavior |

All 176 preceding function bodies match; the enlarged closure contains 179 bodies, 14369 words / 57476 B. Five opaque words remain preserved and unexecuted. Original nlists also identify `_strlen` at `0xfffffe000bc9db70` and `___stack_chk_fail` at `0xfffffe000c629694`. The selected UUID path does not execute either callee. Engine and byte-output descriptions are behavioral findings, not recovered original symbol names. [UF1]

At wrapper entry, X0 is destination, X1 is capacity in bytes and X2 is the original format at `0xfffffe00070d7f36`. Sixteen u64 variadic slots reside at entry SP+0..120; each contains a zero-extended original UUID byte. The format has sixteen `%02X` conversions arranged as 8-4-4-4-12 hexadecimal digits. The wrapper allocates 48 B and builds a two-u64 context at entry SP-32. [UF3]

| Engine entry field | Actual original value |
| --- | --- |
| X0 | Original format pointer |
| X1 | Wrapper entry SP, first variadic slot |
| X2 | Byte-output target 0xfffffe000c300414 |
| X3 | Context pointer, wrapper entry SP-32 |
| W4 | 10, initial radix |
| W5 | 0, flags |
| Context u64+0 | Current destination cursor |
| Context u64+8 | Remaining capacity in bytes |
| X17 at logical PACIA/output BLRAA | 0xae56 |

The engine frame consumes 208 B. It retains context in X20, callback in X21, format in X22 and attempted-character count in W23; the saved variadic cursor is engine SP+0x18. Original integer conversion advances each variadic slot by 8 B. The engine contains 24 authenticated callback call sites. On the selected path each output call uses BLRAA X21,X17 with W0=character, X1=context and X17=`0xae56`. This is a logical transfer under the declared PAC envelope, not proof of native authentication. The original canary is compared against `0xfffffe000cacb000`; the failure branch remains unexecuted. [UF3,UF6,UF-A4]

The 12-word byte callback performs an unsigned remaining-capacity comparison. If remaining >=2, it stores the character's low byte at cursor, increments cursor by 1 B and subtracts 1 B from remaining. For remaining 0 or 1 it leaves cursor, capacity and output bytes unchanged. The callback itself writes no terminator. After engine return, the wrapper reloads the **remaining** capacity and stores NUL at the final cursor iff remaining is nonzero. This load is not the original capacity: the emitter has mutated it. For these runs, initial capacity >0 implies final remaining >=1, so the selected bounded-output result follows. Engine X0 returns attempted characters, independently of truncation. [UF3,UF6]

For the actual UUID call, capacity is 37 B, 36 characters are stored, remaining becomes 1 and the wrapper stores NUL as byte 37. Global output at `0xfffffe000cb2a1a0` is exactly `9B65BD6E-027B-34D1-A22B-AC03DCCFFC84\0`. The original UUID-byte pointer published at `0xfffffe000cb51120` retains its preceding producer. This is observed original-instruction output in private execution, extending the earlier input/format prediction. [UF2,UF3]

The engine conversion table at `0xfffffe000bd15408` is 484 B: 121 signed 32-bit offsets relative to `0xfffffe000bd149b4`, covering conversion bytes 0..120 and yielding 18 distinct in-engine targets. The original unsigned guard selects default `0xfffffe000bd14cb4` for byte >0x78 before table lookup. The exact 121 slot/target pairs and raw bytes are retained. The 33-byte digit table at `0xfffffe000704e797` is `0123456789abcdef0123456789ABCDEF\0`; uppercase lookup starts at `0xfffffe000704e7a7`. Source proofs cover byte-domain quotient/remainder and all sixteen uppercase digits. Generic formatting, arbitrary widths/flags, integer overflow and unexecuted conversion branches remain unknown. [UF1,UF3,UF6]

## Direct capacity and byte-pattern experiments

Twenty-one direct cases execute the original wrapper, engine and callback: three 16-byte UUID patterns times seven capacities. Patterns are all zero, all `ff`, and `00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff`. Their independently expected texts are `00000000-0000-0000-0000-000000000000`, `FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF` and `00112233-4455-6677-8899-AABBCCDDEEFF`. There are no declared API-return models in these direct components. [UF6]

| Capacity B | Stored characters B | NUL stored | Returned X0 | Destination premise |
| ---: | ---: | --- | ---: | --- |
| 0 | 0 | No | 36 | NULL; no output access |
| 1 | 0 | Yes | 36 | Private guarded buffer |
| 2 | 1 | Yes | 36 | Private guarded buffer |
| 17 | 16 | Yes | 36 | Private guarded buffer |
| 36 | 35 | Yes | 36 | Private guarded buffer |
| 37 | 36 | Yes | 36 | Private guarded buffer |
| 38 | 36 | Yes | 36 | Private guarded buffer |

Each direct run attempts all 36 output calls and returns to its entry SP. The 128-byte output guard is initially `a5`; all bytes outside the expected prefix and NUL retain that value. Independent formulas compare the entire private region except a declared 0x1100-byte stack window; fresh replay compares full RAM including that window. The 21 runs total 70428 visits, 798 tracked API entries/returns and 2826 formatter checks. They compare 21928704 nonstack bytes and 2688 guarded output bytes. The selected finite domain does not establish general C/POSIX conformance. [UF6]

## Per-CPU objects and later allocation boundary

Initializer `0xfffffe000c62f35c` has eight original registrations for four object arguments, paired between phase 1 and phase 7 (`zalloc`). All ranks are `0xffffffff`; registry indices below refer to original unsorted records. These are not phase-9 registrations. [UF4]

| Object address | Phase-1 registry index | Phase-7 registry index | Original u64+0, u64+8, u64+0x10 |
| --- | ---: | ---: | --- |
| 0xfffffe000ca90080 | 48 | 49 | 2, 2, 0 |
| 0xfffffe000caac340 | 211 | 212 | 2, 2, 0 |
| 0xfffffe000ca907c0 | 213 | 214 | 2, 2, 0 |
| 0xfffffe000ca9c340 | 774 | 775 | 2, 2, 0 |

All 32-byte headers are retained; only the third object has byte+0x18=1. During phase 1 the phase word is zero. Original code reads u16 CPU ordinal at thread+0x1b8 and computes `pointer = (object + 32 B - (zero_extend64(ordinal16) << 7)) modulo 2^64`. If `((object+32) XOR pointer) & 0xffc0000000000000` is nonzero, it replaces pointer bits 63..48 with `0xc8a2`. It publishes the resulting u64 at object+0x10. All four publications execute for ordinal 0 and ordinal 1. The stride is 128 B, distinct from the 16384 B pointer-adjustment family. Exact object ownership and higher-level type remain unknown; no log/lock identity is inferred from the header alone. [UF4]

The unexecuted nonzero-phase branch reads count u32[`0xfffffe0007e66f38`] and forms count <<7 bytes. Its source call interfaces are retained below; full callee semantics and allocation success are not newly established. [UF4,UF7]

| Branch | Target | Source-prepared arguments |
| --- | --- | --- |
| Count <129 | 0xfffffe000bd71a20 | X0=0xfffffe000caeb540, X1=count*128 B, W2=127 |
| Other count | 0xfffffe000bdc08e0 | X0=u64[0xfffffe0007f860a8], X1=count*128 B, W2=127, W3=0x00200181, W4=13, X5=0; source consumes returned X1 pointer |

The later source initializes 128-byte slots/internal pointers and uses STLUR to publish object+0x10. Phase-7 registration establishes the intended later startup touch point; this increment executes neither phase 7 nor its allocations. Native object lifetime and the loader's initialized-page contract remain unknown. [UF4,UF-A2]

## Stack masks and remaining policy inputs

Stack initializer `0xfffffe000bd3a524` defaults requested bytes at `0xfffffe0007f30770` to 16384, then invokes the original parser for `kernel_stack_pages`, width 4 B, W4=0. A present value is shifted by 14 in W arithmetic, with 32-bit wrapping before zero extension. Source performs alignment/overflow checks and rounds a non-power-of-two requested size upward for its masks. It leaves the published requested size unchanged. Selected values and masks are exact below; arbitrary input admission is not proved. [UF5]

| Selected input | Requested size B | Rounded mask basis B | u64[0xfffffe0007e64500] | u64[0xfffffe0007e64508], signed interpretation |
| --- | ---: | ---: | ---: | ---: |
| Absent | 16384 | 16384 | 16383 | -16384 |
| kernel_stack_pages=3 | 49152 | 65536 | 65535 | -65536 |

The nondefault case is `3 * 2^14 B = 49152 B`; the next power of two is 65536 B. The two source mask publications are `rounded-1` and `-rounded modulo 2^64`. The 49152-byte requested size is not replaced by 65536. [UF5,UF6]

After formatting, the identity initializer consults u32 mode at `0xfffffe0007f8b6f8` and policy byte at `0xfffffe0007f12c60`. When `(policy & 0x19) != 0` and mode is nonzero, mode bit 0 sets u32[`0xfffffe000caceea8`]=1 and bit 2 sets u32[`0xfffffe0007f8b5ec`]=1. The selected earlier policy paths remain constrained by the private inputs. It clears an 80-byte stack buffer and calls the original parser with key `kdp_match_name`, width 80 B, W4=0, then publishes parser status to u32[`0xfffffe0007e5ca28`]. The added input `kdp_match_name=probe` produces status 1; absent cases produce 0. Presence and the actual parser call are established; a downstream debugger connection or use of the temporary text is unknown. [UF5]

| Callback | Source contract and selected boundary |
| --- | --- |
| 0xfffffe000c629adc | Original 24-byte record at 0xfffffe0007e5c2b8 has selector byte 3 and NULL callback at +16. NULL yields W0=1. Selector !=3 or callback result bit 0 clear ORs 12 into u16[0xfffffe0007e62bc8]; selected record preserves it. Non-NULL logical callback uses modifier 0xa51f and is unexecuted. |
| 0xfffffe000c62a0a4 | Nonzero u32[0xfffffe0007f212d8] ORs 0x5dee into u32[0xfffffe0007f18be0]; independent formulas use the preceding produced value. |
| 0xfffffe000c644d1c | Requires previously produced u32[0xfffffe0007f8b648]=1. If copied mode byte &10 is nonzero, clears byte[0xfffffe0007f8b640]. Original image guard zero is not substituted for produced one. |

Boot text, CPU records and chosen properties are explicit private fixtures consumed by original parsers/enumeration. Fairplayd control of these inputs, native boot admission, malformed-tree behavior and unexecuted policy branches remain unknown. [UF5,UF-A3]

## Validation and reproducibility

Decoded capture: 2520544 B, SHA-256 `6d4284002d8bb69ffdeaac36a5588470302f2dac59aa5b5eccef5641273320b4`. Decoded audit: 346788512 B, SHA-256 `3892702cfa3e18cb80d59df513986d50a0d1f7cab5b2258b86ffcc2cdd885ef7`. The four main and 21 direct components total 1640960 original visits and 4584 distinct executed PCs; the four main cases pass 25348 semantic checks. [UF6]

| Private startup input | Original visits | Returned callbacks | Earlier declared no-RAM returns |
| --- | ---: | ---: | ---: |
| continuous_default_phase_one_batch | 310947 | 392 | 3 |
| numeric_boolean_and_string_options | 485766 | 392 | 3 |
| selected_CPU_ordinal1_and_chosen_property | 325129 | 392 | 4 |
| stack_rounding_and_debugger_name_option | 448690 | 392 | 3 |

Main components total 1570532 visits, 24995 tracked API entries and 24987 returns, leaving two outer entries unfinished per case at the phase-two boundary. All 25 formatter results attempt 36 characters each, totaling 900 byte-output calls. Main formulas compare 568976 callback-output/final-global bytes and 4176896 nonstack bytes. Fresh replay checks 415857 reads / 2371290 B, 228296 writes / 1786375 B, 14592 logical PAC/return steps, 19856 other logical effects and all 13 earlier declared leaf contracts. No new return model is introduced. [UF2,UF6]

Replay compares 54525952 private checkpoint bytes. Earlier-region, bootstrap-extra, registry-extra and phase-one-extra checkpoint totals are respectively 1730560, 141328, 4441888 and 200992 B. Eager original page checks total 356352 B at preserved earlier checkpoints and 122880 B at the formatter cut. Final comparisons cover 26214400 private bytes, 3043328 mapped-image bytes and 800 SIMD values across all 25 components. Six initial page snapshots are retained as exact original-page digest references. Counts overlap across checkpoints and components; these are not distinct native object extents. [UF6]

Sixteen new nonvacuous QF_AUFBV queries are UNSAT across 62 distinct PCs, 65 instruction instances and 49 linked-edge obligations. Fourteen preceding tunable-batch queries are rebuilt against the enlarged closure. Each query first requires SAT premises, then UNSAT for the negated result or linked-edge violation, with a 30 s/query limit. The obligations cover wrapper entry/context/varargs/radix/flags, remaining-capacity/NUL behavior, unsigned emitter admission and exact writes, logical callback arguments/LR, attempted count, variadic stride, hexadecimal quotient/remainder/digit lookup, conversion guard, full-u16 per-CPU offset and poison selection, object publication and stack masks. They do not prove all generic formatter paths. [UF6]

Independent source/data checks total 318: all 179 original bodies/hashes, three strings, exact conversion bytes and all 121 signed-offset targets, digit bytes, four object headers, eight original registry relationships and the optional NULL-callback record. Callback formulas evaluate sequentially from the preserved formatter cut, including aliased destinations and all 208 final mutable intervals. Original option/string API contracts are checked again over the full continuation. Semantic-check counts overlap these retained checks; they are not disjoint interface counts. [UF1,UF5,UF6]

Fresh replay imports no executor and independently verifies original visits, reads/writes, logical effects, original API entries/returns, callback SP/outputs, thirteen whole checkpoints per main case, full private RAM, final mapped-image page hashes and SIMD values. At earlier checkpoints replay may eagerly map original pages first needed later in the probe. Existing checkpoint pages match exactly; every additional eager page equals its original logical page. Final page sets match exactly. Initial full-page snapshots containing incidental path strings are represented by address plus SHA-256 of the exact original logical page. Hydration checks the pinned collection and page digest, restores identical bytes and roundtrips back to the same publication row. No executed/read/written/checkpoint byte is changed; reconstruction requires the original collection. [UF2,UF6]

Two controls replace one source word with NOP. At `0xfffffe000c300430`, removing the byte-output store corrupts actual main UUID output and the independent formatter contract rejects it. At `0xfffffe000c300404`, removing wrapper NUL storage is rejected in the all-zero UUID/capacity-17 direct case, whose nonzero guard makes a missing terminator observable. Every declared initial field matches its positive counterpart. Both reach the corresponding expected final boundary. Retained receipts include exact original/replacement bytes, equality fields, rejection, GPR boundary and canonical journal SHA-256; complete control journals are regenerated rather than stored twice. Controls are excluded from positive totals. Common decoder/emulator defects remain possible despite separate formulas, source obligations and controls. [UF6]

Capture is O(K+I+N+R) in collection bytes K, captured instructions I, symbols N and registry records R. Proof construction is linear in source/formula DAG; SMT search is separate. Execution/replay are O(V+J+M) in visits V, journal events J and mapped/compared bytes M, with O(J log J) independent API timeline ordering. Finite formulas are sequential in callbacks/output bytes. These are analysis-tool bounds, not a general complexity proof for the original formatter or sorter. Values are exact little-endian bitvectors/byte extents; arithmetic widths and wrapping are explicit. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, exact decoded roundtrips and decoded/nested path scans. [UF6]

## Mach relevance, assumptions and continuation

The output BLRAA transfers one character/context to a function, and the startup BLRAA transfers an initialization argument. Neither operation emits a Mach message or port right. This increment establishes no new incoming/outgoing port, right transfer or Mach-message emission location. The [Mach-port report](mach_ports_report.md) and [kernel MIG report](kernel_vm_mig_report.md) retain their evidence boundaries. Phase-14 `mach_ipc` registration of MIG hash initializer `0xfffffe000c62a46c` remains established but unexecuted here. Source UUID output and phase-one completion concern kernel startup; a matched daemon/user-client/provider/kernel transaction remains unknown. [UF7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UF-A1: Pinned original collection/fixups identify this build | UF1-UF7 | Rebuild complete bodies, nlists, conversion data, object headers and registry pairs; reject cross-build matches |
| UF-A2: Original logical initialized pages are declared pre-entry fixtures | UF2-UF7 | Exact published formatter-boundary preservation, 208 intervals and hydrated-page hashes; native loader/lifetime unproved |
| UF-A3: Private bootargs/tree/CPU fixtures define the admitted domain | UF2-UF7 | Absent/options/ordinal-1/chosen/nondefault-stack cases with original parsers and independent formulas; malformed/native admission unproved |
| UF-A4: Logical PAC/system operations and prior leaf contracts define execution envelope | UF2-UF7 | Check exact operands/modifiers/LR/SP/system journals and all retained clobber contracts; native PAC unproved |
| UF-A5: Sequential formulas cover selected remaining callback effects | UF4-UF7 | Compare each returned output and all final globals; stack 3 versus default, ordinal 1 versus 0; phase 7 and other policy branches unexecuted |
| UF-A6: UUID format and byte-domain arguments define the selected formatter contract | UF3,UF6,UF7 | Three byte patterns times seven capacities, NULL/zero, a5 guards, full replay, source obligations and two NOP controls; generic completeness unknown |
| UF-A7: Kernel startup progress does not establish a matched FairPlay transaction | UF7 | Pair daemon/provider/kernel epochs, messages, rights, payloads and statuses; currently unknown |

| Impact | Next discriminating work | Evidence sought |
| --- | --- | --- |
| High | Follow prepared phase-two timeout callback and later phase-three callbacks | Actual original effects/returns before later main and phase-14 registration consumption |
| High | Recover original initialized-section producer/fixup lifetime | Replace private initialized-page premise with source-supported loader contract |
| High | Pair daemon/user-client/provider/kernel transaction | Observed FairPlay relevance, rights custody, message PCs and epoch correspondence |
| Medium | Follow phase-seven per-CPU allocation and slot consumers | Allocation/lifetime, returned-register ABI, object type and actual later publication |
| Medium | Exercise additional admitted stack/policy/conversion branches | Distinguish finite selected formulas from general input contracts without inventing return data |
| Medium | Follow debugger status and stack-mask consumers | Establish downstream use, native observability and external-control boundaries |

**QG1**: Factual analysis; no normative content required. **QG2**: UF-A1-UF-A7 state dependencies and falsification probes. **QG3**: Original formatter, continuous state, remaining phase-one interfaces, external inputs and Mach limits covered; full interface goal remains active. **QG4**: Exact widths, extents, modular arithmetic, counts and complexity stated. **QG5**: Remaining/original capacity, requested/rounded stack size, phase-1/phase-7 pairing, registration/invocation and private/native execution distinguished. **QG6**: Original bytes, independent formulas, nonvacuous proofs, fresh replay and altered-source controls retained. **QG7**: Impact-ranked bounded continuation included. Gates apply to this finite increment; native startup and a matched FairPlay transaction remain unknown.


## Phase-two timeout execution follow-up

The [timeout execution report](kernel_timeout_execution_report.md) continues original main through all ten phase-two callbacks, reaching 402 actual callback returns after preserved phase-one/UUID state. It recovers nine timeout descriptors, the shared initializer diagnostic identity, root/chosen/boot precedence, cached scaling, modular multiplication and final saturation, plus selected lock-timeout preparation. Six private cases, twelve new source obligations, sixteen formatter rechecks, full helper/tree/parser/copy contracts, independent replay and two changed-source controls bound this result. The next call is the first phase-three lock initializer and remains unexecuted. Native startup, phase-14 MIG execution and matched FairPlay/Mach custody remain unknown; earlier boundaries describe their original increments and the full goal remains active.
