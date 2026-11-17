# FPMessage parser epoch and completion interfaces

The source-built FPMessage invokes the common parser with a new output destination and caller discriminator. This increment executes that handoff through a second `site.FPTTLV` allocation and reaches the pending first raw-input read. Allocation failure reaches a caller-specific failure continuation. Separately qualified completion cuts establish the pointer store at message offset zero and the first consumer of message byte+0x60. These cuts do not establish completion of the second parse.

Primary evidence is the pinned collection and normalized kext, original instruction words, original chained pointer records, allocation descriptor and exhaustive byte-bank identities. Existing reference data suffice; no live IDA database operation is needed.

| Evidence | Identity / coverage |
| --- | --- |
| Kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `565b2803433729d335ac4535e01be67c5e340e9dd889c3884ce12dc9aee3b6af` |
| Audit, decoded SHA-256 | `fbec01eac93c22b1ef2c6ca299ea7a5544e05ff75d0627e6179e16eb920b1ffb` |
| Frozen new scope | 14 source spans, 436 words, 19 original literal-pointer observations, 13 original branch slots |
| Bank evidence | Eleven source applications, each certified for all 256 byte inputs: 2816 cases |
| Predecessor | Both successful modes from the [FPMessage initialization report](userclient_message_initialization_report.md) |

The [extractor](triage_evidence/recover_userclient_message_parser.py), [auditor](triage_evidence/audit_userclient_message_parser.py), [checks](triage_evidence/userclient_message_parser_checks.json.zst), [audit](triage_evidence/userclient_message_parser_audit.json.zst) and [delivery verifier](triage_evidence/verify_userclient_message_parser_delivery.py) reproduce this increment. Decoded archive hashes are distinct from compressed Git-blob hashes. Verification counts are recorded below after the final rebuild.

## State and control interfaces

F is the retained frame/SP, C the caller storage, S the workspace, I the retained input pointer, N the u32 extent, M the 128-byte message and H2 the second parser-container allocation. H/J/Z denote the earlier parsed container/node/protected record. H2 is separated from those earlier allocations and M by explicit ownership premises. SUCCESS is the raw phase value `0x31ae0066`; arithmetic is modular at the indicated u32/u64 width.

```text
source-built message M, retained I/N, caller tag fbb3f478
    |
    v
a636338: stage output alias M; reset cursor and scalar channels
    |
    v
a636404: typed allocation, descriptor site.FPTTLV / 16 B
    |
    +-- NULL --> a660b88 --> a661144 --> a6650a4 (pending failure)
    |
    +-- H2 --> initialize H2[0..15] to zero
                  |
                  v
              input-pointer/header gates
                  |
                  +-- I == 0 --> a661bfc (pending error)
                  |
                  +-- I != 0 --> a660dcc (pending read at I+6)

separate completion cuts; no record-parsing bridge asserted:
a660b2c --> a660b70: M[0..7] = H2 --> a660b88
    tag fbb3f478 --> a661144: raw status gate
        SUCCESS --> a661180: read M+60
            zero --> a6611e4
         nonzero --> a663c9c
```

Every shortened address in the diagram has prefix `0xfffffe000`. The two paths below the completion heading are source interface cuts with their own register premises. They are not connected to the pending input read by an executed record-decoding path.

| Contract | Source-derived value / exact emitter |
| --- | --- |
| MP1 | Entry `0xfffffe000a636338` copies C+0x718=M to C+0x170 at `0xfffffe000a636348`; this is the parser's output-cell address. |
| MP2 | C+0x18=I is copied to C+0x98 at `0xfffffe000a636358`; S+0xc8=N XOR SUCCESS is copied to S+0xb5c at `0xfffffe000a636354`. |
| MP3 | Entry zeroes cursor S+0xa10, sets S+4=SUCCESS, S+0xc60=`0x8f98c6acce5848ca`, and C+0x690=0. Stores occur at `0xfffffe000a63635c`, `360`, `374`, `378`. |
| MP4 | BLRAA at `0xfffffe000a636404` emits a typed allocation to `0xfffffe000c4ba154`, modifier `0xd0c8`, X0=`0xfffffe000847bb60`, nominal return `0xfffffe000a636408`. Descriptor name `site.FPTTLV`, signature `11`, flags u32 `0xe4`, size 16 B. |
| MP5 | Result H2, including NULL, is stored at C+0xb0 by `0xfffffe000a636428`. Source W19=0x4a2 and W20=0x68e give branch index 0x68e for nonnull, 0x693 for NULL. BRAA `0xfffffe000a6366a8`, modifier `0x1fcb`, selects `0xfffffe000a6366ac` or `0xfffffe000a660b88`. |
| MP6 | Nonnull STP at `0xfffffe000a6366c8` writes exactly two zero u64 words to H2. The composed N=14 path, cursor=0, then reaches the I gate. Nonnull I passes the ten-byte header gate and stops before LDRB `0xfffffe000a660dcc` at I+6. NULL I selects `0xfffffe000a661bfc`; no input byte is supplied in either profile. |
| MP7 | Independent exhaustion/publication cut stores H2 through C+0x170 at `0xfffffe000a660b70`, hence M+0=H2. The earlier caller used C+0x418 as that output destination. The current invocation's leading message word therefore has a source-established parser-result-pointer role on this cut. |
| MP8 | Tag tests at `0xfffffe000a660bb4`, `bc4`, `bd4` recognize `0x89f25623`, `0xfbb3f478`, `0x1830b7ce` in order. The new tag selects `0xfffffe000a661144`; the earlier tag takes the later fallthrough. Unknown tags select `0xfffffe000a636310`. These are internal caller tags, without an external-control provenance claim. |
| MP9 | At the new continuation, all raw status32 values select `0xfffffe000a661180` iff status=SUCCESS; otherwise `0xfffffe000a6650a4`. Emission at `0xfffffe000a66117c`, modifier `0xcb79`. The actual second-allocation NULL path has raw status `0xce515bb2` and reaches this failure target without publishing H2 into M. |
| MP10 | Independent success cut reads M+0x60 at `0xfffffe000a6611a0`. Zero selects `0xfffffe000a6611e4`, nonzero selects `0xfffffe000a663c9c`; BRAA at `0xfffffe000a6611e0`, modifier `0xeeda`. Actual source-built mode0 supplies zero; the other mode supplies one. Subsequent work at either target is unknown here. |

M+0 initially contains zero, as established by the initializer. The pending parser prefix does not change any message byte. The completion cut changes its first u64 word to H2. This establishes a phase-dependent field interpretation; it does not assign a generic structure signature, native ownership or final exported layout. The descriptor's `11` signature is retained as metadata without inferring allocator scanning semantics.

The second parser allocation has a distinct symbolic object identity. The same descriptor and code address used earlier do not identify the same allocation instance. Both modes preserve their actual source-built attributes and message fields during the new entry prefix. Every new store is checked against its exact C/S/F/M address or one of the two H2 words, and all source-selected pointer loads have address obligations. Four independent controller observations remain symbolic after the allocator return; eleven bank applications eliminate controller dependence at the selected indices. No controller value or missing workspace word is concretized.

## Completion-cut premises and evidence limits

The independent status cut supplies the common completion-register interface: X2=C, X4=S, X7=dispatch table, W1=`0x7795e642`, W3=`0x886a1ca3`, W22=`0x7795e3ce`, X28=`0xfffffe0007949dd0`; W23 is arbitrary u32. The caller tag remains the actual source-built `0xfbb3f478`. The separate exhaustion cut starts at `0xfffffe000a660b2c` with W12=0x69c and W30=SUCCESS. Original source derives SUCCESS, the publication branch index and the M+0 store. These inputs are stated cut premises; completed record parsing is not assumed or claimed as executed. The actual NULL-allocation proof instead follows the retained allocator-return state without replacing these registers.

Input custody remains unknown. The pending read address I+6 is established, but I's readable extent, nonwrapping/native mapping, byte values, nonaliasing, lifetime and stability across the earlier table/random/allocator calls are not established. The source-proof NULL-I profile is an admitted symbolic caller case, not a recovered native observation. No stable-input byte fixture is introduced. In particular, this report does not submit the earlier synthetic ADID record to a second parser and does not equate I with the protected Z allocation or table-selected payload.

All allocator returns are ordinary-return premises: saved registers and caller storage persist; X0..X18 and X30 are conservatively replaced with fresh values before X0 is assigned the declared result. PAC admission, actual provider side effects, allocator failure frequency and synchronization are unknown. H2/M nonaliasing is a model premise, not a native allocator execution result. The stopped continuous guest remains at `0xfffffe000a654ae4`.

| Port / emission class | New result |
| --- | --- |
| Incoming Mach endpoint / receive right | None established by this increment. |
| Outgoing Mach endpoint / send right or disposition | None established by this increment. |
| Mach-message emitter | None established by this increment. |
| Deeper local API | Typed allocation BLRAA `0xfffffe000a636404`; its original target is `0xfffffe000c4ba154`. |
| Private control transfers | Allocator-result BRAA `0xfffffe000a6366a8`, completion status BRAA `0xfffffe000a66117c`, message-flag BRAA `0xfffffe000a6611e0`. |

These private transfers extend the architectural interface inventory; they do not change the separate [Mach-port inventory](mach_ports_report.md).

## Verification and controls

All 209 new nonvacuous source-query partitions across 17 semantic contracts pass. Fresh-context rechecks of 217 preceding successful-message-profile partitions pass. All 436 captured words are covered in the new epoch, including four nonnull-container/input-pointer profiles; three source mutations are rejected. The aggregate lifted-instruction-instance count across new query partitions is 1452887 and includes retained predecessor construction. No native target call, input-content byte, continuous-guest extension or IDB mutation is added.

| Copied-source control | Rejected contract |
| --- | --- |
| NOP the output-alias STR at `0xfffffe000a636348` | C+0x170 no longer names M at the typed request. |
| Replace published X9 with XZR at `0xfffffe000a660b70` | M+0 is zero instead of the admitted nonnull H2. |
| Compare W23 with WZR at `0xfffffe000a661160` | SUCCESS selects the failure target. |

Every mutation has a satisfiable environment and a satisfiable normal-contract violation, checked before following its next target. The source is changed only in copied evidence. Original inputs and IDBs remain unchanged. New instruction coverage is counted in this parser epoch, independently of overlapping addresses visited by earlier models.

The selected prefix and fixed completion cuts take O(1) work and space. Evidence construction takes O(I+256R+C*I+query-DAG size) time/space, excluding SMT search, for I captured instruction words, R bank applications and C composed profiles. New QF_BV partitions have 60 s limits; retained queries use fresh contexts and 120 s limits. Each contract first has a SAT environment check; its complete disjunction of counterexamples is partitioned without dropping terms and every partition must be UNSAT. Query counts are static proof receipts, not native observations.

## Assumption register

| Assumption | Dependent contracts / stress test or falsification probe |
| --- | --- |
| MP-A1: Pinned source and prior receipt custody | MP1-MP10. Rehash original images, descriptors, chained slots, banks and dependencies; rebuild the preceding source state and re-solve its two successful message-profile contracts. |
| MP-A2: Correct retained frame/caller/allocation epochs | MP1-MP10. Compare source-built M/I/N/tag and saved roots; reject conflation of H with H2 or another caller's C+0x170 alias. |
| MP-A3: Writable separated nonwrapping declared allocations | MP3-MP7, MP9-MP10. SAT-check each allocation/input-pointer profile, check all store addresses and widths, and test allocation overlap against earlier private/image extents. I's content lifetime remains outside this premise. |
| MP-A4: Ordinary authenticated allocator return with caller-storage preservation | MP5-MP10. Verify target, modifier, link, SP and volatile havoc; native PAC/provider effects must be established independently before native conclusions. |
| MP-A5: Instruction lift and complete bank/source partitions | MP1-MP10. Rebuild every new source word, all 2816 byte cases, source-selected pointers and all counterexample partitions; require the three source controls to violate their normal contracts. |
| MP-A6: Explicit independent completion-register cuts | MP7-MP10. Inspect the recorded cut inputs and compare them with a future actual second-parser return. A mismatched live register/status epoch invalidates composition; the local source-cut relations remain separate. The actual NULL-allocation path does not depend on this cut premise. |
| MP-A7: Scope of original-input and status interpretation | MP6-MP10. Establish I's mapped bytes/lifetime and match a complete parser path before claiming successful parsing, stable two-pass bytes, a daemon packet layer or application-level meaning. Compare raw statuses within their caller phase. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Establish I's readable bytes and lifetime at `0xfffffe000a660dcc`, then compose actual record decoding/publication with the completion cuts, preserving H2/J2/data allocation epochs. |
| High | Follow `0xfffffe000a6650a4` from the actual second-allocation failure and determine message/container cleanup and final caller status custody. |
| High | Recover the downstream consumers at `0xfffffe000a6611e4` and `0xfffffe000a663c9c`; the current evidence assigns only a branch-control role to M+0x60. |
| Medium | Trace M+0 and M+8 through cleanup and publication to establish pointer ownership, replacement and the second leading word's role. |
| Medium | Join matching native daemon/IOKit buffer and allocation epochs to the existing static chain; a shared record shape or address is insufficient. |
| Low | Recover the deeper descriptor-signature interpretation only from its actual allocator consumers; signature `11` alone does not establish memory-scanning behavior. |

## Quality gates

- **QG1**: Pass. Factual source/interface contracts require no normative judgment.
- **QG2**: Pass. MP-A1 through MP-A7 register premises, dependent contracts and falsification probes.
- **QG3**: Pass for this increment. Actual second allocation/input frontier, failure dispatch and independent completion interfaces are covered. The overall investigation remains active.
- **QG4**: Pass. Byte extents, u32/u64 arithmetic, raw phase statuses, exact emitter addresses, source counts and bounded algorithms are reproducible.
- **QG5**: Pass. Actual entry prefixes, independent completion cuts, native allocation/PAC, I's content/lifetime and transport identity have explicit distinct scopes. Complete parsing remains unknown.
- **QG6**: Pass. Original words, descriptor/fixup records, exhaustive banks, solver receipts and source controls provide primary provenance.
- **QG7**: Pass. Impact-ranked continuation covers input custody, parsing completion, failure cleanup, mode consumers, pointer ownership and native transport pairing.

## Subsequent message-allocation failure evidence

The [message-failure report](userclient_message_failure_report.md) continues this report's actual allocation-NULL failure frontier through the message and attribute retirement requests, the zero output publication and preservation of raw status `0xce515bb2` at the pending original-container cleanup. All 126 new proof partitions, fourteen retained checks and three source mutation controls pass. The successful-completion cuts above remain unbridged to a complete second parse.
