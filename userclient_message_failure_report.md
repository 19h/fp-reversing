# FPMessage parser-allocation failure and retirement unwind

The actual second-parser allocation-NULL path retires the source-built 128-byte FPMessage and 112-byte FPMessageAttr, clears their owning cells, returns a zero message output and preserves raw status `0xce515bb2` through the next cleanup request for the original parsed container. The two retirement returns are explicit ordinary-return premises. No native free, PAC admission, completed outer dispatcher or successful second parse is established.

This increment composes the [message-parser failure frontier](userclient_message_parser_report.md) with original source. It introduces no input-content bytes and needs no live IDA access. F denotes the retained frame/SP; C caller storage; S workspace; M the message; A its attribute; H/J/Z the earlier parsed container/node/protected record. The second parser allocation is NULL, so no second container is published into M. SUCCESS is the phase value `0x31ae0066`; ERROR below is `0xce515bb2`.

| Evidence | Identity / coverage |
| --- | --- |
| Collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Checks, decoded SHA-256 | `9f728757b0c37f2a84729651cb2c3dc9bb75282685b783e958beedbc7b15390d` |
| Audit, decoded SHA-256 | `768141cad04eca672907e136c9548e67284cdf86bffc89d8c68d63c31282a007` |
| Original source | 25 spans / 413 instruction words; four literal-pointer observations / 21 branch slots |
| Prefix custody | Three additional cells per predecessor, 30 predecessors: 90 cells / 480 B |
| Bank custody | Four source applications, all 256 byte inputs each: 1024 cases |

The [extractor](triage_evidence/recover_userclient_message_failure.py), [auditor](triage_evidence/audit_userclient_message_failure.py), [checks](triage_evidence/userclient_message_failure_checks.json.zst), [audit](triage_evidence/userclient_message_failure_audit.json.zst) and [publication verifier](triage_evidence/verify_userclient_message_failure_delivery.py) reproduce the source and receipts. Archive Git-blob hashes differ from these decoded hashes.

## Actual unwind and interfaces

```text
second parser allocation NULL; W23=ce515bb2
  |
  v
a6650a4: save raw error in S+d98; stage M in C+1d0
  |
  v
message destructor: visit M+8 and M+0, both NULL
  |                no nested container/node retirement
  v
a660a20: IOFreeTypeImpl(message descriptor, M)
  |      ordinary return assumed; later M dereferences excluded
  v
clear C+1d0, clear C+788; restore error from S+d98
  |
  v
a665144: write zero to retained output C+360
  |
  v
outer callback: preserve error in S+ab8
  |
  v
a656b24: IOFreeTypeImpl(attribute descriptor, A)
  |      ordinary return assumed; later A dereferences excluded
  v
clear C+1b0; restore error from S+ab8; save it in S+1c
  |
  v
pending original-container cleanup at a66229c; X19=C+418
```

All shortened addresses in the diagram have prefix `0xfffffe000`. This is an actual source-state composition under the recorded allocator/provider/retirement premises, rather than the independent successful-completion cuts in the preceding report.

| Contract | Exact source interface / consequence |
| --- | --- |
| MF1 | `0xfffffe000a6650c4` saves W23=ERROR in S+0xd98 before cleanup. `0xfffffe000a66511c` stages M from C+0x788 into C+0x1d0. F+0x6d0 supplies the source-proven alias C+0x1d0. |
| MF2 | The generic wrapper at `0xfffffe000a6621e4` retains its caller-specific callback in C+0x610, cleanup-cell address in C+0x38, and object pointer in C+0x78. First callback is `0xfffffe000a66223c`; the later zero-output invocation instead retains `0xfffffe000a641b3c`. |
| MF3 | The message path invokes the common FPTTLV destructor through the M+8 and M+0 pointer cells. Loads at `0xfffffe000a6604c8` return zero in both cases. The calls are private control transfers, with no deeper retirement call for either NULL child. Source frame word F+0x9ac=`0xf2b6cffb` determines the second-child continuation. |
| MF4 | BLRAA `0xfffffe000a660a20` emits `_IOFreeTypeImpl` at `0xfffffe000c4ba368`, modifier `0x4d6a`, X0=`0xfffffe000847b360`, X1=M, nominal return `0xfffffe000a660a24`. Its descriptor is `site.FPMessage`, signature `1122222222222222`, flags u32 `0x64`, size 128 B. |
| MF5 | After the qualified return, `0xfffffe000a660a84` clears C+0x1d0. `0xfffffe000a662250` clears C+0x788 and `0xfffffe000a662254` restores ERROR from S+0xd98. `0xfffffe000a665144` copies the cleared C+0x788 through C+0x430=C+0x360. Thus the factory output is zero, not the retired message pointer. |
| MF6 | The retained outer callback is `0xfffffe000a636d34`. Its failure path stores ERROR at S+0xab8 (`0xfffffe000a641b1c`), then invokes the generic wrapper on the now-zero C+0x360 cell. That wrapper skips message destruction and returns via its new callback. |
| MF7 | BLRAA `0xfffffe000a656b24` emits `_IOFreeTypeImpl` with modifier `0x4d6a`, X0=`0xfffffe000847b920`, X1=A, nominal return `0xfffffe000a656b28`. Descriptor: `site.FPMessageAttr`, empty signature, flags u32 `0x6c`, size 112 B. F+0x678, already established by the attribute constructor, supplies owning-cell address C+0x1b0. STR `0xfffffe000a656b58` clears that cell after return. |
| MF8 | F+0x688=`0x67da8ba5` participates in the post-attribute status dispatch. Source restores ERROR from S+0xab8, stores it at S+0x1c (`0xfffffe000a641c38`) and requests the original-container cleanup through `0xfffffe000a66229c`, modifier `0xb23e`, X19=C+0x418. H/J/Z remain the earlier live model objects at this pending boundary; their destruction is not executed here. |

The two retirement descriptors are separate source objects from the allocation descriptors. Their complete normalized 64-byte contents match their corresponding allocation descriptors, including size, signature and flags; original pointer encodings are independently retained. This establishes descriptor compatibility in the pinned source and does not establish native ownership or allocator admission.

All four controller observations are independent symbolic u32 values. Four complete byte-bank identities select the two retirement targets and descriptors without concretizing those observations. Every source branch target, modifier, private-cell store, pointer load and retirement argument has a source obligation. The nine previously unknown private values from earlier increments remain symbolic. Additional frame cells are reconstructed from original prefix stores rather than guessed from the desired path.

After each retirement request's modeled ordinary return, every subsequent source load and store receives an exclusion obligation for the retired object's complete extent. No subsequent dereference of M or A is admitted. Pointer values can remain in other private cells; this does not assert erasure of every alias or observation of native freed storage. The 128 B and 112 B extents sum to 240 B of described object storage; this is not a claim about native allocator accounting, wiping or reclamation effects.

Raw ERROR is preserved through two independent saves/restores and the next caller phase. Temporary W23=SUCCESS during cleanup is a local phase value, not recovery from the failure. Similarly, zero output denotes this composed failure result; it does not imply that allocation never occurred.

## Verification, ports and boundaries

All 126 nonvacuous source-query partitions across six semantic contracts pass for both actual source-built modes. Fourteen preceding NULL-allocation-to-caller-failure partitions are re-solved in fresh contexts. All 413 words are covered in this unwind epoch. Source construction and query partitions account for 928030 lifted instruction instances; that aggregate includes retained predecessor construction. Both modes have exactly the two recorded retirement interfaces. No native target call, input-content byte, continuous-guest extension or IDB mutation is added.

| Copied-source mutation | Satisfiable violation |
| --- | --- |
| Save WZR instead of W23 at `0xfffffe000a6650c4` | Restored W23 differs from ERROR; control stops before following that changed status. |
| NOP owning-cell clear at `0xfffffe000a660a84` | C+0x1d0 still contains M after the unwind. |
| NOP attribute-cell clear at `0xfffffe000a656b58` | C+0x1b0 still contains A at the pending next cleanup request. |

All three controls have satisfiable environments and violate their normal contracts. The latter two retain the normal control/status path, so the oracles check memory effects rather than only final targets. Mutations exist only in copied source evidence.

| Architectural class | New evidence |
| --- | --- |
| Deeper API emissions | Two `_IOFreeTypeImpl` requests at `0xfffffe000a660a20` and `0xfffffe000a656b24`; exact typed descriptor, object, modifier and link recorded. |
| Private callbacks/output | Callback-cell reuse, restored raw status, cleared message/attribute ownership cells and zero factory output. |
| Incoming/outgoing Mach ports, rights or dispositions | None newly established. |
| Mach-message emission | None newly established. The [Mach-port inventory](mach_ports_report.md) retains its separate transport evidence. |

The source prefix and fixed empty-child unwind take O(1) work/space. Evidence construction takes O(B+I+256R+C*W+query-DAG size), excluding SMT search. New QF_BV partitions have 60 s limits; prior queries use 120 s limits in fresh contexts. Each semantic contract has a SAT premise check and complete UNSAT counterexample partitions. Query counts are proof receipts, not native events.

## Assumption register

| Assumption | Dependent contracts / stress test or falsification probe |
| --- | --- |
| MF-A1: Pinned source and retained receipt identities | MF1-MF8. Rehash both images, original words/fixups/banks/descriptors and dependencies; rebuild the prior source state and re-solve its fourteen failure-frontier partitions. |
| MF-A2: Same caller/frame/object epochs | MF1-MF8. Reconstruct the 90 additional cells from original stores; compare M/A/H/J/Z, callback cells and output aliases. Another invocation or intervening store invalidates this composition. |
| MF-A3: Declared nonwrapping separated private allocations | MF1-MF8. SAT-check both modes, every address/width and retired-extent exclusion. Verify real native allocation/ownership independently before native conclusions. |
| MF-A4: Ordinary retirement returns preserve saved registers and surviving caller storage | MF5-MF8. Check both exact targets, modifiers, descriptors, object arguments, links and SP; havoc X0..X18/X30. Do not preserve or read retired-object contents after either return. Native free/PAC/provider effects remain unknown. |
| MF-A5: Source lift and complete bank/counterexample partitions | MF1-MF8. Rebuild all 413 words, 1024 byte cases, branch slots, source queries and three mutations. Check repeated common-destructor blocks in their distinct callback epochs. |
| MF-A6: Actual second-parser allocation NULL and source-built M leading zeros | MF1-MF8. Verify the retained failure edge/status and both zero child pointers. A successful second parse or a different M child population requires different destruction paths. |
| MF-A7: Phase-qualified raw statuses and pending final cleanup interpretation | MF5-MF8. Compare S+0xd98, S+0xab8, S+0x1c, temporary W23 and zero output. Follow the remaining H/J/Z cleanup and original dispatcher return before claiming full operation completion or a native daemon result. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Compose the pending original-container cleanup from X19=C+0x418 with H/J/Z retirement and the actual outer status/output return. |
| High | Establish the successful second parser's input-byte custody and complete parsing, then compare nonzero-child message destruction with this empty-child failure case. |
| High | Inspect deeper typed-retirement validation and descriptor admission before assigning native object ownership or free effects to these requests. |
| Medium | Trace remaining opaque aliases to M/A in surviving caller storage; cleared owning/output cells do not establish complete alias erasure. |
| Medium | Correlate matching native daemon/IOKit input, allocation and cleanup epochs; these source contracts establish no new Mach transaction identity. |
| Low | Recover allocator signature semantics from actual deeper consumers rather than inferring them from matching descriptor strings. |

## Quality gates

- **QG1**: Pass. Factual source contracts require no normative judgment.
- **QG2**: Pass. MF-A1 through MF-A7 identify dependent claims and falsification probes.
- **QG3**: Pass for this increment. The actual failure, both retirement interfaces/returns, cleared output and next cleanup request are covered. The full interface investigation remains active.
- **QG4**: Pass. u32/u64 widths, raw statuses, B extents, source counts, modular arithmetic and bounded algorithms are explicit and reproducible.
- **QG5**: Pass. Descriptor compatibility, requested retirement, modeled return, native effects and remaining original-container cleanup have distinct scopes. Input bytes and successful parsing remain unknown.
- **QG6**: Pass. Original source/fixups/descriptors, prefix stores, exhaustive banks, solver receipts and copied-source controls supply primary provenance.
- **QG7**: Pass. Impact-ranked continuation covers remaining cleanup/return, successful parser custody, deeper allocator admission, aliases and native transport pairing.

## Subsequent failure fallback evidence

The [failure-fallback report](userclient_failure_fallback_report.md) continues this report's pending original-container cleanup through record/node/container retirement and the next exact-size allocation. The failure then either requests context/workspace retirement on NULL or protects the original 14-byte input into a new buffer and requests a staged-parser allocation on non-NULL. Raw status, local phase constants and the separate return-decoding cut retain distinct scopes; the original failure does not immediately establish an outer return.
