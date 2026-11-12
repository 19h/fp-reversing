# CoreFP source-produced caller record through the cold constructor

Original caller `0x2e4280` now reaches the cold constructor through its own metadata allocation, VM-buffer construction and ingress/root record stores. Five independently replayed configurations retain operation `0xc1f7`, mode `0x114e4318` and decoded scalar `0x0484c46a`. They decode/free the certificate, construct the seed and environmental tuple, complete two predicates and stop before the optional-input read at `0x8eba44`. No root record, source PC or parent frame is patched.

This closes a source-continuity gap between the [VM lifecycle](corefp_vm_lifecycle_report.md) and [earlier cold constructor](corefp_cold_seed_report.md). Certificate allocation/decode/free was already present in all nine earlier zero-mode cold profiles. These runs are not a mode-only causal experiment: caller frames, source-produced objects and address-keyed records also differ. Native admission, successful processing, selector/holder initialization and daemon/kext pairing remain unknown. The full goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_caller_cold.py), [checks archive](triage_evidence/corefp_caller_cold_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_caller_cold.py), [audit archive](triage_evidence/corefp_caller_cold_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_caller_cold_publication.py) retain the increment. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Source addresses are preferred-base-zero offsets. Offsets are hexadecimal; extents use bytes (B). Original files suffice for these claims; no new live IDA corroboration is asserted.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CC1 | Pinned images, compiler bounds, fixups/imports and frozen contracts identify the source. All results depend on these inputs. | Compare 22 complete source spans totaling 116392 B, every executed byte and authenticated-edge row. Preserve the three supplied inputs. |
| CC2 | The declared aligned entry, tag, scalar and backed private referents describe the analyzed caller configurations. Coherent source continuity depends on them. | Independently reconstruct all five initial CPU/touched-RAM states. Replay every source transition from `0x2e4280`; check all final touched pages. Native admission is unknown. |
| CC3 | Allocation, VM, once, lock, bootstrap, PAC and sequential CASAL effects retain their frozen private contracts. Conditional control/data flow depends on them. | Check argument/effect journals and caller-register clobber. Route certificate `_free` only at original callsite `0x8e9fa8`; metadata free remains owned by the VM lifecycle model. No native concurrency or right identity is inferred. |
| CC4 | Entropy words and clock effects are declared environmental inputs. Seed/tuple results depend on them. | Independently check all 624 seed words per case, the later state-word mix, both predicates and the tuple. Clock-error controls write no scratch bytes; alternate stack fill exposes retained input. Fresh arm64e syntax-only SDK assertions check the clock layout. |
| CC5 | The selector byte retains original image value zero in these executions. Selected optional-pointer provenance depends on that value. | Verify its exact read at image+`0x1d44409`, absence of source writes to the cell, the equality-to-1 branch contract and original dispatch row. Native value, writers and lifecycle remain unknown. |
| CC6 | Execution ends before the unresolved read; private backing remains available for inspection. Negative observations are bounded by this frontier. | Check that `0x8eba44` is absent from executed visits, address4 is never read, no request1200 builder/transport executes and no caller cleanup/return occurs. These are not native fault or leak observations. |

## Coherent source flow [CC1-CC6]

```text
0x2e4280 caller
  -> 32 B metadata constructor -> declared VM allocation, 4096 B
  -> source-publish descriptor and stage 20 B encoded VM prefix
  -> 0x2e490c -> 0x5f4584 ingress -> adapter -> 0x8e81c8 root
  -> original cold once callbacks / declared matching-pointer lock
  -> primary bootstrap 1102 -> fallback bootstrap 0, name fixture0x5034
  -> allocate760 B -> source decode/shift756 B DER -> certificate free
  -> declared sequential CASAL -> selector0 -> source optional pointer :=0
  -> restore token -> entropy / 624-word seed / clock / entropy tuple
  -> original predicate0x1abbe0 -> original predicate0x439734
  -> load optional pointer0; calculate address0+4
  -> STOP before original0x8eba44 reads that address
```

The root record remains at `0x62017ea0`; its output-cell pointer is `0x62017f58`, and its metadata pointer is `0x64000800`. Metadata describes VM backing `0x66000000`, with both encoded extent words decoding to 4096 B under their established contracts. The original caller stages the same 20 B prefix recovered previously. Scalar16 changes only prefix byte11 from `0x61` to `0x71`; zero reads touch the patterned second referent in that case. No higher-level scalar/length meaning is established.

The certificate model returns a distinct 760 B allocation at `0x64000400`. Source XOR/shift processing leaves the 756 B DER followed by the retained final four bytes; independent comparison checks all 760 bytes at free. DER SHA-256 is `a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de`. Certificate free is reached before the first entropy return. Metadata and VM cleanup are not reached before the stop.

| Frame/data location | Earlier direct-root cold fixture | Coherent upstream caller |
| --- | --- | --- |
| Root record | Declared `0x63000800` | Source-produced `0x62017ea0` |
| Decoded mode | `0` | `0x114e4318` |
| Root SP | `0x62016190` | `0x62015f50` |
| Context `C=SP+0x1340` | `0x620174d0` | `0x62017290` |
| Tuple `T=C+0x6f0` | `0x62017bc0` | `0x62017980` |
| Predicate record | `0x62017f38` | `0x62017cf8` |
| Certificate allocate/free | Already present | Present |
| Optional-input stop | Before `0x8eba44` | Before `0x8eba44` |

The frame-dependent addresses shift by -576 B (`-0x240`). Earlier receipts are pinned for this comparison; their nine executions are not newly replayed. The five new complete caller prefixes are freshly replayed independently.

## Context, environment and explicit optional-pointer definition [CC1-CC6]

The source-written context prefix is nine bytes `00 66 64 70 63 00 00 00 01`. The following 119 bytes receive no source store anywhere in the executed caller-to-frontier prefix. They retain `0xa5`, or `0x5a` in the alternate-fill control. Supplying the actual caller-produced descriptor and nonzero mode therefore does not supply that suffix on these paths. This is a private source-prefix observation; native context readiness is unknown.

The tuple's four u32 words are `[third entropy, scratch tv_usec, low32(scratch tv_sec), second entropy]`. Declared entropy returns are `0x12345678`, `0x9abcdef0`, `0x0fedcba9`; the first seeds the 624-word recurrence. Successful clock input supplies signed seconds `0x0123456789abcdef` and microseconds654321. Clock status `0xffffffff` causes no model write, so both consumed scratch words retain the stack fill. Source still reaches the same frontier. Each seed expansion has 623 loop iterations, followed by one independently checked state-word update. Predicate outputs are `0x245a` and `0x252a` at their separately recovered record offsets.

| Original site / source | Checked definition or use |
| --- | --- |
| `0x8ea890`, `MOV X13,#0` | Explicit zero definition, independent of initial X13 |
| Following 22 executed instructions | No X13/W13 definition and no API return before the pointer store |
| `0x8ea8ac/0x8ea8b0` | Saved pointer -> image+`0x1d44409` -> selector byte0 |
| `0x8ea8e8` | IA diversity `0x1414`, original slot `0x1cc62a0` -> `0x8eb7a4` |
| `0x8eb7a4` | Single source u64 store of zero to `SP+0x438` |
| `0x8eba3c` | Load that same pointer cell; X11 already equals4 |
| `0x8eba40` | X12 := X13+X11 =0+4 |
| `0x8eba44` | Next u32 read; stopped before execution |

The unrelated `MOV X13,X28` at `0x8eb798` is not the reaching definition on this branch. The selected edge enters `0x8eb7a4` directly. Independent replay plus the intervening register-definition scan establishes the actual chain. Eight freshly rechecked frozen symbolic obligations cover the seed/tuple and selector/optional-gate contracts; they do not prove whole-function behavior for arbitrary environments.

## Ports, ownership and validation [CC1-CC6]

| Interface / original callsite | Observed private effect / bound |
| --- | --- |
| `_vm_allocate`, `0x1ca598` | Task fixture `0x4201`; request4096 B; declared success writes its output address |
| `_bootstrap_look_up`, `0x1ce1bc` | Source name `com.apple.fpsd`; declared return1102 |
| `_bootstrap_look_up`, `0x1ce448` | Source name `com.apple.fairplayd`; declared success writes name fixture `0x5034` to image+`0x1d44448` |
| Lookup handoff | Returns words `[0x5034,0]`; secondary cache remains0 |
| Request1200 / metadata request1203 | Zero transactions or daemon children on this prefix |
| New Mach send/receive or port transfer | None established; no `_mach_msg` is reached |
| Lock/token at frontier | Held-lock fixture `0x64000000`; token restored to `0x5d96`; no unlock reached |
| Caller VM/metadata release | No deallocation, descriptor free, overwrite loop or outer return reached |

These scalar port fixtures identify source argument/data flow, not native receive objects or rights. Retained VM/metadata backing at a deliberately incomplete execution does not establish a leak.

| Profile | Stack fill | Clock result | Scalar | Frontier |
| --- | --- | --- | --- | --- |
| `caller_cold` | `0xa5` |0 |0 | Before optional read |
| `caller_cold_clobber` | `0xa5` |0 |0 | Same, caller registers clobbered at declared API returns |
| `caller_clock_error` | `0xa5` | `0xffffffff`, no write |0 | Same |
| `caller_payload_16` | `0xa5` |0 |16 | Same, patterned referent unread |
| `caller_stack_5a_clock_error` | `0x5a` | `0xffffffff`, no write |0 | Same, suffix/scratch retain alternate fill |

Independent replay checks five initial CPU frames, 1884160 B of initial touched RAM and the same final extent; 161155 original visits, 25930 reads, 17715 writes, 9255 PAC models and 105 frozen/declared effects. It checks 55 caller,30 VM,40 constructor and40 data-flow checkpoints; ten certificate lifecycle events; 3120 independently calculated seed words; eight UNSAT obligations and63 exact original instructions. Arm64e syntax-only SDK assertions pass. No native code/API/IPC or IDB mutation executes.

Replay/enumeration has conservative bound `O(C*(B+P*F+V*J+R+624))` time/space, including frozen per-page fixup and reaching-load scans. C denotes profiles, B source bytes, P touched pages, F fixups, V visits, J retained journals and R retained state. The execution limit is100000 visits/profile; SMT cost is separate, capped at30 s/query.

| Impact | Remaining question / discriminating evidence |
| --- | --- |
| High | Establish actual writers and lifecycle of selector image+`0x1d44409` and preparation holder image+`0x1d32e18`. A caller-produced descriptor alone does not discharge those premises. |
| High | Recover source-produced context suffix and valid optional-input preparation, preserving record/stack epochs. No unresolved read was executed in this increment. |
| High | Resolve native caller admission and successful processing through cleanup, then pair endpoint, request/result and ownership with daemon/kext evidence in one matched epoch. |
| Medium | Trace further consumers/writers of the encoded20 B prefix and distinct descriptor extent words. Scalar propagation here supplies no general format or field equivalence. |

**QG1** passes: factual technical analysis. **QG2** passes: CC1-CC6 register assumptions and probes. **QG3** passes for this increment; the full objective remains incomplete. **QG4** passes: byte extents, u32/u64 arithmetic, frame displacement and bounded costs are explicit. **QG5** passes: prior certificate evidence, mode/context changes, model ownership and unexecuted reads remain distinct. **QG6** passes: original bytes, fixup rows, complete independent replay and independent byte/seed/predicate oracles support the claims. **QG7** passes: impact-ranked continuation covers environment, input production, admission, successful processing and cross-level pairing.
