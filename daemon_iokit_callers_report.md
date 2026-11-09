# Daemon initialization record callers and result consumers

Two source adapters construct the 8 B selector/result record consumed by `0x1004601D0` and read its result after return. Under their declared table/bank/context premises, calls at `0x1003134D4` and `0x100AFEDD4` reach that entry through original slot `0x1010A0520`. Their consumers test record+4 against `0x8B3DC651`, which is algebraically a decoded-zero predicate. The return register W0 does not select either continuation. Native upstream reachability, the producers of the caller context roots, and startup-specific ownership remain unknown. [CB1-CB12]

[Source contracts and census](triage_evidence/daemon_iokit_callers_contracts.json), [retained compositions](triage_evidence/daemon_iokit_callers_profiles.json), [independent checks](triage_evidence/daemon_iokit_callers_checks.json), [source proofs](triage_evidence/daemon_iokit_callers_proofs.json), [current IDB windows](triage_evidence/daemon_iokit_callers_live_ida.json), [current xrefs](triage_evidence/daemon_iokit_callers_live_xrefs.json), [preservation](triage_evidence/daemon_iokit_callers_preservation.json) and [scoped gates](triage_evidence/daemon_iokit_callers_quality_gates.json) retain evidence. The [error-normalization report](daemon_iokit_errors_report.md) and [synchronization report](daemon_iokit_sync_report.md) supply the preceding callee contracts. The full interface objective remains active.

```text
caller context roots [upstream producers unknown]
  -> construct encoded selector at R+0; R+4 remains unknown
  -> X0=R -> original slot A0520 -> entry 0x1004601D0
       -> selected 5784/09 acquisition and IOKit path
       -> metadata queries or normalized IOKit error
       -> common cleanup -> source writes raw result at R+4 -> return
  -> caller reads R+4
       raw == 8B3DC651 -> zero-result continuation
       raw != 8B3DC651 -> nonzero-result continuation
  -> STOP before selected continuation body
```

These are conditional local interfaces. The investigation has not established that these fragments execute during startup, nor that all other indirect callers have been found. Addresses are preferred file virtual addresses. B denotes bytes. u32/u64 arithmetic is modular; R is an 8-byte-aligned record pointer.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| CB1 | Pinned daemon images and current IDB identify this build | Source addresses, tables and source comparisons | Rehash originals; compare 92 IDB rows covering 416 original bytes |
| CB2 | Entry is at one of the two caller fragments with its declared phase/context | Selected caller/callee composition | Trace actual incoming branches and source producers before assigning native or startup reachability |
| CB3 | Caller313 has right/left banks at caller SP+0x190/+0x198 and table in X25; callerAF has left/right in X14/X15 and table in X27 plus saved SP+0x2B8 | Conditional target 0x1004601D0 | Recover original writers; change roots to challenge target selection; the roots are explicit fixtures here |
| CB4 | Controller pointers are readable and source table data retains original values | Bank/dispatch selection | Exhaust all 256 bank inputs; distinguish controller values from bank-root provenance and runtime table mutation |
| CB5 | R and caller/callee frames are disjoint, writable where required, and R mod 8=0 | Key equivalence, unknown-result preservation and output publication | Quantify aligned R in source proofs; vary two placements and audit every byte epoch; native aliasing remains unknown |
| CB6 | Frozen IOKit/pthread summaries and primary/fallback/once fixtures apply | Full callee execution and returning cleanup | Preserve source sequences and formal arguments; native API/synchronization effects remain unknown |
| CB7 | Initialization phase is 0x5784 with initial state09 | Composed selected initialization | Prove caller phase preimages; other entry/state branches remain outside this composition |
| CB8 | Callee returns and its source guard/PAC premises apply | Caller resumption and saved integer context | Check X19-X29/SP restoration in all compositions; hardware PAC and abnormal returns remain unknown |
| CB9 | Decoded result is algebraically raw XOR0x8B3DC651 | Zero-result predicate | Prove the source comparison for every u32 result; upstream semantic error names remain unknown |
| CB10 | The census covers one exact adjacent instruction pattern in original __text | 23 candidates and bounded search coverage | Search computed modifiers, other registers/forms and other code regions separately; discriminator equality does not establish a target |
| CB11 | IDB xrefs and LC_FUNCTION_STARTS are static database/storage evidence | Current reference and envelope context | Compare original fixups; missing xrefs do not exclude obfuscated callers, and broad envelopes do not establish semantic owners |
| CB12 | Stop before the four selected caller continuations | Scope of recovered control flow | Trace each continuation and the upstream root writers before claiming complete surrounding behavior |

## Caller record and phase contracts

The minimum established selected ABI is X0=R, input selector u32 at R+0, and raw result u32 at R+4. The caller initially writes only the selector. All 40 composed runs retain an unknown mask on the result field before entering the callee; the callee's original source produces the result. No caller-result fixture supplies its value. These two consumers ignore W0; the global return type and other callers' use of W0 remain unknown. [CB2,CB5,CB8]

Let `K(R)=u32((low32(R) XOR0x966E5812)*0x592E2F77)`. The callee decodes phase as `u32(MEM32[R]-K(R))`.

| Local interface | Caller313 | CallerAF |
| --- | --- | --- |
| Source fragment | 0x100313428..0x10031350C | 0x100AFED54..0x100AFEE10 |
| Record / X0 | Caller FP-0x98 | Caller FP-0x98 |
| Source selector word | `u32(K(R)+W21-0xED9)` | `u32(K(R)+W22+0x131C)` |
| Unique phase for decoded 0x5784 | W21=0x665D | W22=0x4468 |
| Internal call PC | 0x1003134D4 | 0x100AFEDD4 |
| Source call target | Slot0x1010A0520 ->0x1004601D0 | Same slot and target |
| Call authentication metadata | IA0x0A74, address diversity0 | Same metadata |
| Source result read | 0x1003134D8, u32 at FP-0x94 | 0x100AFEDE0, u32 at FP-0x94 |

The caller313 key is an obfuscated OR/AND expression equivalent to K(R) under R mod8=0; callerAF uses the direct XOR form. Source proofs establish the selector normal forms first. Separate algebraic obligations establish unique phase preimages from those proved normal forms; the proof metadata records these lemma dependencies. [CB5,CB7]

The bank targets depend on explicit caller-context premises:

| Caller | Left bank | Right bank | Key / additive / constant | Selected index |
| --- | --- | --- | --- | --- |
| 313 | 0x100FC4230 from saved caller SP+0x198 | 0x101031FA0 from saved caller SP+0x190 | 0xE4 /0xCC69 /0x5D | 0xCCC6 |
| AF | 0x100FC4130 in X14 | 0x101031EA0 in X15 | 0x4E /0xCBC7 /0xFF | 0xCCC6 |

Both selected indices address original slot0x1010A0520 in table0x101039EF0. All 256 possible byte-bank inputs are checked for each rule. Source prefix execution and these exhaustive rules establish the conditional call edges; they do not establish who initialized the saved banks/table/registers. [CB3,CB4]

## Result consumers and continuation routes

| Consumer | Raw result predicate | Index | Original slot | Target / IA discriminator |
| --- | --- | --- | --- | --- |
| 313 | raw==0x8B3DC651 | 0x6915 | 0x10106E798 | 0x10040DBA0 /0x817A |
| 313 | raw!=0x8B3DC651 | 0x665D | 0x10106D1D8 | 0x100624B74 /0x817A |
| AF | raw==0x8B3DC651 | 0x4FA3 | 0x101061C08 | 0x100B12828 /0xFDD6 |
| AF | raw!=0x8B3DC651 | 0x4468 | 0x10105C230 | 0x100B01974 /0xFDD6 |

The tests are equivalent to `(raw XOR0x8B3DC651)==0` for every u32 value. The source restores/reads caller context around these tests, and the selected continuation bodies remain unexecuted. No success/failure semantics beyond the zero/nonzero result partition is assigned to those bodies. [CB8,CB9,CB12]

The source-controlled selector and source-written result share one 8 B record, but have distinct codecs. The selector key depends on low32(R) and multiplication; the result comparison uses the fixed XOR mask. The record's presence does not establish an externally supplied Mach/XPC field or an external control origin. [CB2,CB5,CB9]

## Metadata errors and the outer result channel

Six added cases vary whether query22, query23, or both return nonzero status0xE00002C7, at each caller. All six still produce raw0x8B3DC651 and select the zero-result continuation. They retain the preceding source behavior that clears rejected query words and updates the encoded cache. This demonstrates that the outer result field does not distinguish these metadata-query errors from the returning zero-result path in the selected model. It does not establish native query behavior or the later continuation's handling of the cached metadata. [CB6,CB9,CB12]

The 40 profiles have 12 zero-result and28 nonzero-result continuations: six/fourteen at each caller. All original callee source instruction/edge sequences remain embedded, with matching formal IOKit arguments and declared outputs. Caller input pointers and saved registers differ from earlier entry fixtures, so earlier raw stack/read/write epochs are not equated with the new context. Every new epoch is reconstructed independently. [CB5,CB6]

## Census and evidence boundaries

An original-__text scan finds 23 aligned instances of bytes `914E81D211093FD7`, the adjacent sequence `MOV X17,#0x0A74; BLRAA X8,X17`. Four original authenticated slots share this discriminator:

| Original slot | Target |
| --- | --- |
| 0x1010A0400 | 0x10043AC5C |
| 0x1010A0448 | 0x100ABEBE4 |
| 0x1010A0468 | 0x100412EBC |
| 0x1010A0520 | 0x1004601D0 |

Thus the literal discriminator is insufficient to label any candidate as an initialization caller. Only the two declared contexts receive conditional caller edges in this increment. The remaining21 pattern sites are unresolved by this census; that statement does not exclude them from being callers under additional context. [CB3,CB10]

The current IDB has a data reference from slot0x1010A0520 to entry0x1004601D0 and no direct code xref at that entry. Source/fixup recovery is therefore necessary for the indirect interfaces. Original LC_FUNCTION_STARTS envelopes are retained as storage context only. For example, the envelope containing caller313 spans multiple IDB fragments and is not treated as one recovered semantic caller. Startup ownership and the full incoming call graph remain unknown. [CB2,CB11]

## Verification and preservation

Twelve original/simplified source proof pairs cover71 lifted instructions across declared phases. Forty full caller/callee compositions contain59356 source instruction visits; all undergo independent byte/epoch reconstruction, and12 are freshly replayed. All40 preserve the callee's integer callee-saved registers and SP, produce result bytes through source stores, and stop before the selected caller continuation. The checks include120 timed caller-record snapshots and40 initially unknown result cells.

Twenty-three census windows plus two selected caller spans, two exhaustive banks,86 independently decoded original fixups, four continuation routes, four preserved current xref queries and92 IDB rows covering416 B provide separate provenance. The existing API/primitive summaries remain unchanged; no new external model executes.

The private caller SP is C, the tested caller FP is C+0x600, and the initialization frame SP is F=C-0x130. This disjoint layout is an explicit fixture, not an inferred native frame arrangement. Saved context words at C+0x274 and C+0x1B8 are supplied only for source-restored values consumed before the stopping boundary; their native producers and meaning remain unknown. [CB2,CB3,CB5]

Preservation checks cover2617 preceding artifacts, with2611 unchanged and exactly six designated existing report/index edits. All three supplied original inputs retain their sizes and hashes. Native daemon, IOKit, pthread, Mach and hardware PAC operations do not execute.

## Bounded continuation opportunities

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Writers of caller313 SP+0x190/+0x198 and X25; callerAF X14/X15/X27 and saved SP+0x2B8 | Replace local root premises with source-established upstream context |
| High | Incoming branches and phase producers for0x100313428 and0x100AFED54 | Native/startup trigger and high-level caller roles |
| High | Four selected continuation bodies | Actual consequences of the zero/nonzero result partition and metadata-error cases |
| High | Primary/fallback lock-cell writers | Initialization, replacement and lifetime of synchronization objects |
| Medium | Remaining21 literal-pattern sites plus computed-modifier forms | Broader indirect caller coverage without discriminator-based misclassification |
| Medium | Original cache readers after zero-result continuation | Whether rejected metadata is retried, ignored or interpreted elsewhere |

No additional incoming/outgoing Mach port, right disposition or emission site is established. This increment adds a daemon-local record/call/result interface surrounding the previously recovered IOKit interaction.

## Quality gates and reproduction

QG1: factual analysis. QG2: CB1-CB12 include dependencies and falsification probes. QG3: bounded census and two conditional caller/consumer interfaces covered; full objective incomplete. QG4: 8 B record,4 B fields,u32/u64 arithmetic,alignment,unique preimages and complexity explicit. QG5: root premises versus producers,pattern versus target,zero result versus metadata status,record versus W0,local fragment versus semantic owner,and algebraic versus native semantics are distinguished. QG6: original bytes/fixups,IDB,census,source proofs and finite compositions have separate provenance. QG7: bounded continuations have impact labels. Scoped gates are issued after checks and preservation pass.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_iokit_callers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_iokit_callers.py
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_iokit_callers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_callers.py
```
