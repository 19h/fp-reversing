# Continuous early logging to the configuration-object boundary

The retained nonzero `longterm` startup now crosses the unknown-DAIF boundary through one explicit, universally proved state transition, then executes original lock acquisition, timestamp formatting, diagnostic formatting, 47 authenticated callback edges, ring-byte stores, unlock and `_logwakeup` return. It stops before the four-byte configuration-object read at `0xfffffe000c48fc98`. The pointer is the inherited fixture sentinel `0xa5a5a5a5a5a5a5a5`; no executed source writer supplied a configuration object. The outer logger and `_printf` have not returned. Native console emission, timer completion and matched FairPlay IPC remain unknown. [LE-A1-LE-A7]

```text
original main + 1029 completed callbacks + first printf entry
  preserved frontier: MRS X8, DAIF
  one proved block transition; DAIF remains unknown
  _lck_ticket_lock -> preemption count 1
  timestamp wrapper -> original core -> 16 callback byte stores
  main formatter    -> original core -> 31 callback byte stores
  _lck_ticket_unlock -> preemption count 0
  _logwakeup -> return; post-format counter increment
  configuration slot -> inherited poisoned pointer
  STOP before LDR W8,[X8,#12]
```

Primary evidence: original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; [source capture](triage_evidence/kernel_early_logging_execution_checks.json.zst); [execution/proof audit](triage_evidence/kernel_early_logging_execution_audit.json.zst); [prior full-state join certificate](kernel_early_logging_contract_report.md); [unchanged pre-join continuous result](kernel_longterm_bootstrap_execution_report.md). No original input or IDB was changed. The original collection sufficed without IDA.

The prior nonzero-case frontier is preserved exactly: journal visits/reads/writes, models, logical effects, API/callback entries and returns, private RAM, global intervals, general registers, SP, NZCV, vectors, logical system state and all previously known page hashes. An additional 126976 B of original logical pages are admitted with exact original-page digests. Original pages containing forbidden paths retain digest references and exact hydration rather than changed target bytes. [LE-A1-LE-A3]

At `0xfffffe000c48faf4`, the journal records a proof-transition anchor for the original MRS word. It contracts the nine original words from `0xfffffe000c48faf8..0xfffffe000c48fb08` and `0xfffffe000c48f920..0xfffffe000c48f934`. The current u32 phase read is 3. The retained universal relation sets X8=`0xfffffe0007f34000`, X9=3, X24=1, NZCV=`0x80000000`, PC=`0xfffffe000c48f934`; all other general registers, SP, vector/system state and RAM remain unchanged. No DAIF value is read, seeded or substituted. The ordinary CPU memory journal does not claim the contracted phase read; that input is explicit in the proof receipt. Five retained source queries are rederived over the exact captured words. [LE-A2-LE-A4]

| Original callee | Entry / return visit indices | Result at its return |
| --- | --- | --- |
| `_lck_ticket_lock`, `0xfffffe000bd0af50` | 506833 / 506850 | X0=0; lock held |
| Timestamp wrapper, `0xfffffe000c300220` | 506878 / 508391 | X0=0; final character is space |
| Formatting core, `0xfffffe000bd146a0` | 506900 / 508386 | X0=16 |
| Main formatter, `0xfffffe000c3002f4` | 508396 / 510666 | X0=1; final character is LF |
| Formatting core, same address | 508414 / 510661 | X0=31 |
| `_lck_ticket_unlock`, `0xfffffe000bd0b348` | 510670 / 510691 | X0 retains lock pointer |
| `_logwakeup`, `0xfffffe000c2fdda8` | 510692 / 510705 | X0 retains lock pointer |

Indices count journal visits, including logical instruction effects and the one proof anchor; they are not native instruction-retirement counts. All seven calls retain their source stack frames and observed return PCs. The earlier outer `_printf` entry remains unfinished. [LE-A2-LE-A5]

The timestamp uses original format `[%5lu.%06u]: ` at `0xfffffe00070d803f`. In this private state, the retained logical counter is 4886718345, the produced frequency word is 24000000 and the adjacent divisor is 24. Original instructions produce `seconds=floor(counter/24000000)=203` and `fraction=floor((counter mod 24000000)/24)=613264`. The caller places those two values in the stack varargs area. Conditional on interpreting the counter as ticks and the frequency as Hz, the fractional display truncates to microseconds; native counter calibration and elapsed time are unknown.

The main formatter receives the original `Longterm timer threshold: %llu ms\n` format and the original u64 vararg 1. The independently reconstructed combined byte stream is exactly 47 B:

```text
[  203.613264]: Longterm timer threshold: 1 ms\n
```

Here `\n` denotes one byte 0x0a. Both core invocations use the logical character callback `0xfffffe000c2ffae0`, context record at the wrapper's SP+8, W4=10 and W5=1. Source PACIA/BLRAA custody uses modifier 0xae56. All 47 character entries observe thread preemption count 1, so the original callback branch bypasses its DAIF read. Hardware PAC and native delivery remain unproved. [LE-A3-LE-A6]

| Storage | Exact checked effect |
| --- | --- |
| Ring header `0xfffffe000caa3070` +4/+8 | Capacity 131072 B retained; u32 index 0 -> 47 |
| Header +0x10 | Original format-8 logical pointer to `0xfffffe000cb2fe28` retained |
| Ring `0xfffffe000cb2fe28` | Bytes 0..46 equal the exact stream; remaining 131025 B retained |
| Callback byte store `0xfffffe000c2ffdd4` | 47 original one-byte writes, in order to ring+0 through ring+46 |
| Newline byte `0xfffffe000caab110` | Final value 1 from original formatter result/store |
| Lock `0xfffffe000cad0108` +8/+0xc | Ticket word 0x00000144 -> 0x01000144 while held -> 0x01010144 on unlock; owner cleared |
| Current thread +0x1c8 | Original increment 0 -> 1, then original decrement 1 -> 0 |
| Counter `0xfffffe000cbe9e58` | Earlier entry increment preserved |
| Counter `0xfffffe000cbe9ec0` | Original post-format LDADD at `0xfffffe000c48fc70` increments 0 -> 1 |
| Counter `0xfffffe000cbe9eb0` | Retained; its later increment is not reached |

The full global-state oracle compares 381986 B, including unchanged padding/tails and all retained earlier global intervals. The current zero CPU ordinal selects these first-bank addresses. `_logwakeup` reads its readiness byte at `0xfffffe000cb9bf61`; it is zero and the helper returns before its separate DAIF-read path. The callback's nonzero-preemption gate and the wakeup readiness gate therefore have distinct reasons for bypassing their DAIF reads. No native console operation or Mach-message emission is inferred from these storage writes. [LE-A3-LE-A6]

At the new frontier, original instructions load `0xfffffe0007f8b528` and test the pointer before the pending four-byte read at pointer+12. The retained pointer is nonzero because an earlier declared fixture poisoned the 0x200 B mutable interval beginning `0xfffffe0007f8b500`. No recorded source store covers the slot. The original collection contains eight zero bytes at the slot, but substituting them here would change the inherited state premise. A configuration object, its producer and its native lifetime remain unknown. This stop diagnoses an artificial-state limitation; it is not evidence of a native invalid-pointer failure. [LE-A1-LE-A3, LE-A7]

Validation receipts: 510723 journal visits at 5516 distinct PCs; 3909 visits added after the preserved boundary, including one proof anchor; nine contracted original words; 47 original callback/ring-store pairs; seven observed inner returns; 478 new semantic assertions; 1029 retained startup callback returns. The fresh independent replay checks 131797 reads / 803944 B, 91520 writes / 694980 B, final 1048576 B private RAM, 1208320 B of mapped original pages, all general/vector registers and logical system state. The inherited three no-RAM leaf contracts remain unchanged. New system-register values, callback-result models, call-frame epochs and native executions are all zero.

Two full-startup controls use identical initial fields and replace an original word with NOP. Removing the ring-byte store at `0xfffffe000c2ffdd4` is rejected at the ring interval. Removing the callback newline store at `0xfffffe000c2ffd3c` is rejected at the merged interval containing the newline flag. Both still reach the same pending configuration read. The full producer reproduces the controls; delivery rederives the source queries, formulas and preserved frontier while checking the immutable producer replay/control receipts. [LE-A4-LE-A6]

Capture contains 200 original functions, 16695 words / 66780 B, preserves all 195 prior bodies and adds five bodies. Five new mutable intervals admit 131113 B before original main: newline byte, ring header, ring bytes and two counter words. These are original logical initialized-data premises, not native allocations.

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_early_logging_execution_checks.json` | `39a7167f9c1b7ba56ac5d6288682b9f8f36f42eb4c55911a2b5663926bc2d44a` |
| `kernel_early_logging_execution_audit.json` | `a1a6fca236005179e68cb25fdf2d75d57f5ab4c8d7032e4c2ec04c2927efad85` |

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| LE-A1: Pinned original collection defines source/fixups | All source and storage claims | Rebuild 200 bodies, timestamp string and ring pointer; reject image drift |
| LE-A2: Prior private startup defines the pre-join state | Continuity and frontier claims | Exact journal, RAM, register and known-page comparison against the prior nonzero case |
| LE-A3: Original initialized records and declared fixtures bound the environment | Ring, gates, counters and configuration limitation | Preserve original logical pages, track every writer and identify the poisoned configuration root; native loader state unknown |
| LE-A4: Early-phase source relation admits the projected block | Post-DAIF continuation | Rederive five retained source obligations, check phase/source words and replay the explicit transition; supply no DAIF value |
| LE-A5: Logical PAC/system and three retained leaf contracts bound execution | Callback and return custody | Check source operands, frame/register state, exact system map and independent full replay; native authentication unknown |
| LE-A6: Concrete formatting/storage admission defines this finite case | Exact stream, lock lifecycle and output fields | Independent integer/text/whole-memory formulas and two full-startup NOP controls |
| LE-A7: Bootstrap logging does not establish native FairPlay transport | Mach limits and outstanding work | Pair daemon/provider/kernel epochs, rights, payloads, statuses and PCs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Recover the configuration-slot producer/environment | Replace the poisoned root with source-produced custody in a separately declared, verified continuation |
| High | Finish outer logging and nonzero timer initialization | Original printf return, threshold conversion and callback publication |
| High | Execute later CPU/Mach startup and pair FairPlay IPC | Actual right emission/custody across matching daemon/provider/kernel epochs |
| Medium | Broaden logging admission and contention | Later phases, alternate CPU banks, ring wrap and ticket slow paths |
| Medium | Qualify native callback sinks and wakeup consumers | Actual sink identity, scheduling, lifecycle and hardware authentication |

**QG1**: Factual technical analysis; no normative content required. **QG2**: LE-A1-LE-A7 list dependencies and falsification probes. **QG3**: Continuous proof join, inner-call ABI, exact stream/storage, synchronization, new external-state boundary and Mach limits covered for this increment; full goal active. **QG4**: Widths, byte extents, integer arithmetic, conditional time units and journal/contracted-word counts explicit. Journal/source/RAM work is linear; interval sorting O(N log N); SMT search separate. **QG5**: Inner/outer returns, logical/native execution, original zero bytes/poisoned fixture and independent DAIF gates distinguished. **QG6**: Original bytes/fixups, rederived source proofs, exact prior preservation, independent formulas/replay and rejected source controls retained. **QG7**: Impact-ranked bounded continuation included.

Subsequent [collection-header publication analysis](kernel_collection_header_publication_report.md) identifies the configuration slot as the primary kernel-collection header bank and recovers its original boot publisher/getter contract. That separate increment preserves this case and its poisoned fixture exactly. Intervening boot fixups and the earlier registration helper's effects remain prerequisites for a new source-produced startup state.
