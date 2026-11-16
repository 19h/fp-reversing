# Early logging state join and formatter interfaces

The original nine-word logging slice has a complete architectural state relation independent of DAIF whenever the unsigned startup phase is below 19. Five nonvacuous source queries and 96 independent CPU source-cut cases qualify that relation and the formatter/newline interfaces. Original symbols identify the lock pair and `_logwakeup`; the formatter and its authenticated character callback remain unnamed. This increment does not advance the retained continuous bootstrap trace: it still stops before `MRS X8, DAIF` at `0xfffffe000c48faf4`. Native logging, synchronization and matched daemon/FairPlayIOKit transactions remain unknown. [EL-A1-EL-A7]

```text
retained continuous trace: STOP before MRS DAIF
  MRS X8, DAIF -> arbitrary symbolic X8
  nine original words -> full state relation at 0xfffffe000c48f934
    phase < 19: X24=1, X8=page base, X9=phase, NZCV=0x80000000
    later phases: selector can depend on DAIF
  source continuation, not yet continuous execution:
    admission -> ticket lock -> optional timestamp formatting
    main formatter -> authenticated character callback
    newline byte -> unlock -> logwakeup -> counter banks
```

Primary evidence is the original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, the [source capture](triage_evidence/kernel_early_logging_contract_checks.json.zst), the [proof and CPU-cut audit](triage_evidence/kernel_early_logging_contract_audit.json.zst), and the unchanged [continuous timer/logging frontier](kernel_longterm_bootstrap_execution_report.md). The normalized FairPlayIOKit input remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection bytes suffice; no IDA query or mutation was needed.

| Address | Name / established role | Provenance and limit |
| --- | --- | --- |
| `0xfffffe000c48f880` | Logging body | Original source; partial prior execution |
| `0xfffffe000bd0af50` | `_lck_ticket_lock` | Exact original nlist symbol; 24 words |
| `0xfffffe000bd0b348` | `_lck_ticket_unlock` | Exact original nlist symbol; 28 words |
| `0xfffffe000c3002f4` | Format/character-callback wrapper | Recovered role; 47 words; no exact nlist name |
| `0xfffffe000bd146a0` | Shared formatting core | Recovered role from wrapper ABI; 858 words captured; full format language unknown |
| `0xfffffe000c2ffae0` | Character-output callback | Recovered role; 239 words; native sink delivery unknown |
| `0xfffffe000c2fdda8` | `_logwakeup` | Exact original nlist symbol; 84 words |
| `0xfffffe000c300220` | Conditional timestamp-formatting call target | Caller instructions captured; callee body not captured here |

The join comprises `0xfffffe000c48faf8..0xfffffe000c48fb08`, followed by its original branch to `0xfffffe000c48f920..0xfffffe000c48f934`. These are nine executed words, 36 B total, not the intervening linear address range. Let `p` be the u32 phase read from `0xfffffe0007f8b5f0`, and `d` any u64 value that the preceding MRS could place in X8. Define `b = (((~u32(d)) & 0x1c0) != 0)`. The final state is:

| State component | Exact relation |
| --- | --- |
| X8 | `0xfffffe0007f34000` |
| X9 | Zero-extended `p` |
| X24 | `b` if unsigned `p >= 19`, otherwise 1; zero-extended u32 |
| Other 28 general registers, including LR | Unchanged |
| SP | Unchanged |
| PC | `0xfffffe000c48f934` |
| NZCV | Flags of 32-bit subtraction `p - 19`; for every `p < 19`, exactly `0x80000000` |
| RAM | Unchanged; one four-byte read at the phase cell |
| Vector and system-register state | Untouched by the nine decoded instructions |

The source queries check all general-register invariants, SP, PC and linked edges. The source contains no store or vector/system instruction; symbolic memory cells are unchanged. NZCV is derived from the final decoded CMP operands using fixed-width subtraction flags, then checked against the independent CPU result. The architectural MRS premise supplies an arbitrary value, not an inferred native DAIF. Flags are overwritten by the slice. DAIF is never read or seeded in the CPU cuts, which start after MRS. Hardware exceptions, concurrent phase mutation and microarchitectural effects are outside this relation. [EL-A1-EL-A5]

The prior audit records the last phase publication as a four-byte store of 3 at `0xfffffe000c6303b4`, source-visit index 506268, before the retained frontier after 506814 visits. Its system map has no DAIF entry. That makes the early-phase premise applicable to the private retained state, subject to no intervening external writer. The original journal and frontier remain unchanged; the new evidence records their digest and exact boundary rather than replaying them as a replacement epoch. [EL-A2-EL-A4]

| Source interface | Register / storage contract | Qualification |
| --- | --- | --- |
| Logger call at `0xfffffe000c48fc38` | X0=original format in X28; X1=varargs pointer loaded from SP+0x78; same pointer saved at SP+0x1b0 | Source query; callee target `0xfffffe000c3002f4` |
| Formatter local record | 24 B at local SP+8; flags u32 initially 0x10; pointer-sized field at +8 initially zero; newline byte at +0x10 initially zero | Original stores; 0x30 B frame |
| Formatter calls at `0xfffffe000c300364` / `0xfffffe000c300398` | X0/X1 retain format/varargs; X2=logical callback `0xfffffe000c2ffae0`; X3=record; W4=10; W5=1 | Original call setup; PACIA X16,X17 uses modifier 0xae56; hardware authentication unknown |
| Nonzero W2 wrapper route | Flags can change from 0x10 to 0x11 when byte `0xfffffe0007f8b643` bit 0 is set or byte `0xfffffe000caac260` equals 0x20; invokes callback with W0=10 after formatting | Source control flow; full callback effects unexecuted |
| Callback newline store at `0xfffffe000c2ffd3c` | Record+0x10 receives 1 exactly when full W21 equals 10, otherwise 0 | Universal source query; character originates from callback X0 |
| Formatter return at `0xfffffe000c3003a0` | W0=record newline byte AND 1 | Universal source query |
| Logger store at `0xfffffe000c48fc3c` | Low byte of W0 written to `0xfffffe000caab110` | Original store; no completed diagnostic claimed |

The callback has distinct source-gated sinks: a signed-byte helper call at `0xfffffe000c2ffd98`, a one-byte request at `0xfffffe000c2ffd14`, pointer output at `0xfffffe000c2ffd24` and early ring-buffer output at `0xfffffe000c2ffdd4`. The ring arm filters zero, CR and DEL before its indexed byte store. It loads a signed u32 index from header+8, increments that u32, writes through header+0x10 plus the old sign-extended index, then resets the index when the incremented signed value is at least the capacity at header+4. Admission, capacity safety, native sink identity and delivery are not proved by these isolated source observations. These addresses are character-storage/call sites, not established Mach-port emitters. [EL-A1, EL-A5-EL-A7]

| Initialized storage / pointer slot | Width | Original value / recovered use |
| --- | ---: | --- |
| `0xfffffe000caab10c` | 4 B | `0xffffffff`; source sentinel selects the direct formatter branch after lock return |
| `0xfffffe000caab110` | 1 B | 1; newline/timestamp gate |
| `0xfffffe000caab118` | 8 B | Format-8 pointer to header `0xfffffe000caa3070` |
| Header +4 / +8 | 4 B each | Capacity 131072 B; index 0; private initialized-data premise |
| `0xfffffe000caab078` | 8 B | Format-8 bank pointer to `0xfffffe000cbe9e58`; prior logging-entry increment observed |
| `0xfffffe000caab0e0` | 8 B | Format-8 bank pointer to `0xfffffe000cbe9ec0`; later LDADD at `0xfffffe000c48fc70` |
| `0xfffffe000caab0d0` | 8 B | Format-8 bank pointer to `0xfffffe000cbe9eb0`; later LDADD at `0xfffffe000c48fd0c` |

Each later counter address adds the u16 CPU ordinal shifted left 14 to the pointer target. Those increments follow formatter/unlock/wakeup source control and have not been reached by the retained trace. The original phase cell is initially zero in the collection; the retained startup produced phase 3. These are different epochs. Likewise, the initialized newline=1 and capacity=131072 values imply a timestamp-formatting prerequisite on that source path: the body compares capacity against 4096 before the call at `0xfffffe000c48fc24`. Actual live values at that call remain unknown. [EL-A2-EL-A4, EL-A6]

The ticket lock at `0xfffffe000cad0108` is shared by the logger and `_logwakeup`. Acquisition increments thread+0x1c8, uses LDADDA on lock+8 and records thread+0x518 at lock+0xc on the uncontended path. Unlock clears that owner word, increments the byte at lock+0xa with STLURB, decrements thread+0x1c8 and can select preemption handling through the CPU record when the count reaches zero. Trace/slow paths and native memory-order behavior remain unexecuted here. `_logwakeup` also contains a separately gated DAIF read at `0xfffffe000c2fddf4`; proving the early join does not remove that later uncertainty. [EL-A1, EL-A5-EL-A6]

Validation: seven original bodies, 1752 words / 7008 B; nine raw records; four independently reconstructed format-8 pointers. Five nonvacuous QF_AUFBV queries cover 27 instruction instances at 18 distinct PCs with 22 linked edges. The CPU matrix uses phases 0..18,19,20,0x7fffffff,0x80000000,0xffffffff and four explicit X8 proxies per phase: 0,0x1c0,0xffffffffffffffff,0x123456789abcdef0. All 96 cases pass full GPR/SP/PC/NZCV/vector/RAM and exact read/write checks over 864 visits. NOP substitutions at `0xfffffe000c48f92c` and `0xfffffe000c48f930` are rejected. These are finite independent checks of the universal source relation, not native execution or new continuous-bootstrap visits.

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_early_logging_contract_checks.json` | `e37398bcf79b5f39ddd1a13a189615da486ecf83a7d87917eebf2567febd6b07` |
| `kernel_early_logging_contract_audit.json` | `dd2d5e8df62c7feb2648da62a85cb5a90e93daec7fe8da3e8a35a4bd9257cfe2` |

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EL-A1: Pinned collection defines source, symbols and fixups | All source/name/layout claims | Rebuild source capture, SHA-256 and exact symbol records; reject image drift |
| EL-A2: Prior audit defines the retained phase/frontier | Applicability to the existing private case | Check audit digest, exact boundary and last phase writer; preserve original journal |
| EL-A3: No external phase writer intervenes across the nine-word slice | Early-phase application | Instrument phase writes/concurrency; otherwise retain this conditional premise |
| EL-A4: Architectural MRS supplies arbitrary X8 and does not alter other state | Projection across unknown DAIF | Vary every DAIF bit symbolically; reject unconditional extension at phase >=19 |
| EL-A5: Supported instruction semantics match the decoded words | State and local ABI proofs | Independent CPU controls, full flags and memory checks, two NOP mutations |
| EL-A6: Initialized records/fixups are premises for later source paths | Timestamp, storage, synchronization context | Recover actual producers and state at each call; execute timestamp and lock paths without substituted returns |
| EL-A7: Source calls/storage do not establish native transport correspondence | Mach and FairPlay limits | Pair native daemon/provider/kext epochs, rights, payloads, statuses and PCs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Integrate the full join relation into continuous execution | Preserve prior journal, record a proved block transition, supply no DAIF value |
| High | Recover the timestamp wrapper and execute the logging prerequisite chain | Original lock return, timestamp/core callback storage, diagnostic return and nonzero timer conversion |
| High | Continue CPU and later Mach startup, then pair a FairPlay transaction | Actual right custody and emission sites across matching epochs |
| Medium | Resolve later `_logwakeup` DAIF admission | Original readiness/count/phase producers and conditional gate proof |
| Medium | Follow callback sink and ring-header producers | Concrete sink identity, valid index/capacity, lifecycle and ownership |

**QG1**: Factual technical analysis; no normative content required. **QG2**: EL-A1-EL-A7 include dependencies and falsification probes. **QG3**: Full join, local formatter/callback ABI, synchronization names, initialized storage and Mach limits covered for this increment; full goal active. **QG4**: u8/u16/u32/u64 widths, byte extents, modular/sign behavior and conditional dimensional interpretation explicit. Capture/query construction is linear in source/query DAG size; CPU work is linear in cases times state bytes; SMT complexity separate. **QG5**: Source cuts, symbolic MRS projection, unchanged continuous frontier and native execution separated; phase-19, signed-wrap and timestamp boundaries explicit. **QG6**: Original bytes/symbols/fixups, retained audit custody, rebuilt source queries and CPU controls retained. **QG7**: Impact-ranked bounded continuation included.
