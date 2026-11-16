# Post-lock timer bootstrap and nonzero-option logging frontier

Original main now executes the post-lock initializer `0xfffffe000bd64ea4` in three private startup cases. Defaults and explicit `longterm=0` return to main at `0xfffffe000c639e40`, before the CPU initializer call. `longterm=1` enters original `_printf` and its logging path, increments an original counter and stops before `MRS X8, DAIF` at `0xfffffe000c48faf4`: DAIF is unknown in the retained execution envelope. No DAIF value, logging return or timer result is substituted. A separate source proof establishes that the early-phase logging selector is independent of every DAIF value; concrete execution has not crossed that join. All cases retain 1029 completed startup callbacks. Native execution, later startup and matched FairPlay IPC remain unknown. [LT1-LT7]

```text
preserved original main + 1029 callback returns
  BL 0xfffffe000bd64ea4
    parse u32 longterm
      absent / zero -> disabled threshold UINT64_MAX
        -> original list, lock and callback publication
        -> original timeout-record conversions
        -> return to main; STOP before CPU initializer
      nonzero -> u32 option * 1000000 in u64
        -> _printf(format, source-labelled milliseconds)
        -> original logging counter increment
        -> STOP before reading unestablished DAIF
        -> conversion / callback publication not yet reached
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| LT1 | The original 311-word helper has a boot-option branch and a timer/list/callback publication contract | LT-A1-LT-A4 |
| LT2 | Default and explicit-zero cases execute the helper and return to original main | LT-A1-LT-A5 |
| LT3 | Exact-width timeout conversions and preserved fields are checked independently | LT-A1-LT-A5 |
| LT4 | Four reciprocal bounds establish exact unsigned quotients over stated integer domains | LT-A1, LT-A5 |
| LT5 | Nonzero option custody reaches original printf/logging, the concrete DAIF frontier and a universally checked early-phase join | LT-A1-LT-A6 |
| LT6 | Prior published state, fresh replay and two source mutations support the finite continuation | LT-A1-LT-A6 |
| LT7 | CPU initialization, later Mach startup and FairPlay message/right correspondence remain unknown | LT-A1-LT-A7 |

Primary evidence: original kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; [source capture](triage_evidence/kernel_longterm_bootstrap_execution_checks.json.zst); [execution audit](triage_evidence/kernel_longterm_bootstrap_execution_audit.json.zst); and the preserved [lock-bootstrap result](kernel_lock_bootstrap_execution_report.md). The normalized FairPlayIOKit input remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. These are original-byte/private-execution findings, not native timing or scheduling observations. No IDB was mutated.

| Address | Recovered role | Evidence boundary |
| --- | --- | --- |
| `0xfffffe000c639e3c` | Original main BL to timer initializer | Executed in all three cases |
| `0xfffffe000bd64ea4..0xfffffe000bd65380` | Timer initializer, 311 words / 1244 B | Returns in default/zero cases; partial in nonzero case |
| `0xfffffe000bd65380` | Published callback entry, BTI then branch to `0xfffffe000bd65388` | Pointer published in completed cases; callback unexecuted |
| `0xfffffe000bd1573c` | Original nlist `_printf` | Nonzero path entered; no return claimed |
| `0xfffffe000bd15774` | Variadic logging/formatting wrapper | Nonzero path entered |
| `0xfffffe000c490108` | Logging wrapper, reads retained system value and forwards arguments | Nonzero path entered |
| `0xfffffe000c48f880` | Logging body, original per-CPU counter and admission path | Stops before DAIF read at +0x274 |
| `0xfffffe000bd0af50` | Ticket-style lock acquisition source | Captured; unexecuted in these cases |
| `0xfffffe000be780f8` | Next CPU initializer source | Captured; unexecuted |

The initializer itself has no exact nlist name. The `longterm` key at `0xfffffe00070b0587` and original format string at `0xfffffe0007052b8b` provide semantic evidence. The latter labels its `%llu` value as milliseconds. The source parses four bytes, multiplies a nonzero u32 option by 1000000 into u64, divides that value by 1000000 for the diagnostic, then converts it to the produced timebase only after both printing calls. A present zero and an absent option retain the u64 all-ones disabled sentinel. The nonzero case stops before either printing call has returned; its threshold remains the pre-conversion value 1000000. [LT1-LT2, LT5]

| Storage | Width / extent | Completed-case publication |
| --- | --- | --- |
| `0xfffffe000ca92100` | 8 B | Disabled sentinel UINT64_MAX for absent/zero |
| `0xfffffe000ca920a8` | Initialized state within 0x110 B admitted extent | Self-list at +0/+8; cleared linkage; ticket-form tag/flags; all-ones fields; callback record and embedded 0x11 lock state |
| State +0xd8 | 8 B | Logical pointer `0xfffffe000bd65380`, signed by source PACIA X16,X17 with X17=0x73d8 |
| State +0xe0 | 8 B | Callback context: state base `0xfffffe000ca920a8` |
| `0xfffffe000cb7d0b8` | 8 B | Published state base |
| `0xfffffe000cadd708` | 8 B | Exact u32 frequency quotient by 100000; produced frequency 24000000 yields 240 |
| `0xfffffe000cb2a4b4` | 0xac B | Converted/copied timeout record with original padding retained |
| `0xfffffe000cadd6e8` | 8 B | Convert u64 at `0xfffffe000ca92088` after multiplication by 1000 modulo 2^64 |
| `0xfffffe000cb7d0c8` | 8 B | Same operation for u64 at `0xfffffe000ca92090` |

The callback pointer is logical PAC custody only; hardware authentication and execution of its target remain unknown. The callback entry is not a Mach-port emitter in the evidence collected here. [LT1-LT3, LT7]

Let `f` be the produced u32 frequency word at `0xfffffe000ca8c000`, and `x` an unsigned source timeout. The recovered arithmetic contract is:

```text
q = floor(x / 1000000000)
r = x - q * 1000000000
ticks64 = (q*f + floor((r*f) / 1000000000)) mod 2^64
ticks32 = ticks64 mod 2^32
```

Here `r < 1000000000` and `f <= 2^32-1`, so `r*f < 2^62`; the remainder product fits u64. The whole-second product/addition remains modular u64. The first three source fields are u32 and the source stores their results as u32. The remaining converted fields use u64 stores. This describes integer behavior; physical units depend on interpreting `f` as a frequency in Hz. Under that interpretation, nanosecond inputs produce ticks. The diagnostic explicitly supplies the millisecond label for `longterm`; it does not prove native timer behavior. [LT3-LT4]

The timeout record source is `0xfffffe000ca93e08`; destination is `0xfffffe000cb2a4b4`. All offsets below are hexadecimal bytes. They form a packed layout, including deliberately unaligned u64 destinations and a preserved four-byte gap at destination +0x20. [LT3]

| Source offset(s) | Width each | Destination offset(s) | Operation |
| --- | ---: | --- | --- |
| 0,4,8 | 4 B | 0,4,8 | Convert, then truncate to u32 |
| c | 16 B | c | Copy unchanged |
| 1c | 4 B | 1c | Copy unchanged |
| 20,28,30,38,40 | 8 B | 24,2c,34,3c,44 | Convert as u64 |
| 48 | 16 B | 4c | Copy unchanged |
| 58 | 8 B | 5c | Copy unchanged |
| 60,68,70,78,80,88 | 8 B | 64,6c,74,7c,84,8c | Convert as u64 |
| 90 | 16 B | 94 | Copy unchanged |
| a0 | 8 B | a4 | Copy unchanged |

Four exact reciprocal bounds are retained in the audit. For `n=q*D+r`, `0<=r<D`, and `C*D=2^s+E`, the conditions `0<=E<D` and `n_max*E<2^s` ensure `floor(n*C/2^s)=floor(n/D)` for every admitted unsigned input. Pre-shifted divisors divide the original divisor exactly, so floor composition is exact. [LT4]

| Quotient | Input domain | C | s | E | Strict worst-error numerator bound |
| --- | --- | ---: | ---: | ---: | --- |
| u32 / 1000000000 | 0 through 2^32-1 | 18446744074 | 64 | 290448384 | 1247466310165601280 < 2^64 |
| u64 / 1000000000 | n=u64>>9, D=1953125 | 19342813113834067 | 75 | 399807 | 14404565249760926754369 < 2^75 |
| u32 / 100000 | n=u32>>5, D=3125 | 175921861 | 39 | 1737 | 233136191799 < 2^39 |
| u64 / 1000000 | 0 through 2^64-1 | 4835703278458516699 | 82 | 175296 | 3233640449144989559903040 < 2^82 |

Five nonvacuous QF_AUFBV source queries cover present-option scaling/zero selection, the diagnostic reciprocal machine expression, the frequency multiplier, the final shift and the early-phase logging join. Their combined coverage is 27 instruction instances at 27 distinct PCs, with 22 linked-edge obligations. These queries do not prove the entire logging or initializer implementation universally. Exact field formulas, all output bytes and fresh original CPU replay bound the completed cases separately. [LT3-LT6]

For `longterm=1`, `_printf` receives the original format pointer, u64 variadic value 1 at SP and return PC `0xfffffe000bd64f70`. The logging wrapper reads the retained logical register `s3_4_c15_c10_6`, and the body increments bank-0 counter `0xfffffe000cbe9e58` via LDADD. Its format-8 bank pointer originates at `0xfffffe000caab078`; CPU ordinal zero selects the first 0x4000 B bank. The logging admission path reaches DAIF before the captured ticket-lock acquisition helper. Neither a lock acquisition nor console/message emission is claimed. The timer's converted record and callback publication remain unreached in this case. [LT5]

The DAIF uncertainty does not determine the early-phase branch outcome. Linked original cuts `0xfffffe000c48faf8..0xfffffe000c48fb08` and `0xfffffe000c48f920..0xfffffe000c48f934` compute a DAIF-dependent Boolean, then select W24=1 whenever the u32 phase word is below 19. At the join, W9 equals that phase word and X8 has been overwritten with `0xfffffe0007f34000`. The proof covers every u64 DAIF value with a nonvacuous phase premise. The nine-instruction slice has no memory writes; its only memory input is the phase word. Current phase 3 satisfies the premise. This establishes a source-supported continuation opportunity without claiming that concrete execution crossed the read or that native DAIF was recovered. [LT5-LT6]

Validation receipts: **1472250 source visits, 5483 distinct executed PCs, 201 static checks, 40 timer-semantic assertions covering 1428 output bytes, three complete journal replays and two rejected source mutations**. Capture contains 195 functions, 16244 words / 64976 B, preserving all 188 prior bodies and adding seven. The default entry checkpoint exactly preserves the previously published lock-bootstrap journal, prior mutable intervals, private RAM, all registers/vectors/system state and every known mapped-page hash. Additional original pages and storage are explicit premises. Original pages containing forbidden paths use pinned logical-page digest references and exact hydration. The controls replace callback/context publication at `0xfffffe000bd65030` and frequency publication at `0xfffffe000bd650bc` with NOP; identical initial states and the same returned boundary must be rejected by the independent formulas. New architectural register values, callback-result models, native executions and call-frame epochs are all zero. [LT6]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_longterm_bootstrap_execution_checks.json` | `785c05b0bdfa098e792e8c1c6e56579a0304b54c3857b76857ff37713ea3f5e7` |
| `kernel_longterm_bootstrap_execution_audit.json` | `be5fde2e0f53519f66b2a76faeede082e0072f932a4a94956469933669aea379` |

| Assumption | Dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| LT-A1: Pinned collection and normalized input define this case | LT1-LT7 | Recheck SHA-256, original source bytes, symbols and raw records; reject image drift |
| LT-A2: Logical initialized storage and format-8 pointers define private pre-entry state | LT1-LT7 | Verify original page digests and bank pointer; native loader/lifetime unproved |
| LT-A3: Published lock-bootstrap continuation is preserved | LT1-LT7 | Exact default-prefix journals, registers, RAM and known page hashes; no replacement epoch |
| LT-A4: Retained logical PAC/system and three leaf contracts bound execution | LT1-LT7 | Recheck every effect and clobber; introduce no DAIF value; native authentication unproved |
| LT-A5: Exact-width arithmetic and three configurations define concrete formula admission | LT2-LT6 | Reciprocal bounds, per-byte output/copy/padding comparison, full parser contracts, replay and mutations |
| LT-A6: Concrete logging remains partial while its early-phase join is proved | LT5-LT7 | Implement/check the source-supported join; recover native DAIF where later phases make it relevant; verify actual logger publication |
| LT-A7: Bootstrap does not establish FairPlay IPC correspondence | LT7 | Pair daemon/user-client/provider/kernel epochs, rights, payloads, statuses and PCs; unknown |

| Impact | Next discriminating work | Evidence sought |
| --- | --- | --- |
| High | Continue logging using the proven early-phase join | Join execution, lock ownership, diagnostic return and nonzero timer conversion; native DAIF remains unknown |
| High | Execute the next CPU initializer and later startup | CPU ownership/register prerequisites and phase-14 MIG startup |
| High | Pair a daemon/provider/kernel transaction | Actual Mach-right custody, emission sites and FairPlay relevance |
| Medium | Follow the published callback and timeout consumers | Actual scheduling, units, ownership and lifecycle |
| Medium | Recover loader/fixup production | Replace logical initialized-data premises with original producer evidence |

**QG1**: Factual technical analysis; no normative content required. **QG2**: LT-A1-LT-A7 list dependencies and falsification probes. **QG3**: Finite timer/logging control, option custody, arithmetic, layouts, callback and Mach limits covered; full goal active. **QG4**: Widths, extents, integer bounds, modular operations and conditional dimensions explicit. Source/journal/RAM work is linear; interval sorting O(N log N); SMT search separate. **QG5**: Completed/partial cases, disabled/raw/converted values, original names/recovered roles and logical/native PAC distinguished. **QG6**: Original bytes, integer calculations, source queries, independent formulas/replay, prefix preservation and controls retained. **QG7**: Impact-ranked continuation included. Gates apply to this finite increment; native timing and matched FairPlay IPC remain unknown.

Continuation evidence: the [early logging contract report](kernel_early_logging_contract_report.md) strengthens the selector proof to a complete state relation and recovers the formatter/callback and named lock/wakeup interfaces. Its CPU source cuts leave this report's continuous DAIF frontier unchanged; timestamp formatting is a further conditional prerequisite.
