# LSKD value consumption, query publication and RNG handoffs

The [handler/access continuations](lskd_handlers_report.md) now establish the common bridge's complete checked value-access behavior: successful lookup plus a nonnull payload pointer and length8 leads to an original eight-byte big-endian-to-native64 conversion and a caller-output store. Lookup failure or a mismatching length returns through the status record without writing that output. The span bridge instead preserves pointer/length outputs and normalizes raw lookup status.

The query path appends tag0x65/length4/value0x13180000, completes its original inner return with zero stack displacement, publishes the response candidate at `0xfffffe000a522e44`, prepares workspace/auxiliary frees and returns0 to its execution caller. Allocation/free backends remain register-only models. Native validity, physical ownership effects and the original method's later getter/destructor calls remain **unknown**.

A further span shape check requires exactly37 bytes. Twelve additional executions through the original source caller reach a41-byte `_kernel_read_random` request directed to global0xfffffe000ccc2ce0; that call remains unexecuted. Four other next-call sites establish record handoffs to three unnamed helpers. No new Mach port or message emission is established. The broad objective remains active.

[Source contracts](triage_evidence/lskd_values_contracts.json), [retained profiles](triage_evidence/lskd_values_profiles.json), [distinct fresh replays](triage_evidence/lskd_values_replays.json), [independent checks](triage_evidence/lskd_values_checks.json), [fourteen proof pairs](triage_evidence/lskd_values_proofs.json), [source identity](triage_evidence/lskd_values_source_identity.json), [preservation](triage_evidence/lskd_values_preservation.json) and [scoped quality gates](triage_evidence/lskd_values_quality_gates.json) retain the evidence.

```text
common tag0x72 lookup
  -> raw success AND payload != 0 AND length == 8
       yes -> BE64(payload) -> caller's u64 output -> next record helper
       no  -> raw status in record+8 -> original error return/cleanup preparation

span tag0x66 lookup -> pointer/length + normalized status in record+0x0c
  -> handler shape check: length == 37
       yes -> read_random(global,41) arguments -> STOP before call
       no  -> original error return/cleanup preparation

query response initialization -> append [tag0x65, len4, BE32(0x13180000)]
  -> inner return -> displacement0 -> publish candidate pointer
  -> auxiliary/workspace free arguments [REGISTER MODELS] -> execution return0
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LV1 | Original KC and normalized kext identify the pinned build | Instructions, symbols, tables and handoffs | Rehash both; compare complete compiler envelopes, exact source windows and original chain membership |
| LV2 | Guarded private memory and abstract PAC implement the declared conditional execution | All guest results | Reject source/call escapes and unknown value reads; check every original instruction byte; native authentication/reachability remain separate |
| LV3 | Allocation/free register models return declared distinct extents and clobber declared caller registers | Query success, error returns and cleanup-call preparation | Verify native allocator capacities, views and lifetime separately; models initialize/free/write no memory |
| LV4 | Source-produced record phases establish the common decoded state0x148 and query phases | Status/length partitions and query control | Check retained phase registers and original slots; unrelated selectors/entry states remain unknown |
| LV5 | Fixed symbolic cells are distinct except stated source aliases | Local value, output and publication proofs | Reconstruct byte epochs; vary stack placement and auxiliary location; arbitrary aliasing is not proved |
| LV6 | Query caller/decoder key agreement qualifies its shared-key composition; u32 bridge phase W17=0xfffffffe | Query tag/length/word proof | Re-lift both key forms and the actual caller/receiver slices; retain that explicit phase premise |
| LV7 | Source packet extents and explicit valid-stream fixtures are accessible | Payload reads and original caller composition | Verify request bytes, constructor alignment8 modulo16 and actual copy extents; native user-pointer validity remains unknown |
| LV8 | Mutable globals remain stable except recorded source writes during a run | Dispatch and controller state | Original/zero/noise fixtures and exhaustive byte-bank rules; native concurrency remains separate |
| LV9 | At query publication, the original SP and saved output/candidate cells have the checked source values | Pointer publication | Check inner return, source displacement0, frame snapshots and actual store in each case; other successful operations remain unproved |
| LV10 | Memory retained after modeled frees is inspection storage, without native free effects | Final snapshots and source cleanup operands | Do not infer native post-free accessibility or reference balance; recover actual allocator/free effects separately |
| LV11 | The original query caller's later getter/cleanup calls return normally only as an explicit static continuation premise | Interpretation of its eventual W0 load | Those calls are not replayed here; verify their actual schemas, statuses and cleanup behavior before asserting a completed method return |
| LV12 | Discarded original stack probes target WZR and supply no values to later logic | Stack-probe continuation | Check exact one-byte probe sites, mapped addresses and discarded destination; unknown poison is not initialized input |

LV1-LV12 qualify corresponding claims. Source execution has no key substitutions. Shared-key abstractions occur only in the stated symbolic composition, with separate original-source key identities. Retained/fresh equality shares the engine; independent byte reconstruction, compact expected packets, original-slot decoding and source arithmetic check different properties without proving native behavior.

## Primary provenance

| Item | Exact identity / scope |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New extraction |9 complete compiler envelopes,25 bounded windows and one complete static query-caller body |
| New rule evidence | One extracted query-append bank; two additional verifier banks for span RNG target and biased global destination |
| Names | Exact original nlist matches only; no neighboring symbol assignment |

The supplied [call catalog](com.apple.driver.FairPlayIOKit_calls.txt) also lists `_kernel_read_random -> _read_random`; the same-build wrapper/stub/import bytes independently corroborate that relationship. Argument widths and sizes here come from original instructions.

The original symbol for the query caller is `__ZN30com_apple_driver_FairPlayIOKit13wT74ohNhs04OyEv`, at0xfffffe000a50550c. `query` remains an analysis label. No version/key/nonce semantics are assigned to its constant field or to the random buffers.

## Common value bridge and status channel

In the source-produced common access record R, the current continuation establishes:

| R offset | Width, bytes | Contract |
| --- | ---: | --- |
|+0|8|Request pointer |
|+8|4|Raw result status written by bridge |
|+0x0c|4|Address-keyed selector; decoded state0x148 |
|+0x10|2|Encoded tag context leading to wire tag0x72 |
|+0x18|8|Address of caller's64-bit output word |

At `0xfffffe000a52f26c`, the bridge compares generic lookup status with0x5e561849. Only success reaches `0xfffffe000a519b74`, whose CMP/CCMP combination requires a nonnull payload pointer and length8. Three original table slots establish the complete local partition:

| Index | Original slot | Target | Diversity |
| --- | --- | --- | --- |
|0x410|`0xfffffe000846e4a0`|`0xfffffe000a519b74`, pointer/length gate |0xc7cc|
|0x270|`0xfffffe000846d7a0`|`0xfffffe000a54f418`, value decoder |0xc7cc|
|0x148|`0xfffffe000846ce60`|`0xfffffe000a571ee0`, status store/epilogue |0xc7cc|

Source `0xfffffe000a54f420..0xfffffe000a54f484` reads eight payload bytes. The subsequent obfuscated arithmetic reduces exactly to BE64(payload); store `0xfffffe000a54f4f4` writes the resulting native64 word to `[R+0x18]`'s pointed-to storage. The source-derived proof covers every64-bit payload word and all eight read addresses.

Store `0xfffffe000a571ee4` writes raw status at R+8. Lookup failures forward their raw status into this channel; lookup success followed by a failed pointer/length gate prepares0x5e5571af; accepted conversion prepares0x5e561849. The checked failure paths issue no store to the caller output. The original caller had already zeroed that word. X0 retains bridge scratch state in these returns; these callers read the record's status rather than treating X0 as a C status return.

Across212 common-bridge returns,120 produce the expected64-bit output with exactly one eight-byte store each;92 leave the output word unchanged. The latter include60 additional valid TLV fixtures with payload lengths1,4,7,9 or16. Zero-length matching fields also fail this value-access gate, despite successful generic tag lookup. Zero-valued eight-byte payloads decode to0 at this stage; no later policy or processing acceptance follows from that fact.

## Span bridge, auxiliary pointer and37-byte shape

The span bridge's source `0xfffffe000a549e08..0xfffffe000a549e1c` stores `u32(raw_lookup_status-0x5e561849)` at R+0x0c. It preserves the lookup's packet-pointer/length outputs. Its73 checked returns therefore expose a different status channel and normalization from the common bridge.

The handler continuation at `0xfffffe000a50fff4` loads the payload pointer from auxiliary+0x18, reads the returned16-bit length, and source-stores the scratch pointer from SP+0x98 into auxiliary+0x90. In this context that scratch pointer is B+0xd0=workspace+0x150. The store precedes the length comparison; it occurs on the checked rejected shapes too.

With source phase W20=0x30c, the local predicate is exactly `length16 == 37`. Its accepted index0x982 uses original slot0xfffffe0008471030 ->0xfffffe000a52968c, diversity0x0343. Rejection uses index0x30c, slot0xfffffe000846dc80 ->shared inner return0xfffffe000a52e4b0, diversity0x0343.

Twelve added cases start at the original `R2nPsUOYx6h` caller with input length37, the declared64-byte input fixture and output-size fixture8. Its original constructor reserves41 bytes and its span appender produces `BE16(0x66) || BE16(37) || input[0:37]`. Every request byte has source-write provenance. These cases pass the shape gate and stop before the next call:

| Site | Prepared interface | Boundary |
| --- | --- | --- |
|`0xfffffe000a5296e4`|X0=`0xfffffe000ccc2ce0`, W1=41, target exact `_kernel_read_random` at0xfffffe000a508d6c | Call unexecuted |
|Original target slot|`0xfffffe00084714a8`, diversity0x6e7d | Exhaustive256-byte bank identity |
|Destination source|Original slot selected at0xfffffe000a52dde0 supplies pointer0xfffffe000ccc2cec; source subtracts0x0c and saves0xfffffe000ccc2ce0 at SP+0x118 | Original biased pointer provenance |
|Call preparation|`0xfffffe000a5296d8` reloads SP+0x118;0xfffffe000a5296dc sets W1=0x29 | Argument-word proof |

The destination has no exact nlist name in this build. The [previous report](lskd_handlers_report.md) pins the wrapper/stub/import chain through slot0xfffffe000847c4f8 to exact kernel `_read_random`,0xfffffe000be57d68. No random output is generated here. Native global initialization, synchronization, buffer role and subsequent use remain unknown. The earlier start operation's four-byte workspace RNG request remains a separate interface.

## Query field append, inner return and publication

After the source initializer returns, `0xfffffe000a51c02c` reads its raw status from record+0x0c. Under the retained source phases, equality with0x5e561849 selects index0x630, original slot0xfffffe000846f5a0 ->0xfffffe000a525cbc, diversity0x0343.

That continuation prepares a partial24-byte record for the already recovered u32 append bridge. It calls0xfffffe000a54daf8 at `0xfffffe000a525d74`, modifier0x1322. The new caller/receiver key-identity proof and shared-key composition establish tag0x65, payload length4 and big-endian payload0x13180000. The bridge reuses the original generic append implementation and original kernel copy helper; no copy-memory effect is modeled.

| Query append record offset | Width, bytes | Meaning |
| --- | ---: | --- |
|+0|2|Encoded tag |
|+4|4|Raw source-written status on return |
|+8|8|Response candidate pointer |
|+0x10|4|Encoded selector |
|+0x14|4|Encoded32-bit value |

The record's other bytes retain prior epochs. Store `0xfffffe000a54df5c` fills raw status at+4. Source `0xfffffe000a525d78` forwards that status into W8 and uses state0x3be's original slot0xfffffe000846e210 ->inner return0xfffffe000a52e4b0, diversity0x62dc.

All thirteen query cases then complete the original bridge/displacement path with displacement0. Their saved frame cells supply the actual output-reference address from SP+8 and candidate from SP+0x28 at publication. The source executes `STR X9,[X8]` at **0xfffffe000a522e44**, writing the candidate pointer to that reference. This extends the earlier static-only publication result with checked source execution in these private contexts.

| Final candidate field | Value |
| --- | --- |
| Header / operation |1 /0x1b5b |
| Declared field limit / capacity |1 /8 bytes |
| Inline packet |`00 65 00 04 13 18 00 00` |
| Buffer pointer |candidate+0x10 |
| Used-field count / cursor |1 /8 bytes |
| Remaining inline bytes |Zero from the original clear |

The wrapper prepares only auxiliary typed-free and workspace aligned-free calls on this published path; it does not prepare a candidate free. Those backend effects are register-only models. The original wrapper returns0 to its execution caller. The source candidate is not a native-validated response object or an established Mach reply.

For153 completed error cases, the wrapper instead prepares candidate typed-free, auxiliary typed-free and workspace aligned-free calls, returns0xffff5966 and preserves the caller's prior output reference. Every one of the166 completed wrapper returns has a source-computed zero displacement and restored wrapper SP. Snapshots retained after modeled frees do not prove native post-free accessibility.

## Status channels and source-epoch reuse

| Interface | Status location | Representation / checked register behavior |
| --- | --- | --- |
| Generic field lookup |record+0|Raw0x5e561849 /0x5e5571af; X0 retains its record address |
| Metadata getter |record+4|Raw status; separate earlier interface |
| Common64 access bridge |record+8|Raw status; caller reads the record |
| Span access bridge |record+0x0c|`u32(raw-0x5e561849)`; caller reads the record |
| Response initializer |record+0x0c|Raw status; checked X0=capacity8 |
| Query u32 append bridge |record+4|Raw status; caller forwards that field |
| Execution wrapper |X0/W0|`u32(inner_raw_status-0x5e561849)` on completed checked paths |

The shared workspace record at workspace+0xa8 changes roles across these epochs. Equal base addresses and equal status offsets do not establish one original C type or one C return convention. The new byte-epoch audit checks each snapshot at its actual source visit.

## Next caller handoffs and static response consumer

After successful common64 access, four original call sites reach three unnamed helpers. Their calls are unexecuted; full register/partial48-byte record snapshots and original authenticated slots are retained. No semantic name or complete prototype is assigned to the targets.

| Operation / source caller | Next call | Target | Diversity | Cases |
| --- | --- | --- | --- | ---: |
|0x1b69 / scalar64|`0xfffffe000a53486c`|`0xfffffe000a55b390`|0xfab4|48|
|0x1b6b / vault|`0xfffffe000a523638`|`0xfffffe000a50eccc`|0xe246|24|
|0x1b6a / AVD|`0xfffffe000a554df8`|`0xfffffe000a50eccc`|0xe246|24|
|0x1b6c / allowed|`0xfffffe000a5423d4`|`0xfffffe000a55132c`|0x560f|24|

The original query method body is retained as static evidence after its execution-wrapper return at0xfffffe000a50556c. It calls0xfffffe000a50e8a8 with the response pointer and a32-bit stack output at0xfffffe000a5055a4, then compares that word with0x1b5b. Later call0xfffffe000a505608 passes the response, tag0x65 and another32-bit output address to0xfffffe000a50e170. The eventual return load at0xfffffe000a505624 reads that output into W0, after request/response cleanup calls to0xfffffe000a50d088.

Those getters, destructors and the final method return are unexecuted here. The static continuation identifies the intended next response read and its32-bit width. Its completed value, error behavior and lifetime contract require those callees to be established; the marker's business meaning remains unknown.

## Validation and reproduction

| Check | Result / scope |
| --- | --- |
| Distinct fresh executions |343, complete retained-case equality |
| Original source visits / checked bytes |922309 /3689236 |
| Independent reconstructed reads / writes |184777 /101314 epochs |
| Preceding evidence preserved in execution |All271 complete pre-boundary prefixes, including exact visits, reads, writes, calls, branches, boundary state and retained accessor snapshots |
| Actual source caller lineages |156, including12 additional length37 span calls |
| Source constructor records |156; every address8 modulo16 |
| Source-constructed packet bytes |3420 |
| Explicit stream fixtures |187; includes60 additional non-eight-byte scalar payloads |
| Common bridge returns |212:120 output stores,92 unchanged failure outputs |
| Eight-byte source payload reads |960 bytes across120 accepted common accesses |
| Span bridge returns |73 |
| GP/SP bridge contexts preserved |285; source call/return X19-X29 and SP comparisons |
| Query appends / publications |13 /13;52 original copied payload bytes |
| Completed execution-wrapper returns |166:13 query success,153 errors; all source displacement0 |
| Prepared free calls |485; no native free/memory effect |
| Record-helper handoffs /41-byte RNG handoffs |120 /12; callees unexecuted |
| Register-only models |1670; zero modeled memory writes |
| Original discarded WZR probes |343; no undefined private value reads |
| Original continuation table/import edges |1489 /13, including the original kernel-copy import |
| Rechecked byte-bank rules / byte inputs |106 /27136; rule checks include retained identities, one newly extracted query rule and two independent RNG/destination rules |
| Original/normalized proof pairs |14, all UNSAT;324 source instruction instances, including overlapping/composed slices |

The base271 cases retain the earlier caller/stream contexts. Sixty extra valid tag0x72 fixtures use lengths1,4,7,9 or16 across three global fixtures, two stack placements and two auxiliary locations. Twelve new original span-caller cases use length37 across those same contextual variants. The earlier31 base operation fixtures retain their original-global/one-placement scope. These are not exhaustive contextual native executions.

The source proofs cover arbitrary64-bit payload conversion, arbitrary raw-status words, nonnull-pointer/length gating, span length16 comparison, query key agreement/field packing, raw-status forwarding and local publication. Record-phase and memory-cell premises remain explicit. Original execution independently checks actual frame/displacement/publication values in the finite cases. Neither a whole-program theorem nor arbitrary malformed-stream/native memory validity follows.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_values.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_values.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_values.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_values.py
```

Published files remain retained; reproduce in an isolated copy. Extraction is O(B+I+256R) in pinned bytes/instructions/rules. Replay generation is O(C*(B+V+E)) time/profile space. The independent verifier's edge-to-read association scans give O(B+C*(V+E+D*E)+256R+I) time, with D checked edges per case; retained space is O(C*(V+E)+B+I). Each case is bounded to30000 visits. Symbolic DAG construction is O(I); solver complexity is separate, with30 s/query timeout. Widths and extents are in bits/bytes; no physical-unit conversion is required.

## IPC boundary and bounded continuation

The executed publication is an internal object-pointer store, not a Mach-port emission. Internal operations/tags remain distinct from daemon Mach IDs. Native allocator/free/random effects, current processing-helper bodies, final query-method cleanup and any later daemon IPC remain unknown.

| Impact | Bounded continuation / unresolved context | Completion criterion |
| --- | --- | --- |
| High | Three next record-helper targets | Recover their source decoders, field expectations, status and actual downstream callees while preserving handoff snapshots |
| High | Query response consumption and cleanup | Follow the original caller's getters, tag0x65 read and request/response destruction through its actual return |
| High |37-byte span and global RNG state | Recover backend ABI, global initialization/lifetime and post-RNG continuation without assigning nonce/key semantics from size alone |
| High | Native ownership and transport linkage | Establish allocator/view and free effects, then connect any actual emission to destination provenance and original Mach framing |
| Medium | Other selected operations lack original producer lineages | Identify their actual constructors/indirect callers; current empty fixtures prove only their checked rejection paths |
| Medium | Shared arena/record epochs and native concurrency | Establish typed uses and synchronization around the saved scratch/global pointers |

## Scoped quality gates

QG1 passes: factual source/interface analysis. QG2 passes: LV1-LV12 specify dependencies and falsification probes. QG3 passes for this increment: value/status contracts, caller handoffs, query append/publication and37-byte RNG preparation; the broad goal remains incomplete. QG4 passes: fixed widths, byte extents, counts, modular arithmetic and implementation-sensitive complexity are explicit. QG5 passes: raw/normalized and record/register status, pointer/copy, publication/Mach emission, source/model, finite/static/solver and conditional/native claims are separated. QG6 passes: primary bytes/exact symbols/chains, independent epochs, exact prior-prefix equality,343 fresh cases and re-lifted proof pairs. QG7 passes: impact-labeled bounded continuation above. Machine checks: [delivery gates](triage_evidence/lskd_values_quality_gates.json).
