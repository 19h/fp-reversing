# Constructor reply state, context allocation and initialization frontiers

Original constructor entry now connects to original RPC502/RPC700 reply parsing, mapping installation, separate KBCryptShared/KBCrypt allocations and complete624-word seed expansion in three conditional private runs. A fourth cold run reaches IOAESAccelerator discovery before any RPC. All four paths have fresh independent CPU/effect replay:1230691 original instruction visits. The successful replies, VM outcomes, calendar time and logger behavior are explicit models. Application success, native transport, valid global initialization, context publication and returned-token generation remain unknown.

Primary evidence: [original ranges, metadata, symbols, banks and proof](triage_evidence/kext_constructor_reply_state_source.json), [continuous private journals](triage_evidence/kext_constructor_reply_state_profiles.json), [independent checks](triage_evidence/kext_constructor_reply_state_checks.json), [preservation audit](triage_evidence/kext_constructor_reply_state_delivery.json) and [scoped quality gates](triage_evidence/kext_constructor_reply_state_quality_gates.json). The increment extends [constructor request construction](kext_constructor_request_report.md) and [RPC reply ABI](rpc502_reply_bridge_report.md); it does not replace their transport/application assumptions. [Page lookup](kext_page_context_report.md) and [retirement](kext_context_retirement_report.md) describe later consumers under their separately constructed valid-owner premises.

Analysis date:2026-11-04. Original collection SHA-256:`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256:`2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Addresses are unslid static virtual addresses. Eight explicit original ranges contain2574 instructions; four64-byte type views and three exhaustive256-input banks retain original pointer provenance. Every executed instruction is additionally checked against the original collection during independent replay. No IDB bytes or memory-store facts support the new target claims; a read-only IDA query could not select a database unambiguously and its database-listing capability was unavailable. No IDB was changed.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RS1 | Hash-pinned files are the intended static build; all addresses and exact symbol roles depend on this. | Rehash originals, recapture instructions/type views/fixups; establish actual daemon/kernel pairing separately. |
| RS2 | The private warm flag, logical image pointers and zero-backed RAM are declared initial state. | Recover native initialization epochs. The missing mask/table frontier demonstrates that warm=1 alone is insufficient to establish valid startup state. |
| RS3 | Disjoint allocator returns describe private regions of the requested sizes. | Check every allocation, alias-producing store and extent; native heap initialization, allocation success and lifetime are not inferred. |
| RS4 | A successful transport returns the declared392-byte internal reply with marker0xBEEFED02, primary extent4096 and empty auxiliary output. | Validate all supplied reply bytes and original parser guards; join real daemon application outputs and kernel conversion before a native success claim. |
| RS5 | Copyout returns an opaque mapped VA, wire returns the declared0/4, and calendar time writes declared outputs. | Check ABI arguments, exact widths and each model memory effect in fresh CPU state; inspect native effects separately. No mapped payload is supplied as an accepted application result. |
| RS6 | Authenticated instructions/transfers can be represented as logical edges for this CPU analysis. | Recheck original instruction/target/modifier and all source reads/writes; native PAC validity remains unknown. |
| RS7 | Recorded local loop constants and scalar loads apply to the recurrence lift. | Check entry/exit loop snapshots and all623 source iteration stores per warm run. The full-u32 proof covers the local arithmetic, not all native paths or generator outputs. |
| RS8 | Stops before missing-table access and hardware service discovery are sufficient for these bounded conclusions. | Recover global writers and hardware-setup outcomes, then continue original control flow. Native fault behavior, context publication, ownership/reference balance and final return remain unknown. |

The following contracts depend on RS1-RS8 as applicable. File identity, symbolic arithmetic and finite CPU execution remain distinct evidence classes.

```
original fcHfFIGhsx entry
       |
       +-- warm=0 --> FPAESParameters allocation
       |                 |
       |        serviceMatching("IOAESAccelerator",NULL) --> stop
       |
       +-- warm=1 --> original request packing
                         |
                declared internal reply / status0
                         |
                 original RPC502/700 parser
                         |
             copyout model --> record mapping stores
                         |
                wire model, return0 or4
                         |
             KBCryptShared704 --> KBCrypt1088
                         |
                 original arc4random returns0
                         |
                624-word seed expansion
                         |
            calendar-time model / two more random-stub calls
                         |
           missing address-table load --> stop before access
```

The transport model replaces the actual kernel request buffer at `_mach_msg_rpc_from_kernel_proper`, `0xfffffe000bcf5e28`, with the declared reply and returns status0. RPC502 uses reply ID602 and RPC700 uses800. The original clients then validate and copy their outputs through their own original frames; no parser output pointer or post-call register fixture is supplied. This joins earlier separate parser fixtures to the real constructor caller. It does not join actual daemon application processing or native descriptor conversion. The reply layout is392 bytes, with two OOL descriptors,136-byte record0,172-byte record1 and two repeated lengths. Record0 contains only marker0xBEEFED02 before the downstream source mapping stores; other supplied fields are zero. OOL0 is an opaque copy-object word with extent4096; OOL1 is NULL with extent0. These are deliberately incomplete application-data premises.

| Scratch C field | Value/role established at the warm stop | Provenance |
| --- | --- | --- |
| +0x00 | 704-byte KBCryptShared allocation | Original typed allocation at `0xfffffe000a612530`, view`0xfffffe000847baa0` |
| +0x18 | Acquired opaque kernel port object | Source host lookup output, then original request destination |
| +0x28 | Request vm_map_copy_t word | Request copyin model, forwarded through original request packing |
| +0x48 | 1088-byte KBCrypt owner allocation | Original allocation at `0xfffffe000a611288`, view`0xfffffe000847c220` |
| +0x58 | 152-byte FPAppSecurityInfo child | Earlier allocation and original136-byte reply copy |
| +0x60 | Alias of the same FPAppSecurityInfo child | Original source slot transfer |
| +0x80 | Request staging VA | Earlier private IPC-map allocation model |
| +0x90 | Reply OOL0 vm_map_copy_t word | Original successful parser output |
| +0x98 | Separate172-byte fixed-record1 output | Earlier IOMallocData allocation and original parser copy |

KBCryptShared is not the1088-byte list owner. Source allocates Shared first and owner later in all three warm runs. The owner allocation view and normal close/free view`0xfffffe000847ba20` both name`site.KBCrypt` and describe1088 bytes; this is static type-metadata correspondence, not native allocation/free balance. The cold view`0xfffffe000847b460` names`site.FPAESParameters`, size104, distinct from either context.

The original reply mapping code writes the copyout-model VA into child+0x48 and4096 into child+0x50, clears the secondary address/extent fields, and requests page wiring over `[mapped,mapped+16384)` with access3 and user_wire0. Only4096 bytes are declared by the reply; the wire request uses the page-shift14 alignment span. The model allocates no native VM object and performs no wiring. In the paired RPC502 cases, wire return0 versus4 leaves the complete retained instruction path and final scratch/owner/child/shared/seed/head/output state identical. This is a finite source-path observation consistent with the previously recovered unchecked wire-result continuation; it does not establish successful native wiring.

At the stop, original owner initialization has written word+4=0x31AE0066 and twenty bytes0xCD at offsets0x31D..0x330. Other owner bytes are zero; the source-write journal distinguishes explicit zero stores from initially zero storage. The owner has no established normal tag, child association or registry membership yet. The original list head`0xfffffe000cccca58` remains NULL, and the caller's eight-byte output handle retains0xA5 in every byte. The initial word+4 must not be reported as the returned token. Its later writer, publication and result adapter remain unresolved.

Original call`0xfffffe000a6114c4` enters nested helper`0xfffffe000a627d54`, which reaches`0xfffffe000a5b4314`. Its observed work includes a17-byte data allocation, the local random stub, complete seed-state construction, a calendar-time interface and subsequent state-dependent processing. These are recovered functional components, not a complete semantic name for either obfuscated helper.

| Interface | Exact source evidence | Contract / limitation |
| --- | --- | --- |
| Local `_arc4random` | `0xfffffe000a508cc4..0xfffffe000a508cec`; exact kext nlist symbol | Logs the literal at`0xfffffe000790caf5`, then `MOV W0,0` at`...8ce0`; no incoming argument is consumed as random input |
| Logger | Original thunk resolves to exact `_IOLog`, `0xfffffe000c4babac` | Private no-effect logger model; actual logging is not executed |
| Seed0 store | `0xfffffe000a5b4e54` | Stores returned u32 into`0xfffffe000cccb088` |
| Seed recurrence | `0xfffffe000a5b4eb4..0xfffffe000a5b4eec` | Shift30, lifted arithmetic and indexed u32 store |
| Seed completion | `0xfffffe000a5b4ef4` comparison, loop exit at`...4f18` | Source index1..623, final index624 |
| Calendar time | Source call`0xfffffe000a5b4fa4` through adapter`0xfffffe000a508dfc` to exact `_clock_get_calendar_microtime`, `0xfffffe000bce3a8c` | Original callee stores64-bit seconds at its first output and32-bit microseconds at the second; source captured, native callee not executed |
| Two further random calls | `0xfffffe000a5b502c`, `0xfffffe000a5b50a8` | Same original stub, each returns0 regardless of modeled logger return |

The literal is exactly`Warning: arc4random not implemented` followed by newline. This behavior was already identified in foundational triage; the new evidence connects three actual calls and their consumers to the continuous constructor prefix. The kernel's separate `_kernel_read_random` interface remains distinct and is not reached by these three calls.

For all word operations below, arithmetic is modulo2^32 and right shift is logical:

```c
state[0] = 0;  /* original local arc4random return in this static build */
for (uint32_t i = 1; i <= 623; ++i) {
    uint32_t previous = state[i - 1];
    state[i] = 1812433253u * (previous ^ (previous >> 30)) + i;
}
```

State comprises624 contiguous u32 words/2496 B at`0xfffffe000cccb088`. The scalar proof establishes, for every u32 transformed predecessor and every u32 index, that the lifted source stored word and carried W0 equal this recurrence under the recorded constants. The original LSR30 instruction and finite loop bounds are independently captured and executed. Three fresh CPU runs verify all1872 final words and1869 indexed iteration stores. One additional original store rewrites the first state word to zero later in each retained prefix; it does not change the final recurrence array. This is complete seed expansion for the supplied zero seed, not successful generator/output recovery or a native entropy-quality conclusion.

The daemon's separately established [seed expansion](daemon_entropy_return_report.md) has the same624-word recurrence at`0x1010c784c`, using imported userland `_arc4random` rather than this kext compatibility stub. The new kernel proof and original store sequence provide a cross-layer algorithm-family correspondence. There is no established shared seed, transferred PRNG state, interprocess buffer identity or causal IPC relation. The same algorithm does not identify the role of the eventual constructor output.

The private calendar-time model supplies1700000000 s and123456 microseconds (0.123456 s), writing8 B and4 B respectively. These are explicit environmental inputs, not measured time. Source initialization reaches this interface after all624 seed words have been written. It subsequently reaches the two additional zero-return random calls. Calendar-dependent consumers beyond the retained frontier and native time synchronization remain unknown.

| Missing state | Source/pointer provenance | Retained behavior |
| --- | --- | --- |
| Mask u32 at`0xfffffe000ccceaf8` | Original pool slot`0xfffffe0008472470` points directly to it; load at`0xfffffe000a5b5158` | Original file/private value0 |
| Table-base u64 cell`0xfffffe000cccda68` | Original pool slot`0xfffffe0008472290` stores address`0xfffffe000cccda6c`; native -4 adjustment supplies the cell; load at`...5174` | Original file/private valueNULL |
| Indexed table-word load | Effective address computed at`...5178`/`...517c`; next LDR is`0xfffffe000a5b5180` | Effective address0; execution stops before the access |

Both original chained pointers are unauthenticated format8 data rebases; raw words, targets and bias are retained. The mask/table cells have no exact nlist names in the collection. Their complete initialized meanings, valid extents and writers are unknown. No filler table, inferred pointer or guessed mask is substituted. The temporary exploratory fault led to a production stop before the unresolved load; the published runs execute no read through NULL. That modeled frontier does not establish a native fault, native reachability or missing initialization in a real loaded kext.

| Retained case | Warm flag | RPC / reply | Wire model result | Source visits | Stop |
| --- | --- | --- | --- | --- | --- |
| 0 | 1 | 502 /602 | 0 | 350190 | Before missing-table LDR |
| 1 | 1 | 700 /800 | 0 | 528007 | Before missing-table LDR |
| 2 | 1 | 502 /602 | 4 | 350190 | Before missing-table LDR |
| 3 | 0 | None | Not reached | 2304 | Before IOService::serviceMatching |

Case1 exhausted an initial500000-instruction exploratory budget. A completed900000-budget run established its actual stop at528007 visits, and fresh replay checks the complete retained path. Budget exhaustion is not reported as a semantic failure or successful completion.

The cold run allocates FPAESParameters104 through the original dispatcher and reaches exact `IOService::serviceMatching`, `0xfffffe000c4ece88`, with X0 pointing to original literal`IOAESAccelerator` at`0xfffffe000790ba3c` and X1=NULL. The source call is in `_initKernelAESHW` at`0xfffffe000a508070`; original return continuation is`...8074`. No dictionary, provider or hardware result is supplied. This establishes a hardware-discovery prerequisite before the ordinary request path, not successful hardware attachment or an observed native wait. Other startup initialization may precede or follow it.

One additional exhaustive bank binds a later helper candidate to exact `_buildLookupTbl`, `0xfffffe000a509114`, using original slot`0xfffffe000847ac48`. The retained runs do not reach that helper. Its previously recovered VFS behavior must not be replaced with an inferred generic cryptographic/KDF meaning based on pointer/count arguments. This static binding is a continuation lead, not a completed constructor-to-file path.

Verification includes original range/type-view/pointer recapture, three256-input selector identities, one full-u32 arithmetic proof, an independent reply/child/owner/seed/order oracle and four fresh CPU replays. Replay checks100749 source writes/660225 B,259730 reads/1418275 B,19577 logical indirect edges,63 declared API models,24 declared model memory effects/1395 B,17 request snapshots,12 state snapshots and four final boundaries. All four registry-head/output checks pass. These checks establish the declared finite paths and local identity; native IPC/application/VM/hardware/clock/logging/PAC operations and complete lifecycle remain unperformed.

Recovery, probe and validator run in that order using the pinned zut virtual environment and the existing Z3 Python/runtime paths used by the preceding constructor scripts. Seal and independent publication audit follow the refreshed owned manifest. Each script states its complexity. Source capture/CPU replay/byte oracles are linear in image, instruction/effect and retained byte counts, apart from timeout-bounded SMT; CPU working RAM is1 MiB per case plus original image pages and journals. No native target process, kernel, daemon, IDB, original input or memory store is modified.

| Impact | Next interface | Evidence needed / falsification |
| --- | --- | --- |
| High | Mask/table initialization | Identify actual writers of`0xfffffe000ccceaf8` and`0xfffffe000cccda68`, table allocation/fill/extent and the corresponding lifecycle epoch; execute the original initializer rather than supply a guessed table. |
| High | Owner publication and handle | Continue the nested helper through its output writer, constructor list insertion and wrapper output adapter; then join original page/close consumers without reconstructed owners. |
| High | Real daemon reply and ownership | Establish successful application inputs/outputs and exact native peer/build/right identity, then replace the declared transport/copyout effects with verified contracts. |
| Medium | Cold hardware setup | Follow matching/wait/provider paths and all initialization publishers under explicit outcomes; verify hardware-independent continuation and cache ownership. |
| Medium | PRNG outputs and algorithm role | Recover generator/index/twist/consumer contracts past the missing table; distinguish seed-family correspondence from shared state or message provenance. |
| Medium | Mode-dependent deeper work | Explain the extra177817 instructions for retained RPC700 before the same frontier using compact state/control semantics, without treating finite instruction count as a universal property. |
| Low | Later filename-table helper | Bind the original caller/record epochs to `_buildLookupTbl` and its known VFS inputs before assigning constructor success semantics. |

QG1: No normative content is required. QG2: RS1-RS8 register assumptions, dependencies and probes. QG3: The increment covers reply-to-object dataflow, two context types, environmental and hardware interfaces, seed semantics and explicit initialization frontiers; the full goal remains active. QG4: u32/u64, byte extents, modulo domains, time units, exact counts and complexity are explicit. QG5: Supplied replies versus original parsing, allocated versus published owners, cold versus warm state, word identity versus native reachability and budget exhaustion versus termination are distinct. QG6: Hash-pinned original instructions/type views/fixups/symbols, retained journals, independent byte/state oracles and the full-word proof provide primary provenance. QG7: Remaining work is bounded and impact-labelled. All gates pass for this increment; native interaction and full constructor/page/close lifetime remain unknown.
