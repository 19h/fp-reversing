# Original receive frontend, ownership, completion and user copyout

Original user receive setup now performs namespace lookup/retain and publishes its receive context before the existing wait/sender/continuation components. Original receive-results then returns the ordinary turnstile loan, releases the receive hold, translates the destination send-once right into the receive name, packs user bytes, calls the modeled user-copy primitive, executes original kmsg zeroing and requests raw deallocation. Three components reach the original return-to-user boundary; a fourth preserves the uninitialized file validation metadata and reaches its original guard.

Independent checks cover 80 complete functions / 11463 captured instructions, 20 producer + four sender + four results components, 13714 original instruction visits and four bounded scalar proofs. This is a component-level join for simple no-senders message ID70. Native scheduling, hardware authentication, user memory protection, allocator retirement, complex descriptors and an authentic FairPlay RPC502/700 round trip remain unknown.

## Provenance and assumption register

Primary KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. All addresses are preferred VAs; offsets, lengths and capacities are bytes; records are little-endian. The original KC, supplied analysis/decompilation/call files, zut binary/trace, IDBs and memory stores are unchanged. No new IDA query was needed for this increment.

| Artifact | Evidence |
| --- | --- |
| [Source](triage_evidence/kernel_receive_copyout_source.json) | 80 complete bodies, exact symbol records, 15 new instruction roles and source-derived validation metadata |
| [Profiles](triage_evidence/kernel_receive_copyout_profiles.json) | 28 components, initial/final RAM and globals, original read/write journals, frontend/results frames and explicit effect models |
| [Checks](triage_evidence/kernel_receive_copyout_checks.json) | Fresh original no-senders/startup replays, independent ownership/record/byte/zeroing oracles, CPU replay and four scalar proofs |
| [Recovery](triage_evidence/recover_kernel_receive_copyout.py), [probe](triage_evidence/probe_kernel_receive_copyout.py) | Source extraction and explicit component construction |
| [Replay](triage_evidence/replay_kernel_receive_copyout.py), [validator](triage_evidence/validate_kernel_receive_copyout.py) | Independent executor and verification; no probe executor import |
| [Delivery](triage_evidence/kernel_receive_copyout_delivery.json), [quality gates](triage_evidence/kernel_receive_copyout_quality_gates.json) | Preservation, six owned reporting changes and scoped gates |

The [preceding continuation report](kernel_receive_continuation_report.md) supplies block-prefix and invocation-fragment evidence. The [namespace report](kernel_namespace_report.md) supplies the earlier encoded-table contract; the present frontend additionally executes actual typed ticket acquisition and retain. The [zone startup report](kernel_zone_startup_report.md) supplies only the explicitly transferred eight validation bytes. The [earlier copyout report](kernel_user_copyout_report.md) covers additional descriptor/VM paths separately. The [zut trace](zut_trace_report.md) still establishes no successful FairPlay UserClient open or reverse work RPC.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RX1 | The pinned KC, compiler bounds, logical fixups and exact symbols identify the analyzed epoch. All source claims depend on it. | Rehash and recapture all 80 bodies, exact symbols and visited words; reject an image/mapping mismatch. |
| RX2 | Declared port/storage, owner/task/map, typed-object and namespace/SMR records satisfy the selected source path. Source lookup is conditional on these epochs. | Recover native creation/registration, namespace writers, full SMR domain extents and map/owner initialization. The declared name0x303 is not a discovered daemon endpoint. |
| RX3 | Raw turnstile allocation, explicit loan publication and lower sender copy/hash/tag/preflight contracts retain preceding premises. | Recover actual allocator, initial loan owner and primitive effects; verify complete ownership across failure and teardown. |
| RX4 | Whole RAM/global transfers connect separate receiver/sender calls but do not establish an admissible scheduler event order. | Execute actual selection/invocation from complete processor/processor-set state and original stacks. Both private contexts use CPU index0; native interleaving is unknown. |
| RX5 | Invocation-fragment registers and receiver+0x158 saved stack remain explicit; PAC is logical. Continuation/results control depends on them. | Produce the incoming scheduler frame, stack allocation/signing and actual authentication. No hardware key programming or native context switch is established. |
| RX6 | Exactly eight class24 validation bytes from original startup case0 are transferred; the remaining allocator/cache epoch stays declared. | Join the complete startup zone/cache/page lifetime through allocation and copyout. The file-zero countercase reaches the guard; the eight-byte transfer is not a whole-zone initialization proof. |
| RX7 | `_copyout` is modeled as complete byte copy on return0, or return14 with no byte change; keyed hashes and raw deallocation are modeled. | Execute native protected user copy, partial-fault behavior, keyed validation and real deallocation/retirement. Return14 here does not establish that native failures copy zero bytes. |
| RX8 | A simple inline ID70 packet, zero ancillary state and the selected receive options bound coverage. | Extend original complex-message/descriptors, nonzero cleanup, too-large/error, VM and actual daemon dispatch paths. No FairPlay RPC502/700 receive is inferred from this message. |

## Routine roles and coverage

Twenty-three additions contribute 3978 instructions. All bodies are captured completely; only the selected branches execute. Exact nlist names exist for `_copyout` and `_bzero`/`___bzero`; other labels below describe recovered roles and are not recovered symbols.

| Address | Instructions | Role / coverage |
| --- | ---: | --- |
| 0xfffffe000bcd0694 | 70 | Make send-once right: typed checks, original lock, send-once count and object-reference increment |
| 0xfffffe000bcdd4e4 | 147 | User receive frontend: lookup, context publication, common receive entry |
| 0xfffffe000bcc8cf4 | 60 | Receive-name lookup wrapper and retained object result |
| 0xfffffe000bcd2cc0 | 157 | Encoded namespace lookup, SMR epoch and post-lock verification |
| 0xfffffe000bcca438 | 81 | Typed lock-allow-invalid wrapper |
| 0xfffffe000bd0b274 | 53 | Valid-ticket acquisition wrapper |
| 0xfffffe000bc9d5a0 | 20 | CASA ticket-acquisition leaf |
| 0xfffffe000bcdcc7c | 253 | User receive-results, loan/reference completion and final status routing |
| 0xfffffe000bcc1344 | 576 | Ancillary/importance preparation; selected zero-state branches |
| 0xfffffe000bcda458 | 181 | Ancillary receive work; selected zero-state branches |
| 0xfffffe000bcc4e98 | 396 | Header/right copyout and user-name publication |
| 0xfffffe000bcc222c | 89 | Kmsg signature validation/canonical hash setup; keyed result modeled |
| 0xfffffe000bd794c4 | 38 | Fixed-zone element-class/alignment validator |
| 0xfffffe000bccd418 | 169 | Destination special-state precheck; selected fast return |
| 0xfffffe000bcca164 | 121 | Consume destination send-once right/reference and return receive name |
| 0xfffffe000bccf39c | 64 | Port unlock / turnstile maintenance; ordinary unlock branch |
| 0xfffffe000bcc5564 | 370 | Complex descriptor conversion body; simple packet skips descriptor work |
| 0xfffffe000bcc62d0 | 381 | Header deflation, trailer packing, copyout and cleanup |
| 0xfffffe000bcc2868 | 67 | External kmsg-buffer cleanup; inline fast path |
| 0xfffffe000c6480c0 | 44 | Exact `_bzero` / `___bzero`; original destination zeroing executes |
| 0xfffffe000be7798c | 149 | Exact `_copyout`; body captured, byte/protection outcome modeled |
| 0xfffffe000bcce5b8 | 329 | Receive port / turnstile completion adapter |
| 0xfffffe000bd68a7c | 163 | Ordinary turnstile completion and loan return |

## Original frontend and namespace contract

The frontend receives eight arguments `(user_buffer, auxiliary_buffer, receive_options, timeout, boost_name, capacity, auxiliary_capacity, receive_name)`. These components use `(USER,0,options,0,0,capacity,0,0x303)`. User buffers start as 8192 bytes of0xa5. Explicit owner/task fields identify the receiver's namespace and map; they are declared environment records, not native process identities. [RX2]

The declared table pointer is `TABLE|5`, with TABLE=`0x400000100000`. The original decoder takes the bit46-set branch, obtains this base and capacity `0x20 <<5 =1024`. Name0x303 selects index3, a 24-byte entry at offset72. The fixture entry is `<QIIQ>(PORT,0x20001,0,0)`; original rights/generation checks accept it. An explicit SMR sequence0x100 and private CPU0 slot permit the original reader protocol. The touched 16-byte slot is distinct from the nearby private typed-metadata cells; complete native per-CPU/domain extents remain unknown.

Original lookup at0xfffffe000bcdd564 enters0xfffffe000bcc8cf4, which retains the result at0xfffffe000bcc8d54. Original frontend stores then publish:

| Receiver offset | Width | Source-produced context |
| --- | ---: | --- |
| +0x378 | 8 | User buffer |
| +0x380 | 8 | Auxiliary buffer0 |
| +0x388 | 4 | Receive capacity44 or3072 |
| +0x38c | 4 | Auxiliary capacity0 |
| +0x390 | 8 | Receive options2 or0x07000006 |
| +0x398 | 8 | Retained receive objectPORT |
| +0x3a0..+0x3bf | 32 | Cleared before common receive; subsequently populated by original wait/sender code |

Common receive consumes the explicit loan at receiver+0x30, creates priority31 wait membership, installs callback0xfffffe000bcc89bc and reaches the original scheduler-selection boundary with state5 and wait result0xffffffff. The separate original sender consumes this complete RAM/global state without repair, publishes the kmsg pointer/status, releases the receiver to state4/wait result0 and returns0 to the notification caller. The subsequent invocation fragment still requires explicit X19=receiver, X21=stored callback, X25=stored parameter and saved-stack publication. [RX3-RX5]

## Reference ownership and turnstile completion

A receive hold and the message's destination right are distinct. The added original make-send-once call at0xfffffe000bcd0694 increments `port+0x8c` and `object+4`; the frontend lookup adds another reference. These producers supply the references actually consumed later, instead of starting results with an unexplained count. All four sender components preserve reference3 / send-once1.

```text
stage                              refs   send-once   receiver loan / port turnstile
original port initialization          1       0       declared initial loan separately
original make-send-once                2       1       unchanged
original receive lookup/retain        3       1       loan -> port turnstile
original sender return                3       1       turnstile retained; receiver selected
original ordinary loan completion     3       1       loan -> receiver+0x30; port+0x18=0
receive-hold release                  2       1       loan returned
copyout destination conversion        1       0       loan returned
```

Original receive-results sees the outstanding loan, calls the port completion adapter and detaches the sole turnstile at0xfffffe000bcce68c. Original0xfffffe000bd68a7c clears its proprietor, changes generation/kind word0x204 to0x300 and returns it to receiver+0x30 at0xfffffe000bd68c0c. Only afterward does0xfffffe000bcdce04 release the receive-object reference3->2. Later0xfffffe000bcca164 decrements send-once1->0 at0xfffffe000bcca2a4, returns receive name0x303 and releases reference2->1 at0xfffffe000bcca2c0.

This balances the two exercised increments/decrements, conditional on the initial reference1 and selected ordinary path. It does not establish total native FairPlay lifetime balance. The field receiver+0x398 remains PORT after release; its retained bytes alone are not evidence of another outstanding reference. [RX2-RX8]

## Validation metadata and bounded guard countercase

Original fixed-zone validation at0xfffffe000bd794c4 uses class24, class metadata and the within-16-KiB-page offset. Original file bytes have a zero reciprocal field; with those bytes the tested prefix reaches guard0xfffffe000c633aa0 after loan return and receive-hold release, before keyed hash, destination conversion or user copy.

Original zone startup case0 is freshly replayed. Only its record+0x30..+0x37 is transferred to0xfffffe000caec6b0:

| Zone-relative field | Width | Startup-produced value |
| --- | ---: | --- |
| +0x30 | 4 | Reciprocal0x01000000 =2^24 |
| +0x34 | 2 | Element length256 bytes |
| +0x36 | 2 | Page start adjustment0 bytes |

The eight transferred bytes are `0000000100010000`. For unsigned within-page offset d in[0,16383], the original arithmetic predicate is `u32(d *2^24) <2^24`. The bounded scalar proof shows this is equivalent to `(d &255)==0`. The private kmsg address is 16-KiB aligned, so d=0. Typed class24 is an additional explicit fixture. Page-extension metadata branches remain unexecuted. This transfer establishes the arithmetic input used by this component; it does not join the full zone/cache/page startup or prove native allocation admissibility. [RX6]

## Header deflation, trailers, status and zeroing

The original producer supplies a 44-byte kernel notification with ID70, NDR bytes `0000000001000000` and count7. Normal header/right copyout translates kernel destinationPORT into local receive name0x303. Original packing contracts the 32-byte kernel header to a 24-byte user header, preserving the 12-byte payload: `44 -8 =36` message bytes. No complex descriptor conversion or VM mapping occurs for this packet. [RX8]

| User header field | Width | Packed value |
| --- | ---: | --- |
| Bits | 4 | 0x1200 |
| Message size | 4 | 36 bytes; excludes trailer |
| Remote name | 4 | 0 |
| Local name | 4 | 0x303 |
| Voucher name | 4 | 0 |
| Message ID | 4 | 70 |

The KC trailer template at0xfffffe0007010a68 is independently read as 17 u32 words `(0,8,0,0,1,0,...,0)`. Options2 select an 8-byte trailer. Options0x07000006 select a 68-byte trailer; source code updates its size word to68 and uses sequence0, with retained template security words0/1, zero audit words and zero context. These are bytes from the selected original kernel-notification context, not a recovered daemon identity.

| Family | Capacity / options | Copyout request | Modeled bytes copied | Final X0 at0xfffffe000be80980 | Reference / send-once |
| --- | --- | ---: | ---: | --- | --- |
| 0 | 44 /2 | 36+8 =44 bytes | 44 | 0 | 1 /0 |
| 1 | 3072 /0x07000006 | 36+68 =104 bytes | 104 | 0 | 1 /0 |
| 2 | 44 /2; primitive return14 | 44 bytes | 0 | 0x10004008 | 1 /0 |
| 3 | 44 /2; preserve file-zero validation | None; guard prefix | 0 | Unknown; stopped before guard callee | 2 /1 |

Original call0xfffffe000bcc6708 targets exact `_copyout`0xfffffe000be7798c with `(KMSG+0x48,USER,length)`. The primitive's byte/protection result is modeled [RX7]. On modeled success, all copied bytes equal the independent source-packet/header/trailer oracle and the complete 8192-byte destination suffix stays0xa5. On modeled return14 the entire buffer stays0xa5 by explicit contract. Original code, rather than the primitive model, converts that result into final X0=0x10004008. Receiver+0x3a0 remains0: published receive status and final completion status are separate channels.

The 40-byte pack-result record contains message length36 and trailer length8/68 on success, with all remaining bytes0. It remains all-zero on the modeled copy fault. Destination right/reference consumption has already happened in both paths.

Original `_bzero` then executes over all 256 private kmsg bytes before the raw deallocation request. Independent checks require every destination store to be zero, exact 256-byte union coverage, copyout-before-zeroing-before-deallocation order and preservation of the following0xa5 guard byte. Stack-save stores in the `_bzero` prologue are accounted for separately. The source uses STP and DC ZVA; the fresh Unicorn CPU model supplies the latter's cache-block zeroing behavior. This verifies private byte/order effects, not native cache semantics.

The raw deallocation call at0xfffffe000bcc67a0 targets0xfffffe000bd74fcc with `(declared_zone,declared_stats,KMSG,256)`. Its effect remains modeled. Original cleanup and results/completion code then reach0xfffffe000be80980, where execution stops before return-to-user. Zeroing is therefore original executed code; allocator retirement and actual user return remain unknown. [RX5-RX8]

## Data and control boundaries

```text
original init + make-send-once + receive frontend/retain
  -> original wait / continuation storage
  -> STOP before scheduler selection
       == exact whole RAM/globals; separate sender CPU ==>
original no-senders sender -> original selection/release -> caller return0
       == exact whole RAM; explicit fragment registers/saved stack ==>
original continuation -> results -> loan return -> receive-hold release
  +-> file-zero validation -> STOP before original guard
  +-> startup-derived validation8 -> original header/right translation
       -> original user packing/trailer
       -> modeled _copyout byte/protection result
       -> original _bzero(256)
       -> modeled raw zone deallocation
       -> original completion -> STOP before return-to-user
```

No new Mach endpoint or message-emission location is established. The sender remains the previously established ID70 notification source, emitted at0xfffffe000bcd0598. `_copyout` here is a user-memory boundary, not a Mach send. The private receive name0x303 and its namespace are declared inputs. Existing FairPlay endpoints/emissions and daemon dispatch remain in their respective reports; the present join resolves lower receive/ownership/packing interfaces only. [RX2-RX8]

## Independent validation and reproduction

Validation recaptures all 80 bodies and exact symbols, 15 added instruction roles and every visited instruction. Fresh original no-senders and zone-startup replays verify the producer dependencies. Independent plans verify 61 overlay before images, 20 complete port/turnstile/receiver producer records, four unchanged sender joins and four results joins with only the declared saved-stack overlay. Independent oracles verify reference/right/loan stages, complete user buffers, source-derived packing, final status, 40-byte output records and all three 256-byte zeroing sequences.

Fresh CPU replay checks 13714 source visits, 3610 reads /23209 bytes, 3247 writes /20467 bytes, 28 complete final 1-MiB RAM images /29360128 bytes and 469 global ranges. It checks 572 logical PAC steps, four saved-stack authentications, four authenticated continuation edges and 36 declared API models. The latter comprise four raw turnstile allocations, twenty lower sender models and twelve results models. User-copy models request192 bytes and copy148; separate sender byte-copy effects cover176 bytes. Executors share Unicorn's ISA implementation, so fresh replay is not cross-engine verification; independent record/byte/arithmetic oracles add separate semantic checks.

Four fixed-width counterexample queries are UNSAT within their recorded domains: two reference increments/decrements restore initial references for initial values1..0x0ffffffd; reciprocal element validation equals 256-byte alignment within a16-KiB page; an unsigned header size at least32 contracts by8 without dropping below24; and representable message-plus-trailer lengths satisfying the recorded capacity bounds remain bounded. These are scalar facts, not proofs of native reachability, policy, protection or liveness.

```sh
cd /Users/___/dev/dylex/extracted

env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_receive_copyout.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_receive_copyout.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_receive_copyout.py
```

Expected validator output is four family summaries, counts20/4/4 and `all_checks_pass:true`. Recovery is O(image+source) time/space. Execution/replay is O(image+visits+RAM+effects) time and O(image+RAM+journals) space; four fixed-width solver queries have separate solver cost. These bounds provide no native latency, contention or scheduler guarantee.

## Bounded expansion and quality gates

| Impact | Further evidence | Interface resolved |
| --- | --- | --- |
| High | Original scheduler selection/invocation and actual saved-stack ownership | Replace the explicit fragment/call-context premises and establish block/wakeup control continuity |
| High | Complete startup-to-allocation-to-copyout zone/cache/page epoch | Replace the eight-byte validation transfer and declared allocator context |
| High | Complex RPC502/700 descriptor and actual daemon dispatch joins | Extend simple notification packing into the FairPlay work/reply contract |
| High | Original protected copyout, native fault/partial-copy and raw deallocation | Establish real user visibility, error effects and retirement |
| Medium | Nonzero ancillary work and special destination/loan cases | Extend ownership beyond the ordinary zero-state path |
| Medium | Native namespace/name writer and service registration | Replace the private0x303 fixture with an authentic task-local endpoint |
| Low | Exact symbol/private-type corroboration | Refine descriptive routine names without changing the established instruction evidence |

QG1: All conclusions are descriptive technical analysis; no normative conclusion is required.

QG2: RX1-RX8 identify assumptions, dependent results and falsification probes.

QG3: The increment covers original frontend/lookup/retain, loan/reference/right handling, header/trailer bytes, user-copy ABI, zeroing, raw-free ABI, final status and explicit stops. Existing endpoint/emission findings are preserved; full goal completion is not claimed.

QG4: Lengths and offsets use bytes; source-derived36+8=44 and36+68=104 extents, 256-byte zero coverage and fixed-width arithmetic domains are independently checked. No measured native timing or physical-unit calculation is asserted.

QG5: File-zero validation is retained as a guard prefix. Receive-hold versus destination-right ownership, thread receive status versus final X0, source zeroing versus modeled retirement and component RAM joins versus scheduler continuity are distinguished. Unexecuted branches and native behavior remain unknown.

QG6: Primary KC hashes/bodies/symbols/role words, startup/notification producers, overlay before images and all executed source instructions are verified. No external source revision is assumed to be the native host implementation.

QG7: The impact table bounds remaining interfaces and source-epoch gaps. The full interface-investigation goal remains active.
