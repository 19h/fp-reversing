# XPC transaction control producers, clean-exit requests and proc_info ABI

The captured implementation identifies the producers behind the [resource-lifecycle](xpc_resource_lifecycle_report.md) transaction flags. `xpc_transactions_enable` sets enabled byte+`0xa8`; `xpc_track_activity` sets tracking byte+`0xa9`; clean-exit/interrupt APIs set/clear byte+`0xaa`. The selected initializer stage can invoke enable or tracking from XPC_FLAGS. Dirty-process APIs join BSD 336/proc_info selector 8 and kernel flavors 1/2. A separate clean-exit control request uses interface 2/routine 715 and a Boolean `yesno` field. These are conditional source contracts; native flags, registration, permissions, image pairing, process effects, port identity and delivery remain unknown [TC1-TC7].

Evidence: [original source](triage_evidence/xpc_transaction_controls_source.json), [checks/models](triage_evidence/xpc_transaction_controls_checks.json), [reader](triage_evidence/recover_xpc_transaction_controls.py), [validator](triage_evidence/validate_xpc_transaction_controls.py), [preservation](triage_evidence/xpc_transaction_controls_delivery.json), and [quality gates](triage_evidence/xpc_transaction_controls_quality_gates.json). Cache UUID remains `2bd06591-e751-3e84-963f-b08dab6af23a`; daemon SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Kernel collection SHA-256 remains `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. No native API, process/signal/IPC request, recovered CPU path or IDB mutation executes.

```text
XPC_FLAGS -> selected initializer branch
               | bit4             | else bit3
               v                  v
          track_activity -------> transactions_enable
               |                      |
      proc_track_dirty(7/19)    optional track(1), dirty(1)
      signal(15,1)                   |
               +-----------+----------+
                           v
                proc_info syscall 336
                selector 8 / flavor 1 or2 -> kernel admission / control

exit_clean -> flag aa=1 -> count0: exit request
                        -> count!=0: optional interface 2/routine 715
interrupt  -> flag aa=0 -> optional interface 2/routine 715
```

Diagram flag offsets are hexadecimal. Operation715 is a control-plane operation number, not a recovered Mach message ID or FairPlay kext selector.

## Flag producers and selected startup branch

| Original routine | Unslid address | Established source action |
|---|---|---|
| `_xpc_transactions_enable` | `0x184b82720` | Enable byte and optional dirty registration/update |
| `_xpc_track_activity` | `0x184b82cbc` | Tracking registration, enable call and SIGTERM disposition request |
| `_xpc_transaction_exit_clean` | `0x184b84e00` | Set clean-exit flag; immediate exit or pending/control path |
| `_xpc_transaction_interrupt_clean_exit` | `0x184b86024` | Clear clean-exit flag and optionally send the opposite control value |
| `__vproc_transactions_enable` | `0x184b872d0` | One-instruction tail branch to enable |
| `__libxpc_initializer` | `0x184b6c360` | Environment/role setup and selected flag-driven calls |

These routines use the same once-root pointer slot `0x1e01c8ac0`; root+`0x10` is tested for completion and root+`0x18` supplies the context. The allocation fallback requests `0xd8` B with a NULL initialization callback. The captured once allocator publishes its resulting pointer at entry+8. The file template at the once root is zero, but the native runtime once/context state is not observed. No initial-zero value for context+`0xa8..0xac` is inferred solely from that file template.

The initializer retrieves the exact string `XPC_FLAGS`, parses the configured word, and stores it at context+8. At the selected convergence around `0x184b6c818..0x184b6c8b4`, bit13 sets defer byte+`0xc0`; bit4 selects track_activity; otherwise bit3 selects transactions_enable. Bit4 has priority over bit3. Role-specific work can precede/reload this configuration; these predicates apply to the selected loaded word and epoch, not every whole-initializer entry independently of its callees. Prior [registered-port consumers](registered_port_consumers_report.md) and [ProgramVars](initializer_programvars_report.md) reports retain the environment/header/startup prerequisites.

A full direct BL/B word census over all 72021 libxpc text words finds three calls to the queried controls: initializer->enable at `0x184b6c824`, track->enable at `0x184b82d80`, and the vproc tail branch. It finds no direct call to the two clean-exit APIs within that text scope. Indirect references, other libraries, dynamic lookup and native call paths are outside this census.

The daemon's 243 named imports are freshly parsed and compared with dyld_info/otool; none matches the five queried transaction/track/clean-exit/vproc controls. This bounded absence does not establish disabled transactions: initializer and external framework paths remain possible.

## Enable, dirty tracking and signal contract

All three flag bytes below belong to the once context, and the APIs use lock+`0xb0`. They are source state markers rather than proof of kernel state.

| State | Source transition / condition |
|---|---|
| Enabled byte+`0xa8` bit0 already set | Enable returns through unlock without reconfiguring this branch |
| Enabled bit clear, tracking byte+`0xa9` zero | Request proc_track_dirty(pid,1), then set enabled byte to1; the returned status is not tested here |
| Enabled bit clear, any nonzero counter+`0xac` | After setting enabled, request proc_set_dirty(pid, true) |
| Tracking byte+`0xa9` already nonzero | Track activity returns through unlock |
| Tracking byte zero | Set it to1 before unlocking/registration, choose flags7 or19 and request proc_track_dirty |

For the tracking request, defer byte+`0xc0` zero selects7, nonzero selects19. The SDK names their bits:

| Numeric flags | Exact composition |
|---:|---|
| 1 | PROC_DIRTY_TRACK |
| 7 | TRACK + ALLOW_IDLE_EXIT + DEFER |
| 19 | TRACK + ALLOW_IDLE_EXIT + DEFER_ALWAYS |

The track_activity return mask accepts exactly raw statuses0 or16 (`EBUSY`) before its normal continuation to enable and `signal(15,1)`. The SDK identifies these signal arguments as SIGTERM and SIG_IGN. The tracking byte was already written before the registration result; an enabled byte can also be written after an unchecked registration request. Neither local byte proves successful kernel registration.

The earlier [daemon descriptor setup](daemon_descriptor_source_report.md) records the same signal pair at `0x100097a74`, followed by kqueue/CF event-source setup. This is an architectural touchpoint between library initialization and daemon shutdown handling. Native disposition, event delivery, ordering/concurrency and successful shutdown remain unknown.

## Clean-exit flag and control-plane request

Exit-clean writes byte+`0xaa`=1 while holding the transaction lock. A zero u32 counter immediately selects `__exit(0)` at `0x184b84f2c`, independently of the enable-byte test used by the later transaction-end routine. With a nonzero counter it creates a transaction snapshot; if context byte+9 bit2 is set, it builds and submits the control request below. Interrupt-clean-exit first clears byte+`0xaa`; that same context bit gates its control request independently of the counter. None of these paths is executed here.

| Request field / argument | Exit-clean | Interrupt-clean-exit |
|---|---|---|
| `type`, uint64 | 6 | 6 |
| `handle`, uint64 | 0 | 0 |
| `self`, Boolean | true | true |
| `yesno`, Boolean | true | false |
| Interface argument | 2 | 2 |
| Routine argument | 715 (`0x2cb`) | 715 (`0x2cb`) |
| API submission call PC | `0x184b84ea8` | `0x184b860b4` |

The Boolean values are exact original `__xpc_bool_true`/`__xpc_bool_false` atoms, not inferred numeric fields. `__service_create_request` at `0x184b86128` sets type/handle/self using the original uint64/value setters, after which each caller adds yesno.

`__xpc_interface_encode_routine` at `0x184b8a790` has two representations: for its captured runtime-mode byte equal to1 it writes dictionary `subsystem=2` and `routine=715`, returning zero as the pipe-routine argument; otherwise it returns routine 715 in that argument. The interface helper obtains the pipe at context+`0x18` and calls `__xpc_pipe_routine` at `0x184b707e4`. Its role gates, reply audit checks and lower pipe state remain prerequisites. Prior bootstrap-pipe provenance is retained separately; the actual destination Mach name, live packet and receiver handling are unknown.

This establishes control-request schema and API emitter sites. It does not assign operation 715 to Mach msgh_id715 or demonstrate a native clean-exit acknowledgement. The clean-exit and interrupt callers have distinct raw error handling, including special handling for124 and, in interrupt,37; actual results remain unknown.

## Dirty-process user/kernel ABI

| Interface | User wrapper | proc_info selector / flavor |
|---|---|---|
| proc_track_dirty(pid, flags) | `0x18054b0ec` | Selector8 / flavor 1 |
| proc_set_dirty(pid, bool) | `0x18054b14c` | Selector8 / flavor 2 |

Both wrappers call original `___proc_info` at `0x180549100`; its SVC is at **`0x180549104`**, with X16=`0x150` (336 decimal). Their six user argument slots are:

| Slot | Value |
|---:|---|
| X0 | Call selector 8 |
| X1 | PID argument, low32 |
| X2 | Flavor1 or2 |
| X3 | Flags/dirty argument, copied through W3 and zero-extended |
| X4 | NULL buffer |
| X5 | Zero buffer size |

The wrappers return0 for a raw syscall result other than -1; for -1 they obtain the thread/fallback errno word. This errno-valued wrapper result is distinct from the raw syscall result and from a control-plane XPC result. No returned value is supplied by a native run in this increment.

The freshly verified original BSD table entry336 is named `proc_info`, has six arguments and records28 B for its u32-argument representation. Its authenticated handler slot `0xfffffe0007f2e9d8` resolves to `0xfffffe000c368544`. The native LP64 argument frame instead has fields at offsets0,8,16,24,32,40 B. The28 B table value is not that LP64 frame's extent.

The entry passes the six fields into core `0xfffffe000c368588`. Its signed-relative 20-entry jump table selects case8 at `0xfffffe000c368814`, which passes PID, flavor, argument and return-value pointer to dirty-control dispatcher `0xfffffe000c36a664`. Selected flavor 1 reaches lower call `0xfffffe000c2e7aec`; flavor 2 reaches `0xfffffe000c2e7f28`. These targets are recovered routing boundaries; their full mutations are not newly analyzed here.

The captured dispatcher performs target lookup and an admission call at `0xfffffe000c36a6c0`, with selector 8/flavor arguments. A nonzero return prevents the selected normal route. Additional credential/identity/permission branches exist, including another call at `0xfffffe000c36a7d8` on flavor 2. No policy result, privilege assumption or native state mutation is inferred from the user wrapper's availability. Kernel/cache/daemon pairing and runtime PAC remain separate prerequisites.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| TC1 | Pinned daemon, cache and collection define the inspected source contracts. | Rehash all used files/UUIDs, original BSD/fixup records and inherited ranges; require native image pairing separately. |
| TC2 | Once context, lock and loaded initializer word belong to the declared epoch. | Verify pointer publication and selected bit13/4/3 branches; trace role callees and actual environment before a whole-startup/native flag claim. |
| TC3 | Flag producers and normal callees execute with the captured ABI/lifetimes. | Check writes before versus after requests, full byte states, idempotence and ignored/accepted statuses. Local flags do not prove successful registration. |
| TC4 | Clean-exit count/protocol bit and request construction satisfy their prerequisites. | Check immediate-exit versus nonzero-count paths, exact Boolean atoms, request fields, interface/routine representation and distinct caller error branches. |
| TC5 | Pipe/control and dirty-process requests remain distinct interfaces. | Establish actual pipe destination/receiver and syscall result; do not equate operation 715, Mach message IDs, syscall 336, selector 8 and flavors 1/2. |
| TC6 | Original table/jump/frame records describe the matching ABI, while native admission and lower mutation remain unproved. | Check all three BSD pointers, twenty jump entries and selected argument loads/calls; recover lower controls and actual process credentials before permission/state claims. |
| TC7 | Named-import/direct-call absence has the finite stated scope. | Include indirect calls, dynamic lookup, other images and native startup before inferring that fairplayd never enables tracking or requests clean exit. |

## Bounded context, validation and quality gates

| Impact | Established observation | Remaining boundary |
|---|---|---|
| High | Explicit APIs and selected startup flags produce the transaction/clean-exit bytes. | Native environment, once context and effective flags remain unknown. |
| High | Local flag writes can precede or ignore kernel registration results. | Actual dirty-tracking state and native errors remain unknown. |
| High | Clean-exit control schema and BSD dirty-process ABI are separately identified. | Pipe receiver, kernel admission/mutation, process effects and delivery remain unknown. |
| Medium | Library tracking and daemon descriptor setup request the same SIGTERM disposition. | Native signal/kqueue epochs and shutdown ordering remain unknown. |
| Medium | Missing named imports do not exclude initializer/framework control paths. | Complete native callers remain unknown. |

Capture retains seventeen cache and three kernel compiler bodies: 2216 instructions/8864 B. It binds nine import stubs, seven strings, two Boolean atoms, BSD 336 and all twenty relative jump entries. Fresh recovery compares eighteen prior registered-port cache bodies, 24 resource-lifecycle bodies/4104 B and the complete 243-entry daemon named-import/section inventory with independent dyld_info/otool output.

Verification passes 89 exact instruction assertions, sixteen SDK assertions/one compilation, four unsatisfiable scalar queries, 2304 enable-state cases, 36 tracking cases, twelve clean-exit cases, 35 argument-width/route cases, eight initializer-bit cases and eight rejected evidence alterations. SIG_IGN's actual SDK definition is separately retained and hashed. These models do not execute recovered code, controls or malformed native fixtures.

Recovery costs O(S+F+E+C+W+K) time/space for selected bytes S, function metadata F, exports/nlists E, cache chain walks C, text census W and kernel/fixup data K, plus streaming hashes over H source bytes. Verification adds O(I+M) for instructions I and finite models M. Compiler/solver costs are separate; scalar queries each have a 10 s timeout. Selected local flag/argument operations have fixed size; initialization, pipe IPC, snapshot/logging, allocation, native lock progress, kernel admission/mutation and process effects are outside a fixed-runtime bound. Sizes/offsets are B; selectors and widths are explicit.

QG1: Factual interface/process-context analysis requires no normative premise.

QG2: TC1-TC7 state assumptions, dependencies and falsification probes.

QG3: Flag producers, selected initializer control, tracking/signal requests, clean-exit control schema and proc_info user/kernel routing are covered. Full native interfaces and the broad goal remain active.

QG4: Byte flags, u32 counters/status/PIDs, u64 fields/arguments, Boolean values, LP64 frame offsets, u32 representation size, relative jumps and selector namespaces are checked.

QG5: Source flags versus kernel registration, API/schema versus delivery, immediate exit versus last transaction end, named imports versus whole callers and table routing versus admission/mutation remain distinct.

QG6: Original compiler bytes, export/nlist/fixup/table/atom/string identities, fresh import/section/range comparisons, SDK/tool hashes and retained proofs/models provide provenance.

QG7: Impact-labeled producer/status/control/signal/caller observations are bounded above. Native policy/process effects, successful daemon-kext exchange and full-goal completion are not claimed.
