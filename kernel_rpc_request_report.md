# Original FairPlayIOKit constructor to kernel RPC request queue

The original kext constructor now executes continuously into the original kernel RPC request prefix in a private CPU/RAM model. Four cases cover RPC502/host slot17 and RPC700/host slot34 with either an absent or prebound kernel reply port. Each reaches actual original queue insertion and special-reply linkage, then stops before common receive at `0xfffffe000bcc83b4`. No packet, register, stack, SIMD or RAM replacement occurs at the constructor-to-transport boundary. This establishes a conditional source-level connection; native endpoint registration, VM backing, scheduling and daemon delivery remain unknown.

The [ZUT capture](zut_trace_report.md) remains historical runtime evidence of a failed UserClient open, with result `0xe00002c2` and a null connection port. It contains no observed RPC502/700 exchange. The private execution below does not change that interpretation.

## Primary evidence and execution boundary

Original KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses are unslid logical KC virtual addresses. Raw file bytes and decoded chained pointers are distinguished in the existing image reader. Exact compiler function boundaries and nlist records are recaptured independently.

| Artifact | Contents |
| --- | --- |
| [Source](triage_evidence/kernel_rpc_request_source.json) | 123 complete kernel functions / 15666 A64 instructions; thirteen additions / 920 instructions; 21 request-role instructions; four original zone specifications |
| [Profiles](triage_evidence/kernel_rpc_request_profiles.json) | Four fresh zone producers;22 environment components; four continuous constructor/request executions; complete compressed 1 MiB RAM states, CPU frames and effects |
| [Checks](triage_evidence/kernel_rpc_request_checks.json) | Independent source recapture, complete-record/packet/reference/accounting oracles, fresh CPU replays and two scalar proofs |
| [Preservation](triage_evidence/kernel_rpc_request_delivery.json) | Prior 6304 artifact hashes and exactly six owned reporting changes |
| [Quality gates](triage_evidence/kernel_rpc_request_quality_gates.json) | Increment-specific QG1-QG7 and validation totals |
| [Prior manifest](triage_evidence/kernel_rpc_request_prior_manifest.json) | Frozen preceding publication; SHA-256 `14754d1d7d669f38aaf306a3b0bf54d5099eb49bb59817ad8e50764649a207c1` |

The source-built environment is prepared before entering the kext constructor. Separate CPU invocations initialize two service port objects and, for prebound cases, the reply port. Their complete RAM/globals are transferred to the constructor invocation. These setup calls are explicit artificial call epochs. After constructor entry, control follows original kext/kernel instructions continuously, with only the primitive contracts listed below. Execution ends before any receive implementation, so no response or constructor return is manufactured.

```text
original zone startup components -> special-space/bootstrap and service ports
                                                  |
                       declared host slot17 or34 holds service object
                                                  |
original kext constructor -> original host lookup/send-reference acquisition
                         -> original request packing and RPC wrapper
                         -> original kmsg allocation/cache pop/zero validation
                         -> descriptor signing -> reply creation or reuse
                         -> original null-voucher path -> right copyin
                         -> original send -> actual queue insertion
                         -> original special-reply/destination linkage
                         -> STOP before common receive
```

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| KR1 | Original KC and supplied kext bytes represent the target under investigation. All address/semantic claims depend on this. | Recapture original hashes, complete bodies, decoded instructions, nlist records and every executed instruction. Match a live host build separately; live correspondence is unknown. |
| KR2 | Declared thread/task/CPU/owner, type metadata, object backing and bounds represent a consistent private epoch. All private executions depend on this. | Check disjoint typed cells and zone geometry; inspect every read/write and complete final object; replace with independently captured target state before making native claims. Native allocation provenance is unknown. |
| KR3 | Separate source zone/bootstrap/port initialization calls can supply the chosen later call epoch. | Compare complete transferred RAM/globals and ordered overlay before images. Actual boot ordering, storage lifetime and host registration writer are unknown. |
| KR4 | Host slots17/34 contain the selected active ordinary service ports and their source-generated receive context. Endpoint identity depends on this explicit fixture. | Execute original host lookup and send-reference helper; verify selected object/name/reference changes. Identify the native registration producer and destination daemon namespace independently. |
| KR5 | One zeroed256-byte kmsg cache element is populated after source startup. Allocator success depends on this declared inventory. | Execute original allocator, cache pop, statistics increment and zero validation; verify guard and consumed slot count. Source/native population of this inventory is unknown. |
| KR6 | Kext allocation, string length, staging allocation, VM-copy creation, byte copy, keyed hash, tag and preflight contracts have the declared outcomes. Successful request-prefix reachability depends on these outcomes. | Audit exact arguments, return values, clobbers, byte effects and hash inputs. Execute underlying implementations or provide matched native observations to remove each contract. VM-copy backing and native hash/authentication validity are unknown. |
| KR7 | Logical return/data/code PAC permits pointer/control-flow tracking without cryptographic authentication. Pointer interpretation and execution depend on this model. | Verify exact PAC instruction bytes, operand registers, modifiers and indirect targets. Test authenticated values on a matching native execution separately; hardware authentication is unknown. |
| KR8 | Four CPU cases and two full-word scalar identities cover only their recorded domains. | Independently replay complete states; compare fresh/prebound and502/700 variants. Other destination types, voucher states, allocation failures, concurrent receivers, receive/reply delivery and scheduler interleavings remain unknown. |

## Original routines and contracts

Names below are exact nlist names only where stated; other descriptions are recovered roles, not recovered original names. All additions have complete compiler-bounded bodies in the source artifact. Captured bodies for modeled primitives are not counted as executed bodies.

| Start address | Instructions | Name or recovered function | Execution in this increment |
| --- | ---: | --- | --- |
| `0xfffffe000bcf5e28` | 5 | Exact `_mach_msg_rpc_from_kernel_proper`; supplies interruptibility and policy arguments | Original wrapper |
| `0xfffffe000bcf27ac` | 4 | Exact `_host_priv_self` | Returns original host object identity |
| `0xfffffe000bcf258c` | 86 | Exact `_host_get_special_port` | Original slot selection, lock and result publication |
| `0xfffffe000bcd00bc` | 74 | Typed active-port send-reference acquisition | Original class22 validation, lock, send count and object retain |
| `0xfffffe000bcf5f18` | 3 | Exact `_mig_get_reply_port` | Original constructor reply-port helper; common RPC later supplies the bound reply |
| `0xfffffe000bcc2390` | 69 | Internal descriptor-pointer signing | Original type1 descriptor branch; logical PACDA discriminator `0x5d4f` |
| `0xfffffe000bcd0628` | 27 | Locked MAKE_SEND_ONCE reference producer | Original reply send-once count and object-reference increment |
| `0xfffffe000bd57150` | 60 | Thread voucher-context read with original lock fast path | Original null-context path |
| `0xfffffe000bcd9e98` | 41 | Fallback voucher construction/selection | Original no-task-voucher path returns NULL |
| `0xfffffe000bcd8264` | 48 | Voucher-to-port conversion | Original NULL input returns NULL |
| `0xfffffe000bcc0f9c` | 234 | Send preflight | Body captured; result0 remains a primitive contract |
| `0xfffffe000bcd9f3c` | 161 | Message tag helper | Body captured; result0 remains a primitive contract |
| `0xfffffe000c647f10` | 108 | Exact aliases `_memcpy`, `_memmove` | Body captured; disjoint byte-copy effect remains a primitive contract |

The common RPC routine at `0xfffffe000bcf59e0` is inherited source, not a new addition. It prepares the request, reads `thread+0x3f0`, creates a reply port only when absent, writes that reply pointer into the internal header and calls right copyin. The actual kernel send call is at `0xfffffe000bcf5ba8`, targeting `0xfffffe000bcc7040`. These are source-established callsites under KR1; execution reachability is conditional on KR2-KR7.

## Port direction, rights and emission

| Stage | Port/object relation | Original location | Established result |
| --- | --- | --- | --- |
| Destination discovery | Host slot17 for502; slot34 for700 | `_host_get_special_port` at `0xfffffe000bcf258c` | Chosen object returned after acquiring a send right/reference |
| Reply binding | Kernel caller thread -> special reply port | Creator stores `thread+0x3f0`; common RPC reads at `0xfffffe000bcf5a6c` | Fresh and prebound cases converge on the same reply identity |
| Local reply insertion | Internal request header+0x10 -> bound reply object | `0xfffffe000bcf5b2c` | Original constructor NULL local pointer replaced by original common RPC code |
| Right copyin | Remote COPY_SEND19; local MAKE_SEND_ONCE21 | Call `0xfffffe000bcf5b40`; helper `0xfffffe000bcc9718` | Internal remote/local dispositions17/18; destination send count2; reply send-once count1 |
| Request emission | Kmsg -> service port queue | Common send call `0xfffffe000bcf5ba8`; queue routine `0xfffffe000bcc7c34` | Actual original ring insertion; queue count1; no native message emission |
| Reply linkage | Reply port -> destination/send turnstile | Common call `0xfffffe000bcf5c14` -> `0xfffffe000bccef30` | Reply sync-state1; destination pointer retained; primary turnstile hold1 |
| Receive frontier | Current thread waits on reply port+0x10 | Call `0xfffffe000bcf5c44` -> `0xfffffe000bcc83b4` | Exact receive ABI captured before execution |

Private object addresses are fixture coordinates, not Mach port names or native identities. The recipient task-local names `0x303` and `0x403` are declared receive names on the two source-initialized service objects. No daemon-side namespace conversion executes here. The actual native host-special-port population and its relation to the ZUT guest endpoints remain unknown. [KR2-KR4]

## Data and control flow results

| Field or state | Constructor boundary | Queued request / receive frontier |
| --- | --- | --- |
| Request ID | 502 or700 | Preserved |
| Send byte count / reply capacity | 88 /400 bytes as call arguments | Preparation sets header size88; caller capacity remains400 |
| Header bits | `0x80001513` | `0x80111211` after common voucher/right processing |
| Header size word | 0 | 88; original preparation supplies this field |
| Remote pointer | Source-selected service object | Same object |
| Local pointer | NULL | Source-created/reused bound reply object |
| Descriptor/body bytes | One internal type1 descriptor and original constructor body | Descriptor pointer and complete remaining body preserved under logical PAC |
| Voucher | No thread/task voucher in declared epoch | Original NULL-voucher path; voucher header bits still present |
| Destination references / send rights | 2 /1 after original host lookup | 5 /2: message send reference, temporary RPC object hold and reply-link object hold are distinct |
| Reply references / send-once rights | 1 /0 if prebound; absent otherwise | 2 /1 after original MAKE_SEND_ONCE |
| Kmsg storage | Declared zeroed populated cache element | Original256-byte allocator/container, inline header/body and self-linked queue ring |
| Thread receive capacity | Setup epoch | `thread+0x388 = 0xffffffff`; receive fields cleared by original RPC prefix |
| Receive arguments X0-X4 | Not applicable | `(reply+0x10,0,1,current_thread,0)` |

The four finite executions are:502/fresh,502/prebound,700/fresh,700/prebound. Fresh cases execute 6517 original instructions each; prebound cases execute 6376 each. Four full CPU/RAM snapshots at the original RPC wrapper verify uninterrupted handoff without packet imports. Each final kmsg is independently reconstructed byte-for-byte, including queue pointers, internal header/body, trailer, descriptor count and modeled hash-derived field. Complete destination, reply and turnstile records, unselected service-port preservation,256-byte allocator accounting and one send-accounting event are checked separately. [KR2-KR8]

Validation covers 30 source components and 27687 original instruction visits, including 25786 visits in the four continuous requests. Fresh replay checks 10759 writes / 83350 bytes and 3824 reads / 22986 bytes, 98 declared primitive model calls, 30 final boundaries and 31457280 final RAM bytes. The four full caller-to-RPC handoffs are additional intermediate-state comparisons.

One cache slot is an explicit input, while cache pop,256-byte zero validation and accounting are original code. Raw reply/turnstile storage remains modeled; initialization, binding, rights, locks, queue insertion and linkage are original code. Tag, preflight and keyed hashing remain separate primitive contracts. No original whole host lookup, whole kmsg allocator, whole RPC transport, port lock or queue-send helper is replaced by a success model in these executions.

## Reproduction and validation

Run the recovery, probe, independent validation, seal, publication and read-only publication audit in that order. Commands use the existing ZUT Python environment and local Z3 installation; paths and versions are environment-specific dependencies, not native kernel execution.

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_rpc_request.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_rpc_request.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_rpc_request.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/seal_kernel_rpc_request.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/verify_kernel_rpc_request_publication.py
```

Recovery/CPU/replay complexity is O(image bytes + source visits + copied RAM bytes + journal effects) time and O(image bytes + one CPU RAM map + journals) working space. Each private RAM map is 1048576 bytes. The two fixed-width SMT counterexample queries cover low32 mode equivalence and preservation of the remote disposition byte under local/voucher-bit insertion; both must be UNSAT. They do not generalize the finite CPU paths to arbitrary environments. Integer counts and byte sizes are exact; source/native uncertainty is qualitative and explicitly bounded by KR1-KR8.

A journal-order defect was caught during independent validation: the reused constructor helper installed globals before their declared before-image observation. The probe now restores original logical bytes first, then imports the source environment and records caller overlays in order. An additional independent bootstrap-publication oracle detected an omitted kernel-space global in the inter-component transfer list. Both special-space publication cells are now tracked and transferred. Regenerated profiles and the final independent before-image/publication checks cover both corrections.

## Bounded next investigations

| Impact | Pattern / opportunity | Resolving evidence |
| --- | --- | --- |
| High | Queue insertion is now joined to the original caller; native destination identity is still a separate prerequisite. | Recover the actual host-special-port registration writer and correlate its port/namespace lifetime to the daemon's receive endpoint. |
| High | The queued request can become a producer for the existing original dequeue/namespace/descriptor components. | Transfer the complete queued state to an explicitly defined receiver epoch; retain scheduling and task-context changes as declared boundaries. |
| High | Internal type1 descriptor pointer reaches transport unchanged, but authentic VM-copy creation/backing remains unknown. | Join the staging VM-copy producer to actual descriptor copyout and daemon mapping without substituting an independently fabricated packet. |
| Medium | Null-voucher execution exposes an environmental branch previously hidden by whole-transport models. | Recover independent voucher-context producers and non-NULL conversion paths; preserve reference ownership separately. |
| Medium | Tag, preflight and keyed hash are now the remaining transport-prefix helper contracts. | Execute their original bodies with source-derived policy/authentication state, or retain explicitly conditional results. |
| Low | Port rights, object holds and turnstile primary holds have separate lifetimes. | Carry all three ledgers through receive/copyout and eventual cleanup; do not infer balancing from send success alone. |

## Quality gates

- QG1: Technical source/ABI/IPC analysis; no normative conclusion required.
- QG2: KR1-KR8 identify assumptions, dependent claims and explicit falsification probes.
- QG3: Routine roles, incoming reply context, outgoing request queue, emission callsites, data/control/environment contracts and report integration are covered within this increment. The broad investigation remains active.
- QG4: Exact byte counts, addresses, records, journals, arithmetic domains and executable reproduction steps are recorded; no native timing or numerical error estimate is inferred.
- QG5: Header size0 versus send size88, voucher NULL versus disposition bits, rights versus object holds, source initialization versus inventory population and source-level versus native execution are reconciled explicitly.
- QG6: Complete original function bodies, nlist records, instruction roles, raw zone specifications, every visited instruction and fresh CPU effects are independently checked against primary local bytes.
- QG7: Bounded high/medium/low follow-ups and their missing evidence are recorded above; native round trip, daemon delivery, actual VM backing, scheduler behavior and PAC remain unknown.
