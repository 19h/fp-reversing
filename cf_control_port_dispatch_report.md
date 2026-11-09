# Original CF control-port receive dispatch

The original run loop distinguishes control facilities from service-message
sources by the returned local Mach name. Wake messages bypass source lookup.
An empty dispatch root queue with a clear timer flag causes another receive
without completing the outer iteration. Kernel-timer messages enter timer
handling. A root message also enters timer handling when the original callback
has set `mode+0xa8`; the original caller clears that byte first. [CD1-CD8]

Nine finite private CPU cases now continue these branches into the original
service consumer. The subsequent daemon instruction suffix, complete receive/OOL/
reply buffers, final mode/queue objects and collection state match the checked
baseline. Control packets are declared synthetic inputs. Their native kernel
producers, delivery/ownership and actual scheduling remain unknown. This closes
a receive-side control-flow gap; the full interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| CD1 | The pinned daemon/kernel/cache corpus is the selected implementation | Addresses, exact symbols and cross-component interpretation | Recapture 43 original complete cache functions, 25 stubs, 3498 instructions and nine cache-file hashes; attest native image pairing separately |
| CD2 | Prior mode construction, service namespace and receive-return contracts apply | Construction and later service consumer | Freshly replay two baseline mode constructions and four original-kernel paths; compare complete states and original service suffix/buffers; native shared task/namespace epochs remain unknown |
| CD3 | The declared 24-byte control header and 68-byte zeroed audit trailer are returned successfully on the modeled set | Control routing by local name and finite sequence | Independently reconstruct all packet bytes/ordinals and check actual original reads/branches; recover actual root/timer/wake kernel messages before claiming their native format or provenance |
| CD4 | Mode/queue storage, auxiliary membership, CF backends, clocks and no-pending-work contracts apply | Control branches and later iteration | Check original mode/queue fields, all lower effects and final RAM; full runtime allocator, locks, ownership and concurrent work remain unexecuted |
| CD5 | Root queue head at +0x30 is empty, with declared reference-helper effects | Original root perform returns zero | Execute the original empty path, check queue type/head, all five drain returns and retain/release call pairs; nonempty work-item invocation and native reference counts remain unknown |
| CD6 | Mode timer array at +0x78 is NULL | Original no-fired-timer return and empty rearming | Check original timer-array load, three zero-return/rearm paths, deadline stores and complete final objects; nonempty timer scheduling/firing/cancellation remain unexecuted |
| CD7 | Original callback may be entered at its entry after source registration and before the run loop | Set-to-clear timer-flag composition | Compare full CPU/RAM function-entry handoffs, callback byte write and later original clear; native Block delivery and event ordering remain unknown |
| CD8 | Private logical PAC, source/helper/VM contracts and exact stop boundaries delimit execution | Original instruction and consumer evidence | Independent fresh-CPU replay, complete journals/RAM, five altered-record controls and publication audit; native IPC, scheduler, hardware PAC and successful FairPlay round trip remain unknown |

## Primary sources and execution scope

[Source capture](triage_evidence/cf_control_port_dispatch_source.json) adds four
complete bodies and one resolved import stub to the
[mode-construction corpus](cf_mode_construction_report.md):

| Exact original nlist identity | Entry | Captured instructions | Tested role |
| --- | --- | --- | --- |
| `__dispatch_runloop_root_queue_perform_4CF` | `0x185522410` | 324 | Empty queue-head path, reference-helper calls, return zero |
| `___CFRunLoopDoTimers` | `0x184771f9c` | 115 | NULL timer-array path, return zero |
| `___CFArmNextTimerInMode` | `0x18471cd5c` | 139 | NULL timer-array path, write two maximum deadline words |
| `___CFRunLoopModeIsEmpty` | `0x184756d34` | 82 | Check source sets; registered source1 makes result false |

The source records 43 functions, 25 stubs and 3498 instructions in total.
Capture of a full function is not execution of all its instructions. Nine full
cache-file hashes and canonical pointer fixups retain original provenance;
cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The new root-perform stub
at `0x1880868f0` resolves through original pointer bytes to `0x185522410`.
Reference helpers at `0x1855140d8`/`0x185514128` and collection cardinality at
`0x18472907c` remain explicit models with captured original identity/entry bytes.
[CD1,CD4,CD5]

[Profiles](triage_evidence/cf_control_port_dispatch_profiles.json),
[independent checks](triage_evidence/cf_control_port_dispatch_checks.json),
[probe](triage_evidence/probe_cf_control_port_dispatch.py) and
[independent replay](triage_evidence/replay_cf_control_port_dispatch.py) retain
complete CPU/object/model observations, instruction reads/writes and final
private snapshots. The independent replay imports no new probe and recomputes
all new packet/lower contracts. No native daemon/kernel/IPC/scheduler operation
or hardware PAC executes. No additional IDA query was required. [CD1-CD8]

## Receive and routing contract

All offsets/extents are bytes. Local names are u32 private fixture values;
none is identified with an equally numbered native or historical trace port.
The mode facility is `0x507`; auxiliary member effects exist in CF model state.
The separately replayed kernel graph contains the service membership only.
[CD2-CD4]

| Original site | Condition / input | Action |
| --- | --- | --- |
| `0x184757310` | Successful helper return | Load live local name from stack output `sp+0x64` |
| `0x184757314` / `0x184757320` | Live name equals root handle in W22 | Enter root drain |
| `0x184757324` / `0x184757328` | Queue pointer from `mode+0xa0` | Call original root perform; repeat while result bit 0 is set |
| `0x184757330` / `0x184757334` | Read byte `mode+0xa8` | Nonzero selects timer-flag branch; zero leads directly to another receive |
| `0x18475736c` | Root queue empty, flag clear | Call original receive helper again on set `0x507` |
| `0x1847573e4` | Timer flag nonzero | Clear byte `mode+0xa8`; preserve root name for subsequent timer route |
| `0x184757384` / `0x184757388` | Compare live name to u32 `runloop+0x50` | Classify wake name |
| `0x18475739c` / `0x1847573ac` | Compare live name to u32 `mode+0xac` | Classify kernel-timer name |
| `0x184757548` / `0x184757558` | Local name NULL or wake name | Skip source dictionary and reach iteration tail |
| `0x18475756c` / `0x184757588` | Local name equals root handle after flag processing | Call original timer handling |
| `0x184757594` / `0x1847575b4` | Local name equals kernel-timer name | Call original timer handling |
| `0x1847575c0` | Kernel-timer handling returns false | Reset 16 bytes at `mode+0xb8` to all ones |
| `0x1847575cc` | Either timer path returns false | Call original timer rearming |
| `0x1847576f4` / `0x184757718` | Remaining selected service name | Original dictionary lookup and source invocation |

Raw classification at `0x1847573f8` is 2 for wake, 3 for kernel-timer or
flagged-root, and 5 for the selected service. These are observed internal trace
values, not public result enums. Empty root receives with clear flag bypass this
classification site. The native main-thread dispatch-port branch is untested;
the inherited thread contract returns false for `pthread_main_np`. [CD3-CD8]

```text
successful receive on set
  |
  +-- local == root --> original drain until bit0 clear
  |                       |
  |                       +-- timer flag 0 --> receive again
  |                       +-- timer flag 1 --> clear flag --> DoTimers
  |
  +-- local == wake -------------------------------> iteration tail
  +-- local == kernel timer --> DoTimers ----------> iteration tail
  |                              |
  |                              +-- no timer fired --> ArmNextTimer
  |
  +-- local == selected service --> dictionary --> source --> daemon
```

The selected control routes do not consult `msgh_id` before their actions.
One additional wake case changes that word from 0 to `0x7f021234` and retains
the same route. This is a two-value observation supported by original routing
instructions, not a universal claim about arbitrary headers or native ingress.
[CD3,CD8]

## Timer flag, empty work and iteration state

The armed-root case uses original function-entry handoffs:

```text
original AddSource returns
  -> original CopyMode timer callback at 0x1848329a8
       byte mode+0xa8: 0 -> 1 at 0x1848329b8
  -> original run-loop entry
       declared root receive
       original empty queue drain returns 0
       byte mode+0xa8: 1 -> 0 at 0x1847573e4
       original DoTimers(NULL array) returns 0
       original ArmNextTimer(NULL array) writes max/max deadlines
       original ModeIsEmpty sees registered source1 and returns 0
       next iteration receives original-kernel service return
```

No pending root work item executes the callback in this case: the harness enters
the already-constructed original callback before run-loop entry. Native dispatch
Block delivery, callback ordering and concurrent mode access remain unknown.
The original empty root performer executes 36 instructions per call in the
selected path, above declared retain/release helpers. [CD4-CD8]

The empty timer path reads `mode+0x78 == NULL`; it does not invoke any timer
callback. `___CFArmNextTimerInMode` stores two u64 `UINT64_MAX` values at
`mode+0xb8`/`+0xc0` and returns. The kernel-timer caller additionally resets
that pair before rearming; the flagged-root caller does not execute that
caller-side reset. Final fields alone would conceal this branch distinction,
so the validator checks the original reset-store PC separately. [CD6,CD8]

The registered source1 remains in its set. Original `___CFRunLoopModeIsEmpty`
reads the source0/source1 set pointers and receives declared cardinalities 0
and 1; it returns false. Six such checks permit another outer iteration. An
empty queue/timer array therefore does not imply an empty mode. [CD4,CD6]

## Finite cases and preservation oracles

| Case | Declared controls before service | Original visits | Observed result |
| --- | --- | --- | --- |
| 0 | None; service variant 0 | 4390 | Application pre-pthread boundary |
| 1 | None; service variant 2 | 1788 | Run-loop return, raw value 4 |
| 2 | Wake | 2132 | Wake bypass, nonempty-mode check, service |
| 3 | Kernel timer | 2231 | No timer fired, reset/rearm, service |
| 4 | Empty root | 1957 | Immediate receive again, then service |
| 5 | Root after original timer callback | 2272 | Flag clear, no timer fired, rearm, service |
| 6 | Wake, kernel timer, empty root | 2744 | Outer and inner receive paths compose before service |
| 7 | Empty root, empty root | 2125 | Two original drains and two immediate receive-again paths |
| 8 | Wake with changed message ID | 2132 | Same wake route, then service |

Ten synthetic control returns are recomputed byte-for-byte. Each consists of a
24-byte simple header `(bits=0,size=24,remote=0,local=selected,voucher=0,id=value)`
and a 68-byte trailer `(type=0,size=68,remaining=0)`. No OOL region or transferred
right is modeled for these controls. Their generic fields are ABI test fixtures;
actual native control-message sizes, IDs, bits and trailer contents remain
unknown. The receive call retains capacity 3072 bytes, facility `0x507` and the
inherited raw options/timeout. [CD3,CD4]

Each case later consumes one exact original-kernel service return, including
148 bytes of message/trailer and 29 OOL bytes, through the existing kernel/CF
contract pairing. All nine original daemon suffixes and complete 8192-byte
receive, 16384-byte OOL and 384-byte reply buffers match the corresponding
baseline. Mode/queue bytes and model state also match; the application record
matches for case 0. Each case performs exactly one source-dictionary lookup and
source invocation, and none reaches generic reply-send PC `0x184757744`.
The eight variant-2 cases return raw 4; this does not establish successful
FairPlay processing. [CD2,CD4,CD8]

Independent replay checks 21771 original visits and 28311552 bytes (27 MiB) of
complete final private RAM for the nine new cases. Four fresh kernel replays
add 15172 visits and 4194304 bytes (4 MiB). Two fresh mode baselines add 6178
visits and 6291456 bytes (6 MiB). Aggregate validation is 43121 visits and
38797312 bytes (37 MiB) of final snapshots. Snapshot totals are not peak process
memory or exhaustive path coverage. [CD1,CD2,CD8]

Five altered-record controls are rejected: receive local name, receive ordinal,
empty-root return frame, timer-flag clear write and final timer flag. All source
reads/writes, relevant CPU/model frames and final RAM are independently checked;
whole-state agreement does not validate the declared native runtime contracts.
[CD3-CD8]

For this fixed source corpus, byte/function lookup extents are constants.
Recovery costs O(source + symbol data + cache bytes hashed); replay costs
O(instruction visits + journals + snapshots + image) time and space. Publication
rehash costs O(published bytes + links) time with O(manifest + largest parsed
JSON) space. All comparisons are exact; no statistical error bound or native
time-unit inference is made.

## Bounded architectural continuation

| Impact | Finding / remaining interface | Discriminating next evidence |
| --- | --- | --- |
| High | A port-set receive can represent control work without entering daemon MIG dispatch | Correlate actual native local names and auxiliary producer formats before classifying trace events as FairPlay requests |
| High | Root queue emptiness and timer-flag state jointly control receive progress | Recover nonempty root work-item execution and actual Block callback delivery/clearing order |
| High | Root/timer/wake kernel producers remain modeled | Recover original construct/timer/wake producers and membership in one common kernel namespace epoch |
| High | Successful daemon-to-kext round trip remains unknown | Correlate user-client open, selector routing, daemon service exchange and original driver outputs using the existing interface reports |
| Medium | NULL timer array establishes no-work behavior only | Recover nonempty timer-array ordering, deadlines, callback invocation and rearming/cancellation |
| Medium | Source1 membership keeps the mode nonempty after control work | Recover source invalidation/removal and mode teardown with port destruction/reference ordering |
| Medium | Empty root polling can consume several receives inside one outer iteration | Distinguish inner polls from iteration boundaries when correlating traces and scheduling observations |
| Low | Main-thread dispatch, timeout/no-message and malformed/error returns remain untested here | Extend finite cases where an interface question requires these branches |

## Quality gates

QG1: No normative premise is required; conclusions concern original byte behavior.

QG2: CD1-CD8 state assumptions, dependent results and falsification probes.

QG3: Named routine roles, incoming control/service interfaces, branch/callback
flow, ABI field widths, environmental contracts and bounded next steps are covered.

QG4: Exact byte extents, raw internal codes, counts, aggregate sums and fixed-corpus
algorithm costs are stated; no unsupported native timing units are assigned.

QG5: Synthetic controls and original-kernel service returns are separate; empty
work, callback harness ordering, main-thread and lifetime gaps remain explicit.

QG6: Original bytes/nlist/pointers, nine cache hashes, fresh independent replays,
semantic oracles and five rejected altered records provide provenance.

QG7: High/medium/low continuation scope is bounded by the table above.

[Preservation seal](triage_evidence/cf_control_port_dispatch_delivery.json),
[quality record](triage_evidence/cf_control_port_dispatch_quality_gates.json) and
[investigation status](interface_investigation_status.md) retain publication
checks and the active broader goal.
