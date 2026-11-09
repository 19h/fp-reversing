# IOKit asynchronous requests, inherited lookup and completion messages

Original code establishes an async submission interface through Mach2866 and
a separate generic completion interface through message53/type150. For
FairPlay's inspected vtable, the legacy nonnull-wake-port route reaches inherited
async lookup that returns null for every selector, followed by Unsupported.
This conditional result does not establish a supported FairPlay async method,
an observed completion, or the behavior of other dispatch branches. [AC1-AC8]

[Original source](triage_evidence/iokit_async_contract_source.json),
[independent checks](triage_evidence/iokit_async_contract_checks.json),
[preservation](triage_evidence/iokit_async_contract_delivery.json) and
[quality gates](triage_evidence/iokit_async_contract_quality_gates.json)
retain evidence. No target instructions execute/emulate and no messages are
generated or transmitted. The [historical capture](zut_trace_report.md) still
ends with failed open. Earlier [filter](iokit_filter_policy_report.md),
[argument](iokit_structure_arguments_report.md) and
[connection](iokit_connection_lifecycle_report.md) contracts remain separate.

```text
async submission2866 -> immediate reply2966
    connection destination + MAKE_SEND wake-port descriptor + references
      -> kernel argument record -> guarded legacy async lookup
      -> FairPlay inherited default returns NULL -> Unsupported

separate generic completion API
    saved reference -> wake destination + width/error flags
      -> message53 / notification type150 -> kernel send helper
```

B denotes bytes. Addresses are unslid. User Mach names are32-bit; kernel
port pointers and64-bit reference words are64-bit. No numeric runtime name or
native endpoint identity is inferred from these static contracts.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| AC1 | Pinned collection/cache provide this build's original bytes | Addresses, records, bindings and defaults | Rehash/recapture all selected compiler bounds; attest native module pairing separately |
| AC2 | Connection, task, descriptor and policy guards hold | Applying the generic async method path | Establish real client/right/task identity and policy result; the historical open failed |
| AC3 | Client uses its inspected FairPlay vtable, legacy dispatch branch, nonnull wake port and applicable descriptor state | Inherited async lookup -> Unsupported | Check flags and original slots; do not generalize to every2866 request or alternate virtual ABI |
| AC4 | Selected calls return normally and referenced storage remains valid | Local argument/reference and sender behavior | Resolve transitive calls, aliases, concurrency and actual buffer ownership separately |
| AC5 | Map threshold selects the intended receiver format | Reference flag and32-/64-bit completion interpretation | Read actual task map limits and module ABI; image code does not attest a native receiver |
| AC6 | Actual SDK headers corroborate compatible user/kernel layouts/constants | Widths, fields, names and geometry | Compile28 assertions in two separate modes; SDK compatibility is not runtime identity |
| AC7 | Generic completion calls receive their declared valid references/argument counts | Sender fields and local zero coverage | Source checks cover count<=16 and8 reference words; no target callback/completion is invoked |
| AC8 | Prior common send/right contracts retain their premises | Emission frontier and ownership terminology | Preserve prior hashes; native queueing, consumption, whole error cleanup and balanced lifetime remain unknown |

## Submission ports and original emission

| Interface / site | Established contract |
| --- | --- |
| Public async structure wrapper `0x184e9d01c` | Calls IOConnectCallAsyncMethod at `0x184e9d04c`; scalar counts0 for this wrapper |
| IOConnectCallAsyncMethod `0x184e807e0` | Calls internal stub `0x184e79d1c` at `0x184e808bc` |
| Exact framework Mach emission `0x184e79f6c` | Message2866; expects reply2966; uses the previously resolved shared transport stub |
| Header destination | Connection name, COPY_SEND19; separate MIG reply right in local field |
| Wake-port descriptor | One port descriptor, MAKE_SEND20, original word0x00140000 at `0x184e79db4` |
| Kernel routine | Original MIG2866 index66 -> `0xfffffe000be383bc` |
| Received descriptor guard | Requires received send-right type17 at `0xfffffe000be3846c` |

MAKE_SEND describes creation of a send right from the supplied receive-right
name. It differs from the connection header's COPY_SEND and from the kernel's
received representation17. No actual right creation/transfer is observed.
The wake endpoint is distinct from the immediate MIG reply port. [AC1-AC2,AC6]

The request carries an inline64-bit reference array: structural count<=8,
with later method processing rejecting count0. The generic argument record
starts at local SP+80, version2. Its wake-port field+8 is a kernel pointer,
reference pointer+16 and count32+24; actual Kernel SDK assertions corroborate
these offsets and pointer width. Source writes the received wake pointer into
reference[0], and ORs bit0 when the calling task's map-limit comparison selects
the64-bit format. [AC1-AC2,AC5-AC6]

The complex request has one port descriptor and no Mach OOL memory descriptor
on the selected in-band path. Its source-derived user extent is
`104 + 8*referenceCount + 8*scalarInputCount + align4(structureInputBytes)`;
kernel extent adds12 B for header/port-descriptor expansion. This is an ABI
formula, not generated request bytes or a captured FairPlay invocation.
[AC1-AC2]

## FairPlay inherited async lookup

| Original client slot | Target and role |
| --- | --- |
| vtable+0x880, `0xfffffe000846b0e8` | IOUserClient::externalMethod, `0xfffffe000c562bc8` |
| vtable+0x978, `0xfffffe000846b1e0` | getAsyncTargetAndMethodForIndex, `0xfffffe000c562848` |
| vtable+0x968, `0xfffffe000846b1d0` | getExternalAsyncMethodForIndex, `0xfffffe000c5628f0` |
| vtable+0x970, `0xfffffe000846b1d8` | Separate FairPlay synchronous sparse router, `0xfffffe000a503cd0` |

On the selected legacy path, externalMethod tests argument-record wake field+8
and uses async slot+0x978 when nonnull. The adapter calls+0x968, whose entire
original body is BTI / MOV X0,0 / RET. It therefore returns null independently
of selector. The adapter returns that null value; externalMethod's continuation
returns `0xe00002c2+5 = 0xe00002c7`, SDK kIOReturnUnsupported.
The separately implemented17-selector synchronous table does not supply entries
to this inherited async lookup. [AC1,AC3-AC4,AC6]

The selection predicate is the wake field, alongside other guards; the Mach
routine number alone does not determine which virtual lookup occurs. No
unconditional rejection claim for all2866 requests is made. The async stub
publishes a nonzero method return through its simple MIG error-reply form;
that immediate reply is not an asynchronous completion message.
[AC2-AC4]

## Tagged references and the generic completion sender

Exact named wrappers sendAsyncResult64 at `0xfffffe000c569858` and
sendAsyncResult64WithOptions at `0xfffffe000c569864` reach shared anonymous
body `0xfffffe000c5695cc`. The former supplies options0. The sender derives
destination pointer `reference[0] AND ~3`. Low bit0 selects32-/64-bit formatting;
bit1 records the selected error-reporting state. The task-taking setter applies
the same map-limit threshold `0xf0000001` as async argument construction.
setAsyncReference64 preserves the existing low two bits and writes callback
and refcon at reference words1/2; it does not independently establish those
flags' provenance or native right ownership. [AC1,AC4-AC7]

The sender returns0 without sending when the masked destination is null.
With a destination, argument count>16 takes kIOReturnMessageTooLarge. A
supported count reaches the following source-built packet:

| Field | Original source / value |
| --- | --- |
| Header destination | Masked kernel wake-port pointer at message+8 |
| Header bits | 19, COPY_SEND; no complex bit |
| Local/reply and voucher | Zero in the initialized local message |
| Message ID | 53, store `0xfffffe000c569654` |
| Notification content type | 150, source constants at `0xfffffe000c56966c` / `0xfffffe000c5696c8` |
| Reference body | Reserved word0 remains zero; words1..7 copied as receiver-width values |
| Completion content |32-bit result followed by packed argument words |
| Exact kernel send call | `0xfffffe000c5697e0` -> common helper `0xfffffe000bcf55dc` |

The SDK also declares kOSAsyncCompleteMessageID57; it is a different constant
from the53 written by this inspected sender. The immediate2966 reply, generic
53/type150 completion and FairPlay RPC502/700 retain distinct identities.
No FairPlay caller or native completion is established here. [AC1-AC2,AC6-AC8]

For N result arguments,0<=N<=16, real SDK aggregate declarations and original
size arithmetic agree:

| Receiver format | Kernel message extent | User message extent after8 B header contraction |
| --- | --- | --- |
|64-bit |112+8*N B |104+8*N B |
|32-bit |76+4*N B |68+4*N B |

The64-bit content result is4 B and arguments start four bytes later; aggregate
alignment contributes a further4 B at the end. Seventeen size tuples are checked
against actual kernel/user SDK base sizes. Eight original SIMD zero stores cover
the local message's240 B maximum extent before field writes; the reserved word
and fixed padding derive from this specific initialization. This does not assign
values to unrelated structure-output buffers discussed in the preceding report.
[AC1,AC6-AC7]

Options bit0 selects raw common-send flags0x50001 when clear or0x10 when set;
timeout argument is0. Queue behavior remains subject to the common sender and
native state. The [existing kernel-send report](kernel_notification_send_report.md)
provides separate conditional lower contracts. Selected send errors can set
reference flag bit1 before logging; that is separate from delivery or right
retirement. [AC4,AC7-AC8]

Exact releaseAsyncReference64 at `0xfffffe000c56946c` masks both flag bits,
requests `_ipc_port_release_send` for a nonnull destination and returns0.
It does not clear reference[0]. Neither this source request nor absence of a
direct release call in the selected lookup adapter establishes whole-call
ownership balance: common MIG cleanup, retained references, caller behavior and
final native retirement remain unresolved. No lifecycle-fault experiment is run.
[AC4,AC8]

## Verification and bounded continuation

Thirteen kernel and three cache compiler-bounded bodies retain1440 instructions
/5760 B. Sixty-eight instruction assertions, four FairPlay vtable bindings,
one original MIG record,28 actual SDK assertions in two compilation modes/four
header hashes, eight zero-store geometries,17 notification extents and nine
rejected static alterations pass. Target visits, emulation, new runtime
observations and generated wire payloads are0.

| Impact | Remaining evidence | Architectural question |
| --- | --- | --- |
| High | Actual connection, dispatch flags and callback identity | Which authentic clients reach async or alternative dispatch |
| High | Native request/error cleanup and saved reference owners | Complete wake-right ownership and retirement |
| High | Completion caller and user notification receiver | Full emission/delivery/callout correspondence |
| Medium | Large-buffer, compatibility and other inherited virtual branches | Coverage beyond the selected legacy/in-band path |
| Medium | Static and dynamic callers of completion helpers in relevant components | Whether any FairPlay path uses this generic completion facility |

Reference/default lookup and bounded geometry arithmetic take O(1) time/space;
packet copying is O(N), with N<=16 here. Capture takes O(collection+fixups+
symbols+selected cache files) time and O(collection+capture) space. No native
timing/concurrency measurement is inferred. The full interface goal remains active.

## Quality gates and reproduction

QG1: descriptive interface findings require no normative conclusion.
QG2: AC1-AC8 identify assumptions, dependent results and falsification probes.
QG3: async submission, wake/reference ABI, conditional inherited lookup,
completion format/emission and release interface are covered; native use remains unknown.
QG4: explicit rights, word widths, count bounds, header expansion/contraction,
padding, exact sizes and algorithm bounds are reproducible and SDK-checked.
QG5: immediate reply versus completion, MAKE_SEND/COPY_SEND/received type,
conditional lookup versus all requests and release request versus balance are distinct.
QG6: original bytes, records/chains, exact symbols and real SDK declarations
supply verified provenance; no native execution or target changes occur.
QG7: five bounded continuation questions above have impact labels.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_iokit_async_contract.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iokit_async_contract.py
```
