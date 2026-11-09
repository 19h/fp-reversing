# Original CF wake send, dispatch auxiliary vectors and libkernel retry ABI

Original-byte composition now follows `CFRunLoopWakeUp` through `_mach_msg`,
`_mach_msg_overwrite`, the installed dispatch auxiliary-data callback,
`_mach_msg2_internal` and the raw Mach trap stub. The remaining injected result
is at `SVC #0x80`, selector -47; no direct `_mach_msg` result model remains in the
new cases. Kernel entry and message delivery do not execute.

For the original WakeUp options `0x11`, the original lower wrapper retries raw
`MACH_SEND_INTERRUPTED` results with identical packed arguments. Such an
intermediate status does not reach CF in the tested streams. The installed
version-3 callback table selects the message-queue call option. An empty voucher
TLS slot uses scalar transport; a declared nonempty voucher context makes the
original callback produce 40 B of auxiliary data and selects two-record vector
transport. The 24-byte wake header remains unchanged in either form.

This extends the [wake constructor/emitter report](cf_runloop_wake_port_report.md).
Its directly injected interrupted return remains a counterfactual CF diagnostic
test. The new cases resolve the lower retry behavior for the pinned bytes and
options. They do not establish native syscall-return feasibility, queue-full
conditions, timing, authentication, successful FairPlay processing or a live
daemon-to-kext transaction. The full investigation remains active.

## Primary evidence and reproduction

Records: [source capture](triage_evidence/cf_wake_send_wrapper_source.json),
[execution profiles](triage_evidence/cf_wake_send_wrapper_profiles.json),
[independent checks](triage_evidence/cf_wake_send_wrapper_checks.json),
[preservation seal](triage_evidence/cf_wake_send_wrapper_delivery.json) and
[scoped gates](triage_evidence/cf_wake_send_wrapper_quality_gates.json).
Original cache/kernel bytes and exact nlist records establish the routines.
The capture hashes nine cache files and retains original pages, callback pointer
fixups, the auxiliary constant and the original kernel trap-table record.
Pinned public `mach/message.h` supplies ABI nomenclature; its exact revision
match to this binary is unknown and its hash/reference are retained separately.

| Original routine | Entry | Instructions | Established role |
| --- | --- | ---: | --- |
| `_mach_msg` | `0x180547f94` | 9 | Supplies null overwrite-receive pointer and calls overwrite wrapper |
| `_mach_msg_overwrite` | `0x180550848` | 157 | Calls auxiliary hook, constructs scalar/vector packet and packs eight slots |
| `_voucher_mach_msg_fill_aux` | `0x18553c2a8` | 19 | Reads TLS context; returns zero or writes 40 B |
| `_mach_msg2_internal` | `0x18055a894` | 64 | Masks interrupt flags and implements send/receive retry logic |
| `_mach_msg2_trap` | `0x180547c18` | 3 | Loads selector -47, reaches intercepted SVC, returns |
| Kernel `mach_msg2_trap` binding | `0xfffffe000bcdd73c` | 274 | Complete body captured; not entered in these cases |

The complete capture has 173 kernel routines / 22684 instructions and 50 cache
routines plus 26 four-instruction import stubs / 3992 instructions. The new
kernel handler accounts for 274 captured instructions; its capture is static
provenance, not an additional executed kernel case. Original daemon, kext C/call
listing, analysis and ZUT files are preserved. Reference files suffice; no new
IDA query or database mutation is required.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_wake_send_wrapper.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_wake_send_wrapper.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_wake_send_wrapper.py
```

Run from `/Users/___/dev/dylex/extracted`. The
[probe](triage_evidence/probe_cf_wake_send_wrapper.py) and
[independent replay](triage_evidence/replay_cf_wake_send_wrapper.py) separately
implement the new boundaries; the replay does not import the new probe. The
validator recaptures backing bytes and replays all new cases and fresh prior
components. All SVCs are intercepted. Original SVC words are counted as visited,
with declared effects, rather than described as executed native instructions.

## Assumption register

All replay findings depend on SW1-SW4. Native context attribution additionally
depends on SW5, status interpretation on SW6, public ABI names on SW7 and
cross-image interpretation on SW8. Exact captured bytes and table records do
not depend on the declared trap returns.

| ID | Assumption or evidence boundary | Stress test or falsification probe |
| --- | --- | --- |
| SW1 | Pinned kernel/cache/daemon identities are the analyzed build. Effective native image selection is unknown. | Rehash nine cache files, original inputs and complete bodies; recapture the Mach table pointer, name and handler. |
| SW2 | Private task/namespace, CF factory, zone and receiver-loan epochs retain their declared contracts. | Fresh four kernel/five CF factory/one timer startup/three fixed-zone/four loan replays and unchanged semantic fields/buffers. |
| SW3 | Original code uses the installed dispatch table produced by the original initializer; auxiliary TLS state is explicitly seeded. Native thread context is unknown. | Compare root pointer/table/callback, empty TLS case, nonempty TLS case, all 40 output bytes and both complete vector records. |
| SW4 | PAC is interpreted logically, and inherited lower runtime/collection/copy/allocation/lock contracts remain explicit. | Check source bytes, full CPU/journals/patches/final memory; hardware-key/native allocation validation remains absent. |
| SW5 | The explicit external-waker function entry represents a separate waker after original run-loop gate clear. Native caller, scheduling and ownership are unknown. | Preserve waiting-state memory/CPU hashes and disjoint waker stack; trace real callers separately. |
| SW6 | Each SVC return changes X0 to the supplied status and preserves other CPU state and memory. This is a declared trap model. | Check full before/after state and memory hashes; inject finite success/timeout/interrupted/nonretry streams; native status feasibility needs kernel execution. |
| SW7 | Pinned public header names describe the numeric options/vector layout. Exact target-source revision equivalence is unknown. | Rehash the retained header, compare binary-produced layouts and numeric masks independently; retain mismatches as unresolved if found. |
| SW8 | The raw trap selector and original kernel table record identify the static destination; a live exception-dispatch crossing is unknown. | Independently decode the authenticated table pointer, argument metadata, parallel name and handler bytes; do not infer delivery from this binding. |

## Continuous control flow and modeled boundary

```text
original CF factory -> mode/source registration -> original run-loop gate clear
  -> declared external-waker function entry
  -> original CF wake header stores and send call 0x18473af30
  -> mach_msg 0x180547f94
  -> mach_msg_overwrite 0x180550848
       -> installed dispatch fill_aux callback (once)
       -> scalar or two-record vector packing
  -> mach_msg2_internal 0x18055a894
       -> raw trap stub: X16=-47
       -> SVC 0x180547c1c [status-only model]
          interrupted -> original retry -> same raw trap
          other selected status -> unwind wrappers -> original CF check

static kernel table binding: -47 -> 0xfffffe000bcdd73c
                                   [captured, not entered]
```

Original callback invocation is at `0x18055091c`; original packed wrapper call
is at `0x180550a24`. `_mach_msg2_internal` first calls the trap at
`0x18055a8dc`, then uses `0x18055a918` for each send retry. Return through the
original raw stub reaches `0x180547c20`, a `RET` instruction. The final wrapper
status reaches CF at `0x18473af34`. The selected invalid-data result reaches the
original CF diagnostic boundary `0x1848d4168`; its body is not executed.

## Exact scalar and vector trap arguments

The input header is `<6I>(0x13,24,0x807,0,0,0)`, little-endian. CF supplies
`mach_msg(header,0x11,24,0,0,0,0)`. The original wrapper's eighth parameter is
zero. The original initializer publishes table `0x1e24b27d0` at root
`0x1ed83e8d8`; its leading scalar is 3 and callback at offset 40 resolves to
`0x18553c2a8`. The callback is invoked exactly once per send-wrapper invocation,
including cases with repeated raw trap attempts.

| Trap slot | Empty TLS auxiliary context | Nonempty declared context | Meaning in this composition |
| --- | --- | --- | --- |
| X0 | Original 24-byte header pointer | Original 48-byte vector pointer | Data pointer |
| X1 | `0x400000011` | `0x500000011` | MQ-call flag; vector flag only in second form; low options `0x11` |
| X2 | `0x1800000013` | `0x200000013` | Header bits low32; send byte count 24 or vector count 2 high32 |
| X3 | `0x807` | `0x807` | Remote low32 / local high32 |
| X4 | 0 | 0 | Voucher low32 / message ID high32 |
| X5 | 0 | 0 | Descriptor count low32 / receive name high32 |
| X6 | 0 | 2 | Receive byte capacity or vector count low32 / priority high32 |
| X7 | 0 | 0 | Timeout |
| X16 | Signed -47 | Signed -47 | Raw Mach selector |

The pinned header calls `1<<34` `MACH64_SEND_MQ_CALL` and `1<<32`
`MACH64_MSG_VECTOR`. These names describe requested transport options, not proof
that native kernel policy accepted a particular endpoint. Low options `0x11`
remain send plus send timeout, with zero timeout. There is no receive operation
in these cases despite the vector form carrying receive metadata.

All header fields are preserved through the selected raw status streams.
Simple-header packing sets descriptor count to zero without reading a body
count beyond the 24-byte header. The vector records are 24 B each, LP64 layout
`<QQII>`:

| Positional record | Data pointer | Receive address | Send size | Receive size |
| --- | --- | --- | ---: | ---: |
| 0, message | Original wake header | 0 | 24 B | 0 B |
| 1, auxiliary | Original callback output on wrapper stack | 0 | 40 B | 128 B |

The original vector constructor is at `0x180550948` through `0x180550958`.
The auxiliary receive capacity is fixed metadata from this wrapper; it does not
establish an auxiliary receive or an allocation by the kernel. Original packing
selects count 2 in X2/X6 while the actual wake header's size remains 24 B.

## Original auxiliary-data producer and thread context

The dispatch callback reads `TPIDRRO_EL0` and the pointer at TLS offset `0xe0`.
For zero it returns zero and writes no auxiliary bytes. The nonempty case uses
an explicitly declared 72-byte private context, with a nonzero u64 at `+0x30`
and 16 declared bytes at `+0x38`. Their native meaning, origin and lifetime are
unknown. They are not extracted credentials or native thread state.

| Producer PC | Original operation | Output region |
| --- | --- | --- |
| `0x18553c2d0` | 16-byte store from original constant `0x185550960` | Bytes 0..15 |
| `0x18553c2d8` | 8-byte store from context `+0x30` | Bytes 16..23 |
| `0x18553c2dc` | 16-byte store from context `+0x38` | Bytes 24..39 |

The complete 40-byte output is:

```text
<4I>(40, 0, 0x0390cefa, 0)
+ <Q>(declared opaque value 0x1122334455667788)
+ declared bytes 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
```

The first 8 B match the pinned `mach_msg_aux_header_t` size/reserved layout.
The semantic role of the following marker and context payload remains unknown.
The callback returns 40; the wrapper then constructs both vectors. This auxiliary
context is separate from header `msgh_voucher_port`, which remains zero.
The two original SIMD stores appear as paired 8-byte write events: five journal
events cover the three original stores. Validation checks all five addresses,
store PCs, complete 40-byte coverage and equality with the trap's auxiliary data.

Only empty TLS and a nonempty context with nonzero `+0x30` are executed. The
captured callback also has a length check and a zero-field branch. Its native
context creation and these additional input combinations are not established
by the two selected states.

## Retry contract and CF status reachability

Original `_mach_msg2_internal` saves the incoming options, clears mask `0x440`
from options sent to the raw trap, then checks the returned status. The original
options retain the decision whether to restart interrupted operations. For the
WakeUp low options `0x11`, bit 6 (`MACH_SEND_INTERRUPT`) is clear.

| Original PC | Decision or effect |
| --- | --- |
| `0x18055a8d8` | Clear `0x440` from raw trap options |
| `0x18055a8e4` | If original bit 6 is set, skip send-interruption retry |
| `0x18055a8f0` / `0x18055a8f4` | Compare against `0x10000007`; leave send loop on another status |
| `0x18055a8f8` through `0x18055a914` | Restore saved packed arguments for retry |
| `0x18055a918` / `0x18055a91c` | Retry trap; branch back to the comparison |
| `0x18055a978` | Wrapper return path after selected final statuses |

For a finite supplied stream `[INTERRUPTED] * n + [s]`, where
`s` is success, timeout or the selected invalid-data status and `n >= 0`, the
original send-loop structure restores the same eight slots and issues `n+1`
trap attempts. The report's concrete cases validate `n=0,1,2`; the branch and
restoration instructions explain the recurrence. No native timing bound or
interruption frequency is inferred. There is no explicit retry-count limit in
this send loop. The wrapper does not rerun the auxiliary callback between raw
attempts in these paths.

| Case | Declared raw status stream | SVC visits | Original CF outcome |
| --- | --- | ---: | --- |
| Suppressed | Empty | 0 | Return; no wrapper entered |
| Success | `0` | 1 | Return |
| Timeout | `0x10000004` | 1 | Return |
| Interrupted then success | `0x10000007, 0` | 2 | Return with final success |
| Twice interrupted then timeout | `0x10000007, 0x10000007, 0x10000004` | 3 | Return after final timeout |
| Invalid data | `0x10000002` | 1 | Stop before original CF diagnostic body |
| Auxiliary success | `0` | 1 | Return; original two-record vector |
| Auxiliary interruption then timeout | `0x10000007, 0x10000004` | 2 | Return after final timeout; vector unchanged |

The status-only SVC contract preserves all memory and CPU state except X0 and
the advance past SVC. Full before/after frames and memory hashes are checked.
It does not emulate a native error's potential message-right, header, auxiliary
or ownership effects. A native kernel returning a given status for this precise
packet remains unknown. In particular, the invalid-data stream tests propagation
and the CF diagnostic branch; it is not evidence that the supplied valid-sized
header would provoke native `MACH_SEND_INVALID_DATA`.

## Kernel destination and ZUT trace boundary

Original Mach table record `0xfffffe0007efb478` describes argument count 8,
16 u32 words and a non-port-valued return. Its authenticated handler cell at
`0xfffffe0007efb480` resolves to `0xfffffe000bcdd73c`; the parallel original name
is `mach_msg2_trap`. The corresponding complete 274-instruction handler body is
captured. Its initial loads consume the eight-slot argument record, providing
the concrete next kernel-side interface. No native exception dispatch, handler
execution, copyin, port lookup, enqueue or receive is performed here.

The prior [ZUT trap audit](triage_evidence/zut_trap_argument_audit.json) records
27 raw trap records at `0x180547c20` and 22 matching printed sends. Current
captured bytes identify that PC as the RET following the raw SVC. This supports
interpreting that recorded PC as a post-trap location; it does not attest the
historical runtime cache UUID, original trace producer version or which upper
wrapper produced each packet. Historical ZUT port names remain separate from
private fixture names. The historical unsuccessful IOKit user-client open is
not changed by this replay.

## Verification totals and remaining interfaces

| Positive independent replay | Cases | Original instruction visits | Complete final private bytes checked |
| --- | ---: | ---: | ---: |
| New CF factory/wake/wrapper cases | 8 | 12163 | 25165824 |
| Prior factory/wake cases, freshly replayed | 5 | 5425 | 15728640 |
| Prior original kernel construction/member/service receive | 4 | 27756 | 4194304 |
| Dynamic timer startup | 1 | 170 | 1048576 |
| Fixed-zone prerequisites | 3 | 618 | 3145728 |
| Receiver-loan prerequisites | 4 | 216 | 4194304 |
| Total | 25 | 46348 | 53477376 |

`12163 + 5425 + 27756 + 170 + 618 + 216 = 46348` visits.
`(24 + 15 + 4 + 1 + 3 + 4) MiB = 51 MiB = 53477376 B`.
The count includes 11 intercepted SVC instruction visits; 46337 other original
instruction visits remain. These are exact case counts, not native timing or
coverage percentages. New original wrapper/auxiliary paths account for 1135
non-SVC visits. Complete 40-byte auxiliary output and 48-byte vectors are checked
at three trap attempts across two cases.

The six altered-record controls reject changed packed options, packed send size,
vector auxiliary size, auxiliary output bytes, interrupted status and wrapper
return CPU state. Fresh replays retain prior rights, guard contexts, queue
limits, all four memberships, factory/mode fields, suppression states and
untouched receive buffers. The baseline direct-interrupted case remains a
labeled counterfactual and is not promoted by this composition.

For `k` raw trap attempts, original retry work is O(k) time and O(1) additional
loop storage, excluding the retained trace. Capture/replay validation uses
O(image bytes + instruction visits + memory bytes + journal bytes) time and
space. Publication auditing uses O(total artifact bytes + links) time and
O(manifest + largest JSON) working space. Native retry duration and scheduler
cost are unknown.

| Impact | Interface or pattern beyond the immediate send wrapper | Evidence required next |
| --- | --- | --- |
| High | Kernel -47 ingress accepts scalar versus vector arguments and copies the wake data. | Execute the captured original handler with explicit task/thread, argument record and copyin contracts; follow into original send ingress. |
| High | A kernel-produced wake receive closes the wake producer/consumer path. | Original port lookup, rights handling, enqueue/readiness and set receive; compare returned local name, header and trailer before resuming original CF. |
| High | Daemon work changes trigger WakeUp through a particular caller. | Original incoming references and caller-state provenance; this remains independent of generic wrapper behavior. |
| Medium | Auxiliary context follows a second data path even with a zero header voucher name. | Trace original TLS/context construction, ownership and kernel auxiliary ingestion; do not infer authentication from the 40-byte record. |
| Medium | Queue limit 1 and accepted zero-timeout results implement coalescing. | Original kernel full-queue behavior and repeated sends/receives; current options and retry observations alone do not establish coalescing. |
| Medium | Interrupt retries preserve transport data but may affect latency under repeated interruption. | Native status/scheduling observations; original loop has no explicit attempt cap, but native interruption frequency is unknown. |
| Low | Receive-side vector fields coexist with a send-only operation. | Original kernel flag/count handling; supplied capacity metadata is not itself a receive. |

The [investigation status](interface_investigation_status.md) retains the broader
FairPlay daemon/kext/deeper-component scope. A complete successful FairPlay
transaction, native lifetime/ownership model and full environmental equivalence
remain unestablished.

## Quality gates

QG1: Findings are technical observations and explicit conditional models; no
normative content is required.

QG2: SW1-SW8 identify all premises, dependent results and falsification probes.

QG3: This increment covers original user-space send packing, installed callback
selection, auxiliary production, complete trap arguments, send retries,
propagated CF results and static kernel destination. Kernel ingress/delivery and
full-goal completion remain explicitly unestablished.

QG4: LP64 little-endian layouts, byte/count distinctions, 51 MiB arithmetic,
intercepted-SVC accounting and complexity bounds are reproducible.

QG5: Counterfactual direct interruption is separated from original lower retry;
vector count from header size; auxiliary context from header voucher rights;
visited SVC from native execution; static binding from a live crossing; three
original stores from five journal events. Unknown status feasibility and native
memory/ownership effects are explicit.

QG6: Complete byte recapture, original nlist/table metadata, nine cache hashes,
pinned-header hash, independent CPU/RAM/journal replay and six rejected
alterations support the bounded claims. ZUT PC agreement is not historical
runtime identity attestation.

QG7: The impact table identifies bounded additional control/data/runtime
interfaces, their implications and the evidence needed to resolve them.
