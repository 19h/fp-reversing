# Owning-task translation in the archived FairPlayIOKit open

The guest placed its own task control name `0x203` in FairPlayIOKit open request 2862. The candidate RAX bridge translates that guest object into a send reference to the emulator process's own host task port, then moves that reference in the outgoing descriptor. The host would therefore evaluate the open in the emulator process's task context. The archived bridge log gives the host service and reply names but omits the task descriptor and host process identity. [Archived trace](zut_trace_report.md) [Candidate task translation](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L96-L144) [Audit receipt](triage_evidence/archived_iokit_task_translation_audit.json.zst)

## Guest evidence and host projection

The two `task_self_trap` returns at lines 1 and 1125 both report `0x203` on thread `0x2de300001`. The 80 B request at line 1726 comes from that thread. The bridge's line 1734 records service `0x1503`, reply `0x1603`, class `0x200000000` and result zero. The bridge reports 2962 the next line and the guest decodes the normal complex reply at line 1736. [Port custody and open retirement](archived_iokit_open_retirement_report.md)

| Field | Offset | Archived guest request | Host projection under pinned RAX |
| --- | --- | --- | --- |
| Header bits | +0 B | `0x80001513`, complex + local `MAKE_SEND_ONCE` 21 + remote `COPY_SEND` 19 | `0x80001511`, complex + `21 << 8` + `MOVE_SEND` 17 |
| Service destination | +8 B | `0x1903` | `0x1503` in the bridge send log. The bridge moves the extra host proxy reference. |
| Reply receive name | +12 B | `0x507` | `0x1603` in the bridge send log. The bridge makes the send-once right from the exported reply receive right. |
| Task descriptor name | +28 B | `0x203` | The host `mach_task_self_` name. Its numeric value is unknown. |
| Task descriptor disposition | +38 B | `COPY_SEND` 19 | `MOVE_SEND` 17 |
| Properties OOL address and extent | +40 B, +52 B | Address 0, extent 0 B | An address from the bridge's temporary byte vector, with extent 0 B. The numeric address is unknown. |
| Connection type and properties count | +64 B, +76 B | 0 and 0 | The inline words are carried through unchanged on this projection. |

The guest send dump runs before copy-in. Guest copy-in looks up `0x203` and adds one send right for the message without spending a user reference from the guest name. A proxy destination selects host bridge forwarding when host services are enabled. The complex-body copy-in records descriptor offsets relative to the message body. The bridge adds the 24 B header size and rewrites the first descriptor's name and disposition in the outbound buffer at +28 B and +38 B. The separate task and service conversions each create a host send reference for the message to consume. A successful send releases the transient guest message rights. The candidate failed-send unwind deallocates the host references prepared for the send. [Guest copy-in and forwarding](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/syscall/mach/msg.rs#L454-L491) [Host task reference](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/host.rs#L380-L383) [Host descriptor rewrite](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L299-L357)

## Task object, caller context and failure channel

```text
guest task_self_trap -> guest name 0x203 -> guest KObject::Task
  -> add host SEND reference to mach_task_self_
  -> request 2862, task descriptor MOVE_SEND -> host mach_msg2_internal
  -> kernel task_t conversion -> compare with current_task()
  -> accepted task used in both newUserClient task arguments
```

The candidate bridge issues the host call with the guest kernel-object call class and the exported reply name. In the inspected Apple XNU reference, the send path invokes the server routine directly for an active kernel-space destination. MIG declares the open's owning-task parameter as `task_t` and converts its Mach right to a task object. The open rejects a null task or a task object different from `current_task()`. On the ordinary provider path it passes the accepted task object as both owning task and security ID. With a live host self right and the matched send path, the candidate projection explains why the distinct guest and host port-name integers are compatible with that check. [RAX host submission](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L391-L437) [XNU kernel send](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_kmsg.c#L5227-L5239) [MIG open signature](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/device/device.defs#L585-L593) [Task type conversion](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/mach_types.defs#L124-L131) [Task comparison](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4377-L4406) [Provider dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4437-L4445)

The separately audited kernel build `26C5035r` converts the task at unslid `0xfffffe000be81bb4`, compares the converted object at `0xfffffe000c5bdd48`, passes it in X1 and X2 at `0xfffffe000c5bdda8` and `0xfffffe000c5bddac`, then calls the provider at `0xfffffe000c5bddbc`. That build's early task rejection uses a routine error. The archived 2962 is 52 B with an application status of `0xe00002c2` and a null connection, consistent with the separate application-result channel. For the candidate task projection, any FairPlay initializer lookup of the passed task's entitlements would operate on the host emulator's task. The archive provides no matching host entitlement objects, constructor outcome, or historical gate identity. [Collected kernel and FairPlay initializer](live_fairplay_iokit_open_report.md)

## Host memory side effect of task translation

Selecting the guest task object arms the candidate bridge's memory mirror before acquiring the host right. The pre-send hook reserves guest address ranges in the host where possible and establishes a host-region baseline when needed. Before dispatching a host receive, the mirror checks the VM stamp and may adopt newly seen readable, shared host regions outside the backing frame arena at the same guest address. A guest overlap blocks that adoption. The source documents that host library mappings can also meet the selection criteria. This behavior is generic to exporting a task right. Request 2862 lies outside the bridge's separate IOKit memory-fixup list and its OOL properties contain zero bytes. The trace has zero candidate mirror mapping or mirror-error diagnostics, which leaves the historical mirror state and host VM effects unknown. [Mirror lifecycle](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/mirror.rs#L1-L108) [Per-routine memory fixups](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/kernel.rs#L16-L53)

## Assumptions and verification

| ID | Dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| T1 | The historical bridge implements the pinned task-object and host send paths. The projected disposition and symbolic host task name depend on it. | Match the historical producer build and inspect the outbound descriptor in the same ordinary call. | High for task attribution. |
| T2 | The relevant host kernel dispatches this request in the sender's task and applies the inspected object comparison. | Match the historical kernel and correlate the converted owning task with the thread's current task. | High for the host comparison and credential context. |
| T3 | The host initializes this FairPlay client from the projected task. | Correlate the provider call, initializer entry and returned application status from the same invocation. | High for determining the reason for failure. |
| T4 | The candidate mirror was armed in the historical process and a new region met its adoption criteria. | Compare contemporaneous mirror state and host/guest mappings around request and reply. | Medium for environmental fidelity. |

The offline audit reuses the pinned packet decoder, verifies both task-self returns and the guest descriptor offsets, derives the candidate host header bits, checks 54 RAX source anchors across 11 files and 10 Apple reference anchors across four files, and rechecks nine original words in the digest-pinned collected-kernel receipt. The receipt preserves guest packet bytes, host records and the conditional projection. Verification takes O(N) time and O(N) space for N total input bytes. The candidate projection required neither execution nor an IDA database change. [Audit generator](triage_evidence/audit_archived_iokit_task_translation.py) [Compressed receipt](triage_evidence/archived_iokit_task_translation_audit.json.zst)

```sh
python3 -B triage_evidence/audit_archived_iokit_task_translation.py \
  "$RAX_TRACE" "$RAX_CHECKOUT" "$XNU_CHECKOUT"
```
