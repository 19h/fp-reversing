# Cross-task Mach receive-right handoff

On macOS build `26C5035r`, the parent of an audit-owned process transferred a receive right and used its retained send right to deliver a message while the child held the receive right. The child returned the receive right, and the parent observed it under its original numeric name with its original single send reference. The marked case also distinguished temporary ownership from importance donation across both transfers. This establishes a cross-task control for the namespace behavior relevant to launchd's FairPlay check-in and return paths. Native FairPlay handoff and slot 17 object continuity remain unknown. [FairPlay check-in](live_fairplay_checkin_report.md) [Receive-right return](live_fairplay_receive_right_return_report.md)

## Native control and message sites

The parent uses `posix_spawn` to start a second instance of the probe. It temporarily registers a send right to its own rendezvous port at its own task's registered-port index 0. Both tasks verify the three-entry lookup result and that indices 1 and 2 are empty during setup. The parent restores its previous registration after spawn. The child clears its own registration after lookup and keeps the returned send reference for this exchange. An earlier `fork` prototype timed out waiting for the setup messages in both tasks. The cause of that timeout is unknown. [Probe source](triage_evidence/probe_mach_receive_handoff.c)

```text
Parent                                           Child
  |<-- OPEN_CHANNEL carries send to delivery ------|
  |--- HAND_OFF_RECEIVE carries receive right ----->|
  |--- CROSS_TASK_MARKER via retained send -------->|
  |<-- RETURN_RECEIVE carries same receive right ---|
  |--- RETURNED_TASK_MARKER to own original name   |
```

| Message | ID | Emission site and destination | Transferred right or data |
| --- | --- | --- | --- |
| `OPEN_CHANNEL` | `0x465001` | `child_main` calls `put_right` on the inherited parent rendezvous send right. | A `MAKE_SEND` descriptor for the child's delivery port. |
| `HAND_OFF_RECEIVE` | `0x465002` | `exercise` calls `put_right` on the child's delivery send right. | The original port's receive right, sent with `MOVE_RECEIVE`. |
| `CROSS_TASK_MARKER` | `0x465003` | `exercise` calls `put_marker` on its retained original send right. | The child receives marker 1 under its carried receive name. |
| `RETURN_RECEIVE` | `0x465004` | `child_main` calls `put_right` on the parent rendezvous send right. | The carried receive right, sent with `MOVE_RECEIVE`, and the child's receive-status flags. |
| `RETURNED_TASK_MARKER` | `0x465005` | `exercise` calls `put_marker` on its original send right. | The parent receives marker 2 under its restored receive name. |

Both helpers emit via `mach_msg` with a `COPY_SEND` destination and a null reply port. A one-descriptor message is 44 B (24 B header + 4 B descriptor count + 12 B descriptor + 4 B status). A marker message is 28 B (24 B header + 4 B marker). The probe verifies message IDs, copied-out dispositions, destination names and message sizes. Each case uses a fixed number of Mach operations and fixed-size buffers, with O(1) work and space relative to message count and payload length.

| Right state | Parent before | During child ownership | Parent after return |
| --- | --- | --- | --- |
| Original parent name | `SEND + RECEIVE`, 1 send user reference | `SEND`, 1 send user reference | `SEND + RECEIVE`, 1 send user reference |
| Child's carried name | No carried right | `RECEIVE` | `mach_port_type` reports `KERN_INVALID_NAME` |
| Unmarked receive flags | `0x00` | `0x00` | `0x00` |
| Marked receive flags | `0x09` | `0x08` | `0x08` |

The probe allocates a fresh port per case. The parent, child and returned parent observations use the SDK's `MACH_PORT_RECEIVE_STATUS` ABI. The marked case applies `MACH_PORT_TEMPOWNER` before transfer. Its `TEMPOWNER` bit (`0x01`) clears on delivery and its `IMP_DONATION` bit (`0x08`) persists. The child checks its name becomes invalid after return. The parent verifies its original namespace entry and the second marker before cleaning up the remaining rights. [Installed status projection and destination linking](live_fairplay_port_reassignment_report.md)

## Installed registered-port wrapper locations

The audit checks the build, running kernel UUID, running cache UUID, library UUID, two exports and nine instructions. Addresses below are unslid. The static wrapper evidence identifies the available MIG branches. The control calls the public wrappers and measures their results.

| Operation | Public export | Installed branch and request emission |
| --- | --- | --- |
| Register | `_mach_ports_register` at `0x180550880` | Count limit check at `0x1805508a0`. Wrapper calls the three-port stub at `0x1805508fc`. The stub loads MIG ID 3403 at `0x1805746e0` and calls the message helper at `0x1805746ec`. A conditional alternate is reachable at `0x180550940`. |
| Lookup | `_mach_ports_lookup` at `0x180554a14` | Wrapper calls the three-port stub at `0x180554a98`. The stub loads MIG ID 3404 at `0x180574804` and calls the message helper at `0x180574810`. A conditional alternate is reachable at `0x180554a7c`. |

The registered-port lookup is an audit setup channel in the cross-task control. FairPlay's service check-in and kernel notification 69 use separately recovered paths. [Registered-port consumers](registered_port_consumers_report.md) [Launchd recovery policy](live_fairplay_endpoint_recovery_report.md)

## Assumption register and scope

| ID | Assumption and dependent result | Stress or falsification probe |
| --- | --- | --- |
| A1 | Installed instruction addresses and structure sizes apply to the pinned build. The wrapper site table depends on this identity. | Match running and on-disk cache UUIDs, dylib UUID, build and kernel UUID. Decode the instructions and compile-time assert the probe's structure sizes and flag constants. |
| A2 | The child acquires the audit rendezvous through its registered-port result. The cross-task sequence depends on this setup. | Verify distinct process IDs and parentage, the three entries in each lookup and the child's send-only right. Require a valid response carrying the child's delivery send right and successful receipt of both markers. |
| A3 | The parent retains the same namespace entry through return. The continuity result depends on the original name and right checks. | Require one send reference at all three parent checks, verify the receive bit disappears and returns, and require the returned descriptor to name the original entry. |
| A4 | Applicability to a FairPlay slot 17 endpoint depends on tracking that endpoint through a natural service transition. | Native identity and strict guard status remain unknown. A matched receive-right return and subsequent check-in would test the inference. |

High impact for interface triage. The cross-task result verifies that continuous send capability and stable numeric name on re-entry are possible while receive ownership changes. Medium impact for environmental triage. The observed flag values and wrapper locations are scoped to the pinned build. The test did not execute a FairPlay message or observe a service-labeled port, notification 69, or slot 17 continuity.

## Quality gates and reproduction

QG1, factual scope. QG2, assumptions and probes above. QG3, both directions, namespace rights and emission sites recorded. QG4, widths and flag projections checked. QG5, the earlier setup timeout and unobserved native behavior are recorded. QG6, the installed instructions and the probe source digest are pinned in the receipt. QG7, the interface and environmental impact are bounded above.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_cross_task_handoff.py
```

The wrapper compiles with warnings enabled as errors and runs the two-case sequence twice, requiring identical receipts. [Audit script](triage_evidence/audit_live_fairplay_cross_task_handoff.py) [Compressed receipt](triage_evidence/live_fairplay_cross_task_handoff_audit.json.zst)
