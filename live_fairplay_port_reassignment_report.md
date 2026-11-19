# FairPlay receive-right reassignment on the current kernel

On build `26C5035r`, the Mach temporary-owner setter enables importance donation and marks the receive port as temporarily owned for importance accounting. The destination-link path clears the temporary-owner marker when it queues the receive right in transit. Importance donation remains enabled. A native test on private ports reproduced that distinction. The installed kernel also retains a separate service-port return path that restores the saved strict guard before publishing the receive right to launchd. [Endpoint recovery policy](live_fairplay_endpoint_recovery_report.md) [Earlier guard analysis](receive_name_guard_report.md)

```text
launchd receives eligible service port
  -> kernel already restored saved strict guard
  -> launchd asserts guard and marks temporary owner
  -> later ordinary check-in moves the receive right
  -> kernel destination link clears temporary owner
  -> receiving namespace publishes the receive right
```

## Temporary owner, transport and status

The previous launchd audit locates the outgoing temporary-owner call at `0x1000478a8` and the 44 B MIG 3218 emission at `0x18054b7b8`. The current audit follows the set operation through the next transfer and the public readback interface. Addresses are unslid. The collection SHA-256 and running kernel UUID match the current build. The libsystem_kernel image was taken from the cache whose UUID matches the running cache.

| Transition | Current instruction site | Evidence |
| --- | --- | --- |
| Mark temporary owner | `0xfffffe000bd27cf0`, `0xfffffe000bd27cf4` | The flavor-4 path ORs `0x300` into the port flags at +16 B. |
| Pass a receive right to the destination-chain helper | `0xfffffe000bd0c7f8` for the plain user descriptor, `0xfffffe000bd0eeac` for the selected kernel-form descriptor | Both branches originate from a disposition-16 check. The user path supplies the translated receive object and message destination. |
| Link the carried port and clear temporary owner | `0xfffffe000bd08b10`, `0xfffffe000bd14e6c`, `0xfffffe000bd08b98`, `0xfffffe000bd08b9c` | The kernel stores the destination at port +72 B, then clears raw flag bit 9 while leaving bit 8 intact. States 3 and 4 map to transit states 5 and 6, respectively. |
| Read the status | libsystem_kernel `0x18054b698`, `0x180553b50` | The public getter first calls trap 40. The fallback for `0x10000003` emits a 44 B Mach request with MIG ID 3217. |
| Project the flags | `0xfffffe000bd23b08`, `0xfffffe000bdd03bc`, `0xfffffe000bd27910`, `0xfffffe000bd27964` | Trap and MIG reach the same attribute core, with the MIG route through a task-port adapter. For the tested ordinary port, raw bit 8 projects as public `IMP_DONATION` (`0x08`). The path for co-set bit 9 also adds `TEMPOWNER` (`0x01`). The destination is the flags word at +36 B of the 40 B receive-status structure. |

The installed setter, link and projection encodings agree with Apple's published implementation for the selected paths. The source names the paired bits `ip_impdonation` and `ip_tempowner`, and describes link-time adjustment of importance assertions. The audit does not infer a task actually received a boost from either bit. [Apple XNU setter and status projection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_port.c#L1635-L1676) [Apple XNU transfer accounting](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_importance.c#L2171-L2217)

## Separate service-port return and guard restoration

The construction path stores the initial name at service label +16 B and the original guard context at label +8 B. The notification-producing destruction branch clears the live guard and strict bits and the live context while entering state 4. Destination linking then enters state 6 with the label still attached. The plain descriptor reaches generic copyout with a null guarded-descriptor argument. [Current notification 69 emission](live_fairplay_receive_right_return_report.md)

| Stage | Current instruction site | Established operation |
| --- | --- | --- |
| Save service metadata | `0xfffffe000bd283f4`, `0xfffffe000bd283f8` | Stores the original name and context to the label for selected classes 2 and 4. |
| Retire live guard state | `0xfffffe000bd15f48`, `0xfffffe000bd15f50`, `0xfffffe000bd15f84` | Clears guard flags, zeroes the live context and selects state 4 on the notification branch. |
| Select the receiving name | `0xfffffe000bd0d790`, `0xfffffe000bd11da0`, `0xfffffe000bd11db8` | Plain descriptor copyout tries a namespace lookup by exact port object. If reuse fails, the fallback reserves an entry and feeds the chosen name to receive publication. |
| Check the return context | `0xfffffe000bd1ddac`, `0xfffffe000bd1ddd4`, `0xfffffe000bd1dde0`, `0xfffffe000bd1de04` | For service class 2 or 4 in state 6, the kernel checks a recipient-context pointer at +1544 B and bit 0 at +40 B in the referenced object. For a nonzero saved name, the selected name must match it. |
| Restore and publish | `0xfffffe000bd1de14`, `0xfffffe000bd1de1c`, `0xfffffe000bd1deb4`, `0xfffffe000bd1df58` | Restores both live guard bits and copies the saved context to port +120 B. Publishes the selected name and sets the receive bit at entry +8 B. |

Apple's published source names a privileged Jetsam coalition check on one build configuration and an init-process check on another. The installed code explicitly associates the failed context check with returning the service port to launchd. The correspondence supports a recipient-policy interpretation. The audit did not read the live recipient's metadata. This restoration is the kernel writer of the state that launchd subsequently asserts. [Apple XNU service receive-right publication](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_right.c#L2509-L2594)

## Native control on private ports

The audit used two ordinary receive ports in one task and made a send right to each. One carried the other in a 40 B complex message with a single plain `MOVE_RECEIVE` descriptor. The audit repeated the transfer with and without the flavor-4 mark. It queried receive status before marking, before send, while the right was in transit, and after receive. During transit the original name held only a send right, and the receive-status query returned `KERN_INVALID_RIGHT` (17). After receipt both cases reused that name and restored the receive right. Both ports were destroyed at cleanup.

| Case | Initial status flags | Before send | After receive |
| --- | ---: | ---: | ---: |
| Unmarked | `0x00` | `0x00` | `0x00` |
| Temporary owner set | `0x00` | `0x09` | `0x08` |

These controls exercise the ordinary move and name reuse in a single namespace. The service-only guard predicate is established from the installed instructions and published source. Actual FairPlay guard restoration, cross-task reassignment, and continuity of the live host slot 17 object remain unknown.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The captured collection and cache correspond to the audited build. All site addresses depend on the identity checks. | Rehash the collection and verify the running kernel and dyld cache UUIDs before decoding. |
| A2 | The mark, transfer-clear, and readback paths refer to the same port flags word. | Recheck the +16 B accesses and the mask. Repeat both private controls and verify the retained right and receipt name. |
| A3 | The native FairPlay service reaches the state-6 branch with the saved name and admissible recipient context. The installed mechanism establishes the conditional result. | Link a natural notification return in launchd to the selected entry and the successful strict assertion. |
| A4 | Preservation across a real restart requires the same service and slot object lifetimes. Both lifetimes remain unobserved across a restart. | Correlate ordinary publication, return and check-in with same-object evidence and a check for intervening slot writes. |

**High impact.** The temporary-owner marker describes the period before a successful move. A receiver's later `IMP_DONATION` status can remain set after `TEMPOWNER` has cleared.

**Medium impact.** The saved service label and the live guard are separate. The current kernel restores the live guard before launchd performs its assertion. The temporary-owner setter does not supply the saved guard context.

## Reproduction and quality gates

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_port_reassignment.py \
  "$KERNEL_COLLECTION"
```

The script verifies the current image identities and mapped routines, checks the original instruction and dispatch pointer anchors, compiles 10 SDK assertions, and runs both private controls. Given B input bytes, F fixups, N symbols, and I recorded instructions, capture time and working space are O(B + F + N + I). Each private case uses a constant number of Mach calls.

| Gate | Verified item |
| --- | --- |
| QG1 | The report describes decoded and observed transitions. |
| QG2 | A1 through A4 bound the location, state and identity inferences. |
| QG3 | Coverage includes setter, user and kernel-form transfer, status query, and service guard copyout. |
| QG4 | The private descriptor and status projection are independently pinned by SDK sizes and offsets. |
| QG5 | Ordinary private move, service guard restoration, and native FairPlay outcomes retain distinct evidence. |
| QG6 | The receipt preserves original bytes, image identities, dispatch pointers, and test outcomes. |
| QG7 | The implications for importance status and the later strict assertion have explicit bounds. |

[Audit script](triage_evidence/audit_live_fairplay_port_reassignment.py) [Compressed receipt](triage_evidence/live_fairplay_port_reassignment_audit.json.zst)
