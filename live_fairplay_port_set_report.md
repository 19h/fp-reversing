# FairPlay run-loop port-set attachment on macOS 26C5035r

The installed CoreFoundation code publishes its version-1 source in a name-to-source dictionary before requesting the corresponding kernel Mach port-set membership. The installed Mach library provides two paths to the same kernel insertion routine, a direct trap and a conditional MIG 3226 fallback. The kernel resolves the member receive right and the port-set right in one IPC space and attaches their wait queues. A task-local control confirms addition, duplicate handling, explicit removal, and removal upon destruction. FairPlay's native membership remains unknown. [Current CoreFoundation receive path](live_fairplay_cf_receive_report.md) [FairPlay check-in and archived insertions](live_fairplay_checkin_report.md)

```text
CF source -> name-to-source dictionary
      |
      +-> mach_port_insert_member
               +-> trap 22 -------------+
               +-> MIG 3226 fallback ---+-> resolve receive and set names
                                                          |
                                                          v
                                               link queue to port set
```

## Call boundaries and object flow

| Boundary | Current address | Checked contract |
| --- | --- | --- |
| CF dictionary update | `0x184773be0` | Publishes the source using the member name. |
| CF membership request | `0x184773bf8` | Passes the current task, the source receive name, and the port-set name loaded from mode +0x88. The next instruction starts source handling. This call site contains no branch on the return status. |
| Public library wrapper | `0x18054af50` | The call at `0x18054af70` invokes the trap veneer at `0x180548af8`. A trap result of `MACH_SEND_INVALID_DEST` selects the tail call at `0x18054afac`. |
| Kernel trap 22 | `0xfffffe000bd23bb8` | The trap record at `0xfffffe0007f07228` names this handler through an authenticated pointer. The handler obtains the task's IPC space and forwards the member and set names at `0xfffffe000bd23c24`. |
| Conditional library fallback | `0x18056ec18` | Constructs a noncomplex 40 B request, with the member and set names at offsets 32 B and 36 B. The `mach_msg2_internal` call is at `0x18056ec8c`. It expects reply ID 3326 and a 36 B status reply. |
| Kernel MIG 3226 | `0xfffffe000bdcfb20` | The subsystem registration and record resolve this stub. It expects the internal 48 B request form, reads the two names at `0xfffffe000bdcfb64`, and invokes the insertion function at `0xfffffe000bdcfb68`. |
| Shared kernel insert | `0xfffffe000bd27dbc` | The direct trap and MIG fallback reach this entry. It allocates a candidate link and invokes the two-name resolver at `0xfffffe000bd27e30`. |

The two names carry different right types. The resolver checks the receive and port-set entry bits and returns their locked objects. The insertion code passes the receive object's queue and the set object to the attachment routine at `0xfffffe000bd27e48`. The link helper detects an established membership and returns 11. On successful fresh insertion, it links the allocated record from the member and the set, then clears the caller's candidate pointer. The common cleanup releases an unused candidate and unlocks the resolved objects along the ordinary exit. The attachment routine also checks whether the member already has queued messages, which can make a newly attached member immediately available to set reception. Actual receiver selection and scheduling for FairPlay remain unobserved. [Previous receive-path boundaries](live_fairplay_cf_receive_report.md)

The kernel analysis used the boot fileset with SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126` and embedded kernel UUID `90195379-954d-3ca3-baac-327341f14211`. The audit process maps the verified dyld cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`. CoreFoundation and libsystem_kernel UUIDs are `14db37b1-11f1-31ad-9c07-74bed59a8036` and `780a6c1f-be02-34cc-84dd-00e05f61c89b`. Addresses are unslid.

## Task-local control

Two receive rights and one port-set right were allocated in the audit task. After each step, `mach_port_get_set_status` queried actual membership. The receipt uses A and B for the two local names. It records each status without exposing namespace-local numeric names.

| Operation | Status | Observed members |
| --- | ---: | --- |
| Allocate an empty set | 0 | Empty |
| Insert A | 0 | A |
| Insert A again | 11 | A |
| Insert B | 0 | A, B |
| Extract A | 0 | B |
| Extract absent A | 12 | B |
| Destroy B | 0 | Empty |

The compile-only SDK checks establish names for the receive and set right flavors, the two membership statuses and the fallback control status. The audit deallocated every returned name array and destroyed all remaining test rights. It invoked the public APIs in its own namespace. The experiment establishes API behavior without identifying which machine-code route the live wrapper took. The five archived RAX insertions remain the observed FairPlay-specific events. [Archived guest membership](live_fairplay_checkin_report.md)

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The fileset and cache UUIDs identify the inspected build. All source addresses depend on these identities. | Rehash the fileset and verify the running kernel and cache UUIDs. |
| A2 | Origination in the checked CF branch binds to the recorded library entry. This supports the call sequence up to the kernel. | Resolve the chained binding from original bytes and compare the import target with the exported symbol. |
| A3 | The test returns the complete task-local member list through the documented API. This supports the seven transition results. | Query the actual set after every transition, compare the names with the two owned receive rights, and release the returned arrays. |
| A4 | Applying these observations to a native FairPlay receive requires matching the right, local name, membership, and process lifetime. That native association remains unknown. | Correlate a normal daemon membership operation with a receive on the same live member. |

**High impact.** The CF dictionary and the kernel set are distinct state. A source can be present in the dictionary before the kernel operation has succeeded.

**Medium impact.** A single set can retain additional members after one is extracted. Destroying a receive right removes that member while preserving the set, so the set's existence alone cannot establish continued service membership.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_port_set.py \
  "$KERNEL_COLLECTION"
```

The audit checks cache exports, an authenticated binding, trap and MIG records, original instructions, two direct edges into the same insertion routine, and seven live task-local transitions. For B input bytes, F parsed fixups, N parsed symbols, and I selected instruction words, extraction takes O(B + F + N + I) time and working space. The control uses two members and constant-sized queries. [Audit script](triage_evidence/audit_live_fairplay_port_set.py) [Compressed receipt](triage_evidence/live_fairplay_port_set_audit.json.zst)
