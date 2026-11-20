# IOKit matching and translated-process registry properties

The installed IOKit kernel checks the current process and the `IOServiceCompatibility` metaclass before adding `IOCompatibilityMatch` to a matching dictionary. The same check governs the final fallback for individual registry properties. For the archived FairPlayIOKit discovery, the 64 B dictionary contains a single `IOProviderClass` entry on the wire. The post-decode dictionary and the historical kernel's process state remain unknown. The installed legacy matching request `2804` returns `kIOReturnUnsupported`. [Archived discovery and framework stubs](live_iokit_discovery_report.md) [Kernel iterator publication](live_iokit_matching_report.md)

## Ingress and emission

| Request / reply | Framework send | Installed kernel dispatch | Passing request path |
| --- | --- | --- | --- |
| `2881/2981` | `0x184ebd3dc` | `0xfffffe000be7fe24` | Inline dictionary bytes reach shared handler `0xfffffe000c5b9628` at `0xfffffe000be7fec0`. On success the stub exports the iterator as kind `0x28`. |
| `2857/2957` | `0x184f60898` | `0xfffffe000be82270` | Out-of-line mapping wrapper `0xfffffe000c5b9580` calls the same handler at `0xfffffe000c5b95f4` and frees the mapping after the call. The wrapper stores the operation status separately from descriptor publication. |
| `2804/2904` | `0x184f5e230` | `0xfffffe000be86344` | The legacy inline stub publishes `0xe00002c7` at `0xfffffe000be863f8`. The routine takes the simple status-reply path and never enters the shared matcher. |

The outgoing destination is the IOKit main send name. The return right comes from the request's MIG reply endpoint, and the generic kernel server adds 100 to the request ID at `0xfffffe000bd3c678`. It submits the reply to the queue at `0xfffffe000bd0f208`. The valid legacy reply is 44 B internally and 36 B in user space. The installed framework retains a successful-iterator decoder for `2904`. [XNU matching entry points](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2577-L2652) [Common reply submission](live_arcade_registration_reply_report.md)

## Caller and registry state

The shared handler checks the main port, decodes the byte span and verifies the result as an `OSDictionary`. It derives its task from the current thread at `0xfffffe000c5b96c0` and sets `IOServiceNotificationUser` to the Boolean true singleton at `0xfffffe000c5b96f8`. Its second setter at `0xfffffe000c5b975c` adds `IOCompatibilityMatch` when all conditions below hold [A1]. The authenticated dictionary slot at +`0x1f0` binds to `OSDictionary::setObject`. [Public augmentation helper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L395-L445)

| Required condition for kernel insertion | Evidence |
| --- | --- |
| Current task and BSD process pointer are nonnull | The handler skips insertion at `0xfffffe000c5b96fc` or `0xfffffe000c5b9708`. The intervening helper is `get_bsdtask_info`. |
| The process has `P_TRANSLATED` | The handler tests bit 1 at process +`0x456`. The installed `proc_is_translated` extracts bit 17 of the little-endian 32-bit word at +`0x454`. |
| The process word at +`0x620` equals `CPU_TYPE_X86_64` | The handler compares it to `0x01000000 | 7 = 0x01000007` at `0xfffffe000c5b9728`. The comparison identifies the discriminator value. |
| `IOServiceCompatibility::gMetaClass.instanceCount` is nonzero | The handler loads a 32-bit word at `0xfffffe000cbd7964`. This is the named metaclass +`0x24`, the field read by `OSMetaClass::getInstanceCount` and updated by the named constructor and destructor accounting helpers. |

The conditional compare at `0xfffffe000c5b972c` sets Z on a CPU mismatch, so either a mismatch or an equal CPU type with count zero skips insertion. Superclass accounting propagates transitions between zero and nonzero. The count check establishes metaclass instance presence at the read, and the subsequent search evaluates individual candidates. [XNU process flag](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L3068-L3072) [Mach CPU constants](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/machine.h#L120-L147) [Metaclass instance accounting](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libkern/c++/OSMetaClass.cpp#L916-L938)

## Consumers and property precedence

`IOService::getMatchingServices` calls the registry search at `0xfffffe000c53bd50`. The search reads the matching key at `0xfffffe000c523db8`, and when present reaches `IOServiceCompatibility` instance enumeration at `0xfffffe000c523de0` on the normal iterator route. Its matching routine looks for the key again at `0xfffffe000c522ae8`. A successful lookup reaches `copyProperty(IOCompatibilityProperties)` at `0xfffffe000c522b1c`. If the returned dictionary supplies an `IOClass` value, the candidate class test compares that value with the request's `IOProviderClass`. [XNU enumeration and matching](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L5855-L5894) [XNU class comparison](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L7338-L7353)

The property RPCs audited for `IOBuiltin` and `IOMACAddress` reach the same kernel helper at `0xfffffe000c5bbdc0` after the property access check. The helper first asks the registry entry for the named property. On a miss it reads `IOUserServiceProperties`. Only if that backing object is absent does it evaluate the translated x86-64 and metaclass count predicate and conditionally read `IOCompatibilityProperties` at `0xfffffe000c5bbf60`. A chosen backing dictionary supplies a retained value by key. An existing user-service backing object that lacks the key ends the lookup with a null result. [XNU property helper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L3439-L3466) [Property transport and object ownership](live_iokit_registry_property_report.md)

## Evidence bounds

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The pinned fileset identifies the kernel used for static claims. | Dispatch addresses, conditional insert and lookup precedence. | Rehash the collection, verify UUIDs, independently decode the conditional flags and rebind the metaclass and dictionary methods. |
| A2. The archive preserves the original guest request bytes. | Only `IOProviderClass` appears in the archived dictionary. | Reassemble line 1699 and compare all bytes plus its paired guest reply on line 1709. The trace does not expose post-decode kernel state. |
| A3. The recorded live slice identity refers to the registry-attributed FairPlay process. | The compared daemon uses the installed arm64e slice. | Repeat the process-offset and CodeDirectory match. A transaction-level claim still requires that call's process flags and returned service identity. |

High impact attaches to the actual result of the installed legacy transport and to identifying which caller state can affect registry matching and property selection. The verification rechecks the three authenticated MIG records, dictionary slots, symbol initializers, original instruction bytes, predicate truth table and archived request/reply pair. Its runtime is O(B + T) for fileset bytes B and trace bytes T, with the same bound on storage. The current native count and any compatibility-route outcome for a FairPlay transaction remain unknown. [Matched running daemon slice](fairplay_live_slice_identity_report.md) [Verifier](triage_evidence/audit_live_iokit_matching_compatibility.py) [Compressed audit](triage_evidence/live_iokit_matching_compatibility_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_iokit_matching_compatibility.py \
  "$BOOT_FILESET" "$ANNOTATED_TRACE"
```
