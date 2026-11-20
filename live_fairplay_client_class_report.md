# FairPlayIOKit client-class selection and allocation

The registered FairPlayIOKit service provides the class name used by the installed inherited open constructor. Its `IOUserClientClass` property names `com_apple_driver_FairPlayIOKitUserClient`. The kernel looks up that name in its metaclass table, dispatches the matching class allocator and checks the returned object's superclass chain before task initialization. The live registry exposed three attached objects of that class, and read-only class counts immediately before and after the registry query both returned three. [Boot personality and provider matching](live_fairplay_service_personality_report.md) [Open attachment and owner registration](live_iokit_open_owner_report.md)

## Metaclass registration and allocation

| Stage | Installed unslid site | Observed data and control transfer |
| --- | --- | --- |
| Module initializer | `__mod_init_func` slot `0xfffffe0008481058` to `0xfffffe000a545ee8` | Initializes metaclass `0xfffffe000cd47600`. Its constructor takes the class-name string at `0xfffffe000791518a`, a chained reference to `IOUserClient::gMetaClass`, and size `0xf8` B. It installs the class's authenticated metaclass vtable. |
| Name registration | `0xfffffe000c4921a4`, `0xfffffe000c4921d8` | The installed `postModLoad` path interns a class name and inserts the metaclass under that symbol in the dictionary at `0xfffffe000cc1ed00`. |
| Lookup and lifetime | `0xfffffe000c493138`, `0xfffffe000c49314c`, `0xfffffe000c4931a0` | The symbol overload of `allocClassWithName` looks up the key under the class-table lock. A hit increments the metaclass retain count before unlocking. After its virtual allocation call, it decrements that count. |
| Typed allocation | `0xfffffe000c493190` to `0xfffffe000a544d28` | Authenticated metaclass slot +`0xa8` selects FairPlay's `MetaClass::alloc`. The method requests 248 B through `OSObject_typed_operator_new` at `0xfffffe000a544d48`, calls the IOUserClient base constructor at `0xfffffe000a544d5c`, installs the subclass vtable at `0xfffffe000a544d78` and calls `instanceConstructed` at `0xfffffe000a544d80`. |

The supplied `com.apple.driver.FairPlayIOKit.c` independently shows the class name, superclass and size in its metaclass constructor at lines 6866–6883. Its allocator at line 7070 and `com.apple.driver.FairPlayIOKit_calls.txt` at line 30 agree on the allocation and constructor sequence. The installed collection and the extracts have separate address spaces. The receipt pins their inputs by digest and checks the installed instructions and bindings independently. [XNU class insertion](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libkern/c%2B%2B/OSMetaClass.cpp#L810-L878) [XNU metaclass lookup and allocation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libkern/c%2B%2B/OSMetaClass.cpp#L1166-L1209) [Audit receipt](triage_evidence/live_fairplay_client_class_audit.json.zst)

## Open inputs and result

The installed IOKit wrapper emits open request `2862` at `0x184ebdc6c`. The incoming destination selects the provider. The request also supplies the owning-task descriptor and connection type. In the archived type-zero request, the properties descriptor is empty. In the installed inherited constructor at `0xfffffe000c51b630`, the generic fallback reads the class name from that provider through `copyProperty` at `0xfffffe000c51b728`. The interned lookup key originates from the literal `IOUserClientClass` at `0xfffffe00070db808`. The client class is a property of the provider selected by the service right. [Open request and reply layout](live_fairplay_iokit_open_report.md) [XNU client selection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L7681-L7750)

| Property or allocation outcome | Installed route |
| --- | --- |
| Retained `OSSymbol` | The equality test at `0xfffffe000c51b764` selects it directly as the allocator key. |
| Retained `OSString` | The constructor interns it at `0xfffffe000c51b7d4`, releases the original property and attempts to cache the symbol back on the provider at `0xfffffe000c51b820`. |
| Missing or incompatible property | The fallback retains the constructor status `0xe00002c7` (`kIOReturnUnsupported`). |
| Class lookup or allocation returns null | The branch at `0xfffffe000c51b854` leads to `0xe00002c7 - 0xa = 0xe00002bd` (`kIOReturnNoMemory`). The allocator API returns null for a missing class as well. |
| Allocated object is an `IOUserClient` | The constructor walks superclass links at +16 B against `IOUserClient::gMetaClass`. The admitted object becomes the receiver of the inherited five-argument initializer at `0xfffffe000c51b8e8`. A class mismatch releases the object and returns unsupported. |

On successful construction and owner registration, the same client object reaches the connection exporter at `0xfffffe000be81c64`. The stub publishes a type-`0x27` right in reply `2962` through the request's reply endpoint. Archive lines 1726 and 1736 establish service destination `0x1903`, reply name `0x507`, null connection and application status `0xe00002c2`. The capture does not establish which historical class or constructor branch produced that result. [Connection publication](live_fairplay_connection_report.md) [Archived open and retirements](archived_iokit_open_retirement_report.md)

## Native observation and assumptions

| Creator label | Child entry of provider `0x1000002fb` |
| --- | --- |
| `adid` | `0x10000130b` |
| `fairplayd` | `0x100001702` |
| `lskdd` | `0x10026cc8c` |

Both `ioclasscount` samples returned one FairPlayIOKit service and three FairPlayIOKit user clients. The three registry records expose the same object class as the counted class. Individual allocation events, the effective property object's type at open, and native connection names remain unknown.

| Assumption | Dependent claim | Falsification probe |
| --- | --- | --- |
| A1. The installed fileset, build and kernel UUID match the audited inputs. | Constructor, metaclass and exported class bindings. | Rehash the fileset and independently decode the literal, initializer and vtable fixups. |
| A2. The provider uses the inherited generic path and the class name resolves to the registered FairPlay metaclass. | The recovered allocator is selected for a successful open of this provider. | Correlate the provider's property, metaclass pointer and initializer recipient in one native observation. |
| A3. The live class counts and creator-labelled registry rows sample the same stable interval. | Three counted clients agree with three visible attachments. | Repeat the bracketing counts and check the three child IDs. Aggregate counts alone cannot establish per-object accounting. |
| A4. The extracted sources and trace preserve their supplied bytes. | Cross-image agreement on allocation and the historical request/result claims. | Rehash both extracts and decode the historical request and reply independently. |

High impact for tying the service's registry personality to the allocated connection object. Medium impact for distinguishing the missing-class outcome from the archived application status. The audit checks 49 installed instruction sites, 12 authenticated bindings, the initializer and superclass pointers, both extracts and the original Mach bytes. With B fileset bytes, T trace bytes and R selected registry and extract bytes, audit time and storage are O(B + T + R). [Auditor](triage_evidence/audit_live_fairplay_client_class.py) [Compressed audit](triage_evidence/live_fairplay_client_class_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_fairplay_client_class.py \
  "$BOOT_FILESET" "$ANNOTATED_TRACE" "$KEXT_DECOMPILATION" "$KEXT_CALLS"
```
