# IOKit connection export, method routing and close contracts

Original kernel code connects the successful-open contract to the same
type-0x27 object converter used by method message2865 and close message2816.
The legacy method branch reaches FairPlay's sparse selector router through
inherited IOUserClient code. The close branch reaches FairPlay's clientClose,
which requests termination with options0 and returns0 independently of the
termination result. The user IOServiceClose wrapper separately requests
connection-name deallocation after the close RPC returns. These are static
control/data-flow contracts, not an observed successful connection or a native
lifetime proof. [CL1-CL8]

[Original source capture](triage_evidence/iokit_connection_lifecycle_source.json),
[independent checks](triage_evidence/iokit_connection_lifecycle_checks.json),
[preservation seal](triage_evidence/iokit_connection_lifecycle_delivery.json)
and [quality gates](triage_evidence/iokit_connection_lifecycle_quality_gates.json)
retain the evidence. The [open-status report](kernel_iokit_open_report.md)
provides the preceding constructor/result channels. The historical
[ZUT trace](zut_trace_report.md) still ends with failed open and null connection.
No target instruction executes or emulates in this increment.

```text
conditional successful open -> UserClient object
  -> export converter(type0x27)
  -> IOMachPort registry(object,type) -> kernel port pointer
  -> open reply connection descriptor -> user connection name [native unknown]
                  |
                  +-- method2865 -> type0x27 converter -> retained client
                  |    -> argument preparation / optional policy callback
                  |    -> flags-controlled method helper
                  |    -> legacy externalMethod -> FairPlay sparse router
                  |
                  +-- close2816 -> same converter -> retained client
                       -> clientClose -> terminate(options0), ignore result
                       -> framework cleanup and result
                       -> user wrapper deallocates connection name
```

B denotes bytes. All offsets are byte offsets; addresses are preferred unslid
virtual addresses. User names are u32, object/port pointers u64. Numeric port
types below are original byte values, not assumed exported enumeration names.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| CL1 | Pinned collection and supplied extracted kext identify the intended build | Original code, roles and method bindings | Rehash collection/kext; compare three complete kext bodies and ten chained bindings |
| CL2 | A successful open actually produces the analyzed client and its declared object state | Applying export/method/close chain to a live connection | Observe actual client class, port object and reply; the historical ZUT run does not satisfy this premise |
| CL3 | Selected calls return normally, objects remain valid and intervening actors do not replace fields | Source-local publication and reference-request order | Resolve callees, concurrent writers and native lifetime separately |
| CL4 | Client+155 flag bit1 is clear for the selected legacy branch; relevant memory-descriptor fields permit legacy routing | Method -> inherited externalMethod -> sparse router | Inspect flag producer, IOUserClient2022 ancestry and argument fields; do not apply a different virtual-slot layout unconditionally |
| CL5 | Installed SDK corroborates compatible user ABI, not exact runtime build | Named APIs/constants and24/36 B close wire layout | Hash four headers and compile ten arm64e assertions; attest actual runtime modules separately |
| CL6 | Earlier registry and send-reference reports remain conditional lower contracts | Cache/node and reference terminology | Preserve their source/check hashes; current original bodies corroborate call order without importing synthetic native-state claims |
| CL7 | Byte classification is limited to captured flag arithmetic, not native writer coverage | All256 flag classifications | Enumerate all byte values; recover initialization, replacement and concurrency separately |
| CL8 | Prior selector26 record interpretation applies to the freshly resolved pointer table entry | Selector26 -> method record/handler connection | Preserve prior record contract and compare fresh slot target; full payload/transport processing remains outside this increment |

## Connection, service and IORPC object types

| Role | Original operation | Type and evidence |
| --- | --- | --- |
| Export opened UserClient | `0xfffffe000be3599c`; call `0xfffffe000be359bc` | Passes0x27 to registry helper `0xfffffe000c56114c`, then releases the input client reference |
| Import method/close connection | `0xfffffe000be35448`; comparison `0xfffffe000be35480` | Requires active-state bits and type0x27; authenticates port+80 backlink with diversity0x007d |
| Import service for open | `0xfffffe000be35314`; comparison `0xfffffe000be3534c` | Same conversion pattern, type0x28 and diversity0x0072 |
| Export IORPC object | Previously analyzed original object converter | Type0x29; separate role in [IORPC conversion](iorpc_object_conversion_report.md) |

These type values satisfy `0x27 XOR0x5a = 0x7d`,
`0x28 XOR0x5a = 0x72`, and `0x29 XOR0x5a = 0x73`.
The generic association helper explicitly derives this low16 discriminator
from the requested type. Hardware authentication acceptance remains unknown.
Service, connection, registry node, UserClient object, and IORPC queue/object
ports must retain their separate roles even when they use shared helpers.
[CL1-CL3,CL6]

The registry hashes the object pointer, traverses a bucket list, compares the
node's authenticated object pointer, then separately compares its port's type
byte with the requested type. The lookup key is therefore object plus type;
the pointer hash alone does not identify the returned interface. On a miss,
the original path creates an IOMachPort node and calls allocation adapter
`0xfffffe000be35a54`. Type0x27 takes its non-0x29 branch, supplies null
auxiliary storage and creation flags `0x27 OR0x100 = 0x127` to
`0xfffffe000bcf4a5c`, with final argument0. The special auxiliary allocation
in the adapter applies to0x29. [CL1,CL3,CL6]

The lower adapter requests allocation/initialization, signs the wrapper backlink
at port+80 with the type-derived modifier, unlocks and returns the port.
Registry return passes through `0xfffffe000bcf4fa0`, which checks type and
backlink identity before requesting send-reference creation through
`0xfffffe000bccfc94`. Actual zone initialization, allocation failures,
concurrent registry behavior, and final node/port retirement remain unknown.
The original bodies are recaptured; no synthetic registry epoch is executed
or promoted to native evidence here. [CL3,CL6]

## Original MIG entries and method dispatch

| Message / reply ID | Original record / stub | Selected direct calls | Kernel nominal reply bound |
| --- | --- | --- | --- |
| 2862 /2962, open | `0xfffffe0007e6c3d8` / `0xfffffe000be38c4c` | Open implementation, then object exporter `0xfffffe000be3599c` | 64 B, one descriptor |
| 2865 /2965, method | `0xfffffe0007e6c438` / `0xfffffe000be386b4` | Connection converter at `0xfffffe000be387cc`; method implementation at `0xfffffe000be3883c` | 4284 B, no descriptors |
| 2816 /2916, close | `0xfffffe0007e6be18` / `0xfffffe000be3c6ac` | Connection converter at `0xfffffe000be3c6dc`; close implementation at `0xfffffe000be3c6e4` | 44 B, no descriptors |

The reply bounds are original subsystem metadata, not observed packet sizes.
Method replies have variable fields;4284 B is not a fixed user reply size.
The subsystem is the same original `[2800,2892)` registry entry. [CL1,CL5]

Method implementation `0xfffffe000c5708f4` verifies the selected object
class, prepares arguments starting at its local SP+48, handles possible
memory-descriptor preparation, consults client task-associated records and an
optional policy callback, then calls `0xfffffe000c5707ec` at
`0xfffffe000c570ba0` with client, selector and argument-record pointer.
The callback can prevent that call; this static graph is not proof that every
connection holder passes authorization or reaches a selector. Complete argument
schema, memory mapping and policy semantics remain unresolved. [CL2-CL4]

The method helper reads client+155. It derives a lock mode from bit2 and bit3,
and uses bit1 to select a virtual dispatch route:

| Flag condition | Selected behavior |
| --- | --- |
| bit2=0 | No selected pre-dispatch lock call; cleanup receives mode0 |
| bit2=1, bit3=0 | Calls original shared-lock routine; cleanup receives mode1 |
| bit2=1, bit3=1 | Calls original exclusive-lock routine; cleanup receives mode2 |
| bit1=0 | Calls vtable+0x880 with dispatch/target/reference arguments zero |
| bit1=1 | Uses alternate virtual offset0x990; applicability requires its class/flag contract |

The shared/exclusive routine symbols are checked independently. Open setup
compares class ancestry with exact `IOUserClient2022::gMetaClass` at
`0xfffffe000cb5bbc0` and writes bit1 at
`0xfffffe000c56e9a8`. A preexisting bit5 can skip this initialization
block. Consequently neither an arbitrary initial flag byte nor a raw vtable
offset proves a native route. All256 byte classifications check only the local
bit arithmetic and branch selection. [CL1,CL4,CL7]

For the legacy route, original vtable slot `0xfffffe000846b0e8` resolves
to exact `IOUserClient::externalMethod` at `0xfffffe000c562bc8`.
Its null-dispatch/no-memory-descriptor continuation uses slot+0x970 at call
`0xfffffe000c562e60`, with target-output pointer and selector. Slot
`0xfffffe000846b1d8` resolves to FairPlay's
`getTargetAndMethodForIndex` at `0xfffffe000a503cd0`. Async lookup uses
a different slot+0x978; it is not equated to the synchronous router. [CL4]

The router first requires `u32(selector-1) <=39`, then tests bitmap
`0x87e27e8021`, loads the method-record pointer and publishes `this` as
target. The original40-slot table at `0xfffffe000846b770` has exactly
these17 nonnull entries, agreeing with every admitted bitmap position:

```text
1, 6, 16, 18, 19, 20, 21, 22, 23, 26, 30, 31, 32, 33, 34, 35, 40
```

Selector26 uses original slot `0xfffffe000846b838` -> record
`0xfffffe000846b710`. The preserved prior record contract supplies flags3,
16 B input/16 B output and handler `0xfffffe000a504034`; the
[cross-layer ABI report](interface_abi_report.md) links that handler to
provider `0xfffffe000a505198`. The fresh result here is the original
connection/MIG/inherited-dispatch path to this table, conditional on its guards.
It does not establish actual selector26 delivery. [CL4,CL8]

The alternative offset0x990 resolves to the older client's obfuscated
`uOxAg` at `0xfffffe000a5044c8`. Its separately captured body loads the
provider from client+216, invokes provider slot+0x8e8, writes a u32 result
through its pointer argument, and returns0. That is its established getter
role; resolving this raw slot does not establish it as a valid alternate
external-method handler for this older class. [CL1,CL4]

## Close, deallocation and reference-request boundaries

| Stage | Original location | Source-requested behavior and result handling |
| --- | --- | --- |
| Connection -> object | `0xfffffe000be35448` | Lock/check port; retain wrapper; unlock; authenticate wrapper+32 object; retain object; release wrapper; return object |
| Close implementation | `0xfffffe000c56f10c` | Selected class/synchronization checks; call client vtable+0x920 at `0xfffffe000c56f214`; later cleanup; selected return0 |
| FairPlay clientClose | `0xfffffe000a50445c` | Vtable+0x630 resolves exact `IOService::terminate`; original call `0xfffffe000a504490` supplies options0; return0 ignores termination result |
| MIG object-reference cleanup | `0xfffffe000be3c70c` | Release converted client after storing close result; separate from name/right deallocation |
| Public IOServiceClose | `0x184e7b99c` | Call close stub at `0x184e7b9b0`; save result; call mach_port_deallocate at `0x184e7b9c8`; return saved close result |

Retain/release slots for both the client and IOMachPort resolve to exact
OSObject definitions in original chains. These calls establish reference
requests, not balanced native lifetime or final destruction. The open export
helper releases its input client after the registry operation; the open stub
also releases the received owning-task descriptor right at
`0xfffffe000be38de4`, a distinct resource. [CL1-CL3,CL6]

On the public wrapper's normally returning path, the deallocation request
follows the close-stub call regardless of its returned status. It supplies
the original connection name and task-self value; it ignores deallocation's
return and restores the saved close result. Thus driver termination result,
framework close result and deallocation result are separate. A zero public
return does not prove successful termination or final port/object retirement.
[CL3,CL5]

## Close message and exact framework emission

The close stub at `0x184e7b9dc` emits message2816 through the verified
shared `_mach_msg2_internal` stub at call `0x184e7ba44`. Its simple request
is24 B: header bits0x1513, destination=connection name, local=MIG reply name,
voucher0, ID2816, no descriptor or inline argument. Its nominal simple user
reply is36 B, with NDR at+24 and result at+32. Receive capacity is44 B.
The kernel stub checks32 B request, and its metadata declares44 B reply.
The8 B difference is kernel/user header width. [CL1,CL5]

Original shared stub `0x188088a80` resolves to `_mach_msg2_internal`
at `0x18055a894`; deallocation stub `0x18806c480` resolves to
`_mach_port_deallocate` at `0x18054906c`. These are exact framework/library
call locations and names, not observations of close or name deallocation in
the historical capture. Kernel reply construction and common namespace/right
copyout remain separate from actual message emission/delivery. [CL1-CL3]

## Verification, bounds and continuation

Seventeen compiler-bounded kernel bodies, three kext bodies compared with the
supplied extracted image, and two original cache bodies retain2347 instructions
/9388 B. Seventy-nine exact instruction assertions, ten object/vtable bindings,
three original MIG records, forty selector slots/seventeen admitted positions,
two shared-cache stub bindings, ten arm64e SDK assertions/four hashed headers,
all256 flag bytes and ten rejected static alterations pass. Original target
instruction visits, target emulation and new runtime observations are0.

| Impact | Remaining evidence | Architectural question |
| --- | --- | --- |
| High | Actual successful-open client/port/reply identity | Whether a live daemon connection joins this export/import path |
| High | Original memory-descriptor/argument builder and policy callback contracts | Exact method inputs, output provenance and external-control admission before the sparse router |
| High | Native port allocation/no-senders and IOMachPort retirement | Final right/object ownership beyond reference requests and wrapper deallocation |
| High | Full flag initialization, class ancestry and concurrent writers | Which dispatch/locking branches apply to each authentic client class |
| Medium | Termination/stop/free continuations | Distinguish request acceptance, completed teardown and resource destruction |

The shared registry hash is O(1); bucket lookup is O(k) in examined nodes.
Sparse selector admission/table access and local flag classification are O(1)
time/space. Source extraction takes O(image+fixups+symbols+selected cache file
bytes) time and O(image+capture) space. Native timing and synchronization
performance are not measured. The full interface goal remains active.

## Quality gates and reproduction

QG1: descriptive static/interface findings require no normative conclusion.
QG2: CL1-CL8 identify assumptions, dependent results and falsification probes.
QG3: connection export/import, service/IORPC type distinction, original method
and close MIG bindings, guarded legacy dispatch, sparse table and public close
deallocation are covered; actual native processing remains unproved.
QG4: widths/extents, exact selector/type arithmetic, flag semantics and
complexities are explicit and reproducible.
QG5: conditional route versus native reachability, raw slot versus virtual ABI,
reference request versus retirement, and three independent close results are
distinguished; no native successful connection is inferred from static joins.
QG6: original collection/extracted-kext/cache bytes and chains, exact symbols,
source-preserved selector record, and hashed SDK declarations supply provenance.
QG7: bounded continuation questions above have impact labels.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_iokit_connection_lifecycle.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iokit_connection_lifecycle.py
```
