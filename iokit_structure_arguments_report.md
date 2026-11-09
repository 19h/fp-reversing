# IOKit structure arguments, selector26 sizes and task provenance

Original IOKit and kernel code now connect the16 B selector26 descriptor to
the legacy structure adapter. The adapter requires exact16 B input and output
sizes before invoking the handler. Generic argument construction matches the
actual248 B Kernel SDK `IOExternalMethodArguments` layout. Large outer buffers
and FairPlay's nested payload use distinct task sources. The handler publishes
only12 of its16 output bytes; the remaining4 B native value remains unknown.
These are static source/ABI findings, not a successful live transaction.
[SA1-SA8]

[Original source](triage_evidence/iokit_structure_arguments_source.json),
[independent checks](triage_evidence/iokit_structure_arguments_checks.json),
[preservation](triage_evidence/iokit_structure_arguments_delivery.json) and
[quality gates](triage_evidence/iokit_structure_arguments_quality_gates.json)
retain evidence. This extends the [connection lifecycle](iokit_connection_lifecycle_report.md)
through argument construction and the selected structure adapter. The
[historical capture](zut_trace_report.md) still contains failed open and no
selector26 exchange. No target instructions execute or emulate here.

```text
daemon input=output pointer, extent16
  -> IOConnectCallStructMethod -> IOConnectCallMethod
  -> copy input bytes into private request -> Mach2865
  -> kernel request/reply roots -> 248 B argument record
  -> guarded legacy selector26 lookup -> fixed16/16 structure adapter
  -> ucSendFPMessage(input,output,extra size arguments)
       -> nested payload address/size + stored UserClient task -> provider
       -> provider success: publish8 B address +4 B extent to output
  -> framework reply -> user-library copy into original output pointer
```

The arrows describe conditional static interfaces. Original roots and call
sites do not attest native allocation, disjointness, admission or delivery.
B denotes bytes; offsets are byte offsets. Pointers and size_t are64-bit,
named scalar fields use their stated widths, and arithmetic is exact u32/u64.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| SA1 | Pinned collection/kext/cache supply this build's original bytes | Addresses, record fields and bindings | Rehash and recapture; compare three complete kext bodies against extracted bytes |
| SA2 | A valid connection and applicable policy/legacy branch reach the method | Applying argument contracts to actual FairPlay processing | Establish native client identity, flags, policy result and method delivery; historical ZUT open failed |
| SA3 | Selected callees return normally, obey their declared memory contracts and do not replace relevant fields | Local argument/size propagation and handler output writes | Recover transitive callees, aliases and concurrent writers separately |
| SA4 | Common dispatcher provides valid request/reply storage and capacities | Kernel buffer roles and successful marshalling | Inspect allocation/copyin/copyout and native objects; distinct semantic roots alone do not prove disjoint allocations |
| SA5 | Installed Kernel SDK layout/constants corroborate compatible ABI | Field names, widths, size and direction/option labels | Compile thirty assertions against actual headers; SDK/runtime build equivalence remains unproved |
| SA6 | Selected public call supplies scalar counts0, input extent16 and initial output extent16 | In-band path and100/68 B user wire geometry | Inspect public wrapper and request/reply arithmetic; other sizes/modes require their own guards |
| SA7 | Previously recovered daemon call and nested-provider contracts retain their declared premises | Same user input/output pointer, provider/core continuation | Preserve prior source-contract hashes; native module/caller/context continuity remains unknown |
| SA8 | No uninspected allocator or callee is assigned a tail value | Remaining4 B structure output | Trace actual reply allocation/initialization and resulting bytes; absence of a selected source store is not a native disclosure finding |

## Generic argument record and SDK corroboration

Original method implementation `0xfffffe000c5708f4` uses A=local SP+48
for `IOExternalMethodArguments`, version2. Its original stores agree with
the actual Kernel SDK layout compiled for arm64e:

| A offset | Width | Field and source |
| --- | --- | --- |
| +0 /+4 | u32 each | version2 / selector; store `0xfffffe000c570a10` |
| +32 /+40 | pointer64 /u32 | scalarInput / scalarInputCount |
| +48 /+56 | pointer64 /u32 | structureInput / structureInputSize; stores `0xfffffe000c570a20` / `0xfffffe000c570a24` |
| +64 | pointer64 | structureInputDescriptor |
| +72 /+80 | pointer64 /u32 | scalarOutput / scalarOutputCount |
| +88 /+96 | pointer64 /u32 | structureOutput / structureOutputSize; stores `0xfffffe000c570aa8` / `0xfffffe000c570ab4` |
| +104 /+112 | pointer64 /u32 | structureOutputDescriptor / its size |
| +120 | pointer64 | structureVariableOutputData |
| Full extent | 248 B | Actual SDK `sizeof(IOExternalMethodArguments)` |

The actual SDK also establishes `IOExternalMethod` size48 B: object pointer
at+0,16 B C++ member-function representation at+8,4 B flags at+24,
and8 B count0/count1 at+32/+40. Padding and field widths are distinct.
Thirty assertions compile with `-DKERNEL -fapple-kext` against the actual
IOUserClient/IOMemoryDescriptor/IOTypes headers; no copied substitute struct
is used for these assertions. [SA1,SA5]

## Size selection and legacy adapter

Current IOKit public wrapper entries are `IOConnectCallStructMethod`
`0x184e78db0` and `IOConnectCallMethod` `0x184e77d74`.
The structure-only wrapper supplies zero scalar counts. The latter chooses
in-band input for extent<=4096 B and address/extent fields for larger input;
the selected ordinary output path makes the analogous capacity choice.
The separate special output mode in this function is not the selected path.
[SA1,SA6]

For16 B input/output, both outer memory-descriptor pointers are null. The
legacy `externalMethod` continuation at `0xfffffe000c562c88` checks
structure descriptor fields+64 and+104 before reaching the synchronous
router. Selector26 resolves original method record
`0xfffffe000846b710`: flags3 (`kIOUCStructIStructO`), count0=16,
count1=16, direct member target `0xfffffe000a504034`, and zero this-adjustment.
Its original member-function pointer has discriminator0x705d. [SA1-SA2,SA5-SA6]

The selected structure adapter is anonymous function `0xfffffe000c565154`,
called at `0xfffffe000c562fec`. It compares zero-extended input size with
record count0 and the full local output-size value with count1. Unless the
record field equals the32-bit sentinel `0xffffffff`, equality is required.
For this record, output capacity greater than16 does not satisfy the fixed-size
comparison merely because it is large enough. Mismatch continuations return
`0xe00002c2` if their diagnostic calls return. No failed target invocation is
executed or reproduced. [SA1-SA3]

After admission, the direct-member branch supplies:

| Register | Value at final authenticated branch `0xfffffe000c5653b4` |
| --- | --- |
| X0 | Selected target object; this-adjustment0 for selector26 |
| X1 | Structure-input pointer |
| X2 | Structure-output pointer |
| X3 | Zero-extended input size16 |
| X4 | Pointer to local64-bit output-size cell, initially16 |
| X5 /X6 | Zero |

FairPlay's handler uses the first two structure pointers; the extra legacy size
arguments do not appear as formal parameters in its supplied C export. The
original machine ABI establishes their presence without changing that handler's
observed field accesses. Generic externalMethod later checks the high32 bits
of the returned local output-size cell before publishing a u32 size. [SA1-SA3]

## Outer copies and message geometry

User-library input copy at `0x184e77ff4` and ordinary output copy at
`0x184e78200` use verified shared stub `0x18806c550`, which resolves to
`__platform_memmove` at `0x18555cd60`. Input is copied to the library's
private request; output is copied from its received reply into the caller's
output pointer. The daemon's same-pointer API call therefore does not forward
an alias relation as a kernel input/output-pointer argument. [SA1,SA6-SA7]

Kernel MIG2865 derives input from request storage and output from reply storage.
The common dispatcher passes request X0 from X22 and reply X3 from a distinct
stack cell at `0xfffffe000bcf4818` / `0xfffffe000bcf4824`. These are
separate storage roles. Their actual disjointness remains subject to allocator
and dispatcher-storage premises; it is not inferred from the argument names.
[SA3-SA4]

For scalar counts0 and16 B in-band structures:

| Geometry | User representation | Kernel representation |
| --- | --- | --- |
| Request extent | 84+align4(16)=100 B | 92+align4(16)=108 B |
| Success reply extent | 52+align4(16)=68 B | 60+align4(16)=76 B |
| Structure input bytes | Request+44,16 B | Request+52,16 B |
| Structure output bytes | Reply+40,16 B | Reply+48,16 B |

Request fields following the input bytes contain the large-input address/extent,
in-band output capacity, scalar-output capacity and large-output address/extent.
Those address/extent fields are zero for this selected small-buffer path;
the outer message is simple and uses no Mach OOL descriptor. The16 B copied
descriptor still contains a nested payload address/extent interpreted by the
driver. The wire geometry is source-derived, not a captured selector26 packet.
No new packet bytes or executable request generator are produced. [SA1,SA6]

## Task and descriptor-factory provenance

| Layer | Original source | Task / options |
| --- | --- | --- |
| Generic large outer input | Calls `0xfffffe000c570a64` then `0xfffffe000c570a78` | Thread-derived current-task object; options0x20002 |
| Generic large outer output | Calls `0xfffffe000c570ac8` then `0xfffffe000c570adc` | Thread-derived current-task object; options1 |
| Stored FairPlay owner | Initializer `0xfffffe000a5042e0` | Successful initialization stores incoming task at client+224 |
| Nested payload forwarding | Handler `0xfffffe000a504060` | Loads stored task at client+224 and context at+232, alongside provider at+216 |
| Provider payload descriptor | Call `0xfffffe000a5051d4` | Nested payload address, u32 extent, options3, forwarded stored task |

The selected16 B outer path invokes neither generic large-buffer factory call.
The provider's payload can have a different extent from16 B; the outer extent
does not define the nested payload size. [SA1-SA3,SA6-SA7]

Original provider stub `0xfffffe000a69f1e4`, pointer cell
`0xfffffe000847c420`, resolves exact
`IOMemoryDescriptor::withAddressRange` at `0xfffffe000c53a934`.
That factory preserves its task parameter and passes it to initialization.
With a nonnull task it adds virtual type0x10; its task-null alternative differs.
The SDK names0x20000 `kIOMemoryMapCopyOnWrite`, direction2
`kIODirectionOut`, direction1 `kIODirectionIn`, and3 `kIODirectionInOut`.
These describe requested options, not observed mappings or transfers.
[SA1,SA3,SA5]

The supplied C qualification `FPMemoryDescriptor::withAddressRange` is not
proof of a subclass factory or returned runtime class. Original import metadata
establishes the base factory target above; inherited/static qualification and
decompiler type propagation remain separate from instantiated-object identity.
[SA1,SA3]

## Output bytes and initialization boundary

On provider success, FairPlay's handler writes8 B at output+0 and4 B at+8
at `0xfffffe000a5040b0` / `0xfffffe000a5040b8`. It issues no output
descriptor stores on the provider-error branch. The selected handler does not
write output+12..15. Its local output-size cell remains16 under the declared
callee/alias premises because the handler does not use or forward its extra
legacy output-size argument. [SA1-SA3]

The generic builder calls exact `_bzero` at `0xfffffe000c570aa0` with
scalar-output pointer and scalarCount*8 B. This is separate from the structure
output buffer. The common dispatcher initializes its44 B default reply header,
NDR and result at `0xfffffe000bcf4760` through
`0xfffffe000bcf4794`; these stores do not establish the structure payload's
tail contents. The user stub's initial private zeroing and the daemon's original
descriptor zeroing likewise do not attest the returned kernel payload tail.
[SA1,SA3-SA4,SA8]

Consequently12/16 output bytes have the selected handler as producer;4/16
require further allocator/callee/native provenance. This is a byte-provenance
boundary, not a demonstrated native information disclosure or a claim that
the bytes are necessarily nonzero/uninitialized. [SA8]

## Verification and continuation

Nine compiler-bounded kernel bodies, three kext bodies compared with extracted
bytes, and three cache bodies retain2247 instructions /8988 B. Eighty-three
instruction assertions, one original method record and MIG record, original
factory/copy bindings, thirty actual Kernel SDK assertions/four header hashes,
eleven extent classifications and ten rejected static alterations pass.
Target visits, target emulation, new runtime observations and generated wire
payloads are all0.

| Impact | Remaining evidence | Question resolved |
| --- | --- | --- |
| High | Actual successful method delivery with module/client identity | Whether this conditional static path applies to a native daemon/kext exchange |
| High | Reply allocator/callee write provenance | Actual final4 B structure-tail value and complete output producer chain |
| High | Task-associated records and policy callback | Which calling tasks/connections pass method admission before legacy dispatch |
| High | Memory-descriptor construction, preparation and mapping effects | How the stored task and nested payload range become concrete mappings |
| Medium | Non-in-band and variable-output modes | Larger structures, descriptors and distinct size-publication paths |

Scalar size/record selection uses O(1) time/space. Copies use O(n) time in copied
bytes, with existing supplied storage; the captured finite size classifications
do not prove all64-bit execution paths. Extraction takes O(image+fixups+symbols+
selected cache file bytes) time and O(image+capture) space. The full interface
goal remains active.

## Quality gates and reproduction

QG1: factual static/interface findings require no normative conclusion.
QG2: SA1-SA8 identify assumptions, dependent results and falsification probes.
QG3: generic argument layout, fixed-size adapter, copies, nested/outer task
contexts, factory binding and output producer boundary are covered; native
whole-exchange and remaining provenance are not claimed complete.
QG4: byte widths, exact geometry, type/sentinel arithmetic and complexities
are explicit; actual SDK assertions corroborate fields without substitute types.
QG5: semantic storage roots versus disjointness, scalar zeroing versus structure
output, inherited spelling versus runtime class and outer versus nested extents
are distinguished; native tail value remains unknown.
QG6: original bytes, method record, import chains, exact symbols and actual
hashed Kernel SDK declarations supply verified provenance.
QG7: five bounded continuation questions above have impact labels.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_iokit_structure_arguments.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iokit_structure_arguments.py
```
