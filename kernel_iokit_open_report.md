# Original IOKit open status channels and FairPlay initializer chain

The supplied ZUT trace records successful Mach transport followed by a normal
complex open reply containing application result `0xe00002c2` and a null
connection. Fresh static analysis of the matching kernel collection resolves
two different channels for this same numeric status. Early service/task
rejection returns a routine error; failed generic UserClient initialization
publishes an application result through an output pointer. Under the inspected
implementation, the recorded reply shape is consistent with the second channel.
The historical failure cause remains unknown. [KO1-KO6]

[Original source capture](triage_evidence/kernel_iokit_open_source.json),
[independent checks](triage_evidence/kernel_iokit_open_checks.json),
[preservation seal](triage_evidence/kernel_iokit_open_delivery.json) and
[scoped quality gates](triage_evidence/kernel_iokit_open_quality_gates.json)
retain the evidence. This extends the earlier
[ZUT interpretation](zut_trace_report.md) with original kernel instruction and
chained-pointer evidence. No daemon or kernel instructions execute or emulate
in this increment; no new runtime observation is added.

```text
historical request2862 -> Mach transport returns0
  -> historical complex reply2962: connection0, application0xe00002c2

inspected kernel2862 stub -> original open implementation
  -> early service/task rejection: return0xe00002c2
       -> simple routine-error reply
  -> provider newUserClient returns nonzero status
       -> *application_result=status; routine return0
       -> complex reply containing application_result
            |
            +-- inherited generic constructor
                 -> five-argument initializer returns false
                 -> release candidate; return0xe00002c2
```

The diagram compares historical evidence with static alternatives. It does not
assert that these exact kernel bytes ran during the capture. B denotes bytes;
all offsets are byte offsets. Addresses are unslid preferred virtual addresses.
Task/port names are u32; kernel object pointers are u64. Status calculations are
exact modular u32 arithmetic.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| KO1 | Pinned collection and supplied extracted kext identify the analyzed build | Original addresses and inherited methods | Rehash both; compare initializer bytes and seven original chained bindings |
| KO2 | The supplied historical capture is intact and represents the supplied producer command | Observed open fields and bounded absence claims | Rehash capture; independently decode both hex bodies; producer binary/build remains unknown |
| KO3 | The historical host used the inspected kernel/kext behavior | Applying static channel and constructor distinctions to the capture | Match historical host/kernel/kext UUIDs or obtain contemporaneous construction evidence; this premise is unproved |
| KO4 | The provider and client use their inspected inherited vtable entries | Generic constructor and four-argument override chain | Inspect original slots and their discriminators; runtime class replacement and authentication remain unknown |
| KO5 | Selected calls return and accesses complete normally | Source-local status continuations and field publication | Inspect exceptional/nonreturning callees and native lifetime separately; no native completion inferred |
| KO6 | Installed SDK declares compatible user ABI constants and widths | Names for status values and user message layout | Hash four headers and compile twenty assertions; SDK identity does not establish the historical OS build |
| KO7 | Boolean results are represented by their tested low bit | Initializer truth table | Compare original bit tests and bitwise AND; noncanonical words require bit-level interpretation |
| KO8 | Earlier daemon status-adapter contracts apply to this selected open caller | Conditional internal normalized result | Preserve prior contracts; recover actual historical caller/control and output observations before asserting it ran |

## Original functions and architectural roles

| Address | Provenance and recovered role | Boundary |
| --- | --- | --- |
| `0xfffffe000be38c4c` | Original subsystem2800 routine index62, message2862 stub | No exact nlist symbol; role established by original subsystem record |
| `0xfffffe000c56e604` | Stub's direct implementation call at `0xfffffe000be38d7c` | Anonymous body; implements selected service-open/status publication |
| `0xfffffe000c4cc010` | Exact `IOService::newUserClient(task,securityID,type,properties,handler)` symbol | Inherited provider slot, including alternate delegation frontier |
| `0xfffffe000c4cc000` | Exact older four-parameter `newUserClient` overload | Default body returns `0xe00002c7`; generic constructor continues after nonzero old-overload result |
| `0xfffffe000c562b14` | Exact five-argument `IOUserClient::initWithTask` symbol | Calls IOService initialization, calls four-argument override, combines results with AND |
| `0xfffffe000a5040d4` | Supplied and collection-identical FairPlay four-argument initializer | Entitlement checks, base initializer, nonnull task and client-field initialization |
| `0xfffffe000c562a20` | Exact base four-argument `IOUserClient::initWithTask` symbol | Further base initialization and internal state; transitive allocation behavior not closed |
| `0xfffffe000c4df840` | Exact `IOService::init(OSDictionary*)` symbol | Boolean contribution before the four-argument call |
| `0x184e77b74` | Exact IOKit `_IOServiceOpen` symbol | Chooses routine/transport status when nonzero, otherwise driver application status |
| `0x184e77bc0` | Exact IOKit `_io_service_open_extended` symbol | Constructs request and parses success/error reply forms |

The original subsystem range is `[2800,2892)`. Record index62 at
`0xfffffe0007e6c3d8`, pointer cell `0xfffffe0007e6c3e0`, binds the stub above
and declares kernel reply size64 B with one descriptor. Pointer format8,
authentication metadata and exact original words are retained. [KO1]

## Status channels, guards and publication sites

| Source condition | Original sites | Value/channel |
| --- | --- | --- |
| Request complexity/count/size validation fails | `0xfffffe000be38c54` through `0xfffffe000be38c6c`; store `0xfffffe000be38d10` | Routine error -304, `MIG_BAD_ARGUMENTS` |
| Selected descriptor/type/count comparison fails | `0xfffffe000be38c70` through `0xfffffe000be38c98`; continuation `0xfffffe000be38d24` | Routine error -300, `MIG_TYPE_ERROR` |
| Null service or failed selected class-chain comparison | `0xfffffe000c56e634` through `0xfffffe000c56e68c` | Routine return `0xe00002bc+6 = 0xe00002c2` |
| Owning task is null or differs from thread-derived task candidate | `0xfffffe000c56e6b8`, `0xfffffe000c56e6c4`, compare `0xfffffe000c56e6c8` | Same routine return `0xe00002c2` |
| Nonnull properties pointer in selected implementation | `0xfffffe000c56e700` and `0xfffffe000c56e704` | Routine return `0xe00002c7`, `kIOReturnUnsupported` |
| Provider newUserClient returns nonzero | Call `0xfffffe000c56e73c`; branch `0xfffffe000c56e748`; stores `0xfffffe000c56e75c` / `0xfffffe000c56e760` | Publish connection pointer and application status; routine return0 |
| Selected generic initializer returns false low bit | Call `0xfffffe000c4cc2c8`; test `0xfffffe000c4cc2d8`; release `0xfffffe000c4cc340` | Constructor return `0xe00002c7-5 = 0xe00002c2` |
| Successful routine return from implementation | Stub branch `0xfffffe000be38db0`; reply publication `0xfffffe000be38e20` through `0xfffffe000be38e30` | Complex reply, kernel size64 B, one connection descriptor |
| Nonzero implementation routine return | `0xfffffe000be38db4` and `0xfffffe000be38dc0` | Routine-error result and NDR; does not take normal complex-reply publication |

The owning task is an object converted from the task descriptor, not a direct
comparison of user port-name integers. The helper at
`0xfffffe000bd7e9c4` receives the TPIDR_EL1-derived thread value. Its exact
symbol is absent; the comparison's current-task interpretation is bounded by
this original data flow and earlier source context. It is not a recovered
authorization policy for all open paths. [KO1,KO3,KO5]

The selected implementation explicitly passes the same task object in X1 and
X2 as owning task and securityID to the provider call, the connection type in
X3, null properties in X4 and a pointer to its zero-initialized client cell in
X5. A failed generic initializer does not publish a candidate to that cell.
Consequently a construction failure and null connection are compatible here.
Alternate provider delegation, later post-construction checks, and their full
status catalog remain unresolved; the same application status is not uniquely
diagnostic. [KO4-KO5]

The IOKit wrapper initializes a local driver-result cell, calls the extended
stub, then `CSEL W0,W8,W0,EQ` at `0x184e77bb0` selects that cell only when
the stub returns0. The stub stores normal complex-reply application result
from user reply+48 and connection name from +28 at `0x184e77d44` and
`0x184e77d48`. Thus transport, routine/MIG decoding and driver status are
distinct channels even when the public wrapper returns one integer. [KO1,KO6]

## Exact inherited initializer chain

| Original pointer cell | Target | Function within chain |
| --- | --- | --- |
| `0xfffffe000846c070` | `0xfffffe000c4cc010` | Provider address point `0xfffffe000846b8d0` +0x7a0 |
| `0xfffffe000846c078` | `0xfffffe000c4cc000` | Provider address point +0x7a8, older overload |
| `0xfffffe000846b178` | `0xfffffe000c562b14` | FairPlay client address point `0xfffffe000846a868` +0x910, five-argument initializer |
| `0xfffffe000846b180` | `0xfffffe000a5040d4` | Same client address point +0x918, four-argument override |
| `0xfffffe000847c5e0` | `0xfffffe0007f55690` | Exact base IOUserClient vtable symbol |
| `0xfffffe0007f55fb8` | `0xfffffe000c562a20` | Base vtable symbol +0x928, four-argument initializer |
| `0xfffffe000847c600` | `0xfffffe0007f8b500` | Exact `_kOSBooleanTrue` storage symbol |

The five-argument initializer calls `IOService::init(properties)` at
`0xfffffe000c562b40`, retains its returned word, then calls the
four-argument override at `0xfffffe000c562b78` regardless of that first
Boolean result. It combines words with `AND W0,W23,W0` at
`0xfffffe000c562b7c`. This is not short-circuit evaluation. For canonical
Boolean results only `(true,true)` produces true. [KO4,KO7]

FairPlay's override compares entitlement objects with the true singleton. Its
three original NUL-terminated strings are:

| String address | Entitlement |
| --- | --- |
| `0xfffffe000790af41` | `com.apple.private.FairPlayIOKitUserClient.access` |
| `0xfffffe000790af72` | `com.apple.private.ProvInfoIOKitUserClient.access` |
| `0xfffffe000790afa3` | `com.apple.private.FairPlayIOKitUserClient.Virtual.access` |

Absence of all three, or absence of a true object among them, returns false.
Even after entitlement acceptance, the override requires a nonnull task and
nonzero base-initializer result before returning1. It writes null at client+216,
task at +224 and a zero byte at +244 on that success continuation. These
additional dependencies prevent identifying missing entitlements from the
application status alone. The supplied decompilation's base-vtable expression
is corroborated by original instruction addresses and original chained-pointer
cells above, rather than interpreting its rendered `MEMORY[...]` address as
an independently verified runtime cell. [KO1,KO4-KO7]

## Historical message and port contracts

| Field | User offset / extent | Captured value |
| --- | --- | --- |
| Request header | +0 /24 B | Complex; ID2862; size80 B; destination guest service0x1903; reply guest0x507 |
| Request body descriptor count | +24 /4 B | 2 |
| Task port descriptor | +28 /12 B | Guest task name0x203; COPY_SEND19 |
| Properties OOL descriptor | +40 /16 B | Address0; length0 |
| Implicit NDR | +56 /8 B | Distinct from explicit NDR below |
| Connection type | +64 /4 B | 0 |
| Explicit NDR / properties count | +68 /8 B; +76 /4 B | NDR bytes retained; count0 |
| Reply header/body | +0 /28 B | Complex; ID2962; size52 B; descriptor count1 |
| Reply connection descriptor | +28 /12 B | Null name; PORT_SEND17; type0 |
| Reply NDR/application result | +40 /8 B; +48 /4 B | `0xe00002c2` |

Request and reply are capture lines1726 and1736. Line1742 records trap return0.
The request's COPY_SEND19 and server-side received PORT_SEND17 describe
different sides of descriptor conversion, not a conflicting disposition.
The original kernel stub checks request92 B and publishes reply64 B;
user wire lengths are80 B and52 B. Their equal12 B expansion is consistent
with kernel header expansion8 B and one port descriptor expansion4 B; this
is an ABI interpretation, not an additional captured kernel message. OOL
descriptor length remains16 B. Counts, converted pointers and authentication
are separate from raw user bytes. [KO1-KO3,KO6]

No new incoming or outgoing port is observed. IOKit library emission at
`0x184e77c6c` calls the same shared transport stub established in the
[BootPolicy backend report](bootpolicy_backend_report.md); it is a static
framework location, not a daemon caller PC captured in this trace. The kernel
sites above construct a reply; actual kernel reply emission is outside these
selected bodies. Port-name namespace identities and emission limitations in
the [port report](mach_ports_report.md) remain applicable. [KO1-KO3]

## Connection to daemon status handling

The prior [daemon object-flow report](daemon_iokit_objects_report.md) places
the original IOServiceOpen call at `0x100478bb0`, followed by service release
at `0x100478c2c`, including failed opens. The
[daemon error report](daemon_iokit_errors_report.md) proves the saved Open
status survives release and reaches status adapter `0x100422a60` through
call `0x1004bdc5c`. If this caller receives `0xe00002c2`, its signed value
falls outside the passthrough interval and positive1..99 classes. The adapter
therefore produces decoded -42600 and raw `0x74c29fc9`, also used by other
errors. This conditional normalization loses the distinct open status; it is
not an additional observation from the historical trace. [KO8]

## Verification and bounded continuation

Fresh recapture covers eight compiler-bounded kernel bodies, the588 B FairPlay
initializer compared byte-for-byte with the extracted kext, and two original
cache bodies:1497 instructions /5988 B total. Eighty-one exact instruction
assertions, seven original chained bindings, one MIG record, both independently
decoded historical messages, twenty arm64e SDK assertions/four hashed headers,
four Boolean combinations and ten rejected static alterations pass. Checks
execute analysis Python and syntax-only SDK compilation; target instruction
visits, target emulation and new runtime observations are all0.

| Impact | Remaining evidence | Question resolved |
| --- | --- | --- |
| High | Historical RAX producer hash and host kernel/kext UUIDs | Whether this static status-channel implementation applies to the captured run |
| High | Existing host-task identity/entitlement and constructor diagnostics from that run | Entitlement rejection versus base initialization or another application failure |
| High | Full post-construction and delegated newUserClient status catalog | Other producers compatible with the same application-result value |
| Medium | Caller-attributed Open return before normalization | Preserve the original IOKit result before several errors collapse to -42600 |
| Medium | Kernel reply transport and connection-object conversion provenance | Separate reply construction, transferred right and actual port emission |

No successful selector26, RPC502 or RPC700 exchange is added. Further runtime
identity, native authorization/lifetime, whole-daemon reachability and hardware
PAC conclusions remain unknown. The broad interface objective remains active.

## Quality gates and reproduction

QG1: factual analysis; no normative conclusion required.
QG2: KO1-KO8 identify dependent conclusions and falsification probes.
QG3: selected status channels, inherited routines, message/port contracts,
emission boundaries and daemon error-normalization linkage are covered; the
full interface objective remains incomplete.
QG4: byte extents, exact u32 status arithmetic, original pointers and Boolean
composition are explicit. Status selection and Boolean composition take O(1)
time/space. Extraction takes O(image+fixups+symbols+selected cache files) time
and O(image+capture) space; publication hashing takes O(artifact bytes+links).
QG5: same-number/different-channel statuses, user/kernel extents,
non-short-circuit initialization, supplied decompiler expressions and historical
versus static identities are distinguished. Unknown cause is not a contradiction.
QG6: original collection/kext/cache bytes, original binding metadata, capture
hex and hashed SDK declarations supply verified provenance; exact symbols are
separate from anonymous role inferences.
QG7: five continuation questions above have bounded impact labels.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_iokit_open.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_iokit_open.py
```
