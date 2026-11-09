# AES platform device, capability predicate and controller interfaces

Original AppleS8000AES code casts its provider to AppleARMIODevice, stores it at provider+0x138 and derives the dispatch flag at +0x1d2 from an OSData-compatible `service-gates` property. Separate clock/power calls and combined PSD calls reach different controller virtual interfaces. The nominal AppleARMIO implementations of all three methods return 0xe00002c7. Original callers continue toward register access despite that value. Native device/controller identity, registry contents, activation and hardware effects remain unknown. [PL1-PL8]

```text
declared raw provider -> original safeMetaCast -> accelerator+0x138
declared registry result -> original safeMetaCast(OSData) -> flag+0x1d2
  flag=0: _enableDevice -> device.enableDeviceClock(enable,0)
                        -> device.enableDevicePower(enable,NULL,0)
  flag=1: _enableDevice -> device.enablePsdService(enable,0,-1,-1)
                              |
           device tables/counts + controller pointer at device+0x88
                              |
       controller clock / power / PSD virtual dispatch
                              |
       nominal AppleARMIO original body -> 0xe00002c7
                              |
       original _enableAES(true) -> [STOP before register-base load]

candidate AppleH16GFamilyIO: clock/power overrides; PSD inherits base stub
native controller subtype and pairing: unknown
```

[Original source and bindings](triage_evidence/aes_platform_gate_source.json), [15 CPU profiles](triage_evidence/aes_platform_gate_profiles.json), [independent replay and semantic checks](triage_evidence/aes_platform_gate_checks.json), [preservation](triage_evidence/aes_platform_gate_delivery.json) and [scoped gates](triage_evidence/aes_platform_gate_quality_gates.json) provide reproducible evidence. Starting objects/globals come from case 0 of the [hardware-job profiles](triage_evidence/aes_hardware_job_profiles.json). Prior allocation, construction and mapper premises carry forward. The historical [zut capture](zut_trace_report.md) is unchanged; none of these CPU components extends that capture or demonstrates a daemon-to-kext transaction.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PL1 | The pinned collection supplies the original source, symbols and fixups. | Rehash collection; recapture 76 retained/new functions, 6726 instructions, 22 slots and named class definitions. A different runtime build requires remapping. |
| PL2 | The accelerator/provider/device/controller objects use declared nominal vptrs and a 0xa00-byte private accelerator reservation. Native identity, owner extents and lifetime are unknown. | Match actual start arguments, registry ancestry, object extents, class/vptr and controller subtype. Base-class behavior alone cannot identify the native backend. |
| PL3 | Registry lookup returns a declared absent, nominal OSData or nominal OSString object. Real safeMetaCast/getMetaClass bodies execute; negative cases use explicitly terminating superclass links. | Recover the authentic registry object and initialized metaclass hierarchy. Changed tail bytes are fixtures, not valid constructed OSData payloads. |
| PL4 | Device gate counts/tables, context pointer and controller+0x88 are declared private inputs. The real initializer is captured statically but not executed. | Follow registry-to-table parsing, allocations, actual counts and initDeviceWithProvider caller epoch; match controller publication before applying numeric gate values. |
| PL5 | Original nominal AppleARMIO stubs execute; their returned register is not a native activation outcome. | Establish runtime controller override and its actual effects. Candidate H16G slots establish static inheritance/bindings, not machine pairing or hardware acceptance. |
| PL6 | Debug globals use file values or explicit trace-enabled inputs; kernel_debug is a no-effect model. Native values/log emission are unknown. | Match boot/runtime debug flags, actual trace implementation and captured events. No native tracing is enabled by this analysis. |
| PL7 | The activation components enter _enableAES with outstanding=0, enabled=0, platform-skip bit=0 and family field=0, and stop before register-base load. | Recover authentic state, mapped resources, family, later register/interrupt flow and enabled-flag publication. The current frontier does not establish successful activation or return. |
| PL8 | Logical PAC and the existing CPU/API harness remain conditional; SDK IOReturn names are separately versioned. No native kernel/IPC/registry/platform/device/PAC operation executes. | Match actual authentication, synchronization, SDK/kernel source revision and native execution before asserting end-to-end constructor/daemon behavior. |

## Primary identities and exact interfaces

Collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The source record preserves exact compiler function ranges, original bytes, nlist symbols, chained-pointer fields, named vtables/metaclass cells and import stubs. Fifteen functions are added to the prior 61-function capture. No IDB is changed.

| Function | Exact original entry | Use in this increment |
| --- | --- | --- |
| AppleS8000AESAccelerator::_enableDevice(bool) | 0xfffffe0009d4f650 | Original 65-instruction function executes. |
| OSMetaClassBase::safeMetaCast(const OSMetaClassBase*,const OSMetaClass*) | 0xfffffe000c442080 | Original cast and original class getters execute. |
| AppleARMIODevice::enableDeviceClock(unsigned,unsigned) | 0xfffffe0008cb39b8 | Index/count, trace and controller dispatch. |
| AppleARMIODevice::enableDevicePower(unsigned,unsigned*,unsigned) | 0xfffffe0008cb3ac8 | Index/count, trace and controller dispatch. |
| AppleARMIODevice::enablePsdService(unsigned,unsigned,unsigned,unsigned) | 0xfffffe0008cb3894 | Service-word split and controller dispatch. |
| AppleARMIO::enableDeviceClock(unsigned,unsigned) | 0xfffffe0008cb2d90 | Original four-instruction unsupported return. |
| AppleARMIO::enableDevicePower(unsigned,unsigned,unsigned*) | 0xfffffe0008cb2da0 | Original four-instruction unsupported return. |
| AppleARMIO::enablePsdService(unsigned,unsigned,char*,unsigned) | 0xfffffe0008cb2dc0 | Original four-instruction unsupported return. |
| AppleARMIODevice::initDeviceWithProvider(AppleARMIO*,IORegistryEntry*) | 0xfffffe0008cb3f80 | 403-instruction complete function captured; not executed. |

| Nominal receiver/vptr | Offset | Original slot | Target | PAC diversity |
| --- | --- | --- | --- | --- |
| Device, 0xfffffe0007ff24e0 | +0x2d8 | 0xfffffe0007ff27b8 | 0xfffffe000c4c79ec, getProperty(char const*) const | 0x37a5 |
| Device | +0x8a8 | 0xfffffe0007ff2d88 | 0xfffffe0008cb39b8, clock wrapper | 0xd07d |
| Device | +0x8b0 | 0xfffffe0007ff2d90 | 0xfffffe0008cb3ac8, power wrapper | 0xa515 |
| Device | +0x8c8 | 0xfffffe0007ff2da8 | 0xfffffe0008cb3894, PSD wrapper | 0x5e87 |
| Controller, 0xfffffe0007ff1a68 | +0x8a8 | 0xfffffe0007ff2310 | 0xfffffe0008cb2d90, clock base | 0x61db |
| Controller | +0x8b0 | 0xfffffe0007ff2318 | 0xfffffe0008cb2da0, power base | 0x17da |
| Controller | +0x8c0 | 0xfffffe0007ff2328 | 0xfffffe0008cb2dc0, PSD base | 0xd7c0 |

The source also records the ARM/data type imports, metaclass cells, three original class-getter slots, debug globals, trace import and candidate controller slots. All 22 pointers use format 8; 15 are authenticated key=0/IA, address-diversity=1. The seven unauthenticated imports/data pointers are retained distinctly. These metadata records do not constitute hardware PAC verification. [PL1,PL2,PL8]

## Original provider and capability publication

The startup fragment at 0xfffffe0009d4eb10 loads the exact AppleARMIODevice metaclass import, calls original safeMetaCast and stores its result at accelerator+0x138 at 0xfffffe0009d4eb28. The positive fixture returns/stores the device pointer. The OSData fixture returns/stores NULL under the declared terminating hierarchy. Execution stops at 0xfffffe0009d4eb2c before the subsequent branch; complete startup/rejection behavior is not claimed.

The capability fragment 0xfffffe0009d4ef54..0xfffffe0009d4ef90 calls device getProperty with the original NUL-terminated 14-byte string `service-gates`, casts the result to OSData and stores a byte at accelerator+0x1d2 at 0xfffffe0009d4ef8c. Its local predicate is:

```text
flag = (safeMetaCast(getProperty(device,"service-gates"), OSDataMeta) != NULL)
```

| Declared property result | Original flag |
| --- | --- |
| NULL | 0 |
| Nominal OSData vptr | 1 |
| Nominal OSString vptr with terminating superclass link | 0 |
| Same nominal OSData vptr, remaining 120 object bytes changed to 0x5a | 1 |

Both OSData-tail cases have identical original PC sequences. Their sole read within the 128-byte property-object reservation is the eight-byte vptr. No payload, length or Boolean value is read by this observed interval. The static cast also supports matching a superclass-chain entry; real subtype/hierarchy initialization remains unproved. [PL3]

## Two-level gate ABI and count guards

The accelerator reads +0x1d2 bit 0. When clear it calls device clock with index=0, then device power with pointer=NULL and index=0. The clock result in X0 at 0xfffffe0009d4f6f4 is immediately overwritten by the device pointer; power executes even when that value is 0xe00002c7. When set, the function tail-calls device PSD with index=0 and both remaining u32 inputs=0xffffffff. Device and controller PSD slots differ: +0x8c8 versus +0x8c0.

The real initializer's store at 0xfffffe0008cb3fdc publishes its typed AppleARMIO argument into device+0x88. It also contains writers for counts and array pointers at +0xa0/+0xa8, +0xb0/+0xb8 and +0xd8/+0xd0. Only static provenance is claimed; current counts/tables are fixtures. [PL4]

| Device fields | Source consumer |
| --- | --- |
| +0x88: controller pointer | Receiver for the second virtual call. |
| +0xa0: u32 count; +0xa8: array pointer | Clock index guard and raw u32 gate ID. |
| +0xb0: u32 count; +0xb8: array pointer | Power index guard and raw u32 gate ID. |
| +0xd8: u32 count; +0xd0: array pointer | PSD index guard and encoded u32 service word. |
| +0xf0: context pointer | PSD controller X3, whose exact symbol declares char*. |

For the three wrappers, index >= count returns 0xe00002c7 before the controller call. The selected driver index is zero. The zero-clock-count case skips only the clock controller call and still invokes power. The zero-service-count case makes no PSD controller call. Power count remains one in this case set; its full source guard is captured but no zero-power-count profile is supplied.

PSD splits the selected word S as `gateID = S & 0x0fffffff`, default selector `S >> 28`, and state mask `(enable != 0 ? 0x80000000 : 0) | (input3 & 0x7fffffff)`. Input4=0xffffffff selects the default selector; other values are forwarded. This formula follows captured source. CPU cases test enable 0/1 and the driver's fixed -1 inputs, not all u32 inputs or large indexes.

| Declared table input | Controller arguments after this, for enable=1 | For enable=0 |
| --- | --- | --- |
| Clock[0]=0x123 | gateID=0x123, enable=1 | gateID=0x123, enable=0 |
| Power[0]=0x456 | gateID=0x456, enable=1, pointer=NULL | gateID=0x456, enable=0, pointer=NULL |
| PSD[0]=0xa0000789 | gateID=0x789, mask=0xffffffff, context, selector=0xa | gateID=0x789, mask=0x7fffffff, context, selector=0xa |

All three nominal controller bodies actually execute `BTI; MOV W0,0x2c7; MOVK W0,0xe000,LSL16; RET`. The local SDK IOReturn.h names this value kIOReturnUnsupported; its hash and unmatched-source-revision limitation are recorded. No opaque backend-success model is used for these bodies. The final _enableDevice register value comes from power or PSD; a C++ return type is not inferred from non-template mangled names alone. [PL5,PL8]

## Activation frontier and runtime subtype boundary

Two separate components enter original _enableAES(true), 0xfffffe0009d4f964, with the declared state in PL7 and the source-produced capability flag. They execute _enableDevice and continue despite the unsupported return. Both stop at 0xfffffe0009d4fa20 before loading accelerator+0x178, the register-base field. There is no register/MMIO access in these components. Source bookkeeping writes occur in the explicitly enlarged private reservation. Accelerator+0x1f8 remains zero; the later store at 0xfffffe0009d4fbc0 has not executed. No completed activation, interrupt setup or public return is established.

The collection contains a concrete candidate override family:

| Candidate AppleH16GFamilyIO binding | Original slot | Target |
| --- | --- | --- |
| vptr 0xfffffe000838c4e0, clock +0x8a8 | 0xfffffe000838cd88 | 0xfffffe0009f764ac, AppleH16GFamilyIO::enableDeviceClock |
| power +0x8b0 | 0xfffffe000838cd90 | 0xfffffe0009f76580, AppleH16GFamilyIO::enableDevicePower |
| PSD +0x8c0 | 0xfffffe000838cda0 | Original AppleARMIO unsupported stub |
| superClass cell | 0xfffffe000838c4c8 | 0xfffffe000cc08960, AppleARMIO::gMetaClass |

Exact vtable/superClass definitions and both override bodies are captured. Their internals are not executed or semantically recovered here. Static presence and matching signatures do not establish that this SoC driver controls the investigated accelerator. In particular, selecting the PSD path on this candidate nominal table would still reach the inherited stub. Registry-to-platform matching and runtime object identity remain high-impact evidence gaps. [PL2,PL4,PL5]

## Environmental trace and adjacent RPC surface

Clock/power wrappers conditionally call `_kernel_debug` through stub 0xfffffe0008cff338 and import slot 0xfffffe0008012e70 -> 0xfffffe000c26972c. The predicate is `(gIOKitDebug & 0x400) != 0 && (kdebug_enable & 0xfffffff7) != 0`. Original file values are 0x800000 and zero respectively; they are not observed runtime values. A declared enabled case changes those inputs to 0x800400 and one. It produces these original call arguments, with no native trace effect:

| Caller site | Event code W0 | Remaining X1..X5 |
| --- | --- | --- |
| 0xfffffe0008cb3a44 | 0x05070000 | device, index 0, clock ID 0x123, enable 1, zero |
| 0xfffffe0008cb3b5c | 0x05070004 | device, index 0, power ID 0x456, enable 1, zero |

The same platform image exposes capitalized IORPC entry points and Invoke adapters:

| Method | Entry | Invoke |
| --- | --- | --- |
| EnableDeviceClock | 0xfffffe0008cfa1e8 | 0xfffffe0008cf98e8 |
| EnableDevicePower | 0xfffffe0008cfa2e4 | 0xfffffe0008cf9994 |
| EnablePsdService | 0xfffffe0008cfa5fc | 0xfffffe0008cf9b9c |

This is an exact nlist inventory, not recovered RPC packet or port semantics. Current bindings select the lowercase direct methods. No new Mach port, right, message ID or emission site is established; neither a pointer nor a gate ID is assigned Mach-port identity. Native daemon traffic and these adjacent IORPC surfaces require independent joins. [PL6,PL8]

## Verification and bounded continuation

All 15 cases pass fresh independent A64 replay: 1317 original instruction visits, 306 reads / 2150 bytes, 138 writes / 1052 bytes, 97 logical authentication steps, 43 indirect edges, six declared API models, 15 boundaries, 2370 final object images, 30 source-global images and 60 environmental-global images. Frame checks cover six casts, four property lookups, nine _enableDevice entries, 14 device methods, 12 controller methods, five clock-return sites, two _enableAES entries and two trace calls. Every prior nonprovider object is unchanged: 149 objects per case, 2235 comparisons. Allocation accounting and DMA metadata snapshots remain unchanged; no new jobs or DMA objects are created.

Cases 0-1 check typed provider publication; 2-5 typed property presence and tail independence; 6-9 split/combined enable/disable; 10-11 zero-count guards; 12-13 activation frontiers; 14 trace arguments. Only property lookup and kernel_debug are modeled in these cases, with explicit caller-clobbering registers, no memory effects and no native operations. The original cast/getters, wrappers and base returns execute.

Run from the extracted directory: `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_platform_gate.py`. Complexity is O(image bytes + visits + journal events + object bytes) time and O(image bytes + journals + private RAM) space. Addresses/offsets are hexadecimal; u32/u64 widths and byte counts are exact; one byte is 8 bits. No duration, bandwidth or hardware measurement is inferred.

| Impact | Remaining evidence | Architectural purpose |
| --- | --- | --- |
| High | Authentic provider/controller class, registry ancestry and initialization epoch | Determines whether base methods, H16G overrides or another implementation applies. |
| High | Actual service-gates/gate tables, parser allocations and counts | Joins type-presence selection to real platform resources; a typed property alone proves no valid gate entry. |
| High | Register resource mapping, remaining _enableAES state transitions and later enabled-flag store | Connects the current frontier to authentic activation before accepted AES configuration/submission. |
| High | Historical RAX UserClient-open rejection and effective host-task identity | The zut capture stops at BadArgument/null connection; selector26 and reverse RPC remain unobserved there. |
| Medium | Capitalized IORPC entry/Invoke framing and actual callers | Determines whether a separate RPC transport is used; names alone establish no Mach endpoint. |
| Medium | Actual debug predicate and matching captured event stream | Could correlate source gate IDs/order with observations without assigning hardware success. |
| Medium | Wider counts/indexes, power guard, hierarchy/subtype and non-Boolean enable inputs | Extends finite component coverage; no exhaustive platform ABI claim is made. |

QG1: Descriptive technical evidence is sufficient for this increment.

QG2: PL1-PL8 list premises, dependent results and falsification probes.

QG3: This increment covers typed provider/property producers, two-level gate ABI, selected guards, base returns, activation frontiers, trace arguments and adjacent RPC inventory. The full daemon/kext investigation remains active.

QG4: Fixed-width fields, service-word arithmetic, zero indexes, exact byte extents and replay totals are explicit and reproducible.

QG5: Typed presence, payload, count validity, platform call result, enabled flag, candidate override and native activation are distinct. Untested guards/general inputs and runtime unknowns are explicit.

QG6: Original bytes, nlist definitions, chained slots, snapshot transfers, source journals and fresh independent A64 replay support the local claims. SDK names are separately versioned; native IPC/PAC/registry/device effects are unexecuted.

QG7: The impact-labelled continuation identifies unresolved platform, transport, environment and daemon joins. Scoped passage does not establish successful native activation or a complete FairPlay transaction.
