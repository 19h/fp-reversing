# Corroboration of analysis.md

The architectural inventory is substantially corroborated. Several stronger statements about dispatch reachability, class inheritance, Mach special ports, Hoover, zero-copy operation, and cryptographic fallback are contradicted or unproved. The original analysis is preserved unchanged.

## Evidence and scope

Primary evidence inspected on 2026-11-01:

| ID | Artifact | SHA-256 |
| --- | --- | --- |
| A | `analysis.md`, 163 lines | `f6421fe1c9652a27b0afb7c2827fd568728941263a3664b79bdd236c46c63ce6` |
| C | `com.apple.driver.FairPlayIOKit.c`, 249635 lines | `dfb28b99b293db95a78a5d2dd20f6fcf1a95f1a53245b99a090370e7a3327f08` |
| G | `com.apple.driver.FairPlayIOKit_calls.txt`, 255 lines | `3aafca153c8a9a9ac192cb738d0073dc1e6b2ff1ab9215b8a7a8706a6ae9a857` |
| B | Backing binary identified through IDA | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |

References below use `A:line`, `C:line`, and `G:line`. These are original artifact line numbers. IDA evidence is saved in [analysis_corroboration_ida.json](analysis_corroboration_ida.json) and [analysis_corroboration_native.json](analysis_corroboration_native.json).

The references were inspected first. IDA was used only where they lacked dispatch records, contained contradictory VFS evidence, or could not establish the claimed addresses/import uses. The selected database was `com.apple.driver.FairPlayIOKit.i64`, short identity `a90cf8ec0d88`, with input `/Users/___/dev/dylex/extracted/com.apple.driver.FairPlayIOKit`. All IDA queries were read-only. No database changes, native execution, or runtime tests were performed; synthetic tool diagnostics were not used as evidence.

`C` is decompiler output, not original source. Its PTN annotations contain inferred flows, sometimes inconsistent with the accompanying code. For example, constructor annotation C:6809 assigns an incorrect constant argument, whereas C:6825-6829 shows `classSize: 0x30u`. Its introductory xref labels also report `None` despite visible calls. `G` lists selected call edges; it does not encode complete control flow, conditional execution, or argument semantics. The screenshots and original `nm -C` output mentioned by A:1 were not supplied. Exact `T/t/U/S/b` classifications are therefore not certified by this report.

## Assumption register

| Tag | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| AS1 | The two exports describe the same image/address layout as A. All cross-artifact conclusions depend on this. | Compare named function addresses. `getTargetAndMethodForIndex`, `initWithTask`, AES, VFS, and module stubs agree. IDA input SHA-256 matches the backing file. These checks do not certify the origin of the unavailable screenshots. |
| AS2 | A pseudocode operation is evidence of the corresponding static operation, subject to decompiler accuracy. Findings explicitly based on C depend on this. | Compare machine instructions when C and G disagree. `_buildLookupTbl` fails this test: its pseudocode omits a native read path. Its full native instructions override that pseudocode. No blanket accuracy assumption is made for the obfuscated core. |
| AS3 | The loaded `IOExternalMethod` layout describes the dispatch records: object at byte 0, 16-byte method representation at byte 8, flags at byte 24, counts at bytes 32 and 40; record size 48 bytes. Interpretation of the selector table depends on this. | IDA's local type and 21 consecutive records agree with the layout; selected pointers resolve to matching functions/thunks. Raw fields are retained in JSON. Flags are uniformly 3. Counts below are interpreted as legacy structure I/O byte sizes; `0xFFFFFFFF` is the variable-size convention, not a measured allocation. |
| AS4 | Descriptive names and diagnostic strings identify intended roles, without establishing complete semantics. Provisioning/media/app labels depend on this. | Trace caller arguments and callees. Names alone do not establish acronym expansions, codec, external caller identity, HDCP version, daemon identity, or key provenance. Those remain unknown where stated. |
| AS5 | A static path establishes capability or dispatch availability, not successful execution on a particular machine. All architecture conclusions depend on this limit. | Native/runtime tests with matching OS, services, entitlements, and inputs would test actual behavior. No such execution was performed. |

## Requirement coverage and verdicts

“Supported” means supported within AS1-AS5 and the cited static evidence. “Partial” separates the supported observation from the additional interpretation. “Unsupported” means the supplied evidence does not establish it; it does not assert impossibility.

| Original section / claim | Verdict | Evidence and correction |
| --- | --- | --- |
| 1A: driver, UserClient, metaclasses, lifecycle | Supported with correction | G:1-47,159-163 and C:16739 show the classes and lifecycle calls. `__realmain` and `__antimain` are data slots used by `__start`/`__stop`, not additional code stubs; C:129270,129329. IDA places them in `__common`. |
| 1A/2 inbound 1: provider start/stop call LSKD and core init/exit | Supported | G:159-160; C:16739-16797. Start calls `LSKDKext_start` then `cmam7f` conditionally; stop calls `LSKDKext_stop` and `uzZm1ih0`. “Lease/Key Delivery” is an unverified expansion of LSKD. |
| 1B: 21 named UserClient methods, each externally dispatched and thunked | Contradicted | There are 21 listed method bodies, but only 17 routed selectors. Six routed entries point directly to method bodies; the other 11 use thunks. Four additional bodies/thunks exist without a route in this dispatcher. See exact table below. |
| 1C: hardware AES and parallel LSKD state | Supported | G:85-95; C:13068-13133,13613-13680. Both initializers match `IOAESAccelerator`, allocate a kernel buffer with capacity `0x14000` bytes (81920 bytes), and maintain separate state. This establishes the provider interface, not physical DMA execution. |
| 1C: generic crypto helpers | Partial | Software AES-CBC calls are explicit at C:13543-13559. `_buildLookupTbl` and `_getCBCMacForPageIndex` are VFS helpers, not evidence of a software AES lookup-table implementation. `_arc4random` is a warning-and-zero stub, C:14216-14223. |
| 1D: FPMemoryDescriptor overrides IOMemoryDescriptor | Contradicted | Its metaclass explicitly names `OSObject` as superclass, C:6826-6840, confirmed by IDA at `0xfffffe000a5039c4`/`...39c8`. It owns an `IOMemoryDescriptor` plus mapping/buffer state. Composition, not IOMemoryDescriptor inheritance. |
| 1D: four descriptor groups and helper families | Supported | C:15242-15745 defines the groups and lifecycle/read/write helpers. Exact global ordering is corrected below. “Four pipelines” is an architectural interpretation of four descriptor roles, not evidence of independent concurrent execution. |
| 1D: VM/map wrappers | Supported | G:130-145 and C:14683,15765,15820 show VM copy/wire and descriptor mapping wrappers. Mapping API availability does not establish the destination address space or every caller's usage. |
| 1E: OS abstraction wrappers | Supported | G:97-132 directly maps wrappers to locks, threads, memory, time, and kernel APIs. `kernel_memcpy` wraps `memmove`, and `kernel_printf` wraps `IOLogv`, rather than proving exact libc semantics. |
| 1F: VFS, registry, NVRAM access | Supported | G:133-135,146-147; C:14842,15101,15974,16145. `_buildLookupTbl` requires native confirmation because C omits its read path; confirmation is below. `_accessNVRAMProperty` also has a mode-dependent branch, so describing it solely as a query is incomplete. |
| 1G: Mach/MIG imports | Partial | The two RPC functions visibly use MIG reply ports, NDR, synchronous Mach RPC, and message destruction, G:205-206, C:129683 onward. The matching collection now resolves a conditional native17/34 lookup path and protected RPC callers; see [current port evidence](kernel_port_resolution_report.md). |
| 1H: obfuscated identifiers and retained C++ parameter names | Supported with limits | G:48-84 and the C function inventory retain the types and alphanumeric names. `sub_*` is an IDA-generated name; it does not alone prove deliberate symbol stripping. Source naming history is unknown. The exact spelling `_Prn3ccdCvCjGlvZGIjqWqiZK` is not found; the case-correct near-match `_Prn3cCdCvCjGlvZGIJqWqiZK` occurs at C:47232. |
| 2 inbound 2: provider probe/start as IOKit callbacks | Supported at interface level | Provider method bodies and names exist in C; provider `start` at C:16739 confirms initialization. Actual matching on a running system is not observed. |
| 2 inbound 3: entitlement gate | Supported, more precise than original | C:7561-7687 tests three entitlement objects against `kOSBooleanTrue`, then requires a non-null task and successful superclass initialization. Task parameters on other provider methods do not independently establish authorization checks. |
| 2 inbound 4: client address wrapping/mapping | Supported | G:36-37,148 and C:7846 onward show descriptor wrapping; FPDI uses IOMemoryDescriptor/buffer APIs. API routing is the sparse 17-selector mapping below, not `0..N` over all 21 methods. |
| 2 inbound 5: AppleAVD calls these public exports | Unsupported as an actual caller claim | `_AVDDecryptParams`/`SliceInfo_` signatures support an AVD-oriented interface, G:61,73-74. No other kext's call sites or linkage records were supplied. Global text visibility also does not establish C++ `public` access control. |
| 2 outbound 1: all six obfuscated methods follow the same AES buffer pattern | Contradicted for KLzN | Five named provisioning/crypto methods match `IOAESAccelerator` and use I/O buffers, C:11177,11553,12083,12614,12832. `KLzN` matches `AppleSTDP2700` and uses `OSData`; G:81, C:11800-11921. |
| 2 outbound 2: sub_A5A2204 gets a privileged special port | Contradicted | `0xfffffe000a5a2204` is an instruction inside `sub_FFFFFE000A5A2064`; IDA shows `LDUR X11, [X10,#0xCC]`. The second RPC function is `sub_FFFFFE000A5A22D4`, G:206. Subsequent native special-port calls are established elsewhere at A60AC04/A60ACB8; this original address/attribution remains incorrect. |
| 2 outbound 3: three VFS helpers directly read files | Supported at native level | C confirms reads for `readFCDFileVersion` and `getCBCMacForPageIndex`; G:133-135 lists all three. IDA confirms six native `vn_rdwr` call sites in `buildLookupTbl`, despite missing pseudocode. A call-edge set does not prove the same linear API sequence on every branch. |
| 2 outbound 4: registry paths/properties | Supported | C:10999,11046,15974,16145 and G:76-78,146-147. Product ID lookup specifically uses `IODeviceTree:/product` and `product-id`. |
| 2 outbound 5: sub_A5A1B84 copies decrypted data to userspace | Unsupported as stated | The VM copyout wrapper exists at C:14683. Neither reference contains the claimed `sub_FFFFFE000A5A1B84` function/call edge. Its destination is a caller-supplied `vm_map_t`; neither “userspace” nor “decrypted” follows from this wrapper alone. Descriptor completion is not itself proof of wiring or copyout. |
| 3.1: direct wrapper mappings reveal exact core purposes | Partial | The edges are corroborated by G:48,57-63,70,75, with spelling corrections below. The app-origin parameter supports an app-decryption association; exact core state semantics are unknown without further recovery. C++ mangling exposes type names independently of RTTI and does not reveal structure layout. |
| 3.2: identical five-step lock/state-machine bracket | Contradicted | G:69 and C:9649-9655 show B7VLiasHfyHOIb7FW simply forwarding to `bv0pQIFuAPhAERxjZ7R(0)`. Other wrappers share conditional status/context/cleanup patterns, not an identical sequence. No recovered semantics establish that the obfuscated helpers acquire locks. |
| 3.3: portable core shared across multiple environments | Plausible inference only | The shim layer is directly visible, G:97-132. Shared source, other builds, execution environments, and complete portability are unknown. |
| 3.4: Hoover/fairplayd special-port upcalls fetch keys/state | Unsupported; Hoover association contradicted | A conditional17/34 acquisition and RPC502/700 callers are now established; full receiver-object identity and payload purpose remain unknown. The observed Hoover interface targets `AppleSTDP2700`, not a named daemon. |
| 3.5: zero-copy physical-page identity and H.264/HEVC handoff | Unsupported as stated | C:15739 implements only pointer equality. C:6540 onward includes a conditional allocated copy in FPMemoryDescriptor; C:13194 uses `IOBufferMemoryDescriptor::withBytes` and an output read. Media/sample interfaces and some same-descriptor AES calls are supported. Codec, physical-page aliasing, and decoder handoff are unknown. |
| 3.6: hardware preferred, software automatic fallback | Partial | Hardware and software AES code coexist. No hardware-failure-to-software branch is established. `performHWAES` returns initialization/provider errors rather than calling `performAESCBCDecryption`, C:13194-13305. Lookup/MAC file helpers do not establish software key unwrapping. |
| 3.7: device provisioning, dongle/HDCP, SU expansion, Apple TV board | Partial | Device-specific product comparison, provisioning strings, and dongle-named methods are supported. `J42dAP`, Apple TV HD identity, HDCP, Lightning-to-HDMI, “Downstream Session,” and “Software Update personalization” are not established by these files. These expansions and hardware assignments remain unknown within this evidence set. |

## Exact external-method dispatch

The dispatcher at `0xfffffe000a503cd0` uses this predicate, reproduced in C:7189:

```text
n = uint32(selector - 1)
if n > 39: return NULL
if ((0x87E27E8021 >> n) & 1) == 0: return NULL
*target = this
return pointer_table[n]
```

Time and auxiliary space are both O(1). Unsigned subtraction rejects selector 0; out-of-range and clear-bit selectors return NULL without assigning `*target`. Enumerating the 40 bits gives 17 accepted selectors. This is a static route count, not a count of successful operations or an enumeration of every possible inherited interface.

IDA supplies the missing data records. The pointer table is at `0xfffffe000846b770`; it indexes 48-byte records beginning at `sMethods = 0xfffffe000846b380`. There are 21 consecutive records in the record region; four have no pointer in this selector table. Each selected record has null object, zero method adjustment, and flags 3. Addresses and raw counts are retained in the JSON artifact. Byte-count interpretation depends on AS3.

| Selector | Method | Input bytes | Output bytes | Entry form |
| --- | --- | ---: | ---: | --- |
| 1 | `uOxAg` | 0 | 4 | thunk |
| 6 | `initKextSession` | 32 | 32 | thunk |
| 16 | `DSSessionDongleProcessKey` | 608 | 608 | thunk |
| 18 | `ProcessEncryptedData` | 3096 | 3096 | thunk |
| 19 | `GetReEncryptionVault` | 3088 | 3088 | thunk |
| 20 | `ucDecryptOneSample` | 32 | 32 | direct |
| 21 | `ucRunVersioned` | 552 | 552 | direct |
| 22 | `ucGetVersion` | 0 | 4 | direct |
| 23 | `ucGetProtocolCapabilities` | 0 | 4 | direct |
| 26 | `ucSendFPMessage` | 16 | 16 | direct |
| 30 | `ucGenerateSeed` | 1028 | 1028 | thunk |
| 31 | `ucExchangeWithHoover` | variable (`0xFFFFFFFF`) | variable (`0xFFFFFFFF`) | thunk |
| 32 | `ucGetEncryptedSeedSegment` | 124 | 16 | thunk |
| 33 | `ucGenerateInFieldSeed` | 2052 | 2052 | thunk |
| 34 | `ucEncryptSUInfo` | 2008 | 2008 | thunk |
| 35 | `ucEncryptWithWrappedKey` | 140 | 140 | thunk |
| 40 | `ucSendFPDIMessage` | 32 | 32 | direct |

The bodies `LQ1N1WLcw`, `decryptOneSampleWithCTR`, `decryptSliceData`, and `decryptSliceDataWithCTR` exist at C:8049 onward and in the function inventory C:85-88, with thunks C:69-72. None is selected by this router. This does not prove that no other internal route reaches them.

## Access control and corrected topology

`initWithTask` checks these exact names (C:7583-7592):

| Entitlement | Observed admission condition |
| --- | --- |
| `com.apple.private.FairPlayIOKitUserClient.access` | Object equals `kOSBooleanTrue` |
| `com.apple.private.ProvInfoIOKitUserClient.access` | Object equals `kOSBooleanTrue` |
| `com.apple.private.FairPlayIOKitUserClient.Virtual.access` | Object equals `kOSBooleanTrue`; also sets the field at object offset `0xF0` to 1 |

At least one true entitlement is necessary on this path. Admission additionally requires successful superclass initialization and a non-null task, C:7664-7678. A merely present false/non-Boolean entitlement is insufficient. The effects of the virtual-mode field beyond initialization were not exhaustively traced.

```text
Client task
  -> initWithTask: one of three entitlements == kOSBooleanTrue
  -> getTargetAndMethodForIndex: 17 sparse selectors
  -> UserClient method / virtual thunk
  -> provider methods / internal core
       +-> IOAESAccelerator: AES/provisioning interfaces
       +-> AppleSTDP2700: KLzN / exchangeWithHoover
       +-> kernel wrappers: VM, locks, threads, registry, VFS

Port supplied as RPC argument
  -> sub_A5A2064 or sub_A5A22D4
  -> synchronous Mach RPC
  -> receiver identity unknown
```

This diagram intentionally leaves the Mach RPC functions disconnected from a named UserClient or external-driver route: no such complete chain was established. The first sends message ID `0x1F6` (502), with expected normal reply ID `0x25A` (602); the second sends `0x2BC` (700), with expected normal reply ID `0x320` (800). Both call with send size `0x58` bytes (88 bytes) and receive capacity `0x190` bytes (400 bytes); a normal complex reply is checked against `0x188` bytes (392 bytes). See C:129757-129786 and C:129984-130018. These are protocol fields, not evidence of a particular daemon or key-fetch purpose.

IDA confirms synthetic UNDEF symbol placeholders for `_host_get_special_port` at `0xfffffe000cccf700`, `_host_priv_self` at `...f708`, and `_ipc_port_release_send` at `...f718`. No IDA xrefs were returned for those three placeholders. This initial placeholder check did not classify indirect use. The subsequent [matching-collection analysis](kernel_port_resolution_report.md) establishes actual bindings and conditional native calls through protected tables.

## Descriptor, crypto, and VFS corrections

IDA resolves the global descriptor ordering precisely:

| Address | Symbol |
| --- | --- |
| `0xfffffe000ccc7858` | `_sample_sizes_desc` |
| `0xfffffe000ccc7860` | `_samples_desc` |
| `0xfffffe000ccc7868` | `_input_desc` |
| `0xfffffe000ccc7870` | `_output_desc` |

`InputIOMDEqualsOutputIOMD` returns `input_desc == output_desc` (C:15743), including true if both are null. It does not compare task addresses, lengths, physical segments, or mapped pages. Conversely, different descriptors could describe overlapping memory. It cannot establish the physical-page equivalence claimed in A:156. `performAESonSamplesIOMD` does pass the same samples descriptor for input and output, C:15759; this supports an in-place descriptor interface in that helper.

FPMemoryDescriptor's mode bit `0x4` selects an `IOMallocData` buffer and `memmove` path in `initWithOptions`, C:6573-6609. `releases` conditionally copies back when bit `0x2` is also set, C:6680-6710. The implementation therefore supports both mapped access and copied buffers. Actual use of each mode depends on caller flags [AS2, AS5].

The software CBC helper supplies a 16-byte key and `a5 >> 4` blocks to the kernel AES implementation, C:13554-13556. Its block count is `floor(a5 / 16)`; for length `a5 = 16q + r` bytes, `0 <= r <= 15`, it requests `q` blocks, covering `16q` bytes. The helper itself does not reject a nonzero remainder. This observation does not establish that any reachable caller passes an unaligned length or that kernel crypto rejects/accepts it in a particular way. No automatic software fallback is visible in the examined hardware wrapper.

`getCBCMacForPageIndex` locates a record, bounds-checks offsets, and reads bytes from a file with `vn_rdwr(..., rw: UIO_READ, ..., segflg: UIO_SYSSPACE, ...)`, C:15101-15228. The visible helper retrieves file data; it contains no AES computation. The name does not prove that it computes a CBC-MAC or verifies authenticity.

The strongest reference contradiction is `_buildLookupTbl`: G:134 lists file reads, whereas C:14997-15027 reduces its valid-input branch to open/getattr/close/return 5. Native IDA instructions retain a conditional branch at `0xfffffe000a509220` to `0xfffffe000a509270` and six `vn_rdwr` calls at `...92f4`, `...9374`, `...93e8`, `...9474`, `...9514`, and `...9568`. Thus the full machine-code function corroborates the VFS read capability in G. The cause of the decompiler omission is unknown; it is not evidence that the native read path was removed.

For this discrepancy, all 1348 bytes (`0x544`) of `_buildLookupTbl` were compared between IDB and backing file and matched. The 1328-byte (`0x530`) record/pointer-table region and 88-byte (`0x58`) dispatcher also matched. No patched bytes were reported in the inspected VFS function range. These checks cover those ranges only, not the entire IDB.

## Exact wrapper and identifier corrections

G:48-75 establishes these mappings without assigning unrecovered core semantics:

| Provider method | Direct callee in G |
| --- | --- |
| `DCkic`, `xhU6d1`, `ycJai39mD8` | `_fcHfFIGhsx` |
| `Kp0289aEmoqcAa` | `_sk3kcwm3l2` |
| `HJZF2FkXmBuuy` | `_De20DmHh3jVChIyH` |
| `WkhY6wTBlbHrpaT0` | `_zgcqcxw1qve0CY` |
| `LasdMdn12cas` | `_kratpzs81h` |
| `Trped0719ab` | `_lapsl183ah` |
| `uOxAg` | `_V2F1SYee` |
| `Q5TC6` | `_QIWEiU` |

These provider methods are distinct from identically named UserClient methods. In particular, the provider `uOxAg()` mapping is not itself a direct edge from the UserClient `uOxAg(unsigned int *)` body.

| Spelling in A | Exact spelling in references |
| --- | --- |
| `u0xAg` | `uOxAg` |
| `xHu6d1` | `xhU6d1` |
| `yt8uP0Vu` | `yt8uPOVu` |
| `_egYabpI0CbFA` | `_egYabpIOCbFA` |
| `ZURJELCowjwysX` | `ZURJElCowjwysX` |
| `HJZF2FKXmBuuy` | `HJZF2FkXmBuuy` |
| `glMABVgh` | `glmABVgh` |
| `DqyxC6zf2Sv` | `Dqyxc6zf2Sv` |
| `J8i0aN2gZ6hA3n6` | `J8i0aN2gZ6hA3nG` |
| `WT74ohNhs040y` | `wT74ohNhs04Oy` |
| `R2nPsU0Yx6h` | `R2nPsUOYx6h` |
| `B7VLiasHfyH0Ib7FW` | `B7VLiasHfyHOIb7FW` |
| `eJ7hq0h8Z` | `eJ7hqOh8Z` |
| `_zzLw2e0Vu9p0HqpiNw1K4ki` | `_zzLw2eOVu9pOHqpiNw1K4ki` |
| `_V9Z6DQ1D8vW2ehH161m` | `_V9Z6DQ1D8vW2ehH1G1m` |
| `_Hpu7ZB0FQYIwvPDYn9` | `_Hpu7ZBOFQYIwvPDYn9` |
| `_KDISAVDDecryptionAllowedParamsIO` | `_KDIsAVDDecryptionAllowedParamsIO` |
| `ovHBHGCR5ZAwSmgzDIbVv20x` | `ovHBHGCR5ZAwSmgzDIbVv2Ox` |
| `RVbEMromyROSkm` | `RVbEMromyR0Skm` |
| `RwyEg0MUTKuzQ` | `RwYEgOMUTKuzQ` |
| `_L8NEoIll0BwWkdF06PuGxiiehGZr` | `_L8NEoIlLOBwWkdF06PuGxiiehGZr` |
| `_T68NEoIll0BwWkdF06PuGk48xiiehGZrfj` | `_T68NEoIlLOBwWkdF06PuGk48xiiehGZrfj` |

## Bounded additional findings

| Impact | Finding / analytical consequence | Bound |
| --- | --- | --- |
| High | The C export omits a genuine native VFS path. Native CFG checks are necessary before classifying branch absence or constant failure in this export. | Demonstrated for `_buildLookupTbl`; no claim that every function is affected. |
| High | The actual exposed surface is 17 sparse selectors. Four named handlers and four physical method records do not imply external reachability through this router. | Does not enumerate all inherited or internal interfaces. |
| Medium | The obfuscated context helper `TdtbU9WbbSyE1sdsj` sets up temporary state, dispatches through `sub_FFFFFE000A55F5E4`, and tears state down, C:17617-17649. This supports examining a shared execution-context mechanism instead of assigning lock semantics from call topology. | A VM/state-machine interpretation remains a hypothesis; opcode and state semantics were not recovered. |
| Medium | `_arc4random` logs “not implemented” and returns zero, C:14216-14223. It must not be counted as functioning entropy generation. | Caller reachability and any security effect are unknown. `_kernel_read_random` separately wraps `_read_random`, G:103. |
| Medium | `GetProductID` requires exactly 20 bytes; `isJ42dDevice` compares all 20 bytes against a stored reference using accumulated XOR, C:10997-11075. | Reference bytes/product naming alone do not establish an Apple TV board identity. |
| Low | `FPDebugDisplayStatusMsg` returns true precisely when status is zero and logs on nonzero status, C:14200-14207. It is also a branch predicate, not merely a logging side effect. | It supplies no synchronization semantics. |

## Quality-gate review

| Gate | Result within this corroboration scope |
| --- | --- |
| QG1 | Pass: factual static analysis; no normative judgment required. |
| QG2 | Pass: AS1-AS5 identify dependencies and falsification probes. |
| QG3 | Pass: all eight inventory groups, inbound/outbound groups, and seven inferred behaviors are evaluated. |
| QG4 | Pass: selector arithmetic is explicitly unsigned; addresses and byte counts are exact; CBC block arithmetic and remainder bounds are explicit. No empirical uncertainty estimates are asserted. |
| QG5 | Pass: contradictions are identified and bounded, including VFS decompilation versus native instructions and call-edge versus reachability distinctions. Unknown receiver identity, core semantics, and decompiler omission cause remain explicitly unknown rather than assumed resolved. |
| QG6 | Pass: claims are grounded in supplied primary artifacts and recorded read-only IDB evidence. Unavailable screenshots, source history, and acronym/hardware expansions are not treated as verified provenance. |
| QG7 | Pass: additional findings are restricted to evidence fidelity, reachable surface, context mechanism, entropy stub, device comparison, and status predicate, with impact and limits stated. |


## Subsequent cross-layer corroboration (2026-11-01)

The [ABI report](interface_abi_report.md) now aligns the kext RPC502 client with the loaded daemon server stub. The [matching-collection report](kernel_port_resolution_report.md) resolves the actual host helper addresses, conditional17/34 acquisition, and protected RPC502/700 callers. The original misidentified A5A2204 call remains incorrect. Current native launchd reports `com.apple.unfreed` active on slot17 for the exact universal daemon image. Whole-path object identity, selected runtime slice, slot34 semantics, RPC700 receiver, and native exchange remain unproved; the earlier absence of local call-site/publication evidence has been superseded.

## Further native corroboration: context and text-pager clients (2026-11-01)

[text_pager_interface_report.md](text_pager_interface_report.md) recovers the constructor's omitted record fields, a named kernel client and pager lifecycle, original virtual-slot bindings, and conditional CPU/origin meanings for the RPC502 scalars. The direct caller scan and fresh live IDA xrefs agree on three provider constructors passing mode1. The origin enum is a separate argument; equating origin2 or UserClient virtual mode with the alternate34/700 route is not supported. The opaque output is visibly zero-extended from a 32-bit value despite its C++ pointer spelling. Original analysis.md and its source exports remain preserved.

## Further native corroboration: shared daemon receive callback (2026-11-01)

[daemon_receive_interface_report.md](daemon_receive_interface_report.md) establishes all five callback-to-family routes and exact reply emission/destruction locations. The callback includes the compatible MIG502 implementation path and excludes700 from all recovered ranges. This supersedes the earlier callback-routing gap, while preserving the distinct unknowns of service registration, kernel port-object identity, application policy and native delivery. The two single-ID demultiplexers inline validation/application calls; callback range recognition is wider than actual stub recognition for500/501/41472/61472.

## Further native corroboration: request VM objects and destination cleanup (2026-11-01)

[kext_port_vm_report.md](kext_port_vm_report.md) supersedes the ordinary-constructor payload-serialization gap: filename-plus-NUL bytes are staged in `ipc_kernel_map` and converted into a kernel VM-copy object. It recovers reply copyout into `kernel_map`, an auxiliary-copy discard, a page-wire attempt with untested status, and a guarded `_ipc_port_release_send` call at `0xfffffe000a615f2c`. Two previously unnamed external pointers are explicit +4-biased references to exact map globals. These results retain conditional alias/frame assumptions and do not establish full allocation bounds, successful wiring, total reference ownership or a native RPC exchange. Original analysis.md and its supplied associated files remain preserved.

## Further corroboration: matching kernel RPC implementation (2026-11-01)

[kernel_rpc_transport_report.md](kernel_rpc_transport_report.md) replaces the source-only per-thread reply-port explanation with matching native common-helper, creation/binding and teardown ranges. It separates message COPY_SEND and temporary object-reference accounting, recovers receive/retry/size guards, and establishes the bit37 descriptor PAC transition across the kext ABI. Both RPC clients pass 400-byte receive capacity, distinct from the 392-byte normal kernel inline reply. Original function-start metadata, symbols and bytes support these results; exact source provenance for stripped helper names, downstream namespace/destruction and runtime transaction identity remain unknown.

## Further corroboration: native user copyout and audit provenance (2026-11-01)

[kernel_user_copyout_report.md](kernel_user_copyout_report.md) recovers the matching native user receive-results/copyout/packing path, OOL mapping and descriptor flags, and header namespace roles. It traces null-task kernel trailer initialization to a constant containing eight zero audit words, preserved by inspected packing and copied by the daemon MIG502 stub under explicit intervening-framework assumptions. This distinguishes kernel sender metadata from the constructor origin scalar and the initiating task. The supplied zut trace still contains no such RPC exchange. A synthetic trailer-delivery witness identifies a framework proof obligation, not a native fault or authorization result.

## Further corroboration: RPC502 private record and PID predicate (2026-11-01)

[daemon_rpc502_report.md](daemon_rpc502_report.md) recovers the original-image application wrapper, its private 120-byte argument prefix and protected operation tag0xbc84919b. A verified local route extracts the audit PID and requires zero; nonzero selects decoded status0xffff5bbf (-42049). This is compatible with the prior kernel audit-template path, conditional on standard library/framework behavior. Filename NUL scanning precedes the PID predicate and does not use the supplied OOL extent as a bound. Full policy, native reachability and successful output ownership remain unknown. Current connection visibility exposed only the kext database, so this increment uses original bytes and refreshed prior proof-source hashes rather than a new daemon IDA snapshot.

## Further corroboration: RPC502 environment and encoded comparison (2026-11-01)

[rpc502_environment_report.md](rpc502_environment_report.md) extends that route through scheduling convergence, CPU/origin marshalling, a guarded global, CSR inquiry and the BootPolicy caller boundary. Original bindings establish two imported BootPolicy data cells and the function call at `0x1004cfe24`; nonzero import-table addends cancel native adjustments before cell loads. Actual imported values/types and library-internal IPC remain unknown. The CSR result reduces to a three-valued local indicator, not a complete authorization result. Full-domain arithmetic proofs and ten finite PAC-bypassed/import-modeled Unicorn fixtures are explicitly separated from native execution. Original analysis.md and its two supplied associated files remain preserved.

## Further corroboration: BootPolicy backend and mode partitions (2026-11-01)

[bootpolicy_backend_report.md](bootpolicy_backend_report.md) extends original-byte corroboration into the installed BootPolicy library and matching kernel component: imported default-value identities, root-volume/filesystem inputs, exact additional user-client/Mach interfaces, entitlement/command guards and SEP endpoint/shared-memory bindings. The original daemon declares the required full BootPolicy entitlement in its XML signature slot; signature trust and effective task state remain separate. Its returned mode has a full-domain three-way marker partition whose final effect is unknown. All new analysis is static; runtime library selection and successful delivery remain unverified. The three original inputs remain preserved.

## Further corroboration: support runtime, VMM predicate and CoreKE exports (2026-11-01)

[rpc502_runtime_report.md](rpc502_runtime_report.md) joins the original daemon's dynamic symbol requests to two exact CoreKE exports and recovers their wrapper argument records. It establishes support synchronization calls, an affine VMM-name decoder, the local loader predicate and the next sidecar-file emission. Four SMT checks and16 explicitly modeled private fixtures support bounded claims; no CoreKE/native target code is executed. A synthetic sidecar path has unexplained leading bytes, so native path construction remains unknown. Original analysis.md and its two supplied associated files remain unchanged.

## Further corroboration: installed-cache CF delivery and cached registration (2026-11-01)

[cf_receive_report.md](cf_receive_report.md) now corroborates the framework side of the daemon registration wrappers and common callback with original cache instructions and fresh IDA wrapper bytes. Initial receive capacity3072 bytes, requested68-byte AV trailer and eleven fixed request-size guards close the ordinary trailer-capacity prerequisite. Native source1/CFMachPort bridges forward the inline size, and the run loop disposes grown inline storage after the callback; OOL mappings and port rights retain separate ownership obligations. Constructor cache reuse preserves the old callback/context, and voucher/TSD callouts introduce runtime state beyond audit-token bytes. Six proofs and42 private profiles with229 checks support bounded claims; runtime pairing, service identity, PAC and successful native exchange remain unverified. The three supplied inputs remain preserved.

## Further corroboration: five named registration chains and startup status (2026-11-01)

[daemon_registration_report.md](daemon_registration_report.md) closes the local name-to-check-in-to-CF-wrapper/source/publication chain for unfreed, fairplayd, fpsd, arcade.fpsd and fpsd.sim. Original decoders match the historical trace's names/order; main's native caller/control ABI and exact CF-object cells are retained. Earlier failures can be overwritten by the final helper's success status, failed destination fields remain unchanged, and source failure invalidates/releases the CF object. Nineteen original spans,27 exhaustive banks, eight proofs, eleven fresh IDA byte matches and14 private fixtures with706 checks support the increment. Actual cached callback/namespace identity, full initialization, native resource consequences and later startup remain open. An independent protected new-port caller is retained as a separate interface lead. The three supplied inputs remain unchanged.
