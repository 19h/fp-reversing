Based on the `nm -C` symbol table dump (Images 1–8) and the static call-graph cross-references (Images 9–10) of `com.apple.driver.FairPlayIOKit`, we can reconstruct the architectural layout, external interfaces, control-flow paths, and internal mechanics of this XNU kernel extension (kext).

---

### 1. Semantic Grouping of Import and Export Symbols

The symbols can be segmented into **eight distinct semantic categories** based on their naming conventions, C++ class scopes, call-graph relationships, and linkage types (`T` / `t` for defined global/local text, `S` / `s` / `b` / `d` / `D` for data/BSS, and `U` for undefined kernel imports).

#### A. IOKit Driver & UserClient Lifecycle (`com_apple_driver_FairPlayIOKit*`)
* **Kext Module Stubs & Static Initializers (`T`, `t`, `s`, `d`, `D`):**
  * Standard kext entry/exit stubs: `__start` (`0xfffffe000a5a1c40`), `__stop` (`0xfffffe000a5a1ca0`), `__realmain` (`0xfffffe000ccc77e8`), `__antimain` (`0xfffffe000ccc77f0`), `_kmod_info` (`0xfffffe000ccc2a20`), `__kext_apple_cc` (`0xfffffe000ccc2ae4`).
  * Subsystem lifecycle: `LSKDKext_start()` (`0xfffffe000a5053f4`), `LSKDKext_stop()` (`0xfffffe000a505480`).
  * Kext metadata helpers: `_OSKextGetCurrentIdentifier`, `_OSKextGetCurrentLoadTag`, `_OSKextGetCurrentVersionString`.
  * C++ static initializers/destructors: `__GLOBAL__sub_I_FairPlayMemoryDescriptor.cpp`, `__GLOBAL__sub_I_FairPlayIOKitUserClient.cpp`, `__GLOBAL__sub_I_FairPlayIOKit.cpp`, and `__GLOBAL__D_a*`.
* **IOService Provider Class (`com_apple_driver_FairPlayIOKit`):**
  * `init(OSDictionary*)`, `probe(IOService*, int*)`, `start(IOService*)`, `stop(IOService*)`, `free()`, plus `MetaClass` constructors/destructors and vtables (`0xfffffe000846b8c0`).
* **IOUserClient Class (`com_apple_driver_FairPlayIOKitUserClient`):**
  * `initWithTask(task*, void*, unsigned int)`, `start(IOService*)`, `stop(IOService*)`, `clientClose()`, `clientDied()`.
  * External method dispatcher: `getTargetAndMethodForIndex(IOService**, unsigned int)` (`0xfffffe000a503cd0`) and its backing static dispatch table `sMethods` (`0xfffffe000846b380`).
* **Inherited IOKit / Libkern Imports (`U`):**
  * Standard vtable and runtime dependencies from `IOService`, `IOUserClient`, `IORegistryEntry`, `OSObject`, `OSMetaClass`, `OSData`, and `OSString` (e.g., `copyClientEntitlement`, `externalMethod`, `serviceMatching`, `waitForService`, `safeMetaCast`).

#### B. UserClient External Methods & RPC Handlers (`T`, `t`)
Methods exposed on `com_apple_driver_FairPlayIOKitUserClient` (each paired with a `_vfpthunk_` wrapper in `t` for virtual function pointer resolution in IOKit dispatch tables):
* **Session & Protocol Management:**
  * `initKextSession(ovHBHGCR5ZAwSmgzDIbVv20x*, ovHBHGCR5ZAwSmgzDIbVv20x*)`
  * `ucGetVersion(unsigned int*)`, `ucGetProtocolCapabilities(unsigned int*)`, `ucRunVersioned(kJAimpk const*, kJAimpk*)`
  * `ucSendFPMessage(FPUserFPMessageParams_ const*, FPUserFPMessageParams_*)`
  * `ucSendFPDIMessage(FPDIUserFPMessageIO_ const*, FPDIUserFPMessageIO_*)`
  * `ucExchangeWithHoover(unsigned char const*, unsigned char*, unsigned long, unsigned long*)`
* **Provisioning & Seed Generation:**
  * `ucGenerateSeed(ProvInfoIOKitUserGenerateSeedIO_ const*, ProvInfoIOKitUserGenerateSeedIO_*)`
  * `ucGenerateInFieldSeed(ProvInfoIOKitUserGenerateInFieldSeedIO_ const*, ProvInfoIOKitUserGenerateInFieldSeedIO_*)`
  * `ucGetEncryptedSeedSegment(ProvInfoIOKitUserGetEncryptedSeedSegmentInput_*, unsigned char*)`
  * `ucEncryptSUInfo(ProvInfoIOKitUserEncryptSUInfoInput_ const*, ProvInfoIOKitUserEncryptSUInfoInput_*)`
  * `ucEncryptWithWrappedKey(ProvInfoIOKitUserEncryptWithWrappedKeyInput_ const*, ProvInfoIOKitUserEncryptWithWrappedKeyInput_*)`
* **Media & Content Decryption:**
  * `decryptSliceData(KDDecryptDataForSliceDecIO_*, KDDecryptDataForSliceDecIO_*)`
  * `decryptSliceDataWithCTR(KDDecryptSliceDataWithCTRIO_*, KDDecryptSliceDataWithCTRIO_*)`
  * `decryptOneSampleWithCTR(KDDecryptDataWithCTRIO_*, KDDecryptDataWithCTRIO_*)`
  * `ucDecryptOneSample(lvIKvKE const*, lvIKvKE*)`
  * `ProcessEncryptedData(RwyEg0MUTKuzQ*, RwyEg0MUTKuzQ*)`
  * `GetReEncryptionVault(KDReEncryptionVaultIO_*, KDReEncryptionVaultIO_*)`
  * `DSSessionDongleProcessKey(KDDSSessionDongleIO_*, KDDSSessionDongleIO_*)`
* **Obfuscated UserClient Methods:**
  * `u0xAg(unsigned int*)`
  * `LQ1N1WLcw(RVbEMromyROSkm*, RVbEMromyROSkm*)`

#### C. Hardware & Software AES Cryptography (`T`, `t`, `U`, `b`, `s`)
* **Hardware AES Accelerator (`*AESHW*`, `*LSKD*`):**
  * *Initialization/Teardown:* `_initKernelAESHW`, `_initKernelAESHWLSKD`, `_cleanupKernelAESHW`, `cleanupKernelAESHWLSKD()`.
  * *Execution:* `performAESonIOMD(IOMemoryDescriptor*, IOMemoryDescriptor*, unsigned long long, IOAESIV*, IOAESOperation, IOAESKeyData*, unsigned long long, unsigned long long)`, `_performAESonSamplesIOMD`, `_performHWAES`, `_performHWAESLSKD`, `_performHWAESOnBuffer`, `_performHWAESOnBufferLSKD`, `_performHWAESOnGlobalBuffer`, `_getSupportedAESOptions`.
  * *Global State (`b`):* `gAESAcceleratorProvider`, `gAESAcceleratorIOBMD`, `gAESAccelatorProviderInitialized` (and their `*LSKD` counterparts at `0xfffffe000ccceb00`–`0xfffffe000ccceb28`).
* **Software / Generic Crypto (`T`, `t`, `U`, `s`):**
  * *Internal/Exported:* `_performAESCBCDecryption`, `_getCBCMacForPageIndex`, `_PIKDecryptWithFixedSharedKey` (`0xfffffe000a59c3c4`), `_buildLookupTbl`, `_arc4random`, and `LDdKLPm0(...)::kSeedConstants` (`0xfffffe000790cc8c`).
  * *External Kernel Crypto Imports (`U`):* `_aes_decrypt_cbc`, `_aes_decrypt_key`, `_read_random`, `_random`.

#### D. Memory Descriptor & DMA Buffer Management (`T`, `S`, `U`)
* **Custom Subclass (`FPMemoryDescriptor`):**
  * Overrides `IOMemoryDescriptor` (`withAddressRange`, `initWithOptions`, `getAddress`, `getLength`, `releases`, `free`).
* **Global Descriptor State (`S`) & Lifecycle Helpers (`T`):**
  * Four dedicated pipelines: `Input`, `Output`, `Samples`, and `SampleSizes` (backed by `_input_desc`, `_output_desc`, `_samples_desc`, `_sample_sizes_desc` at `0xfffffe000ccc7858`–`0xfffffe000ccc7870`).
  * Each pipeline has a symmetric set of C functions: `_create*IOMD`, `_prepare*IOMD`, `_readBytesFrom*IOMD`, `_writeBytesTo*IOMD`, `_complete*IOMD`, and `_release*IOMD`, plus `_InputIOMDEqualsOutputIOMD`.
* **Low-Level VM & Mapping (`T`, `U`):**
  * *Exports (`T`):* `_kernelMap`, `_kernelUnmap`, `_kernelMapOOLFile`, `_kernelUnmapOOLFile`.
  * *Imports (`U`):* `IOMemoryDescriptor::withAddressRange`, `IOBufferMemoryDescriptor::inTaskWithOptions`, `IOBufferMemoryDescriptor::withBytes`, `_vm_map_copyin`, `_vm_map_copyout`, `_vm_map_copy_discard`, `_vm_map_wire`, `_vm_map_unwire`, `_vm_deallocate`, `_ipc_kernel_map`, `_kernel_map`, `_kernel_task`.

#### E. OS / Kernel Abstraction Layer (`_kernel_*` Exports vs. XNU `U` Imports)
The kext defines a C-linkage wrapper layer (`T _kernel_*`) around standard XNU kernel APIs (`U`):
* **Synchronization:** `_kernel_lock_*` (wrapping `_IOLock*`) and `_kernel_iorw_lock_*` (wrapping `_IORWLock*`).
* **Threading:** `_fp_kernel_thread_start`, `_kernel_thread_call_*`, `_kernel_thread_deallocate` (wrapping `_thread_call_*`, `_kernel_thread_start`, and `_thread_deallocate`).
* **Memory & Libc:** `_kernel_kmem_alloc`, `_kernel_kmem_free`, `_kernel_memcpy`, `_kernel_memset`, `_kernel_printf`, `_kernel_snprintf`, `_kernel_vsnprintf`, `_FPDebugDisplayStatusMsg`.
* **System Info & Time:** `_kernel_sysctlbyname`, `_kernel_clock_get_calendar_microtime`, `_kernel_clock_interval_to_deadline`, `_kernel_microuptime`, `_kernel_read_random`.

#### F. File System (VFS), NVRAM, and Platform Properties (`T`, `U`, `b`)
* **VFS Imports (`U`) & File Helpers (`T`):** `_vnode_open`, `_vnode_getattr`, `_vn_rdwr`, `_vnode_close`, `_vfs_context_current`, `_vfs_context_proc`, `_vfs_context_ucred` used by `_readFCDFileVersion`, `_getCBCMacForPageIndex`, and `_buildLookupTbl`.
* **Hardware / Platform Inspection (`T`, `b`):** `_accessNVRAMProperty`, `accessNVRAMProperty::fNVRAMOptions`, `_getDeviceProperty`, `GetDeviceProperty(...)`, `GetProductID(...)`, `isJ42dDevice(bool*, unsigned char*)`.

#### G. Mach IPC & MIG RPC (`U`)
* Direct kernel Mach messaging imports: `_mach_msg_rpc_from_kernel_proper`, `_mach_msg_destroy_from_kernel_proper`, `_mig_get_reply_port`, `_mig_put_reply_port`, `_mig_dealloc_reply_port`, `_host_priv_self`, `_host_get_special_port`, `_ipc_port_release_send`, `_NDR_record`.

#### H. Obfuscated Core Logic (`T`, `t`, `S`, `sub_*`)
* **C++ Methods on `com_apple_driver_FairPlayIOKit` (`T`):** Randomly generated alphanumeric method names (e.g., `ycJai39mD8`, `sxvHysrIgQq2V`, `ZURJELCowjwysX`, `tbzvC93d1UX`, `glMABVgh`) whose parameter types remain visible due to C++ name mangling (revealing internal structs like `guNUWjBHDxSrlXfjY*`, `rp6S0jzg*`, `_AVDDecryptParams*`, `SliceInfo_ const*`, `_ProvInfoSeedVersion_`, `_PUCryptoOperation_`, `FPAppDecryptOrigin_`).
* **Internal C Functions (`t`), Globals (`S`), & Stripped Subroutines (`sub_*`):** Obfuscated local symbols (e.g., `_De20DmHh3jVChIyH`, `_Prn3ccdCvCjGlvZGIjqWqiZK`, `_zzLw2e0Vu9p0HqpiNw1K4ki`), obfuscated globals (`_L8NEoIll0BwWkdF06PuGxiiehGZr`, `_T68NEoIll0BwWkdF06PuGk48xiiehGZrfj`), and stripped internal subroutines (`sub_FFFFFE000A50B36C` through `sub_FFFFFE000A69E2E0` in Image 10).

---

### 2. Evidence-Based Entry and Exit Points Worth Investigating

When analyzing an XNU IOKit kernel extension, **entry points** are where execution transitions from the kernel/userspace into the kext, and **exit points** are where the kext calls out to external kernel subsystems, other drivers, or userspace.

#### Primary Entry Points (Inbound Execution)
1. **Module Load / Unload & Global Constructors:**
   * `__start` / `__realmain` and `__stop` / `__antimain` (standard kext entry/exit).
   * `LSKDKext_start()` and `LSKDKext_stop()`: Secondary subsystem initialization/teardown specifically tied to the `LSKD` (Lease/Key Delivery) logic. As shown in the call graph (Image 10), `com_apple_driver_FairPlayIOKit::start(IOService*)` directly invokes `LSKDKext_start()` and `_cmam7f`, while `stop(IOService*)` invokes `LSKDKext_stop()` and `_uzZm1ih0`.
   * `__GLOBAL__sub_I_FairPlayIOKit.cpp`, `__GLOBAL__sub_I_FairPlayIOKitUserClient.cpp`, and `__GLOBAL__sub_I_FairPlayMemoryDescriptor.cpp`: C++ static initializers that set up `OSMetaClass` instances when the kext loads.
2. **IOKit Matching & Instantiation:**
   * `com_apple_driver_FairPlayIOKit::probe(IOService*, int*)` and `start(IOService*)`: Entry points invoked by IOKit when the driver matches against the IORegistry.
3. **UserClient Connection Establishment (Privilege Gate):**
   * `com_apple_driver_FairPlayIOKitUserClient::initWithTask(task*, void*, unsigned int)` (`0xfffffe000a5040d4`): Invoked when a userspace process calls `IOServiceOpen`.
   * **Call-graph evidence (Image 9):** `initWithTask` directly calls `IOUserClient::copyClientEntitlement(task*, char const*)` and `_IOLog`. Along with task-accepting provider methods (`cRAdZe9(task*) -> _egYabpI0CbFA`, `qtQQt(task*, ...) -> _UeFdbi`, `yt8uP0Vu(rp6S0jzg*, task*, ...) -> _RUD5XlDtQjk`, and `uej58Beal(..., task*) -> _PRnut72j9`), this is the primary access-control boundary validating client tasks and entitlements.
4. **UserClient External Method Dispatch Table (Primary Attack/API Surface):**
   * `com_apple_driver_FairPlayIOKitUserClient::getTargetAndMethodForIndex(IOService**, unsigned int)` and `sMethods` (`0xfffffe000846b380`): This is the legacy IOKit dispatch router invoked via `IOConnectCallMethod` from userspace. Inspecting the `sMethods` array in the `__CONST` / `__DATA_CONST` segment directly maps selector indices (`0..N`) to the 21 `uc*` / decryption methods and their expected input/output struct sizes.
   * **Call-graph highlights (Images 9–10):**
     * `initKextSession` and `ProcessEncryptedData` immediately wrap raw client addresses in `FPMemoryDescriptor::withAddressRange` and query `getAddress()` / `getLength()`.
     * `ucSendFPDIMessage` maps client buffers via `IOMemoryDescriptor::withAddressRange` and `IOBufferMemoryDescriptor::inTaskWithOptions`.
5. **Cross-Driver Public Exports (`T`):**
   * `com_apple_driver_FairPlayIOKit` exports numerous public (`T`) methods taking `_AVDDecryptParams*`, `SliceInfo_ const*`, and `_KDISAVDDecryptionAllowedParamsIO*` (e.g., `sxvHysrIgQq2V`, `Kp0289aEmoqcAa`, `ZURJELCowjwysX`). These serve as direct in-kernel entry points called by other Apple media/video decoding kexts (such as `AppleAVD` — Apple Video Decoder).

#### Primary Exit Points (Outbound Execution & Side Effects)
1. **Hardware AES Accelerator Calls:**
   * `_initKernelAESHW`, `_initKernelAESHWLSKD`, `_performHWAES*`, and `performAESonIOMD`: Where the kext locates the platform's hardware AES `IOService` provider (`IOService::serviceMatching` -> `IOService::waitForService`, stored in `gAESAcceleratorProvider` / `gAESAcceleratorProviderLSKD`) and dispatches DMA-backed crypto operations.
   * **Call-graph evidence (Images 9–10):** `KLzN`, `DqyxC6zf2Sv`, `Fd7DxKaV3`, `LDdKLPm0`, `fDkV4Su`, and `J8i0aN2gZ6hA3n6` also follow this exact `serviceMatching` -> `waitForService` -> `IOBufferMemoryDescriptor::inTaskWithOptions` outbound pattern.
2. **In-Kernel Mach RPC (`_mach_msg_rpc_from_kernel_proper`):**
   * **Call-graph evidence (Image 10):** `sub_FFFFFE000A5A2064` invokes `_mig_get_reply_port`, `_mach_msg_rpc_from_kernel_proper`, `_mig_put_reply_port`, `_mig_dealloc_reply_port`, and `_mach_msg_destroy_from_kernel_proper`, while `sub_FFFFFE000A5A2204` invokes `_host_priv_self`, `_host_get_special_port`, and `_ipc_port_release_send`. This proves that the kext makes synchronous Mach IPC upcalls from the kernel to a privileged userspace daemon (attached to a Mach special port, such as `fairplayd`).
3. **Direct VFS File I/O (`_vnode_open` / `_vn_rdwr`):**
   * **Call-graph evidence (Images 9–10):** Implemented inside helpers `_readFCDFileVersion` (`0xfffffe000a508e54`), `_buildLookupTbl` (`0xfffffe000a509114`), and `_getCBCMacForPageIndex` (`0xfffffe000a509658`), each calling `_vfs_context_current` -> `_vnode_open` -> `_vnode_getattr` -> `_vfs_context_ucred` -> `_vfs_context_proc` -> `_vn_rdwr` -> `_vnode_close` to directly open and read files from the filesystem using kernel VFS contexts.
4. **NVRAM & IORegistry Queries:**
   * **Call-graph evidence (Images 9–10):** `_accessNVRAMProperty` (`0xfffffe000a50a40c`), `_getDeviceProperty` (`0xfffffe000a50a198`), and `GetDeviceProperty` call `IORegistryEntry::fromPath` and `OSMetaClassBase::safeMetaCast` to query platform device-tree nodes, IORegistry planes, and NVRAM variables.
5. **Userspace Memory Copyout (`_vm_map_copyout` / `IOMemoryDescriptor`):**
   * `_kernel_vm_map_copyout` (called by `sub_FFFFFE000A5A1B84`), `_writeBytesToOutputIOMD`, and `_completeOutputIOMD`: Where processed or decrypted buffers are wired, written, and returned to the caller's address space.

---

### 3. Inferred Behaviors and Architectural Insights

From the symbol metadata and call-graph topology, several concrete behaviors can be inferred without looking at assembly instructions:

1. **Selective Symbol Obfuscation Mixed with C++ RTTI Leaks:**
   * Internal core functions (`t` and `sub_FFFFFE000...`) and sensitive `com_apple_driver_FairPlayIOKit` methods (`T`) have had their identifiers replaced with random strings (e.g., `guNUWjBHDxSrlXfjY`, `sxvHysrIgQq2V`) or stripped (`sub_FFFFFE000A50B36C`–`sub_FFFFFE000A69E2E0`).
   * However, because `com_apple_driver_FairPlayIOKit` is an IOKit `OSObject` subclass that relies on C++ virtual tables and cross-kext linking, the compiler mangled the parameter type names into the symbols. Furthermore, UserClient methods (`ucGenerateSeed`, `decryptSliceDataWithCTR`) and struct names (`_AVDDecryptParams`, `_ProvInfoSeedVersion_`, `FPAppDecryptOrigin_`) were left unobfuscated, revealing the exact purpose of the obfuscated functions they call.
   * **Direct Wrapper Mappings (from Images 9–10):**
     * `DCkic`, `xHu6d1`, and `ycJai39mD8(..., FPAppDecryptOrigin_, rp6S0jzg**)` all delegate directly to `_fcHfFIGhsx` (app decryption context initialization).
     * `Kp0289aEmoqcAa(rp6S0jzg*, _AVDDecryptParams*)` delegates to `_sk3kcwm3l2`.
     * `HJZF2FKXmBuuy(guNUWjBHDxSrlXfjY*, unsigned long long*)` delegates to `_De20DmHh3jVChIyH`.
     * `WkhY6wTBlbHrpaT0` delegates to `_zgcqcxw1qve0CY`.
     * `LasdMdn12cas` -> `_kratpzs81h`; `Trped0719ab` -> `_lapsl183ah`; `u0xAg` -> `_V2F1SYee`; `Q5TC6` -> `_QIWEiU`.

2. **Centralized Session/State-Machine Bracketing Pattern:**
   * The call graph (Images 9–10) reveals that major entry points (`LSKDKext_start`, `LSKDKext_stop`, `WT74ohNhs040y`, `R2nPsU0Yx6h`, `B7VLiasHfyH0Ib7FW`, `eJ7hq0h8Z`, `KDGetReEncryptionVault`, `sxvHysrIgQq2V`, `ZURJELCowjwysX`) all execute an identical five-step sequence:
     1. `_mzRQjC7QF6ZQbBAmA` (and/or `_JmmzRQjC7QF6ZQbBA` / `_zzLw2e0Vu9p0HqpiNw1K4ki`)
     2. `_FPDebugDisplayStatusMsg`
     3. `_TdtbU9WbbSyE1sdsj`
     4. Core operation handler (e.g., `_V9Z6DQ1D8vW2ehH161m`, `_kfszHrZ3N4HMtvfB5Bws`, `_Hpu7ZB0FQYIwvPDYn9`, `_bv0pQIFuAPhAERxjZ7R`)
     5. `_npoKianhz5eqeqJHjqa9`
   * This consistent prologue/epilogue structure indicates a centralized lock/context-acquisition and status-logging wrapper around the internal FairPlay state machine.

3. **Portable Core Library Design (`_kernel_*` Wrapper Pattern):**
   * The kext exports a complete C abstraction layer (`_kernel_kmem_alloc`, `_kernel_memcpy`, `_kernel_lock_lock`, `_kernel_printf`, `_kernel_vm_map_copyin`). This indicates that the core FairPlay logic is compiled from a portable, OS-agnostic C library shared across multiple execution environments, binding to XNU primitives through this thin shim layer.

4. **Kernel-to-Userspace Upcalls via Mach Special Ports ("Hoover" / `fairplayd`):**
   * Normally, userspace calls into a kext. Here, imports like `_host_get_special_port` and `_mach_msg_rpc_from_kernel_proper` (in `sub_FFFFFE000A5A2064` and `sub_FFFFFE000A5A2204`) alongside `ucExchangeWithHoover` and out-of-line file mapping (`_kernelMapOOLFile` in `sub_FFFFFE000A5A1F6C`) indicate a bidirectional architecture: when another kernel driver or subsystem requests a FairPlay operation, the kext can pause the kernel thread and perform a Mach RPC upcall to a userspace daemon to fetch session state or keys.

5. **Zero-Copy / DMA Media Decryption Pipeline (`IOMD` & `AVD` Integration):**
   * The four `IOMemoryDescriptor` pipelines (`Input`, `Output`, `Samples`, `SampleSizes`), combined with `SliceInfo_`, `_AVDDecryptParams`, and `CTR` / `CBC` modes (`decryptSliceDataWithCTR`, `decryptOneSampleWithCTR`), show that the kext is heavily optimized for streaming video decryption (e.g., H.264/HEVC NAL units or slices).
   * `_InputIOMDEqualsOutputIOMD` (`0xfffffe000a509fc8`) shows explicit checks for **in-place decryption** over shared physical memory pages (`IOMemoryDescriptor`) before handing buffers off to hardware video decoders (`AVD`).

6. **Dual Cryptographic Backends (Hardware DMA vs. Software Fallback):**
   * The kext prioritizes hardware-accelerated AES (`_performHWAES*`, `gAESAcceleratorProvider`, and parallel `*LSKD` instances) using `IOBufferMemoryDescriptor` (`gAESAcceleratorIOBMD`) for bulk media sample decryption, while maintaining a software AES/lookup-table implementation (`_aes_decrypt_cbc`, `_buildLookupTbl`, `_PIKDecryptWithFixedSharedKey`) for internal key unwrapping, provisioning (`ProvInfo`), and metadata protection (`_readFCDFileVersion`, `_getCBCMacForPageIndex`).

7. **Device-Specific Behavior & Dongle/HDCP Support:**
   * The call graph (Images 9–10) shows `DqyxC6zf2Sv` and `LDdKLPm0` (which take `_ProvInfoSeedVersion_`) calling `isJ42dDevice` -> `GetProductID` -> `GetDeviceProperty` before invoking `IOService::serviceMatching` (and `LDdKLPm0` additionally invokes `_PIKDecryptWithFixedSharedKey`).
   * Combined with `DSSessionDongleProcessKey` / `KDDSSessionDongleProcessKey` (Downstream Session Dongle key processing for external display adapters/Lightning-to-HDMI) and `ucEncryptSUInfo` (Software Update personalization info), this demonstrates that this single kext handles device-specific provisioning (specifically checking for `J42d` — Apple TV HD board ID `J42dAP`), app decryption (`FPAppDecryptOrigin_`), media sample decryption, and external display link protection.
