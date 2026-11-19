# Current selector 26 provider transfer and status lifecycle

The current FairPlayIOKit provider `uej58Beal` retains the selector 26 copy and cleanup path established in the pinned build. Its 151-instruction body differs in four machine words, all at addressing or call sites. The 40-instruction user-client handler differs in two words. The current provider stages the task buffer, calls the core, requests copy-back, then completes and releases the descriptors before returning the saved core result. The user-client handler publishes the descriptor address and extent on low-32-bit status zero. [Current selector map](live_kext_selector26_report.md) [Pinned transfer and return proof](userclient_transfer_boundary_report.md)

| Boundary | Pinned call PC | Current call PC |
| --- | --- | --- |
| Task descriptor construction | `0xfffffe000a5051d4` | `0xfffffe000a546364` |
| Kernel staging buffer construction | `0xfffffe000a505250` | `0xfffffe000a5463e0` |
| Task descriptor copy-in | `0xfffffe000a5052ec` | `0xfffffe000a54647c` |
| Core call | `0xfffffe000a5052fc` | `0xfffffe000a54648c` |
| Task descriptor copy-back | `0xfffffe000a505344` | `0xfffffe000a5464d4` |
| Handler's descriptor output | `0xfffffe000a5040b0`, `0xfffffe000a5040b8` | `0xfffffe000a545240`, `0xfffffe000a545248` |

The table identifies original instructions in the two boot collections. The current collection's embedded kernel and kext UUIDs match their runtime reports. The executed dynamic receiver classes, transfer counts, copied bytes and a current `fairplayd` transaction remain unknown. [Current registry observation](daemon_iokit_native_registry_report.md)

## Task buffer and status

The provider prepares the task descriptor at `0xfffffe000a54639c`, then prepares the kernel buffer at `0xfffffe000a546418` and obtains its backing pointer at `0xfffffe000a54644c`. The copy-in and copy-back request the same zero-extended 32-bit extent and use offset zero. The provider passes the backing pointer, extent, and provider context to the current `PRnut72j9` entry at `0xfffffe000a676398`. The callee stores these arguments at stack offsets `0x8f8`, `0x878`, and `0x738`, respectively. The provider saves the returned X0 in X21 at `0xfffffe000a546490` and restores it to X0 at `0xfffffe000a546568`. The call sequence between those instructions requests copy-back, then completes and releases the staging descriptor followed by the task descriptor. The caller has no conditional branch on either copy count or on the saved core status before copy-back.

| First setup failure | Cleanup requested before returning |
| --- | --- |
| Task descriptor construction | None |
| Task descriptor preparation | Release task descriptor |
| Staging descriptor construction | Complete and release task descriptor |
| Staging descriptor preparation | Release staging descriptor, then complete and release task descriptor |

Each listed setup failure returns the same low-32-bit status, `0xffff5bd4`. The output handler branches on that low word at `0xfffffe000a545224`. Its success path stores an eight-byte address at `0xfffffe000a545240` and a four-byte extent at `0xfffffe000a545248`. The producer for the other four bytes of the 16-byte outer output is unknown. The kernel's copy-back request targets the task buffer before the method returns. The Mach reply carries the status and, on method success, the outer output. The daemon's modeled acceptance checks compare the outer extent with 16 and the returned nested extent with the submitted extent. [Mach transport](live_iokit_mach_transport_report.md) [Daemon return checks](daemon_selector26_pidpath_returns_report.md)

## Descriptor dispatch and success reply

The changed provider words at offsets `0x8c`, `0x90`, `0x98`, and `0x9c` still load the `kernel_task` and `PAGE_SHIFT_CONST` imports through chained fixups. The staging allocation passes task `kernel_task`, options `0x13`, the nested extent and alignment `sign_extend_64(uint32_t(1) << (PAGE_SHIFT_CONST & 31))`. The runtime alignment is unknown. The task descriptor factory requests options 3 and receives the task argument from the user-client handler. The two changed handler words at `0x68` and `0x6c` still address the same diagnostic string. The audit verifies both descriptor factories, the logger and core entry against original symbols in each collection.

| Receiver vtable | Byte offset from address point | Nominal method | Current entry after any branch thunk |
| --- | --- | --- | --- |
| `IOGeneralMemoryDescriptor` | `0x208` | `readBytes` | `0xfffffe000c580b0c` |
| `IOGeneralMemoryDescriptor` | `0x210` | `writeBytes` | `0xfffffe000c5808d8` |
| `IOBufferMemoryDescriptor` | `0x308` | `getBytesNoCopy` | `0xfffffe000c574180` |
| Both | `0x218` | `prepare` | `0xfffffe000c584a08` |
| Both | `0x220` | `complete` | `0xfffffe000c584080` |
| Both | `0x28` | `release` | `0xfffffe000c493f98` |

On the success branch at `0xfffffe000be816fc`, the current kernel MIG stub reads the structure extent at `0xfffffe000be81718`, rounds it up to four bytes and adds eight bytes per returned scalar. The store at `0xfffffe000be81754` publishes the kernel message size in bytes as `60 + round_up(structure_extent, 4) + 8 * scalar_count`. For 16 B and zero scalars, that is 76 B in the kernel layout. Removing the eight bytes of kernel header expansion yields a 68 B user message. The size calculation is conditional on the successful stub path and those returned counts. [Mach header layouts and reply packing](live_iokit_mach_transport_report.md)

The extractor takes the current decompressed collection as its positional input and an optional `--pinned` collection. It validates the fileset identities, compares all 191 instructions in each build, follows imports and vtables through original chained fixups, and records raw instructions and their decoded operands. [Extractor](triage_evidence/audit_live_kext_selector26_transfer.py) [Compressed evidence](triage_evidence/live_kext_selector26_transfer_audit.json.zst)

## Assumptions and evidence gaps

| Assumption or boundary | Dependent result | Falsification probe |
| --- | --- | --- |
| The two collection identities match the pinned and runtime-selected builds | Current addresses and instruction comparison | Compare container hash and embedded kernel and kext UUIDs |
| Runtime receivers use the nominal descriptor class dispatch | Specific implementation reached by a virtual call | Observe the runtime receiver class or dispatch target |
| A normal return reaches the provider epilogue | Call order and saved status | Observe the provider return and correlate it with the method reply |

The actual daemon transaction and byte counts have high impact on validating the data path. The remaining four outer bytes have medium impact on interpreting the complete inline output. Internal behavior of the current core is unknown and falls outside the caller-level equivalence.
