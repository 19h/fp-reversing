# Selector 26 in the currently loaded FairPlayIOKit build

The boot kernel collection selected on the live host contains the FairPlayIOKit Mach-O UUID reported by the runtime kext list, `316464f8-eade-30ca-938e-2f430b1ed5bc`. The embedded kernel UUID also matches `kern.uuid`. The recovered synchronous method router in this collection has the same seventeen populated selector slots as the pinned older build. Selector 26 again declares fixed outer counts of 16 B input and 16 B output.

| Boundary | Pinned build | Current collection |
| --- | --- | --- |
| Synchronous selector router | `0xfffffe000a503cd0` | `0xfffffe000a544e60` |
| 40-slot pointer table | `0xfffffe000846b770` | `0xfffffe0008482210` |
| Selector 26 slot | `0xfffffe000846b838` | `0xfffffe00084822d8` |
| Selector 26 method record | `0xfffffe000846b710` | `0xfffffe00084821b0` |
| Selector 26 member | `0xfffffe000a504034` | `0xfffffe000a5451c4` |
| Nominal provider method | `0xfffffe000a505198` | `0xfffffe000a546328` |

Addresses are preferred addresses in the respective decompressed filesets. The current result is a static inspection of the runtime-matched build. The prior registry observation establishes an attached client attributed to `fairplayd`. Its task-local connection name, method requests, reply rights and actual selected method remain unknown. [Live registry observation](daemon_iokit_native_registry_report.md) [Pinned connection lifecycle](iokit_connection_lifecycle_report.md)

## Collection provenance

`kmutil inspect --show-kernel-uuid-only` selected boot collection `dcaa3cdb-9299-98bf-0c80-2d25f66cf024` with embedded kernel `90195379-954d-3ca3-baac-327341f14211`. `kmutil inspect --show-fileset-entries` located the FairPlayIOKit member at file offset `0x910a90` and reported its UUID. The live query `kmutil showloaded --bundle-identifier com.apple.driver.FairPlayIOKit` reported the same kext UUID. The selected wrapped payload measured 33,785,679 B. `ipsw kernel dec` produced a 126,763,008 B Mach-O with SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The decompressed root and embedded kernel/kext headers independently recover the three UUIDs. The [compressed evidence](triage_evidence/live_kext_selector26_comparison.json.zst) retains both fileset identities and selected original fixup words.

## Method names and ABI fields

The exact current router symbol demangles to `com_apple_driver_FairPlayIOKitUserClient::getTargetAndMethodForIndex(IOService**, unsigned int)`. It uses `u32(selector - 1) <= 39`, takes bitmap `0x87e27e8021` from three immediate instructions and reads the allowed slot by an eight-byte stride. It stores `this` to the target output. The separate `sMethods` nlist symbol identifies the first method record at `0xfffffe0008481e20`. The actual table address comes from the router's ADRP/ADD at `0xfffffe000a544e90` and `0xfffffe000a544e94`.

Each populated slot agrees across both filesets in its member nlist name, flags, target word, this adjustment and both extents. All seventeen records have flags 3, null target word and zero this adjustment. All twenty-three other slots are zero. The following member names are from the original nlist entries. For thunk entries, the table gives the corresponding function name and notes the thunk.

| Selector | Member | Input B | Output B |
| ---: | --- | ---: | ---: |
| 1 | `uOxAg` (virtual thunk) | 0 | 4 |
| 6 | `initKextSession` (virtual thunk) | 32 | 32 |
| 16 | `DSSessionDongleProcessKey` (virtual thunk) | 608 | 608 |
| 18 | `ProcessEncryptedData` (virtual thunk) | 3096 | 3096 |
| 19 | `GetReEncryptionVault` (virtual thunk) | 3088 | 3088 |
| 20 | `ucDecryptOneSample` | 32 | 32 |
| 21 | `ucRunVersioned` | 552 | 552 |
| 22 | `ucGetVersion` | 0 | 4 |
| 23 | `ucGetProtocolCapabilities` | 0 | 4 |
| 26 | `ucSendFPMessage` | 16 | 16 |
| 30 | `ucGenerateSeed` (virtual thunk) | 1028 | 1028 |
| 31 | `ucExchangeWithHoover` (virtual thunk) | Variable | Variable |
| 32 | `ucGetEncryptedSeedSegment` (virtual thunk) | 124 | 16 |
| 33 | `ucGenerateInFieldSeed` | 2052 | 2052 |
| 34 | `ucEncryptSUInfo` (virtual thunk) | 2008 | 2008 |
| 35 | `ucEncryptWithWrappedKey` (virtual thunk) | 140 | 140 |
| 40 | `ucSendFPDIMessage` | 32 | 32 |

Both raw selector 31 extent fields are `0x00000000ffffffff`, the variable-count sentinel tested by the flags-3 adapter. The archived audit retains the complete mangled names and original pointer authentication metadata. [Audit](triage_evidence/audit_live_kext_selector26.py) [Pinned adapter](daemon_selector26_legacy_admission_report.md)

## Connection and synchronous method path

The current IOKit subsystem header at `0xfffffe0007e77bf8` declares request IDs `[2800,2892)`. The three selected records match the pinned builds' descriptor counts and reply reservations. These reservations are record fields in the kernel representation.

| Request / reply ID | Current stub entry | Reply descriptor count | Reply reservation B |
| --- | --- | ---: | ---: |
| 2816 / 2916, close | `0xfffffe000be85524` | 0 | 44 |
| 2862 / 2962, open | `0xfffffe000be81ac4` | 1 | 64 |
| 2865 / 2965, synchronous method | `0xfffffe000be8152c` | 0 | 4284 |

At `0xfffffe000be81644` the method stub calls the connection converter, which compares type `0x27`. The method implementation call is at `0xfffffe000be816b4`, and the synchronous dispatch helper selects the legacy virtual slot +0x880 at `0xfffffe000c5bff1c`. The FairPlay client's slot resolves to `IOUserClient::externalMethod` at `0xfffffe000c5b2248`. Its synchronous router call at `0xfffffe000c5b24e0` uses slot +0x970, which resolves to the current router in the first table. These bindings are conditional on the selected client and ordinary synchronous dispatch.

The flags-3 branch calls the structure adapter at `0xfffffe000c5b266c`. The adapter loads the two fixed counts from record offsets +0x20 and +0x28. With selector 26, the input and output mismatch branches are at `0xfffffe000c5b4804` and `0xfffffe000c5b4828`. A 272 B or 288 B outer input takes the input mismatch branch, which forms `0xe00002c2` under ordinary return. The 16 B descriptor passes both outer count checks when submitted with 16 B output capacity. The stub publishes a nonzero result at reply header +40 B at `0xfffffe000be816e8`. This identifies the status store. The reply's queue handoff and numeric Mach names are outside the inspected live-build slices. [Pinned short-reply contract](iokit_sync_error_reply_report.md)

## Provider boundary

The first 104 B of the two selector 26 members are byte-identical. The current member's nlist names `ucSendFPMessage(FPUserFPMessageParams_ const*, FPUserFPMessageParams_*)`. The member loads the nested pointer from input+0 and the u32 extent from input+8, then reads the task from client+0xe0, context from +0xe8 and provider from +0xd8. It calls through provider address point +0xa20 at `0xfffffe000a54521c` with discriminator `0x3499`. The nominal provider slot binds the obfuscated symbol `uej58Beal(unsigned char const*, unsigned int, void*, task*)`. On success the handler echoes the nested address and extent at output offsets 0 and 8.

The provider supplies the nested address in X0, zero-extended extent in X1, options 3 in W2 and the stored task in X3 to the veneer called at `0xfffffe000a546364`. The original pointer at `0xfffffe0008492ec0` resolves to `IOMemoryDescriptor::withAddressRange` at `0xfffffe000c589f88`. This establishes the memory-descriptor request and its argument sources in this kext. Behavior after construction, the data written by the provider and the daemon's receipt of those bytes remain unknown in the live build. [Pinned task and descriptor provenance](iokit_structure_arguments_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| LC1 | The current selected boot payload and live registry observation refer to the identified runtime build. The cross-build association depends on this identity. | Repeat the selected-collection, runtime kernel and loaded-extension UUID queries and compare the embedded headers after decompression. |
| LC2 | The static fileset's format-8 chain bounds and relocation interpretation apply. Table, member, imported factory and vtable bindings depend on them. | Walk the original chains and independently decode the retained target, discriminator and key fields. |
| LC3 | A request reaches the chosen synchronous path with the indicated class and counts, and diagnostic/provider calls return normally. The count and output results depend on these conditions. | Compare subtype, runtime connection identity, dynamic method target, method arguments and return in a passive ordinary transaction. |
| LC4 | The exact nlist symbols identify the named source-local entries. A thunk symbol labels its entry and argument declaration. | Compare call-through targets, original immediate/register sources and emitted status/data for semantic claims beyond the name. |

The audit checks eighty method-table cells across the two filesets, thirty-four members, six MIG records and both selected dispatch/descriptor paths. Independent runtime queries and a direct decode of four original pointer words reproduce the selected identity, member, provider and factory bindings. It runs in O(B + F + N) time and space for file bytes B, chained fixup words F and scoped symbol data N, with the reported selector count and source windows fixed. No kernel instructions were executed, no device-method call was issued, and no IDA database changed in this increment. QG1–QG3 cover the scoped claims and assumptions. QG4–QG5 cover byte counts, branch conditions and reservation widths. QG6–QG7 cover original header/instruction/fixup provenance and the remaining observations below.

```sh
ipsw kernel dec "$SELECTED_BOOT_PAYLOAD" -o "$DECODE_DIRECTORY"
uv run --no-project --python 3.14 --with capstone \
  python triage_evidence/audit_live_kext_selector26.py "$CURRENT_COLLECTION" \
  --pinned-collection "$PINNED_COLLECTION"
```

| Impact | Open evidence |
| --- | --- |
| High | Correlate the observed `fairplayd` user-client registry entry with a live connection right and a descriptor-form method request and reply. |
| High | Follow the current provider after descriptor construction to establish native output provenance. |
| Medium | Identify the matching live IOKit wrapper and kernel reply-send addresses and compare the wider selector map beyond declarations. |
