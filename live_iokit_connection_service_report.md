# FairPlayIOKit connection-to-provider query

The installed FairPlayIOKit user client inherits `IOUserClient::getService()`, which returns null. On an admitted connection to that class, `IOConnectGetService` therefore takes the `kIOReturnUnsupported` (`0xe00002c7`) status-only reply path. The known IOService-plane parent and child entries establish registry attachment. The connection query cannot recover that parent as a Mach send right on this compiled path. The pinned daemon has no direct binding to this API, and the archived RAX trace contains neither its request nor its reply. Native invocation remains unknown. [Observed registry attachment](daemon_iokit_native_registry_report.md) [Audited open and owner registration](live_iokit_open_owner_report.md)

```text
connection send name -> IOKit request 2817 -> import kind 0x27
                                                |
                                                v
MIG reply name <- status-only reply 2917 <- FairPlay getService() -> null
```

## Framework, kernel and driver binding

The evidence covers build `26C5035r`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`, FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc` and dyld cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`. Kernel and cache addresses are unslid. The public framework wrapper delegates to `io_connect_get_service`, and the XNU interface declares an input connection plus one output `io_object_t`. The installed request reaches the IOKit MIG subsystem directly. The method selector table used by request `2865` is a separate path. [Apple IOKit wrapper](https://github.com/apple-oss-distributions/IOKitUser/blob/main/IOKitLib.c#L1612-L1618) [XNU MIG definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/device/device.defs#L231-L238) [Selector 26 method routing](live_kext_selector26_report.md)

| Role | Installed location | Port or data flow |
| --- | --- | --- |
| Framework request emission | `_IOConnectGetService` at `0x184ec182c`, transport call at `0x184ec189c` | Sends simple request `2817`, 24 B in user space. Header bits `0x1513` use `COPY_SEND` for the connection name and `MAKE_SEND_ONCE` for the MIG reply name. The receive capacity is 48 B. |
| Kernel dispatch and import | Authenticated table entry `0xfffffe0007e77e40` binds the stub at `0xfffffe000be853ec`. Import call at `0xfffffe000be85434`. | Accepts a simple 32 B internal request. Loads the destination port object from header +`0x08`. The converter checks kind `0x27`, the connection port kind also used by open and method dispatch. |
| Driver getter | `0xfffffe000c5be99c` calls vtable +`0x930` with authentication discriminator `0x3e51`. | The FairPlay slot at `0xfffffe0008481c38` and the base slot at `0xfffffe0007f627a8` resolve to the named `IOUserClient::getService` at `0xfffffe000c5b202c`. It writes zero to X0 and returns. The implementation adds `5` to `0xe00002c2`, producing `0xe00002c7`, and stores null in its kernel output cell. |
| Kernel reply emission | Generic reply header at `0xfffffe000bd3c654`, status store at `0xfffffe000be85470`, queue submission at `0xfffffe000bd0f208` | The generic header uses the request-associated reply right and computes `2817 + 100 = 2917`. The FairPlay status goes to internal +`0x28`, corresponding to user +`0x20`. The status path leaves the existing simple 44 B internal and 36 B user shape, with no service descriptor. |
| Framework status delivery | Decoder at `0x184ec18dc` through `0x184ec1918` | On the accepted 36 B status reply, returns the nonzero 32-bit status and leaves the caller’s service output cell unchanged. |

If a different client supplies a nonnull provider, the generic implementation retains it and returns status zero. The MIG stub calls the kind-`0x28` service-object port exporter at `0xfffffe000be854ac` and constructs a one-descriptor reply, 52 B internal and 40 B user. The framework checks the reply size, descriptor count, null remote name and received port-send type/disposition. It copies the descriptor name from user +`0x1c` at `0x184ec1970`. This generic branch provides the reference for the FairPlay null result. [XNU service getter and retain contract](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4365-L4386) [IOKit status definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/IOKit/IOReturn.h#L128-L145)

## Daemon and capture evidence

The pinned arm64e `fairplayd` file’s 61,737 parsed fixups include 12 distinct `IOKit` binding targets, including `IOServiceOpen`, `IOConnectCallStructMethod` and `IORegistryEntryGetParentEntry`. The direct binding census finds zero `IOConnectGetService` or `io_connect_get_service` targets. Indirect acquisition and other images are outside this census [A3]. The 44 archived guest headers contain one `2862` open and one `2962` reply, with zero `2817` or `2917` headers. The port names for a native connection query remain unknown. [Archived open and reply](live_fairplay_iokit_open_report.md) [Kind and status audit receipt](triage_evidence/live_iokit_connection_service_audit.json.zst)

## Assumption register and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. Kernel, kext and cache identities describe the inspected build. | The offsets, static targets and ABI apply to these image versions. | Repeat the UUID checks and compare the exact function and chained-pointer bytes. |
| A2. The query reaches the inspected FairPlay client vtable after normal connection import. | The `0xe00002c7` outcome follows from the inherited getter. | On a later passive capture, correlate the received connection class and vtable with its status-only reply. The static audit covers the authenticated slots and return value. |
| A3. The pinned daemon and parsed archive cover their recorded scope. | No direct binding and no recorded exchange. | Verify the hashes and rerun the census. Compare any independently observed native invocation with the same message pair. |

High impact attaches to eliminating this connection query as a provider-right correlation path for the inspected FairPlay class. Medium impact attaches to locating the generic reply and distinguishing a status-only result from the successful object export. The audit checks 20 framework instructions, 28 kernel instruction anchors, four direct kernel calls, two class slots, 172 retained kernel instructions and the pinned daemon and trace inputs. All sizes are exact bytes. Time and storage are linear in the audited image, fixup, trace and retained instruction volumes. [Audit script](triage_evidence/audit_live_iokit_connection_service.py)

```sh
python3 -B triage_evidence/audit_live_iokit_connection_service.py \
  "$BOOT_FILESET" "$PINNED_DAEMON" "$ANNOTATED_TRACE"
```
