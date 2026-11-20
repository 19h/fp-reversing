# DeviceIdentity certificate IPC to mobileactivationd

In macOS build `26C5035r`, the DeviceIdentity framework used by `fairplaydeviceidentityd` has an issuance path that sends a synchronous NSXPC request to the privileged Mach service `com.apple.mobileactivationd`. The request is issued at shared-cache address `0x1b7898d60`. The installed server advertises that Mach service and exports the matching Objective-C selector at `0x100020da4`. The call path is conditional on certificate state, options and client checks. The evidence is static. Numeric port names, Mach message IDs and the final libxpc send and receive instructions for this request are unknown. [Daemon wrapper](live_fpdi_deviceidentity_completion_report.md)

## From the daemon to the framework worker

The daemon's import at `0x1000013dc` binds to `DeviceIdentityIssueClientCertificateWithCompletion`. The installed cache exports it at unslid address `0x1b78964c0`. The three arguments are a callback queue, options dictionary and completion block.

| Framework site | Role |
| --- | --- |
| `0x1b789657c` | Calls `isSupportedDeviceIdentityClient` with W0=0 and an error out pointer. The false branch dispatches a completion block that passes a null key and array and a provider error at `0x1b7896898`. |
| `0x1b7896594`, `0x1b78965ac` | Tests for a virtual machine and, on that path, checks for a host key. The unsuccessful VM path dispatches a second error block with null key and array at `0x1b7896a20`. |
| `0x1b7896650` | Enqueues the operational block at `0x1b7896a34` on the framework's serial queue. It captures options at block+32 B, the caller queue at +40 B, the caller completion at +48 B and a byref error at +56 B. |
| `0x1b7898610`, `0x1b7898670` | Conditional local keychain lookups for a key item and certificate data. Both helpers call `SecItemCopyMatching`, at `0x1b78917e0` and `0x1b7892108`. Available chain bytes reach `parseDERCertificatesFromChain` at `0x1b78986d0`. |
| `0x1b7898210`, `0x1b7898240` | Checks the `SkipNetworkRequest` option for an `NSNumber` and reads its `boolValue`. The default is 0. The branch at `0x1b789886c` distinguishes whether to proceed when the local certificate path falls through. The nonzero path there constructs the error describing missing or expired certificates and a skipped network request. |
| `0x1b7898b1c` | Calls the framework's system-key attestation helper on the applicable issuance path. Related calls cross into Security at `0x1b78a24c0` for `SecKeyCopySystemKey` and `0x1b78a276c` for `SecKeyCreateAttestation`. |

The daemon boxes its mode as `SkipNetworkRequest`. Mode 1 supplies true and mode 0 supplies false. A false value allows the issuing route if the other checks admit it. It can also complete from the local keychain path. These operations establish distinct Security and activation boundaries. The underlying Security service connection and any path from this issuance request to FairPlayIOKit remain unknown.

## Named Mach service and application-level request

| Site | Recovered operation |
| --- | --- |
| `0x1b7898ba8` | Creates an `NSXPCInterface` for `MobileActivationMacOSProtocol`. The protocol reference at `0x1e173ce10` resolves to that name in the original cache. |
| `0x1b7898bd0` | Calls `-[NSXPCConnection initWithMachServiceName:options:]` with `com.apple.mobileactivationd` and `0x1000`. The option is `NSXPCConnectionPrivileged` in the installed Foundation header. |
| `0x1b7898be0`, `0x1b7898be8` | Installs the remote interface and resumes the connection. |
| `0x1b7898bf0`–`0x1b7898c90` | Copies the input options to a mutable dictionary. It removes `AccessControls` when present and removes `LocalAuthenticationContext`. It sets `AppID`, `RKAttestationData` and `RKAttestationPublicKey` from worker values. The `AccessControls` removal branch also sets `UseRKSigningInterface`. |
| `0x1b7898cec` | Obtains a synchronous remote proxy with a transport error block at `0x1b789b2ac`. |
| `0x1b7898d60` | Issues `issueClientCertificateWithReferenceKey:options:completion:`. X0 is the proxy, X2 is the reference-key argument, X3 is the adjusted options dictionary and X4 is the reply block. This is the application-level emission site. |
| `0x1b7898d68` | Invalidates the connection after the synchronous proxy returns. |

The service constant at `0x1e1738988` resolves through a cached `CFString` to `com.apple.mobileactivationd`. The installed launch plist declares this service in `MachServices`. The nominal request flows from the DeviceIdentity framework inside the calling process to the mobile activation daemon. The callback and its error handler are local blocks with separate invoke addresses. Their presence does not provide the actual Mach rights allocated to an execution.

## Receiving side and return

The arm64e `mobileactivationd` slice names `MobileActivationMacOSDaemon` as conforming to `MobileActivationMacOSProtocol`. Its connection delegate at `0x100018228` sets the exported interface at `0x10001827c`, exports the daemon object at `0x100018288`, assigns the peer's XPC queue at `0x1000182a8` and resumes the accepted peer at `0x1000182b8`.

The public method implementation at `0x100020da4` checks caller support at `0x100020f9c` and the SPI entitlement at `0x100020fc8`. Requests for the listed device identifier or manifest OIDs take a further device-identifiers entitlement check at `0x100021094`. The admitted branch calls the internal certificate method at `0x100021240`. Its Objective-C implementation starts at `0x10001c024` and dispatches the issuance worker. [Server issuance and network transport](live_mobileactivation_certificate_report.md)

| Return layer | Incoming data and location |
| --- | --- |
| Proxy transport error | The block at `0x1b789b2ac` receives an `NSError`, wraps it, and stores it in the forwarded error cell at `0x1b789b2fc`. |
| Remote method reply | The block at `0x1b789b320` receives an `NSDictionary` and an `NSError`, as established by its descriptor signature. It reads `RKCertification` through the array type check and stores it at `0x1b789b384`. It reads `ServerResponseDate` through the date type check and stores it at `0x1b789b3d4`. It retains and stores the error at `0x1b789b3f4`. |
| Framework-to-daemon completion | The issuance worker enqueues its final callback block at `0x1b7897638`. The block at `0x1b789b4c8` invokes the daemon's completion at `0x1b789b578` with key, certificate array and error. The daemon subsequently performs its exact-two count and semaphore signal. |

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| M1 | The installed cache, daemon slice and launch configuration describe the same target build. Both endpoint identities and addresses depend on this pairing. | Compare cache and image UUIDs, hashes and the effective launch job. |
| M2 | The issuing branch reaches `0x1b7898bd0` and receives the normal proxy for the stated service. The named RPC depends on the branch, launch job and successful connection. | Correlate an ordinary call with the resolved service endpoint and the receiving method entry. |
| M3 | The server dispatch uses the protocol and exported object observed in the listener delegate. The endpoint-to-method join depends on these bindings. | Verify the effective exported interface and receiver for an ordinary certificate request. |
| M4 | The protocol reply and callback use the argument layouts in their recovered descriptors. Field interpretation depends on these layouts and the local type checks. | Compare the reply classes and callback argument types on a normal completion. |

High impact for identifying the named outgoing service, receiving daemon, application-level emission site and paired receipt path. Medium impact for distinguishing cache use and native Security calls from the activation RPC. The observed selectors and callback locations do not resolve the libxpc wire format or kernel-level rights. [FairPlayIOKit Mach transport](live_iokit_mach_transport_report.md)

## Reproduction

Primary evidence is the installed dyld shared cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`, DeviceIdentity image UUID `cab8c302-6770-316e-878e-bc2db99fcbd8`, and mobileactivationd arm64e UUID `828906ff-d325-3bc9-9f28-0b3a8fd7af5b` with SHA-256 `d6c33e737346613383570a14f5be5ff87e27cfabf87a955b2cfaaf210f7f658d`. The audit reads cache bytes and validates slide-chain membership before decoding pointers. It retains 729 provider and 423 receiver instructions, checks 49 provider anchors, 18 selector stubs, eight authenticated provider C call sites and nine receiver calls, and verifies the launch plist, block signatures and SDK option. Cache inputs are read by range. With M mapping records, B retained/read bytes and P slide-chain entries visited, memory scales as O(M + B) and time as O(M log M + B log M + P), excluding the independent whole-image disassembly and Objective-C metadata scan of the server. [Auditor](triage_evidence/audit_live_deviceidentity_activation.py) [Compressed receipt](triage_evidence/live_deviceidentity_activation_audit.json.zst)

    python3 -B triage_evidence/audit_live_deviceidentity_activation.py MOBILEACTIVATIOND LAUNCH_PLIST NSXPCCONNECTION_HEADER
