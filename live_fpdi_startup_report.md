# fairplaydeviceidentityd launch, sandbox, and XPC activity

In macOS build `26C5035r`, the installed FPDI launch configuration declares a named Mach service and a scheduled XPC activity. The original arm64e entry installs the named sandbox before registering either interface. The activity can reach a DeviceIdentity certificate request independently of the named listener's peer worker. The sandbox explicitly admits the FairPlayIOKit user-client class. Native port names, startup timing and the join from either entry point to a specific driver call remain unknown. [Peer worker](live_fpdi_xpc_report.md) [Earlier process and IORegistry observations](live_fairplay_additional_clients_report.md)

## Startup sequence

`LC_MAIN.entryoff` is `0x2264`. The sequence below uses preferred virtual addresses and describes the path on which sandbox setup returns normally and listener creation succeeds.

| Call site | Operation | Argument or continuation |
| --- | --- | --- |
| `0x10000228c` | Local sandbox setup at `0x100001fd0` | Calls the named profile; setup failure reaches `exit(1)` at `0x100002210`. |
| `0x1000022ac` | `xpc_activity_register` | Name `com.apple.fairplaydeviceidentityd.baa-prefetch`, imported `XPC_ACTIVITY_CHECK_IN` object and global block at `0x1005c00c0`. |
| `0x1000022c8` | `dispatch_queue_create` | Label `com.apple.fairplaydeviceidentityd`. |
| `0x1000022e4` | `xpc_connection_create_mach_service` | Name `com.apple.fairplaydeviceidentityd`, created queue and listener flag value 1. |
| `0x100002348` | `xpc_connection_set_event_handler` | Handler invokes `0x1000025a8` and captures the queue. |
| `0x100002350` | `xpc_connection_activate` | Uses the listener handle. |
| `0x100002354` | `dispatch_main` | Main queue execution. |

A null queue or listener returns `-0xae6c` from the entry. The plist declares user `_fpsd` and sets `DYLD_PAGEIN_LINKING=0`. It maps the listener name under `MachServices`. Neither the plist entry nor the static listener call supplies a numeric Mach receive right.

## Sandbox and environment

The setup routine reads `HOME` through `getenv` at `0x100002014`. If absent, the fallback uses `getuid` and `getpwuid`, then reads the home-directory pointer from the returned record. The selected home is canonicalized at `0x100002044`. The routine sets the Darwin user-directory suffix to the service name at `0x100002058`. It requests the Darwin user temporary and cache directories using selectors 65537 and 65538 into a 1,024 B scratch buffer and canonicalizes each result. The named profile call at `0x1000020ec` takes the service name, flag 1 and a null-terminated alternating key/value array. The three keys are `HOME`, `TMPDIR` and `DARWIN_CACHE_DIR`. The flag and selector names are from the installed SDK's `sandbox.h` and `unistd.h`.

The installed profile uses those three parameters and explicitly permits registration of `com.apple.fairplaydeviceidentityd`. Its explicit lookup clause names seven endpoints for mobile activation, system keychain, securityd XPC and CoreAuthentication. The [audit receipt](triage_evidence/live_fpdi_startup_audit.json.zst) retains the exact labels. These are declared permissions. An observed send or lookup would require runtime evidence.

| Explicit `iokit-open` class | Architectural association |
| --- | --- |
| `AppleKeyStoreUserClient` | The profile identifies this class as a DeviceIdentity framework dependency. |
| `AvpFairPlayUserClient` | An independently named FairPlay user-client class in the same policy. |
| `com_apple_driver_FairPlayIOKitUserClient` | Matches the client class recovered for FairPlayIOKit in the installed kernel collection. |

The profile is positive evidence for admitting the FairPlayIOKit class after sandbox setup. It supplies no connection right, caller identity, selector or proof of a successful open. [Kernel collection method contract](live_kext_selector26_report.md)

## Scheduled activity and DeviceIdentity

The launchd activity uses maintenance priority, requires network connectivity and Class C, permits battery operation and Power Nap, and repeats at a configured interval of 43,200 s. The random initial delay parameter is 21,600 s. These values describe configured scheduling criteria. The original authenticated invoke fixup at `0x1005c00d0` resolves to `0x100002358`.

| Site | Activity behavior |
| --- | --- |
| `0x100002378` | Reads the activity state. Zero takes the check-in log path and returns. The code branches on zero versus nonzero here. |
| `0x1000023a0`, `0x100002400` | Reads and updates `BackgroundActivityLastRan` in the daemon preference domain. |
| `0x10000248c` | Calls `0x100000d40` with mode 0 and a 4 B state output. The helper checks `BAAScheduledPrefetchAbsoluteTime` and the current time before dispatching further work. |
| `0x100002548` | Unregisters the activity when mode 0 returns zero and writes state 2. |

The due-work branch at `0x100000dfc` enters `0x100000e44`. That routine calls `0x100001130` with its first mode argument set to 1 and can call it again with 0. The latter function checks `DeviceIdentityIsSupported` at `0x10000117c`, prepares a queue and completion block, issues `DeviceIdentityIssueClientCertificateWithCompletion` at `0x1000013dc`, and waits on a semaphore at `0x1000013e8`. The wait uses all ones in X1. The certificate provider's subsequent IPC and any linkage to the selector 26 candidate are unknown. [Completion and output ABI](live_fpdi_deviceidentity_completion_report.md)

## Assumption register

| ID | Premise and dependent claim | Falsification probe |
| --- | --- | --- |
| S1 | The installed plist, profile and daemon are the intended matched system artifacts. The startup and policy associations depend on that pairing. | Rehash the three inputs and compare the running image and effective launchd job to the pinned artifacts. |
| S2 | The recovered imports have the ABI indicated by their original authenticated stubs and the installed SDK. This governs parameter and callback labeling. | Recheck the dyld slots, SDK declarations and original producer instructions. |
| S3 | The sandbox setup returns normally, and each allocation or service call on the success path returns its expected object. The ordered startup path is conditional on those results. | Observe an ordinary boot or job launch and match sandbox completion, check-in registration and listener activation. |
| S4 | The scheduled callback reaches the due path and DeviceIdentity reports support. The certificate request is conditional on those checks. | Compare the original callback state and preference-derived deadline with a native request and completion. |

High impact for establishing the policy that admits the driver class and the two independent XPC entry paths. Medium impact for recovering configuration and environmental dependencies. The allocator's enable-store and arena publication still need a separate origin trace. [Allocation audit](live_fpdi_allocation_report.md)

The primary inputs are the installed daemon's arm64e slice, its launch plist and the named sandbox profile. The [auditor](triage_evidence/audit_live_fpdi_startup.py) checks 22 call sites and their authenticated stubs, five additional fixups, seven original strings, the selected plist values and matching sandbox clauses. The [compressed receipt](triage_evidence/live_fpdi_startup_audit.json.zst) contains 669 instruction records and the three source hashes. For total input bytes B, decoded fixups F and retained instruction records I, verification takes O(B + F + I) time and space.

    python3 -B triage_evidence/audit_live_fpdi_startup.py DAEMON LAUNCH_PLIST SANDBOX_PROFILE
