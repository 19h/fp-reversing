# FairPlayIOKit service publication and provider matching

The inspected boot fileset contains the FairPlayIOKit personality. The native IOService registry contains its service as a direct child of `IOResources`, with every personality property preserved and `IOMatchedAtBoot = true`. This establishes the provider topology for the service the daemon looks up. The archived `2881` request searches for the already published service class. Its historical service object's registry identity remains unknown. [Kernel registry lookup](live_iokit_matching_report.md) [Archived discovery](live_iokit_discovery_report.md)

## Boot metadata and registered objects

| Property or runtime observation | Primary FairPlayIOKit | Alternate AvpFairPlayDriver |
| --- | --- | --- |
| Installed bundle version | 72.19.0 | 2.10.0 |
| Service personality `IOClass` | `com_apple_driver_FairPlayIOKit` | `AvpFairPlayDriver` |
| Personality `IOProviderClass` | `IOResources` | `AppleVirtIOTransport` |
| Provider condition | `IOResourceMatch = IOKit`, `IOMatchCategory = FairPlayIOKit`, `IOProbeScore = 1000` | `IOVirtIOPrimaryMatch = 0x1a08106b`. A second personality selects `AppleVirtIOPCITransport` under `IOPCIDevice` with the same `IOPCIPrimaryMatch`. |
| `IOUserClientClass` | `com_apple_driver_FairPlayIOKitUserClient` | `AvpFairPlayUserClient` |
| Inspected boot fileset | Fileset entry and prelink personality present | No fileset entry or prelink record |
| Live registry on build `26C5035r` | `IOResources` entry `0x1000002f5` has child `0x1000002fb` | Zero matches for `AvpFairPlayDriver`, `AppleVirtIOTransport`, and `AppleVirtIOPCITransport`. |

The fileset's `__PRELINK_INFO,__info` section starts at file offset `0x56b4000` B and contains 383 records. The selected personality agrees with the installed bundle plist and adds `IOPersonalityPublisher = com.apple.driver.FairPlayIOKit`. The prelink executable extent `0x1f9eac` B agrees with the loaded-kext row for UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. The live parent publishes the `IOKit` resource with value `IOService`. The named property and its existence are relevant to matching. The snapshot alone gives no timing for the initial insertion. [Compressed audit](triage_evidence/live_fairplay_service_personality_audit.json.zst)

## Installed matching and startup

| Stage | Installed unslid site | Data and control transfer |
| --- | --- | --- |
| Register the resource | `0xfffffe000c539a80` | `IOService::publishResource` invokes the property setter on the global `IOResources` object. The published XNU power-root setup supplies the `IOKit` key to this helper. |
| Select a personality | `0xfffffe000c5283bc`, `0xfffffe000c5288c0` | `IOService::doServiceMatch` calls `IOCatalogue::findDrivers` with the provider, then invokes `probeCandidates` on the result along the selected route. The public catalogue implementation orders candidates by probe score and enumerates the provider metaclass hierarchy. |
| Apply the resource predicate | `0xfffffe000c531ba8`, `0xfffffe000c531e30` | The authenticated `IOResources::matchPropertyTable` slot loads `IOResourceMatch` from the personality. Its string callback queries that name through the provider's `getProperty` slot. The nonnull test at `0xfffffe000c531e34` selects the success Boolean. |
| Probe the candidate | `0xfffffe000c529a28` | The authenticated probe call takes the candidate, provider and score address. For the FairPlayIOKit vtable it selects `0xfffffe000a54bcc8`, which tail-calls `IOService::probe`. |
| Start and register FairPlayIOKit | `0xfffffe000c52ad14`, `0xfffffe000c52ae30`, `0xfffffe000a54bd68` | For the global resource provider, `startCandidate` takes the branch that skips the two blocking `checkResources` calls. Its start call selects `0xfffffe000a54bce8` through the FairPlayIOKit vtable. The passing start branch calls `registerService(0)` and returns true. |

The `IOResourceMatch` predicate acts during personality matching against the resource provider. For an `IOResources` candidate, the later startup path therefore has two distinct decisions, the property lookup and the branch around the blocking waits. Published XNU supplies the corresponding implementation and the meaning of the resource property. [XNU catalogue matching](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOCatalogue.cpp#L199-L235) [XNU IOKit resource publication](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L1532-L1542) [XNU resource predicate](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L6890-L6924) [XNU candidate startup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L4597-L4622)

## Daemon-facing boundary

The archived `2881` request at line 1699 carries a 64 B dictionary containing only `IOProviderClass = com_apple_driver_FairPlayIOKit`. The framework emits it at `0x184ebd3dc` on the installed image. The archive sends to guest main name `0x1703`, supplies guest reply receive name `0x507`, and receives iterator name `0x1803` in reply `2981`. The kernel personality's identically named field describes the FairPlay service's own parent class, `IOResources`. The open then concerns the matched FairPlay service and its named user-client class. The observed `kern.hv_vmm_present = 0` and topology are consistent with the daemon's recovered primary-class branch. The sampled daemon cache and context bytes at its selection site remain unknown. [Daemon VMM and class gate](daemon_selector26_class_gate_report.md) [Open and constructor dispatch](live_fairplay_iokit_open_report.md)

## Assumption register

| Assumption | Dependent claim | Falsification probe |
| --- | --- | --- |
| A1. The inspected boot fileset applies to the running kernel and driver. | Metadata, dispatch sites and class slots describe the current build. | Compare the collection digest, running kernel UUID, loaded-kext UUID and authenticated pointers. |
| A2. The two bundle plists and the registry snapshot describe this installation. | The primary personality survives into the child properties and the alternate was absent in the queried registry. | Rehash both plists, compare the explicit parent-child IDs and repeat the three class queries on the same boot. |
| A3. The historical trace preserves its original guest buffers. | The class value and guest names in the daemon's lookup. | Reassemble the guest bytes, recheck the trace digest, the complete dictionary and the paired reply. A historical registry entry ID would be needed to join the two observations. |

High impact for locating the origin of the service being opened and distinguishing the two uses of `IOProviderClass`. Medium impact for identifying the alternate's provider dependencies. Native boot event order, native daemon selection and live method pairing remain unknown. The auditor reads, hashes and parses fileset bytes B, trace bytes T and selected registry and plist bytes R in O(B + T + R) time and storage. It verifies 26 original instruction sites, eight vtable bindings, two bundle digests and the archived matching dictionary. [Auditor](triage_evidence/audit_live_fairplay_personality.py) [Compressed audit](triage_evidence/live_fairplay_service_personality_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_fairplay_personality.py \
  "$BOOT_FILESET" "$ANNOTATED_TRACE"
```
