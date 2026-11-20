# IOKit main-port publication and version negotiation

On the installed kernel, the IOKit initializer stores the main port at `0xfffffe0007f5da98` and publishes a send right in host-special slot 3. The host RPC `205/305` copies a send right from that cell. The archived fairplayd session uses the resulting guest name for version RPC `2877/2977` and FairPlayIOKit matching RPC `2881/2981`. The native verifier independently observed that two ordinary `IOMainPort` calls produce two send user references under one name in its task. [Framework discovery and archive](live_iokit_discovery_report.md) [XNU host slot definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/host_special_ports.h#L72-L79)

## Boot publication

The initializer passes the backing cookie `0xfffffe0007e78798` and selector `0x125` to the allocator at `0xfffffe000bd83228`. The allocator masks the selector to its low byte at `0xfffffe000bd3c9c4` and stores the authenticated backing pointer in the port at +`0x50` B. At `0xfffffe000bd83230` the initializer stores the returned port in the main cell. It calls the send-right producer with expected kind `0x25` at `0xfffffe000bd8323c` and passes the result to the host-special replacement routine at `0xfffffe000bd83250` with slot 3. The generic host-special getter also uses the main cell and the send-right copy helper at `0xfffffe000bd3a54c` and `0xfffffe000bd3a550`. [Host publication core](live_rpc700_publication_report.md) [XNU host getters](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/host.c#L1305-L1346)

## Request and reply paths

| Request / reply | Framework emission | Installed kernel path and result | Archived guest namespace |
| --- | --- | --- | --- |
| `205/305` `host_get_io_main` | `0x18056b448` sends to the host name from `mach_host_self`. | The host MIG table dispatches to `0xfffffe000bdce7e8`. The stub imports the destination as a host object at `0xfffffe000bdce82c` and calls the getter at `0xfffffe000bdce834`. The getter loads the main cell at `0xfffffe000bd3a624` and copies a send right at `0xfffffe000bd3a628`. | Destination `0xc03`, reply name `0x507`, main name `0x1703`. Lines 1677/1681. |
| `2877/2977` `io_server_version` | `0x184ebc3cc` sends to the acquired main name through the version once block. | The IOKit MIG table dispatches to `0xfffffe000be803ac`. The stub emits the compiled u64 constant `0x0134647a` at `0xfffffe000be803cc` and zero routine status at `0xfffffe000be803d0`. | Destination `0x1703`, reply name `0x507`, version `0x0134647a`. Lines 1687/1692. |
| `2881/2981` binary matching | `0x184ebd3dc` sends the matching dictionary to the main name. | The matching handler loads the same global at `0xfffffe000c5b964c` and compares it with the request destination object at `0xfffffe000c5b9650` before dictionary decode. | Destination `0x1703`, reply name `0x507`, iterator name `0x1803`. Lines 1699/1709. |

The successful host stub writes the authenticated descriptor at `0xfffffe000bdce87c` and a descriptor count of one at `0xfffffe000bdce894`. Its complex reply is 52 B in the expanded kernel representation and 40 B in the archived user representation. The framework copies the descriptor name from +28 B at `0x18056b510`; its caller releases the temporary host name at `0x184ebc2b4`. A null converted host reaches the getter's status-4 exit at `0xfffffe000bd3a668`. [XNU host MIG definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/mach_host.defs#L135-L145)

The version reply is 52 B internally and 44 B in the archived user representation. It has no descriptors, carries status at +32 B and carries the u64 version at +36 B. The framework stores that version at `0x184ebc4c0`. The once block starts with serialization bit 0 set and clears it on probe error or version at most `0x01335184`. The observed `0x0134647a` exceeds that threshold, preserving the binary matching option. The generic kernel reply path adds 100 to the request ID at `0xfffffe000bd3c678` and submits to the reply right supplied by the request at `0xfffffe000bd0f208`. [XNU IOKit version implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2290-L2298) [Generic kernel reply path](live_arcade_registration_reply_report.md)

## Verification and assumptions

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The input is the pinned installed fileset and the live observer uses build `26C5035r` with the pinned kernel and dyld cache UUIDs. | Boot and MIG addresses, live version comparison. | Repeat the fileset hash, UUID, authenticated MIG pointer and instruction checks with the auditor. |
| A2. The archived trace preserves guest bytes and namespace labels. | Historical use of the same destination name for version and matching. | Recheck the digest, message bytes, trap arguments and right sequence. The historical kernel build is unknown. |
| A3. The verifier starts in a fresh task and owns both acquired references. | Send user-reference sequence 1 then 2. | Start a fresh process, check both returned names and reference counts, release both and repeat the name lookup. |

The verifier observed version `0x0134647a`, two successful deallocations and status 15 (`KERN_INVALID_NAME`) on the final lookup. This measurement covers the verifier's own names and version cell. A native FairPlay transaction remains unverified. High impact for locating the origin of the shared main-port capability and the matcher's destination check. Medium impact for explaining how the compiled version affects dictionary transport. The auditor reads and hashes fileset bytes B and archived trace bytes T, so the verification uses O(B + T) time and storage with a fixed installed cache. [Auditor](triage_evidence/audit_live_iokit_main_port.py) [Compressed audit receipt](triage_evidence/live_iokit_main_port_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_iokit_main_port.py \
  "$BOOT_FILESET" "$ANNOTATED_TRACE" --observe
```
