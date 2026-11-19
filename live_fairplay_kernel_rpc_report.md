# Current FairPlay kernel-to-daemon RPC anchors

The kernel collection matching the running kernel and FairPlayIOKit UUIDs retains the privileged-host lookup, both RPC constructors and the selected send-reference cleanup. The two constructors emit request IDs 502 and 700 through the same kernel RPC wrapper. The live registry and launchd observations establish service publication. They leave the port object returned by either protected lookup and actual RPC delivery unknown. [Current bootstrap rights](fairplay_live_service_rights_report.md) [Pinned dispatcher contract](kernel_port_resolution_report.md)

| Role | Current call PC | Current table index or lower target |
| --- | --- | --- |
| `host_priv_self` | `0xfffffe000a64bd94` | `0xf9e` to `0xfffffe000bd3a6a0` |
| `host_get_special_port` | `0xfffffe000a64be48` | `0xfad` to `0xfffffe000bd3a480` |
| RPC 502 constructor dispatch | `0xfffffe000a64ca38` | `0xf6e` to `0xfffffe000a5e31f4` |
| RPC 700 constructor dispatch | `0xfffffe000a64e54c` | `0xfb9` to `0xfffffe000a5e3464` |
| RPC 502 wrapper call | `0xfffffe000a5e3288` | Authenticated veneer to `0xfffffe000bd3dd1c` |
| RPC 700 wrapper call | `0xfffffe000a5e34f8` | Same wrapper |
| Common kernel send | `0xfffffe000bd3da9c` | `0xfffffe000bd0effc` |
| Selected caller cleanup `ipc_port_release_send` | `0xfffffe000a6570bc` | `0xf11` to `0xfffffe000bd1833c` |

The current dispatcher table is `0xfffffe00084899c0`. For each of five indirect calls, the audit decodes the chained bank pointers, applies the retained interior biases where present, and checks all 256 byte inputs. Each resolves to the indicated index. Original chained entries and the calls' IA modifiers agree. The three kernel interfaces are exact symbols. The two constructors are identified by the 32-bit message IDs loaded from their header constants and stored immediately before their wrapper calls.

## Destination and reply endpoint

In the current lookup block, a preserved comparison selects 17 or 34 at `0xfffffe000a64bda4`. The call receives node -1 and an output pointer at X28+0x18. The RPC dispatch predecessor loads the destination from X28+0x18 at `0xfffffe000a64c988`. The selected cleanup again loads X28+0x18 before releasing its send reference. Correspondence to the earlier request-word rule is conditional on the retained dispatcher frame and predecessor. Under those premises, request word 1 pairs slot 17 with RPC 502, and the other branch pairs slot 34 with RPC 700. The live receiver for RPC 700 remains unknown. [Pinned rule and provenance](kernel_port_resolution_report.md) [Pinned cleanup path](kext_port_vm_report.md)

Each constructor passes an 88 B send size and 400 B receive capacity. The shared wrapper enters the common transport at `0xfffffe000bd3d8d4`. That transport reads the current thread from TPIDR_EL1, loads the thread's separate reply endpoint at +0x3f0, then writes it into the internal message header at `0xfffffe000bd3da20`. The common send call uses the internal message, options `0x10001` and timeout argument 0. These sites locate outgoing transport and reply-endpoint insertion. The wider receive and ownership behavior is documented for the prior collection. [Pinned kernel RPC transport](kernel_rpc_transport_report.md)

The known `fairplayd` RPC 502 application call is at preferred PC `0x1000051f8`. The current launchd declaration and active bootstrap endpoint associate `com.apple.unfreed` with slot 17. That association and the source-level message ID establish a candidate join to the daemon receiver. No correlated native transaction establishes that join. In particular, the established selector 26 core entry and these protected RPC call blocks have separate source proofs, and current end-to-end reachability from either daemon's IOKit call remains open. [Daemon RPC 502 receiver](daemon_rpc502_report.md) [Current selector 26 core](live_kext_selector26_core_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The file matches the running kernel and kext identities. | Current source PCs and original chained words. | Compare embedded UUIDs with kernel and kext metadata and rehash the source collection. |
| The retained dispatcher frame initializes the same table, banks and X28 scratch role. | Indexed call correspondence and repeated destination field. | Check each captured bank pointer and branch discriminator, then correlate the scratch object across calls. |
| The selected message reaches the common kernel send normally. | Header reply endpoint and send arguments. | Observe the constructed header and destination/reply objects within a matched ordinary transaction. |

The byte-table verification uses O(K * 256) time for K selected calls, after loading the collection. The kernel send PCs have high impact on correlating a native exchange. The unseen slot-34 receiver and actual destination identity remain high-impact gaps. [Audit script](triage_evidence/audit_live_fairplay_kernel_rpc.py) [Compressed evidence](triage_evidence/live_fairplay_kernel_rpc_audit.json.zst)
