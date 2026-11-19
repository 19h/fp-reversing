# Current FairPlay kernel RPC and daemon reply ABI

The installed FairPlayIOKit clients for RPC 502 and RPC 700 use the same message layouts, output stores and kernel return path. They send IDs 502 and 700 and expect IDs 602 and 800, respectively. The arm64e image selected by the running fairplayd process contains a matching RPC 502 body parser and RPC 602 reply producer. The live RPC 700 peer remains unknown. [Current request send sites](live_fairplay_kernel_rpc_report.md) [Current mode and producer audit](live_fairplay_constructor_mode_report.md)

The boot kernel and kext UUIDs match the current collection. The daemon's CodeDirectory hash and process slice offset independently select the installed arm64e image with UUID 204741e9-b89f-32b4-9321-51f3975c7cac. Its 262 byte differences from the reference image fall in the CMS signature slot. The current audit can therefore use the reference file's text and fixup bytes for the installed daemon. [Live image identification method](fairplay_live_slice_identity_report.md)

## Request and reply ports

| Step | PC | Port and message role |
| --- | --- | --- |
| Kernel send | 0xfffffe000bd3da9c | Kernel message carries the host-special destination and the thread-bound reply endpoint. Both generated clients send 88 B and specify 400 B of receive space. |
| Daemon RPC 502 stub | 0x1000050c8 | Receives an 80 B user Mach message. The application call at 0x1000051f8 receives the local service name from request +0x0c. |
| Daemon RPC 602 header construction | 0x100005274 | Copies the incoming remote name into the reply destination, clears local and voucher fields, and adds 100 to the incoming ID. |
| Daemon reply send | 0x100035184 | Sends the reply via _mach_msg using its inline size. All 256 byte selectors for this call reduce to original import slot 0x1010a1288. |
| Kernel return | 0xfffffe000bd3dc70, then 0xfffffe000bd3dcb4 | Converts the reply destination in the internal header, then copies into the kext buffer. |

The receiving service name and the outgoing reply destination are separate daemon-local names. The kernel header converter puts the old internal local field into the new internal remote field at 0xfffffe000bd0e24c. For the generated daemon reply the old local field is zero, which agrees with the kext parser's null remote-field check. This uses the previously recovered port-role conversion and assumes normal delivery of the corresponding reply. The actual names and kernel port objects remain unobserved. [Pinned request conversion](rpc502_receive_bridge_report.md) [Pinned kernel transport](kernel_rpc_transport_report.md)

    FairPlayIOKit -> kernel send -> fairplayd RPC 502 stub
                                         |
                                      _mach_msg
                                         |
    kext reply parser <- kernel copyback <- thread reply endpoint

## Serialized field correspondence

| Request field | Internal offset | Daemon user offset | Width |
| --- | --- | --- | ---: |
| OOL descriptor count | 0x20 | 0x18 | 4 B |
| OOL object or address | 0x24 | 0x1c | 8 B |
| OOL extent / repeated extent | 0x30 / 0x3c | 0x28 / 0x34 | 4 B each |
| Three scalar arguments | 0x40 / 0x48 / 0x50 | 0x38 / 0x40 / 0x48 | 8 B each |

The internal OOL field holds a copy object. The daemon field holds a mapped user address. The daemon checks one OOL descriptor and equality of the two extents, then passes the address, extent and three scalar arguments to its application. The table gives compatible field positions. Current VM conversion and delivery remain separate obligations.

| Successful reply field | Daemon user offset | Internal offset | Width |
| --- | --- | --- | ---: |
| Descriptor count | 0x18 | 0x20 | 4 B, value 2 |
| OOL0 address / extent | 0x1c / 0x28 | 0x24 / 0x30 | 8 B / 4 B |
| OOL1 address / extent | 0x2c / 0x38 | 0x34 / 0x40 | 8 B / 4 B |
| Fixed record0 | 0x44 | 0x4c | 136 B |
| Fixed record1 | 0xcc | 0xd4 | 172 B |
| Repeated extents | 0x178 / 0x17c | 0x180 / 0x184 | 4 B each |

The daemon produces a 384 B complex reply on application status 0, or a 36 B simple reply carrying the application error. The corresponding internal inline sizes are 392 B and 44 B. The current kernel return path reads inline size S at 0xfffffe000bd3dc38. With a valid reply and no overflow, a capacity below S takes the size-error path, one from S through S+7 copies S, one from S+8 through S+67 copies S+8, and a capacity of at least S+68 copies S+68. Thus S=392 B and capacity=400 B select the 8 B trailer path. The caller's policy bit 37 selects the return path that authenticates OOL memory pointers and writes raw object values back to the generated client. The data-authentication discriminator for those pointers is 0x5d4f. [Pinned reply layouts and output ABI](rpc502_reply_bridge_report.md) [Reply descriptor conversion](rpc502_reply_copyin_report.md)

| Current client | Constructor | Expected-ID compare | First fixed-record store | OOL output stores |
| --- | --- | --- | --- | --- |
| 502 | 0xfffffe000a5e31f4 | 0xfffffe000a5e32d0 | 0xfffffe000a5e338c | 0xfffffe000a5e3408 through 0xfffffe000a5e3418 |
| 700 | 0xfffffe000a5e3464 | 0xfffffe000a5e3540 | 0xfffffe000a5e35fc | 0xfffffe000a5e3678 through 0xfffffe000a5e3688 |

Both current clients have 624 B compiler extents. Of 156 positionally compared A64 words, eight differ. Six are BL encodings with shared destinations. The other two select the request-ID constant and compare the expected reply ID. The accepted complex reply has two type-1 OOL descriptors, null internal remote field, and matching descriptor and repeated extents. The clients copy the two fixed records to the X6/X7 destinations, then publish the two OOL address/count pairs through four stack arguments. The RPC 700 geometry is a client requirement. Its actual producer remains unknown.

## Assumptions and reproducibility

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| Kernel/kext UUIDs, collection digest and daemon CodeDirectory evidence identify the intended build. | Current preferred locations and ABI correspondence. | Rehash the source, requery UUIDs, and compare process slice attributes and exact windows. |
| Kernel-to-user copyout supplies the standard Mach header, descriptor and trailer forms recovered in the earlier model. | Argument correspondence across the request representations. | Observe the kernel message and received user fields in one ordinary matched transaction. |
| The daemon callback selects the RPC 502 service branch and the application produces the declared output. | RPC 602 uses the recovered allocation, result stores and send call. | Observe the stub selection, status, actual output extents and reply destination in a correlated dispatch. |
| Normal return conversion supplies the corresponding internal message and object references. | Closed header-role and size arithmetic for a compatible reply. | Correlate the same reply through header conversion, descriptor copyback and the generated client's output stores. |

The read-only audit records compiler-bounded client bodies, selected Mach import bindings, the original daemon's emitter and request/reply instructions, current header/descriptor copyback, and scoped runtime image metadata. The static work is O(B + F + N) time and space for source bytes B, fixups F and symbol records N at fixed capture sizes. The artifact preserves field widths and reports the original-byte checks separately from modeled transport roles. High impact attaches to the verified compatible RPC 502/602 ABI. Native round-trip delivery, output ownership beyond this boundary, and the identity of the RPC 700 peer remain open. [Audit](triage_evidence/audit_live_fairplay_rpc_abi.py) [Compressed receipt](triage_evidence/live_fairplay_rpc_abi_audit.json.zst)

The current reply-right audit follows the thread receive binding through make-send-once, daemon namespace publication and the waiting kernel client's completion path. It locates the separate caller, message and transport holds on the service destination. [Reply rights and lifecycle](live_fairplay_reply_rights_report.md)
