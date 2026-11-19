# Installed CoreADI adid selector 26 sites

The installed CoreADI `adid` contains two ARM slices with corresponding selector 26 call blocks. In the earlier arm64e source analysis, the primary FairPlayIOKit stage passes a 16 B descriptor for a 96 B record. The optional Avp stage passes the 96 B record directly. The corresponding installed call blocks and immediate return branches are byte-identical across the two slices after accounting for their different virtual addresses. The loaded slice of the registry-attributed `adid` process remains unknown. [Earlier transport recovery](adid_iokit_report.md) [Registry observation](daemon_iokit_native_registry_report.md)

| Site or field | Installed arm64e | Installed arm64e.x1 |
| --- | --- | --- |
| Slice UUID | `4d24325f-3529-39b1-bbf8-64bbcf406049` | `3973829c-93ea-3818-88c7-a7793e974f82` |
| Primary call with selector 26 and structure length 16 B | `0x10001f908` | `0x10001f790` |
| Primary output size, u64 at SP | `0x10001f90c` | `0x10001f794` |
| Primary inner extent, u32 at SP+16 B | `0x10001f950` | `0x10001f7d8` |
| Primary inner address, u64 at SP+8 B | `0x10001f9b4` | `0x10001f83c` |
| Avp direct-form call with selector 26 | `0x10004967c` | `0x100049180` |
| `_IOConnectCallStructMethod` chained bind | `0x1002d8400` | `0x1002d0400` |

The primary call places the shared input and output structure at SP+8 B and passes SP as the output-size pointer. Its first post-call branch compares the full u64 size to 16 B. Later blocks load the inner extent and address and use a separate status derivation. These local roles correspond to the count, extent and address roles at the `fairplayd` descriptor helper. The Avp direct call passes its buffer extent from X20 and passes the same buffer in X2 and X4. Its first return block derives a status from W0. The 96 B extent and stage identities come from the previously recovered arm64e paths. The selected x1 windows show matching call and return instructions. Their service acquisition and authenticated branch targets remain to be independently replayed. [Two-stage caller recovery](adid_iokit_caller_report.md) [fairplayd reply fields](daemon_selector26_reply_fields_report.md)

The current arm64e SHA-256 differs from the retained full-slice digest. The UUID and all eleven retained original instruction windows compare equal. The current receipt records both installed slice digests. Each original chained slot contains the same raw 64-bit word with IA diversity `0xe258` and address diversity zero. That identifies the import binding as decoded by the host's `dyld_info`. The earlier arm64e private runs supply the selected lookup-to-bind evidence. Authentication in a running process remains unknown.

The prior registry capture places both daemons under one FairPlayIOKit service and attributes separate user-client entries to them. In the current IOKit framework, the common struct-method path uses Mach request 2865 and reply 2965. The names reside in the calling task’s Mach namespace. The framework supplies the reply name from thread-local storage. The earlier Avp stage targets its own separately acquired connection. No observed message ties either installed `adid` slice to a native selector 26 transaction. [Mach transport and rights](live_iokit_mach_transport_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The installed file contains both ARM subtypes under the recorded digests. | Table addresses and code comparison. | Re-read fat headers, per-slice UUIDs, bytes and chained words. |
| The earlier arm64e service selection and lookup apply to the matching selected windows. | Primary and Avp labels, 96 B inner/direct record semantics. | Verify the service-class argument, connection cache and authenticated call target on the matching slice. |
| A native call follows the corresponding framework path. | Mach request and reply IDs and rights dispositions for that call. | Match the process image and caller PC to one observed request and reply. |

The comparison processes O(B+F) data for B file bytes and F printed fixups. The current file comparison takes O(B+F) space. Identifying the loaded subtype has high impact on matching a native caller PC. Joining the primary reply fields to their later `adid` consumers has medium impact on the cross-client ABI. [Audit](triage_evidence/audit_adid_selector26_installed.py) [Compressed receipt](triage_evidence/adid_selector26_installed_audit.json.zst)
