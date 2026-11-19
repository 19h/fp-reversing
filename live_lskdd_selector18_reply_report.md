# lskdd selector 18 reply handling

The installed FairPlayIOKit handler writes the provider result at output +0xc14 B and returns zero in W0 on both its ordinary and descriptor-failure paths. The installed `lskdd` daemon tests the outer IOKit result before reading that embedded provider status. Six offline reply cases track both channels to the daemon's store at context +0x30 B. [Connection provenance](live_lskdd_selector18_connection_report.md)

| Field | Current kernel producer | Current daemon consumer |
| --- | --- | --- |
| Outer IOKit result | `0xfffffe000a54594c` sets W0 to zero in the selected method body. IOKit also has a separate short-error reply before a full structure is available. | `0x100584cf0` compares W0 with zero on the modeled frame. The nonzero branch goes directly to the context store. |
| Embedded u32 status at +0xc14 B | `0xfffffe000a545910` stores the provider return. `0xfffffe000a545944` stores −39 on descriptor failure. | `0x1005647dc` loads and `0x100564814` tests it. A nonzero value takes the context store with the status translated by adding `0x2ee02eab` modulo 2^32. |
| First provider u32 at +0x0c B | `0xfffffe000a5458f0` passes its address. Both provider and mapping failure paths clear the field. | `0x1005d9e94` loads it after zero outer and embedded status. A zero value takes the context store. The nonzero branch checks the upper bound 3,072. |
| Second provider u32 at +0x10 B | `0xfffffe000a5458f4` passes its address. | `0x1005d5fc8` loads it and checks that its zero-extended value is below 3,073 on the selected route. |
| Output data at +0x14 B | `0xfffffe000a5458ec` forms the pointer and `0xfffffe000a545900` supplies the 3,072 B capacity. | The six paths observed read the field words above and reach the context store without reading the data region or the framework's size cell. |

The reply record ends after the embedded status. Its width is 20 B of prefix + 3,072 B of data + 4 B of status = 3,096 B. The current method table declares that width on input and output. The normal inline reply ID is 2965. It occupies 3,148 B with the full returned structure, and the ordinary short error reply occupies 36 B. The request leaves the framework at `0x184ebe090`. It uses the connection as COPY_SEND destination and a separate local reply port as MAKE_SEND_ONCE. [Installed method table](live_kext_selector26_report.md) [Mach transport](live_iokit_mach_transport_report.md) [Framework copy and count update](live_lskdd_method_abi_report.md)

## Observed daemon outcomes

The context store at `0x1005b3410` writes W22. In each case the replay stopped before the authenticated return at `0x1005b344c`. The returned-register column records W0 at that point. The meaning of the status constants in the next caller is unknown.

| Modeled IOKit result | Embedded result | Provider fields at +0x0c / +0x10 | Context status | W0 at return |
| --- | --- | --- | --- | --- |
| `0xe00002c2` | Unavailable | Unavailable | `0x2edf8807` | `0xe00002c2` |
| 0 | `0xffffffd9` | 0 / 0 | `0x2ee02e84` | 0 |
| 0 | `0xffff5966` | 0 / 0 | `0x2edf8811` | 0 |
| 0 | 0 | 0 / 0 | `0x2ee02eab` | 0 |
| 0 | 0 | 3,072 / 0 | `0x2edf880f` | 0 |
| 0 | 0 | 3,072 / 3,072 | `0x2edf880f` | 0 |

For the embedded-error branch, let R be the u32 at output +0xc14 B. In the recovered frame, the shift at `0x1005647f4` is one bit and `0x7dcadfde = 2 * 0x3ee56fef`. The XOR and masked shift therefore sum to `R + 0x3ee56fef` modulo 2^32. The next addend is `0xeffabebc`, giving the recorded translation. This uses constant time and storage. The six replay cases use time proportional to the executed instructions and retain one record per distinct authenticated edge.

## Assumption register

| ID | Premise and dependent result | Falsification check |
| --- | --- | --- |
| LR18.1 | The kernel collection and installed daemon match the recorded hashes and UUIDs. All preferred PCs and record offsets depend on them. | Compare both original images with the receipt, including the selector record and checked words. |
| LR18.2 | The daemon enters from the modeled open and selector 18 call. This qualifies the branch constants and status translation. | Compare a separately observed frame's registers at the method return and verify the two status comparisons. |
| LR18.3 | The framework exposes either a full 3,096 B structure on success or the modeled outer failure without a structure update. The read census applies to these six cases. | Observe reply ID, size, framework return and output count together for a native transaction. |
| LR18.4 | The zero-filled model represents the unused record bytes and local environment for the tested paths. The summary statuses for the nonempty cases are fixture observations. | Reinspect the downstream helper and caller with independent ordinary runtime data. |

High impact for the cross-layer distinction between IOKit and provider status. Medium impact for identifying which record fields the tested daemon continuation consumes. Native reply delivery, subsequent interpretation of the context status, and selector 19 connection reuse remain unknown.

## Reproduction

Use the unmodified fat executable and decompressed current boot collection. Run with Python, Capstone, Unicorn and Apple `dyld_info`.

```sh
python3 triage_evidence/audit_live_lskdd_selector18_reply.py "$LSKDD_IMAGE" "$CURRENT_COLLECTION"
```

The auditor reads the current selector record, checks the kernel instructions and replays six synthetic IOKit returns through the daemon. It retains original instruction and fixup records, per-case read offsets and the final register and context words. [Auditor](triage_evidence/audit_live_lskdd_selector18_reply.py) [Compressed receipt](triage_evidence/live_lskdd_selector18_reply_audit.json.zst)
