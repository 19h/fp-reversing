# Installed FairPlayIOKit mode lookups and retirement

Both continuations from `FPMessage+0x60` load the just-published container from `FPMessage+0x00` and query it by tag. All three queried tags also appear at independently verified lookup sites in the pinned `fairplayd`. The two retained scalar fixtures give a miss for each query. The zero-byte branch carries raw status `0xce515b45` into cleanup. The byte-one branch carries `0xce515bda`. Both retire the two parser object graphs under modeled ordinary returns, clear the message output and reach a request to allocate a 14 B fallback buffer. [Continuous parser predecessor](live_fairplay_message_parse_completion_report.md) [Auditor](triage_evidence/audit_live_fairplay_message_modes.py) [Replay receipt](triage_evidence/live_fairplay_message_modes_audit.json.zst)

## Shared record identifiers

The selector 26 successor audit follows its copied aggregates through the zero-mode continuation. After the first miss, four subsequent queries return matching nodes and the caller reaches a private helper. [Selector 26 nested records and found-key dispatch](live_fairplay_selector26_nested_report.md)

The kext reads the first four stored bytes of the sole second-pass node's record on each query and decodes its tag. The recovered fixture tag is `0xfa834112`. Its successor is null. Every selected query returns `0xce515bda` and a zero matched-node output. The three queried keys agree across the kext and pinned daemon after undoing each component's key encoding. Kext W9 uses XOR `0x31ae0066`. Daemon W9 uses XOR `0x8b3dc651`.

| Decoded tag | Installed kext transfer and encoded W9 | Pinned daemon transfer and encoded W9 | Daemon role |
| --- | --- | --- | --- |
| `0x5c241ab2` | `0xfffffe000a6a2418`, `0x6d8a1ad4` | `0x10066e5e8`, `0xd719dce3` | First keyed record query after first child-container publication. [First key](daemon_outer_first_key_report.md) |
| `0x7976211a` | `0xfffffe000a6954bc`, `0x48d8217c` | `0x1008b35d8`, `0xf24be74b` | Optional typed u32 record and context-default route. [Optional u32](daemon_reader_option_default_report.md) |
| `0xfd2821c7` | `0xfffffe000a6a3370`, `0xcc8621a1` | `0x1006d6c2c`, `0x7615e796` | Borrowed record span passed into the nested parser. [Nested input](daemon_reader_nested_input_report.md) |

All three installed transfers target the shared lookup entry `0xfffffe000a6a3c44` with modifier `0x0ee9`. The zero-byte branch reads the container at `0xfffffe000a6a238c` and queries the first tag into C+0x68. Its saved continuation is `0xfffffe000a6a3e5c`. On this fixture it then reads M+0x61 and M+0x14 and selects `0xce515b45` before cleanup. The byte-one branch reads the container at `0xfffffe000a6a4e50`. It first queries the optional u32 key into C+0x710 and returns via `0xfffffe000a6a2dc4`. The missing-key path writes the fixture's default scalar zero to S+0x260 and queries the nested key into C+0xa0, with continuation `0xfffffe000a6a4540`. This second miss supplies the status at cleanup.

The archived source-built 144 B Avp method-100 request contains `0x7976211a` at outer offset 18 B with type `0x9777`, length 4 B and value zero. It contains `0xfd2821c7` at outer offset 32 B with type `0x50db` and length 80 B. The auditor verifies those headers directly from the frozen bytes. These are field-level correspondences across components and fixture types. The installed kext replay uses the two 14 B scalar fixtures. A native request pairing and the consumer behavior for found keys remain unknown. [Frozen Avp packet](adid_avp_packet_report.md)

## Cleanup and fallback ABI

M and A denote the message and its attribute. H/J/Z denote the first parser's container, node and buffer. H2/J2/Z2 denote the second parser's objects. C is the auxiliary region and S the workspace. Installed code stores the branch-specific raw status at S+0xd98, S+0xab8 and S+0x1c, at `0xfffffe000a6a4ea8`, `0xfffffe000a682cac` and `0xfffffe000a682dc8`, respectively.

```text
mode-specific lookup miss -> save raw status
  -> retire Z2, J2, H2 -> retire M, clear output C+0x360
  -> retire A -> retire Z, J, H -> request 14 B fallback allocation
```

| Order | Installed call site | Target, modifier and arguments |
| --- | --- | --- |
| 1, then 6 | `0xfffffe000a6a1978` | `_IOFreeData` at `0xfffffe000c509e6c`, modifier `0x085d`. X0=Z2 or Z, X1=14. |
| 2, then 7 | `0xfffffe000a6a1898` | `_IOFreeTypeImpl` at `0xfffffe000c509988`, modifier `0x4d6a`. X0=`0xfffffe00084928c0`, `site.FPTTLVNode`, 32 B. X1=J2 or J. |
| 3, then 8 | `0xfffffe000a6a1754` | Same typed target and modifier. X0=`0xfffffe0008492880`, `site.FPTTLV`, 16 B. X1=H2 or H. |
| 4 | `0xfffffe000a6a1bb0` | Same typed target and modifier. X0=`0xfffffe0008491e00`, `site.FPMessage`, 128 B. X1=M. |
| 5 | `0xfffffe000a697cb4` | Same typed target and modifier. X0=`0xfffffe00084923c0`, `site.FPMessageAttr`, 112 B. X1=A. |
| Pending | `0xfffffe000a682e88` | `_IOMallocData` at `0xfffffe000c509c2c`, modifier `0xca0c`, X0=14. |

The modeled return after each of the eight retirement requests marks that exact extent inaccessible to subsequent source loads and stores. The requests total 364 B per case. The message destructor visits the null child at M+0x08 first and the populated M+0x00 child second. By the fallback request, C+0x1d0, C+0x788, C+0x360, C+0x1b0 and C+0x418 hold zero. Neither case has reread the original input by that point. This extends the earlier original-container fallback contract to two mode-specific lookup failures following a successful second parse. [Earlier failure fallback](userclient_failure_fallback_report.md)

## Verification and assumptions

The audit pins installed build `26C5035r` and the thin daemon SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. It compares the complete preceding receipt, including the 29 archived proof rechecks. It compares each visited kext word to the normalized original kext, resolves the selected dispatch slots and reads the typed descriptors from the installed collection. The three daemon key immediates and their emitter instructions come directly from the pinned daemon. The reproduction command is `python3 triage_evidence/audit_live_fairplay_message_modes.py COLLECTION DAEMON`, using the two pinned image files.

Eight paths cover both input fixtures and both writer scratch patterns per mode. Each selected lookup walks one node and cleanup walks one node per container, with O(1) work and additional scratch space at these fixed fixture sizes. For a finite list of k nodes the documented shared lookup and destruction contracts use O(k) steps. Native retirement, hardware pointer authentication, downstream fallback behavior in these two replay epochs and matched Mach traffic remain unknown. [Shared destruction contract](userclient_parser_cleanup_report.md) [Mach inventory](mach_ports_report.md)

The eight suffixes cover 10,984 visits, 2,032 loads, 288 stores, 584 logical control transfers, 12 lookup returns and 64 retirement requests. The audit compares 1,088 instruction words including the pending allocator call. Ten words fall in five verified pool-base relocation pairs. There are 54 checked dispatch fixups. Decoded receipt SHA-256 is `022237eba39fd01ae86ca0948d9ea991881a71e95d1e384cf9c54ac0deb2ee54`.

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. Pinned collection, normalized kext and original daemon | Rehash the images, compare the trace's instruction words and logical targets, and decode both halves of each daemon key before its transfer. |
| A2. Each mode starts with the preceding live replay state | Reproduce the full predecessor receipt. Check the container pointer, one-node graph, exact serialized tag loads and zero lookup outputs in both scratch variants. |
| A3. Distinct allocations with ordinary allocator and retirement returns | Check the eight argument pairs and modifiers, restrict reads and writes after each modeled retirement, and inspect the five cleared cells. A native trace must establish which allocations the calls actually retire. |
| A4. The source-built method-100 packet is the archived fixture | Rehash the archive, independently walk its big-endian headers and compare the two exact outer offsets. Establish a matching native method call before assigning transport identity. |

| Impact | Open interface |
| --- | --- |
| High | Resolve found-key paths for the optional u32 and span consumers using the existing packet evidence and establish the resulting output or callback. |
| High | Continue the shared fallback from the 14 B request and observe how each raw status survives the final caller return. |
| High | Match a native daemon request to its kernel-visible bytes, caller epoch and returned output. |
| Medium | Trace other saved aliases through both retirement sequences. The five cleared cells establish ownership updates at those sites. |

QG1 factual scope, QG2 assumptions and probes, QG3 both observed mode paths and their cross-image tag mappings, QG4 exact source words and extents, QG5 modeled returns and native evidence boundaries, QG6 pinned provenance, and QG7 impact-ranked follow-ups pass for this increment.
