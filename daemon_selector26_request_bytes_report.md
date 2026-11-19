# Selector 26 request bytes and the Avp record comparison

All four reconstructed `fairplayd` selector 26 aggregates carry `0x7976211a` and `0xfd2821c7` at offsets 24 B and 106 B inside the same outer span. The archived `adid` Avp packets carry these tags at outer offsets 18 B and 32 B. The tags and types agree across call forms, and the payloads differ. A native exchange and the installed parser's eventual use of these nested fields remain unknown. [Shared lookup sites](live_fairplay_message_modes_report.md)

## Request custody

The replay follows the positive self-process-path continuation to the original `IOConnectCallStructMethod` call. It retains both prior comparison histories and the established fixtures for caller classes `0x98` and `0x99`. The process query supplies an 18 B synthetic path. Logical pointer authentication and modeled private calls, process-query, and allocation results carry over from the earlier work. The audit reads the full referenced memory at the call and independently reconstructs it with the last journaled store at every offset. [PID-path producer](daemon_selector26_pidpath_paths_report.md) [Audit](triage_evidence/audit_daemon_selector26_request_bytes.py)

| Class | Caller PC | API input and initial output capacity | Aggregate in the method request | 2865 userspace size |
| --- | --- | ---: | --- | ---: |
| `0x98` | `0x1002069c4` | 272 B or 288 B | Entire buffer inline | 356 B or 372 B |
| `0x99` | `0x100293074` | 16 B | Inline descriptor references 272 B or 288 B of task memory | 100 B |

The 16 B descriptor uses a little-endian u64 address at +0 B and a u32 nested extent at +8 B. The final four input bytes at +12 B are zero in both descriptor cases. The inline count and message sizes use the synchronous zero-scalar framework route, `84 B + align4(input extent)`. In the pinned legacy adapter, the direct call's outer extent fails the 16 B input count check. The descriptor form meets both outer counts. On the current provider's successful setup path, `uej58Beal` issues the task-buffer read at `0xfffffe000a54647c` and passes its staging pointer and the same nested extent to `PRnut72j9` at `0xfffffe000a54648c`. These source paths supply the predicted custody for the two call forms. [Legacy admission and request geometry](daemon_selector26_legacy_admission_report.md) [Current provider copy sites](live_kext_selector26_transfer_report.md)

The modeled 2865 destination is a COPY_SEND of the connection right. The local field makes a send-once reply right from the issuing thread's reply port. The installed framework emits the method at `0x184ebe090` and receives reply 2965 through that separate reply name. No numeric names were established for the modeled calls. In the supplied RAX trace, the last observed request is 2862, open, on line 1726 with service name `0x1903` and reply name `0x507` in the guest namespace. Its reply 2962 arrives on `0x507` at line 1736. The decoded result is `0xe00002c2` and the returned connection is null. The 44 decoded send/receive events contain neither 2865 nor 2965. [Current transport emission and rights](live_iokit_mach_transport_report.md) [Supplied trace](zut_trace_report.md)

## Selector 26 outer records

The four buffers each partition exactly into four records using the 10 B big-endian field layout. Their first record is the same 14 B scalar shape, with a distinct key from the `0xfa834112` used in earlier installed parser fixtures. The class `0x98` and `0x99` buffers have different SHA-256 hashes even at the same extent. All offsets below count from the aggregate start. [Installed parser input layout](live_fairplay_early_header_report.md) [Earlier installed schema fixture](live_fairplay_schema_search_report.md)

| Key | Type | Header in 272 B aggregate | Header in 288 B aggregate | Body extent |
| --- | --- | ---: | ---: | ---: |
| `0x744b91e8` | `0x9777` | 0 B | 0 B | 4 B |
| `0x812b9aed` | `0x50db` | 14 B | 14 B | 208 B or 224 B |
| `0x172ba3a8` | `0x50db` | 232 B | 248 B | 19 B |
| `0x00000000` | `0x50db` | 261 B | 277 B | 1 B |

The final allocation begins at the modeled return from `0x100a05060`. The byte store at `0x1009166b8` supplies all bytes before the zero-tag trailer. Ten individual stores from `0x100848610` through `0x1008487f0` construct the trailer header, and `0x100902de0` writes its last byte. The write journal and memory snapshot agree for all 1,120 aggregate bytes across the four fixtures. [Producer context](daemon_selector26_pidpath_paths_report.md) [Write and hash receipt](triage_evidence/daemon_selector26_request_bytes_audit.json.zst)

Two of these outer tags also match previously recovered lookup inputs in the pinned kext. The comparisons use the raw tag XOR `0x31ae0066` after decoding the protected in-memory record. This matches field identities across layers at the tag level. Eligibility for the second lookup depends on the command scalar and the saved caller state. A separate 96 B `adid` selector 26 fixture also starts with `0x744b91e8` and the same scalar type and length. [Pinned kext command dispatch](userclient_command_dispatch_report.md) [Pinned kext copying reader](userclient_input_reader_report.md) [Separate adid selector 26 producer](adid_iokit_report.md)

| Selector 26 raw tag | Encoded kext request | Pinned kext lookup setup |
| --- | --- | --- |
| `0x744b91e8` | `0x45e5918e` | Command scalar lookup at `0xfffffe000a656ca4` |
| `0x172ba3a8` | `0x2685a3ce` | Copying reader setup at `0xfffffe000a63dd84` through `0xfffffe000a63ddcc`, exclusive |

The selected daemon route depends on `_getpid`, `_proc_pidpath` and `_strnlen`. The replay supplies the process path before interpreting the allocation and copy sequence. The RAX trace records a `proc_info` call with the same PID-query argument pattern before IOKit open. Its path bytes and exact daemon call site are unknown. [Self-process path boundary](daemon_selector26_self_pidpath_report.md)

## Nested record comparison

The body of selector 26's `0x812b9aed` span partitions exactly into the five records below. Offsets count from the aggregate start, including the outer header. The shared tag offsets are exact child record boundaries in all four cases. [Framing and comparison receipt](triage_evidence/daemon_selector26_request_bytes_audit.json.zst)

| Key | Type | Header in 272 B aggregate | Header in 288 B aggregate | Body extent |
| --- | --- | ---: | ---: | ---: |
| `0x7976211a` | `0x9777` | 24 B | 24 B | 4 B |
| `0xf93d7930` | `0x50db` | 38 B | 38 B | 16 B |
| `0xf7859101` | `0x50db` | 64 B | 64 B | 32 B |
| `0xfd2821c7` | `0x50db` | 106 B | 106 B | 96 B or 112 B |
| `0x00000000` | `0x50db` | 212 B | 228 B | 10 B |

The archived `adid` method-100 baseline and twelve follow-up fixtures put two of the shared keys at the outer level. The twelve follow-up buffers are byte-identical. Both distinct packets begin with a `0x6125a127` record of type `0x8485` and length 8 B, emitted at `0x100058a1c`. The third mode key, `0x5c241ab2`, has zero raw big-endian matches across all checked buffers. [Shared lookup sites](live_fairplay_message_modes_report.md) [Avp source and buffers](adid_avp_packet_report.md)

| Key | Outer header offset | Type | Body in 144 B packet | Body in 320 B packet |
| --- | ---: | --- | --- | --- |
| `0x7976211a` | 18 B | `0x9777` | 4 B, u32 zero | 4 B, u32 zero |
| `0xfd2821c7` | 32 B | `0x50db` | 80 B span | 256 B span |

The selector 26 scalar at offset 24 B has a nonzero body in all four cases, established by byte comparison with the same header and zero body in Avp. The selector 26 span at offset 106 B has a different extent from either Avp outer span. The 320 B Avp packet also contains inner occurrences at offsets 94 B and 108 B with a zero scalar and a 128 B span, respectively. Full-packet and opening-record searches returned zero matches in every selector 26 aggregate. These observations establish reuse of record identifiers and field types across the compared interfaces. The data path that produces or consumes their respective bodies across both interfaces remains unknown. [Avp nested structure](live_fairplay_early_schema_report.md) [Record comparison receipt](triage_evidence/daemon_selector26_request_bytes_audit.json.zst)

The command follow-up extracts the first outer scalar and follows the installed dispatcher to the reader request for the separate 19 B outer span. [Installed command and reader dispatch](daemon_selector26_command_report.md)

## Verification

Source images are the pinned thin `fairplayd.arm64e` SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` and the separately pinned `adid` SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`. The audit verifies 69 original fixup words on the selected positive-route edges, checks all 1,120 byte positions, parses both packet forms and validates the supplied trace by SHA-256 before decoding its final reply. Two independent runs of the replay yielded identical aggregate and inline digests. The only new execution is offline interpretation of the pinned daemon instructions. [Avp producer and archives](adid_avp_packet_report.md) [Compressed receipt](triage_evidence/daemon_selector26_request_bytes_audit.json.zst)

```sh
uv run --offline --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_request_bytes.py "$RAX_TRACE" "$RECEIPT"
```

The script uses the existing pinned daemon loader and takes the original trace and output receipt as arguments. The write reconstruction takes O(J + W + B) time and O(B) auxiliary space for J journal entries, W bytes written into the checked range and a B-byte final buffer, excluding instruction interpretation. The record walk uses a 10 B big-endian header and advances by its size plus the u32 body extent. It checks each end against the supplied limit before accepting the record. Its time and stored entries are linear in the number of headers visited.

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The selected modeled predecessors and synthetic process-query and private call results characterize the four replay cases. Their concrete bytes depend on those initial states. | Vary the process string, PID, predecessor and allocation layout. Compare journaled last writers and request digests. |
| A2 | The original fixups identify authenticated logical dispatch. The reported execution PCs and caller identity depend on those bindings. | Decode the actual fixup words and compare slot targets with the replay edges. |
| A3 | The legacy count adapter and zero-scalar synchronous framework apply to the projected wire sizes. The current provider path describes staging when its setup succeeds. | Passively correlate a successful open, 2865 header and counts, concrete client method and copy boundary in the same build. |
| A4 | The archived Avp data and the retained RAX trace bound the byte comparison and observation window. | Rebuild the pinned Avp cases, compare their digests, and re-decode the final RAX request/reply pair from the hex dump. |

| Impact | Open evidence |
| --- | --- |
| High | A matched passive selector 26 transaction that connects the daemon buffer to the current provider's actual staging bytes and reply. |
| Medium | The first downstream decode that can relate this aggregate's scalar and spans to the identified kext lookups and their selected continuations. |
| Low | Stability of the byte images across other positive process path and allocator profiles. |

QG1–QG3 cover the factual scope, conditional assumptions and request, transport and consumer claims. QG4–QG5 cover byte counts, exact frame boundaries, full write coverage and the two outer count outcomes. QG6–QG7 cover pinned evidence, reproducibility and the unresolved boundaries listed above.
