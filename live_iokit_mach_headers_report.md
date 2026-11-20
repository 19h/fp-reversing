# Native FairPlayIOKit discovery and open message headers

A native verifier captured the five synchronous Mach exchanges from IOKit main-port acquisition through a public `IOServiceOpen` call on the FairPlayIOKit service. Open request 2862 completed with Mach status zero. The 52 B complex reply 2962 carried a null connection and application status `0xe00002c2`, which the public wrapper returned. All ten native messages agree byte-for-byte with the archived `fairplayd` guest messages after masking the documented task-local name fields. [Archived open](live_fairplay_iokit_open_report.md) [Original trace audit](archived_iokit_open_retirement_report.md)

## Capture boundary

The debugger launched a standalone arm64 verifier on macOS build `26C5035r`, kernel UUID `90195379-954d-3ca3-baac-327341f14211` and shared-cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`. The audit used exported addresses to establish the loaded slide, verified that the two loaded images had the expected UUIDs, and checked the actual BL instruction at each breakpoint site before setting it. It read the request buffer immediately before each BL to `_mach_msg2_internal` or its veneer. After return, it read the transport status and the reply in that same buffer before the MIG decoder ran. Every stop belonged to the issuing verifier thread. [Installed discovery](live_iokit_discovery_report.md) [Installed Mach transport](live_iokit_mach_transport_report.md)

| Register before BL | Field checked against the buffer |
| --- | --- |
| X0 | Message buffer |
| X1 | `0x200000003`, kernel-object class with send and receive |
| X2 | Request size in the high 32 bits, header bits in the low 32 bits |
| X3 | Local reply name in the high 32 bits, remote destination in the low 32 bits |
| X4 | Message ID in the high 32 bits, voucher in the low 32 bits |
| X5 | Receive name in the high 32 bits, request descriptor count in the low 32 bits |
| X6 and X7 | Receive capacity in bytes and timeout zero |

The compiler verified the 24 B Mach header, message ID offset +20 B and 12 B port descriptor against the arm64 SDK. The auditor preserved exactly each message's declared extent. The same task's cached name from `mig_get_reply_port` matched the local name in every request, receive selector and reply. The verifier read the cached name before discovery and again after releasing the service, iterator and main rights. [MIG reply-name lifecycle](live_iokit_mig_reply_port_report.md) [Earlier sequence measurements](live_iokit_reply_queue_report.md)

## Observed name transfer and open result

The numeric names below come from the retained verifier run and are valid in its Mach namespace. All five requests use local reply name `0x707`. All five replies use local name `0x707`, remote name zero and voucher zero.

| Operation | Request / reply | Unslid emission site | Request remote name | Reply payload | Send / receive size |
| --- | --- | --- | --- | --- | --- |
| Acquire IOKit main port | 205 / 305 | `0x18056b448` | Host `0x1d03` | Main send name `0xa03` | 24 B / 40 B |
| Query server version | 2877 / 2977 | `0x184ebc3cc` | Main `0xa03` | Version `0x0134647a` | 24 B / 44 B |
| Match FairPlayIOKit class | 2881 / 2981 | `0x184ebd3dc` | Main `0xa03` | Iterator send name `0xb03` | 100 B / 40 B |
| Advance the iterator | 2802 / 2902 | `0x184ebd59c` | Iterator `0xb03` | Service send name `0x1a03` | 24 B / 40 B |
| Open the returned service | 2862 / 2962 | `0x184ebdc6c` | Service `0x1a03` | Null connection, `0xe00002c2` | 80 B / 52 B |

The matching body contains the same 64 B binary dictionary as the trace, including `IOProviderClass` and `com_apple_driver_FairPlayIOKit`. Open request bits `0x80001513` encode a complex message with a copied service send right and MAKE_SEND_ONCE for the reply. A separate descriptor carries self task name `0x203` with COPY_SEND. The second descriptor has out-of-line type 1, address zero and extent zero. Connection type at request +64 B is zero. The receive buffer contains one port-send descriptor with name zero at +28 B and application result `0xe00002c2` at +48 B. After framework decoding the caller has a null connection. A separate native log probe recorded the missing-entitlement branch during its open with the same result. [Installed open reply decoder](live_iokit_open_reply_copyout_report.md) [Native open admission](live_fairplay_open_admission_report.md)

## Comparison with the archived guest

The auditor verifies the SHA-256 of `annotated-strace-rax-user.txt` and decodes the five pairs from its hexadecimal message dumps. For the ten pairwise comparisons it masks only the remote and local names at request +8 B and +12 B, the received local name at reply +12 B, the task descriptor name at request 2862 +28 B, and the returned send names at replies 305, 2981 and 2902 +28 B. It preserves the null connection field in reply 2962, the two status channels, dispositions, message IDs, sizes and payloads. All ten comparisons match after masking. The archive's `0x507` and the retained verifier's `0x707` identify their respective local queues. Production `fairplayd` successful open and method delivery remain unknown. [Archived reply names](live_iokit_mig_reply_port_report.md) [RAX namespace import](archived_iokit_reply_import_report.md)

## Assumptions and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The loaded Apple images and breakpoints correspond to the installed emitting instructions. This qualifies the call-site addresses. | Check both loaded image UUIDs, the two independently derived slides and each BL encoding; require the same thread at entry and return. |
| Successful transport overwrites the saved request buffer with the reply before the stub parses it. This qualifies the message IDs and channel. | Compare the pre-call argument registers with the packed request. On return check status, reply ID, receive name and extent before any decoder instruction executes. |
| The numerical fields omitted from the archive comparison are namespace-local names. This qualifies the byte comparison. | Verify the main, iterator and service descriptor names against the next destination and the C wrapper outputs. Preserve all other bytes, including the zero connection field. |
| The verifier makes an ordinary type-zero open of the service it just found. This qualifies the result as a native baseline. | Check the matching dictionary, iterator reply, service destination, task argument and zero connection type. The daemon's native credentials and intermediate provider state require their own evidence. |

High impact for verifying the actual native message IDs and reply channel. Medium impact for comparing the normal verifier with the emulated daemon. The receipt retains the original native bytes, sites, parsed values and archive comparison hashes. Replay can assign different Mach names. For total captured byte count B and archive length T, parsing and comparison take O(B + T) time and space. Run `python3 -B triage_evidence/audit_live_iokit_mach_headers.py "$TRACE"` on the pinned build with the installed Xcode tools and Capstone available. [Auditor](triage_evidence/audit_live_iokit_mach_headers.py) [Compressed receipt](triage_evidence/live_iokit_mach_headers_audit.json.zst)
