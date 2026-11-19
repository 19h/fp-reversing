# fairplayd CoreADI reply copy and field publication

The `fairplayd` CoreADI client copies the XPC dictionary's borrowed `data` into its own response buffer, releases the XPC objects, and parses the private copy. The four-byte `ffff4ffb` fixture returns that value to the original caller, leaving all four outputs zero. A separate 19 B fixture yields two caller-facing pointer/length pairs before a pending notification registration. The frame values that previously stopped the replay are copied between local cells and do not influence either observed result. The actual provider reply to the `fairplayd` operand and native daemon–kext pairing remain unknown. [Previous reply boundary](daemon_adid_reply_reader_report.md) [Provider operand and reply evidence](adid_otp_ingress_report.md)

```text
adid XPC dictionary -> borrowed data -> private response buffer
                                            |
                                   release XPC objects
                                            |
                                     BE32 status
                                      /        \
                         0xffff4ffb /          \ zero in fixture
                                    v            v
                           free response     read two lengths
                           and request       allocate and copy two spans
                                    |            |
                           caller return     publish ptr,len,ptr,len
                                             pending notify_register_check
```

## Frame reload and copy

The compiler function starts at `0x100e1e5ec` and ends before the next function at `0x100e25560`. The original text has 11 direct stores to frame+0x21c. All 16 retained non-NULL routes reach `0x100e24cc0` before any of those instructions executes. The complete write history for each route also contains no overlapping write through an aliased base. The first loads of the unresolved cells consume 56 B across eight disjoint locations. The replay assigns those cells two independent byte patterns and separately follows all undefined frame bytes through the observed suffix. Their uses are confined to frame loads and stores, including the `w19` reload's later spill at `0x100e224b8`. They do not supply branch or address operands, imported call arguments, or the checked outputs. This establishes path-specific noninterference. The native values in those cells and the producers on other paths remain unknown.

The 4 B copy reads borrowed offsets 3, 2, 1, 0 at `0x100e1fa78` and stores them at identical offsets at `0x100e1fa7c`. The 19 B copy reads offsets 18 through 0 in descending order using the scalar tail and the unrolled eight-byte loop. The private copy equals the full payload in both cases. Queue, connection, request dictionary and reply dictionary releases follow the last borrowed read. The first status read follows the reply release at `0x100e22fac` and uses the allocated response buffer. The recorded parser does not read the borrowed range after that release.

## Fields and caller outputs

| Field | Offset (B) | Width (B) | Original consumer | Observed result |
| --- | ---: | ---: | --- | --- |
| Status | 0 | 4 | Byte reads at `0x100e246dc`, `0x100e246e4`, `0x100e246f4`, `0x100e24700`. The BE32 value in W28 is compared with zero at `0x100e2470c`. | `0xffff4ffb` for the error fixture, zero for the marker fixture. |
| First length | 4 | 4 | Byte reads at `0x100e2481c`, `0x100e2482c`, `0x100e24838`, `0x100e24840`. The assembled BE32 W24 is saved to frame+0x198. | 3 B in the marker fixture. |
| First span | 8 | 3 | Pending allocation at `0x100e24bb0`, followed by descending byte copy under a non-NULL return model. | Bytes `61 62 63`. Original pointer and u32 length stores at `0x100e24bbc` and `0x100e1fc30`. |
| Second length | 11 | 4 | Byte reads at `0x100e24a44`, `0x100e24a50`, `0x100e24a64`, `0x100e24a6c`. The assembled BE32 W0 is saved to frame+0x15c. | 4 B in the marker fixture. |
| Second span | 15 | 4 | Pending allocation at `0x100e1fc98`, followed by descending byte copy under a non-NULL return model. | Bytes `57 58 59 5a`. Original pointer and u32 length stores at `0x100e1fca4` and `0x100e1fd34`. |

For the 4 B fixture, the client performs only the four status reads. It frees the response buffer, response record, request buffer and request record at `0x100e24e28`, `0x100e24eec`, `0x100e24fdc` and `0x100e2507c`. W0 is `0xffff4ffb` at original caller `0x100701a7c`, equivalent to signed i32 −45,061. That fixture's bytes came from the separate archived `akd` operation. The audit does not assign this status to the native `fairplayd` exchange.

For the 19 B fixture, the four output cells have widths 8, 4, 8 and 4 B. Their values are the first owned output pointer, 3, the second owned output pointer and 4. At the replay boundary, the next imported call is `notify_register_check` at `0x100e1fe88`, with X0 naming `com.apple.adid.midchangedV1` and X1 pointing at the u32 token output at `0x1010ca2c0`. This receipt stops before the registration and before the outer caller return. Native delivery, token values, output ownership at the outer caller, and the complete length grammar remain unknown. The observed shape matches the layout used for the named `akd` client controls. [Named client and reply controls](akd_adid_client_report.md) [Notification analysis](daemon_notification_registration_report.md)

## Assumptions and verification

| ID | Dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Recorded addresses and instructions belong to the pinned original arm64e image. | Hash the image, derive the function extent using original Mach-O metadata and verify the original chained words for each modeled API call. |
| A2 | The eight cases per fixture represent the retained clock-success predecessors. | Recheck the exact send prefix and the PC, SP, 31 registers and visit count at the earlier strict stop. Any write overlapping frame+0x21c before the cut invalidates the no-observed-producer result. |
| A3 | Unknown frame bytes are immaterial to these two observed routes. | Cross each case with two different values for the unresolved bytes. A separate byte/register dependency pass rejects any opaque input to dispatch, effective-address arithmetic, an API argument, an output store outside the frame or the final result. A path change requires a new check. |
| A4 | The modeled XPC dictionary, allocation and release returns represent the disclosed experiment. | Check every borrowed byte and every copy offset, reject post-release use, verify status and length registers, and check all four caller cells. Native PAC, object lifetimes and reply identity remain unknown. |

The audit executes 32 private replays with 84,784 original instruction visits, including 31,184 visits after the old stop. Six distinct original chained words cover the modeled API targets. Reported sizes are bytes and visits are counts of original instructions. The verification groups reads, stores and instruction visits by ordinal, using O(V + E) additional space and O(V + E) time for the fixed frame and byte-sized operands, where V is visits and E is recorded effects. Primary evidence is the pinned original binary and the retained XPC request/reply receipts. [Audit script](triage_evidence/audit_daemon_adid_reply_fields.py) [Audit results](triage_evidence/daemon_adid_reply_fields_audit.json.zst)

High impact remains at the cross-layer evidence boundary between the `adid` provider's actual result for the `fairplayd` request and the client's now recovered reader. Medium impact remains at the notification registration and subsequent caller return. No new native Mach port, Mach emission or kext call is established by either receipt.
