# fairplayd CoreADI reply acquisition and cleanup

The original `fairplayd` clock-success request reaches the reply getter at `0x100e21a08` under private XPC return models. A NULL data result returns `0xffff5028`. A non-NULL result enters two local allocations. Failure of either returns `0xffff5035`. The reported extent has a 4,096 B comparison under the checked predecessor state. The two non-NULL reply fixtures with successful allocations reach the same unresolved frame reload before reading any reply byte. [Request origin](daemon_adid_request_origin_report.md) [XPC transport call sites](live_fairplay_adid_ipc_report.md)

```text
pending sync send -> modeled reply dictionary -> get_data("data", &extent)
  |
  +-- NULL ---------------------------> release / free -> 0xffff5028
  |
  +-- pointer -> malloc(24) -> malloc(4096)
                     |             |
                     +-- NULL -----+--> release / free -> 0xffff5035
                                   |
                                   +--> extent comparison -> frame reload
```

## Reply arguments and allocation

| Boundary | Unslid PC | Verified object or argument |
| --- | --- | --- |
| Synchronous call | `0x100e21718` | The connection for `com.apple.adid` and the source-built request dictionary. The audit resumes the exact retained send boundary. |
| Check returned object type | `0x100e21770` | Receives the modeled reply object. The checked continuation supplies the dictionary type. |
| Get the reply field | `0x100e21a08` | X0 reply dictionary, X1 key `data`, X2 extent output at frame F+0x1b0. The pointer return is saved to F+0x318 at `0x100e21a10`. |
| Allocate response record | `0x100e21aa8` | Requests 24 B when the data pointer is nonzero. |
| Allocate response buffer | `0x100e21b54` | Requests 4,096 B after the record allocation succeeds. `0x100e21b60` stores its return value at response record +0. |
| Compare reported extent | `0x100e21bf0` | The source compares the u64 extent against X25+0xfc3. The checked phase supplies X25=61, so the comparison operand is 4,096 B. |

The unsigned HI predicate at `0x100e21bf4` selects branch slots `0x1010b0630` for extent at most 4,096 B and `0x1010b1140` for extent above 4,096 B. Their targets are `0x100e241c4` and `0x100e21c14`, respectively. Both slot words and their IA discriminator `0xb51a` were read from the pinned binary. The audit observes the first branch with extents 4 and 19 B. The other target comes from original branch arithmetic and fixup readback. The comparison alone does not determine the outcome of later buffer handling.

## Cleanup and caller-visible results

| Modeled condition | Response-specific cleanup | Helper result at `0x100701a7c` |
| --- | --- | --- |
| Getter returns NULL | No response allocation | `0xffff5028` |
| 24 B allocation returns NULL | No response allocation | `0xffff5035` |
| 4,096 B allocation returns NULL | `free(response record)` at `0x100e23ccc` | `0xffff5035` |

All three paths request these releases and frees in the listed order. `xpc_release` resolves to original import slot `0x1010b1550`. `free` resolves to `0x1010b1578`.

| Order | PC | Object |
| ---: | --- | --- |
| 1 | `0x100e22df0` | Queue object |
| 2 | `0x100e22e40` | XPC connection |
| 3 | `0x100e22f08` | Request dictionary |
| 4 | `0x100e22fac` | Reply dictionary |
| 5 | `0x100e24fdc` | Request byte buffer |
| 6 | `0x100e2507c` | Request record |

The original helper's entry stores clear the four caller cells of widths 8, 4, 8 and 4 B. Those zeros survive all checked failure routes to the original caller consumer. The modeled releases end the reply object's byte-borrow premise, and replay rejects subsequent source access to retired spans. Native reference counts, allocation state and Mach right dispositions remain unknown.

## Non-NULL reply continuation

One 4 B fixture is the exact prior `adid` error reply for the separately retained `akd` OTP request. The 19 B fixture contains a zero status and two small, inert marker spans, using the previously compared `akd` reader layout. With the response allocations supplied, both fixtures reach `0x100e24cc0`, before `ldr w19, [sp,#0x21c]`. The replay has no defined value for that frame slot. Three immediate load/store pairs before the boundary preserve earlier opaque bytes without assigning them values. The audit observes zero reads from the two reply payloads before the stop. The application status interpretation, success fields, four output values and subsequent ownership remain unknown in this client. [Prior provider reply and akd reader controls](akd_adid_client_report.md)

## Assumptions and verification

| ID | Premise and result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | The pinned original and prior receipts identify the reply call sequence. | Rehash the thin image, compare the original send boundary, instruction digest, SP, registers and request receipt, and decode eight original format-12 chained words. |
| A2 | The checked caller state starts at the retained clock-success cut. | Cross two controller pairs, two stack placements and two lookup-flag settings. Compare setup visits, writes, reads, edges, registers and flags with the prior receipt. |
| A3 | Ordinary modeled API returns delimit the local reply and cleanup paths. | Run the missing-field control, both allocation failures and both non-NULL fixtures. Vary caller-saved general-purpose registers and flags, require exact call arguments, and check ownership in the model. |
| A4 | Every value used by the replay must have a defined producer. | Keep all three reply-path frame copies opaque and stop at the next unresolved load. A source-traced value at F+0x21c would permit a further continuation. |

The audit covers 40 runs, each matched to a retained send prefix, and 70,896 original instruction visits. Twenty-four runs return to the original caller and sixteen stop at the same frame reload. The receipt preserves both replies as fixtures, the exact dispatch words, and the observed cleanup. Two runs of the audit produce identical JSON. Replay cost is O(B + V + E) in loaded bytes B, visits V and retained events E, with O(B + V + E) space. The IDA MCP endpoint was unavailable when queried for relevant annotations. The calculations use original binary bytes and the retained source receipts. [Audit script](triage_evidence/audit_daemon_adid_reply_reader.py) [Compressed evidence](triage_evidence/daemon_adid_reply_reader_audit.json.zst)

| Impact | Remaining evidence |
| --- | --- |
| High | Recover the frame bookkeeping producer and follow the first actual payload read to output publication on the client. |
| High | Recover the provider's OTP reply producer and match its ordinary success layout to the client reader. |
| Medium | Observe ordinary native delivery with the named service's Mach destination and reply context. |
