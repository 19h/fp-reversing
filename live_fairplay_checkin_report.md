# FairPlay receive-right check-in on macOS 26C5035r

The current launchd binary registers XPC interface 5, dispatches routine 206 to its service check-in handler, and sends the handler's reply through the common XPC server path. The handler places a receive right under `port`. In the archived RAX trace, `fairplayd` receives that descriptor for `com.apple.unfreed` and successfully adds its guest name to the run-loop port set. The current binaries establish the normal implementation. The archived trace establishes the guest handoff and insertion. A native handoff, native port-set membership, and equality with FairPlayIOKit's live slot 17 object remain unknown. [Earlier check-in ABI](bootstrap_checkin_handoff_report.md) [Current host-special publication](live_host_special_publication_report.md)

```text
fairplayd check-in -> libxpc interface 5:206 -> launchd endpoint
                                                      |
                receive name <- reply "port" <--------+
                      |
                      v
                  CF port set

launchd publication sends a reference to the kernel host slot table
                     -> FairPlayIOKit looks up slot 17 in mode 1
```

## Current request and reply path

The PID 1 CodeDirectory hash and universal file offset select the installed arm64e launchd slice with UUID `96360fc3-2fde-3eee-a403-7dfca7b44ac3`. The audit process maps dyld cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`, and the parsed library has UUID `94e40b03-44c5-3636-aa1a-c64a5d6b6bbb`. The daemon-side call to `bootstrap_check_in` is at `0x10044038c` in the previously matched daemon image. The code-address columns use unslid locations. [Process and slice evidence](fairplay_live_slice_identity_report.md) [Daemon registration](daemon_registration_report.md)

| Transition | Site | Checked result |
| --- | --- | --- |
| Start bootstrap operation | libxpc `0x184bc58ac` | Public entry calls `bootstrap_check_in3` with zero flags. A mode byte selects the XPC or legacy MIG route. |
| Invoke the XPC request | libxpc `0x184bc59e4` | Sends interface 5, routine 206 and the dictionary constructed for the check-in. |
| Emit request through Mach | libxpc `0x184be8678` to `0x184be9290` | The XPC pipe calls its Mach wrapper. The authenticated stub binds to `mach_msg` at `0x180548f94`. |
| Register and select callback | launchd `0x10002d43c`, `0x100046738` | Registers group 5 with dispatcher `0x10002e16c`. The common server invokes the match from parallel group and callback arrays and passes a pointer to its reply slot. |
| Dispatch routine 206 | launchd `0x10002e234`, `0x10002e2f4` | The dispatcher subtracts 200 and reads signed table entry 6. Entry 6 resolves to `0x10002e2e0` and reaches handler `0x100038178`. |
| Resolve and wrap service right | launchd `0x100038200`, `0x100038224`, `0x100038238` | Resolves the named endpoint, reads its local Mach name from the returned send object, and places that name in a receive wrapper under `port` in the associated reply. |
| Send server reply | launchd `0x1000467e4`, libxpc `0x184be8b18`, `0x184be8b2c`, `0x184bc8310` | The handler returns the object through the supplied reply slot. The server reloads that object and calls `xpc_pipe_routine_reply`. The library packs it and reaches the shared Mach wrapper. |
| Transfer the receive right | libxpc `0x184bcf268`, `0x184bcf298` | The serializer atomically exchanges the wrapper's name with `0xffffffff` and appends the original name with disposition 16, `MACH_MSG_TYPE_MOVE_RECEIVE`. |
| Return a daemon-local name | libxpc `0x184bc2d00`, `0x184bc5a1c` | The client extracts the receive name from its wrapper and stores the 32-bit value through the original bootstrap output pointer. |

The existing-endpoint success path calls the activation helper at `0x100059a08`, then retains the send wrapper returned by the getter at `0x100059a44`. On the audited normal branch the activation helper gets the endpoint name through `0x100046c48` and issues `mach_port_unguard` with the context at endpoint +0x70. The success getter can reach the same send-object producer at `0x10005cb70` and cache field at endpoint +0x68 used by the host-special publication path. This shared object path connects the publication and check-in roles in the current executable. The caller and endpoint checks still determine which particular object is returned. [Prior activation and notification analysis](bootstrap_checkin_handoff_report.md) [Current publisher](live_host_special_publication_report.md)

## Archived observations matched to the current contract

Each row compares the original binary dump against the retained packet decode and then checks the later member insertion in the same check-in interval. All requests have ID `0x400000ce`, all replies have ID `0x20000000`, and each reply has a disposition-16 port descriptor. The fallback bootstrap MIG reply also uses decimal ID 502. That reply has a separate destination and 64 B success layout from the FairPlayIOKit request that uses ID 502. The five archived check-ins follow the XPC branch. [Original trace interpretation](zut_trace_report.md) [Bootstrap protocol comparison](bootstrap_checkin_handoff_report.md)

| Service | Request / reply trace lines | Guest receive name | Successful insertion line |
| --- | --- | --- | --- |
| `com.apple.unfreed` | 1500 / 1516 | `0xe03` | 1539 |
| `com.apple.fairplayd` | 1541 / 1557 | `0x1303` | 1573 |
| `com.apple.fpsd` | 1575 / 1591 | `0x1403` | 1607 |
| `com.apple.arcade.fpsd` | 1609 / 1625 | `0x1503` | 1641 |
| `com.apple.fpsd.sim` | 1643 / 1659 | `0x1603` | 1675 |

All five insertions target guest port-set name `0x1003` and return zero. The same numeric name had a different role in a separate native audit task. The current CoreFoundation path uses the local name returned in the received message header to select a member's source, so a native record of the port-set name alone would leave the delivering member unknown. [Current CoreFoundation dispatch](live_fairplay_cf_receive_report.md) [Independent native bootstrap snapshots](fairplay_live_service_rights_report.md)

## Assumptions and verification

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The PID 1 signing and slice-offset queries refer to the installed executable throughout the comparison. They support current server PCs and import identities. | Compare process start, repeated signing queries and hashes computed from the selected bytes. |
| A2 | The inspected cache layout applies to the process resolving a given libxpc call. The library PCs and transport binding depend on this identity. | Compare the process's mapped cache and image UUIDs and resolved import against the originals. |
| A3 | Each archived packet pair and later insertion refer to the same guest episode. This supports the guest receive-name join. | Recheck request/reply names and IDs, the descriptor bytes, the insertion arguments, and their order before the following request. |
| A4 | The current endpoint selected for publication is the one selected at check-in. Native slot-to-receiver identity depends on this unresolved join. | Compare object identity across a native publication event and the ordinary daemon receive or port-set membership event. |

**High impact.** The current send-wrapper producer connects launchd's publisher with its check-in handler. The archived trace also resolves each guest receive member. Establishing the same connection natively requires a correlated kernel or receive observation.

**Medium impact.** The bootstrap reply and FairPlayIOKit request can reuse the decimal message ID 502 across distinct layouts and directions. The specific five check-ins in the trace use different XPC IDs.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_checkin.py \
  "$LAUNCHD_IMAGE" "$ANNOTATED_TRACE"
```

The audit checks original instructions and signed table entries, Mach import bindings, guest packet bytes, and guest membership-call results. It queries the running launchd identity without performing a check-in. For B input bytes, N parsed cache symbol and metadata records, I decoded instructions and T trace lines, time and working space are O(B + N + I + T) with fixed function and episode counts. [Audit script](triage_evidence/audit_live_fairplay_checkin.py) [Compressed receipt](triage_evidence/live_fairplay_checkin_audit.json.zst)
