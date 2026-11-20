# Host-port fallback and voucher provenance in the archived FairPlay check-ins

The archived host-special request immediately before FairPlay's first launchd check-in asks for node -1, slot 1 (`HOST_PORT`). Its Mach transport succeeds and the 36 B MIG reply returns `KERN_INVALID_ARGUMENT` (4). The installed libdispatch initializer preserves the original `mach_host_self` name on this result and uses it to create the default task voucher. The archive shows that same guest host name passed to voucher creation, followed by five check-in requests carrying guest voucher name `0xd03`. The installed library sequence and two address comparisons support this attribution. The historical stack, voucher out-cell bytes and host-side voucher header remain unknown. [Archived trace and port inventory](zut_trace_report.md) [Current launchd check-in path](live_fairplay_checkin_report.md)

```text
Installed source path
  XPC pipe -> libkernel voucher hook -> libdispatch default task voucher
    -> host_self -> slot 1 lookup (412 / 512)
         status 4 -> cache the original host name
    -> voucher creation trap -70 -> cache returned voucher name
    -> add voucher to guest Mach header -> XPC pipe send

Archived trace
  guest host 0xc03 -> slot 1 lookup -> status 4
  guest host 0xc03 -> voucher creation -> status 0
  guest bootstrap 0x707 -> five check-ins with guest voucher 0xd03
                      bridge -> host bootstrap 0x80b, host reply 0xc03
```

## Installed emission and fallback

The audit pins cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`. The libxpc, libdispatch and libsystem_kernel UUIDs are in the receipt. The addresses below are unslid. The earlier cache's original libdispatch body independently contains the same node and slot operands, status-4 branch and retained-name store. Its global address differs. [Current cache census](live_rpc700_dependency_scan_report.md) [Earlier cache census and retained bodies](rpc700_endpoint_inventory_report.md)

| Transition | Original instruction or data | Effect |
| --- | --- | --- |
| Pipe requests a voucher | libxpc `0x184be8610` | Passes the outbound Mach header to libkernel's `voucher_mach_msg_set` at `0x180549a34`. The pipe sends the same header at `0x184be8678`, through the `mach_msg` veneer at `0x184be9290`. |
| Resolve the callback | libkernel `0x180549a38` through `0x180549a44` | Loads the installed table and calls its +8 B member when nonzero. Libdispatch's initializer at `0x1855bcc4c` supplies table `0x1e24a74d0`. The authenticated chain at table +8 B resolves to libdispatch `0x1855bc9a0`. |
| Select the task voucher | libdispatch `0x1855bc9d0`, `0x1855bca3c`, `0x1855d04d4` | A null thread-local voucher takes the default route. The cold path supplies `__voucher_task_mach_voucher_init` to `dispatch_once_f` for an incomplete once predicate. |
| Obtain and query the host name | libdispatch `0x1855b9c8c`, `0x1855b9ca0` | Saves `mach_host_self()` in W19. Calls `host_get_special_port` with node -1, slot 1 and `SP+0xc` as the output address. The installed getter issues Mach request 412 at libkernel `0x180549acc`, reaching the Mach2 SVC at `0x180548c1c`. |
| Select the cached name | libdispatch `0x1855b9cb4`, `0x1855b9cf8`, `0x1855b9cfc`, `0x1855b9ce4` | A nonzero getter status skips the success-only deallocation and output reload. Status 4 branches directly to the W19 zero check. A nonzero W19 is stored in `__dispatch_mach_host_port` at `0x1ed95db00`. |
| Create the voucher | libdispatch `0x1855bb700`, libkernel `0x180549e30` and `0x180548cac` | Passes the cached host name, a 16 B recipe at `0x1855d2970` and an output pointer to `host_create_mach_voucher`. The wrapper first issues trap -70. |
| Publish the voucher name | libdispatch `0x1855bb71c`, `0x1855bb728` | On success stores the returned 32-bit name in both `__voucher_default_task_mach_voucher` and `__voucher_task_mach_voucher`. |
| Attach the voucher | libdispatch `0x1855bca18` through `0x1855bca24` | With a nonzero selected name and empty voucher bits, writes the name at header +16 B and inserts disposition 19 (`COPY_SEND`) in bits 16 through 20. |

In the getter's 36 B simple reply path, it reads the routine result at +32 B and returns that result when the remote reply-header name is zero. The success-only complex path writes the returned name through the output pointer at `0x180549b94`. In the initializer, status zero takes the distinct deallocate-and-reload route. That route deallocates the original host name and tests the name from the output cell before publishing it. Status -301 (`MIG_REPLY_MISMATCH`) reaches a `BRK #1` cold path. A zero selected name reaches the separate diagnostic “Could not get unprivileged host port” and its `BRK #1`. [Original code, table member and ABI assertions](triage_evidence/archived_checkin_voucher_audit.json.zst)

The installed recipe contains four little-endian 32-bit fields, `03 00 00 00 62 02 00 00 00 00 00 00 00 00 00 00`. Key 3 is `MACH_VOUCHER_ATTR_KEY_BANK`; command 610 selects `BANK_CREATE` in the pinned RAX implementation. Previous voucher and content length are zero. The SDK layout places the flexible content field at +16 B, so this recipe has no content bytes. The archive records a pointer and length only. The archived recipe pointer `0x185550970` and installed recipe address differ by `0x82000`, equal to the difference between the previously retained and installed libdispatch slot-1 call sites. The three observed libkernel return PCs for host-self, Mach2 and voucher creation each differ from the installed sites by `0x1000`. These comparisons support a library attribution subject to A1. [Source and archived comparisons](triage_evidence/archived_checkin_voucher_audit.json.zst)

## Archived wire data and bridge boundary

At lines 1488–1499 the guest host name is `0xc03`. Request 412 goes to that name, with guest MIG reply name `0x507`. The reply carries no descriptor. The next voucher trap takes host name 3075, which is `0xc03`, and returns zero. In the entire 1,748-line trace this is the only printed voucher-creation trap, and only the following five messages carry a nonzero voucher field.

| Service | Guest request line and size | Guest voucher | Bridge send line | Guest reply line and voucher |
| --- | --- | --- | --- | --- |
| `com.apple.unfreed` | 1500, 172 B | `0xd03` | 1513 | 1516, zero |
| `com.apple.fairplayd` | 1541, 172 B | `0xd03` | 1554 | 1557, zero |
| `com.apple.fpsd` | 1575, 168 B | `0xd03` | 1588 | 1591, zero |
| `com.apple.arcade.fpsd` | 1609, 176 B | `0xd03` | 1622 | 1625, zero |
| `com.apple.fpsd.sim` | 1643, 172 B | `0xd03` | 1656 | 1659, zero |

Each 0x400000ce guest request has three distinct header roles. Destination `0x707` is the bootstrap send name, `0xb03` supplies the special reply receive name, and `0xd03` supplies the voucher send name. There is also one `COPY_SEND` body descriptor naming `0x707`. The 0x20000000 guest reply contains one receive-right descriptor. Host `0xc03` in the five bridge send annotations denotes the bridge's reply port in a separate namespace from guest `0xc03` at the host-self call. [Port-set membership and receive rights](live_fairplay_checkin_report.md)

RAX source at revision `4748a6ae8bd285369fe1413787b35587832f4dd3` defines a local host-object path for request 412 that returns status 4. Its voucher creation handler accepts a guest host object, inserts the resulting voucher send right into the guest space and writes the name through the output pointer. Its host send path releases the guest message's voucher reference, builds a zero-initialized host header, encodes voucher disposition zero and leaves header bytes +16 through +19 B zero. Its host receive path deallocates a received host voucher when the header carries one and presents an empty voucher field to the guest. These rules explain the possible loss of voucher identity at the bridge. The archived bridge annotations preserve lengths, descriptor counts and port names but omit the host header bytes. Historical launcher attribution, launchd's input voucher and any native voucher policy effect remain unknown. [Bridge source revision and checked lines](triage_evidence/archived_checkin_voucher_audit.json.zst)

## Assumptions and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The archive used the same library route as the installed implementation and the earlier recorded slot-1 caller. | Candidate attribution to libdispatch's task-voucher initialization. | Recover the historical mapped cache UUID, recipe bytes and caller stack. The audit already checks the two libdispatch address deltas, three libkernel deltas and the earlier slot argument and fallback. |
| A2. The first attached voucher came from the preceding successful trap. | Candidate link between the trap's unlogged output and guest voucher `0xd03`. | Recover the trap output cell and subsequent default-voucher stores. The audit independently decodes all five packet headers and checks the unique printed creation trap. |
| A3. The pinned bridge source describes the historical binary at the checked boundaries. | Candidate local status-4 reply and zero host voucher field. | Identify the historical RAX executable/revision and recover the outgoing host header. The existing host annotation cannot verify its voucher bytes. |
| A4. The inspected table is installed and the default-voucher once path is reached. | Current source-level route from the XPC pipe through the voucher initializer. | Compare the effective callback root, thread-local voucher and once predicates from the same transaction. Original pointer-chain evidence establishes the available callback. |

High impact attaches to distinguishing the archive's host-port fallback from FairPlay host slot 17 and the separate unresolved slot 34, and to distinguishing guest voucher attachment from launchd receipt. Medium impact attaches to the likely source of the startup voucher and its reuse. The audit reads original cache ranges, the immutable RAX source revision and the archived packet bytes. It compiles nine SDK assertions and performs no target IPC. Time and working space are O(T + B + S) for trace bytes T, selected cache and symbol data B and retained source bytes S. The audited contracts cover the name, disposition, status and layout transitions above. The receipt preserves the unknown historical joins explicitly. [Audit script](triage_evidence/audit_archived_checkin_voucher.py)

```sh
python3 -B triage_evidence/audit_archived_checkin_voucher.py "$ANNOTATED_TRACE" "$RAX_SOURCE"
```
