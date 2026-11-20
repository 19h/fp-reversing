# Observed fairplayd caller sites for FairPlayIOKit discovery and open

A fresh run of the archived arm64e `fairplayd` under `rax-user` joins the FairPlayIOKit discovery and open packets to specific daemon call sites. The daemon calls `IOServiceOpen` at `0x100478bb0`. Request 2862 succeeds at the Mach transport layer. Reply 2962 carries application result `0xe00002c2` (`kIOReturnBadArgument`) and a null connection. The daemon then releases the service at `0x100478c2c` and the iterator at `0x100483cc0`. The capture associates these packets with the discovery path recovered alongside the selector 22/23 query code. Neither query ran in the captured sequence. The archived run's caller and the host's exact provider error branch remain unknown. [Capture audit](triage_evidence/daemon_iokit_callsite_capture_audit.json.zst) [Original object and query path](daemon_iokit_objects_report.md) [Current kernel and application status channels](live_fairplay_iokit_open_report.md)

## Call sites and Mach emission

Return addresses came from stack frames on the same guest thread as the syscall results. For each request, the audit ties the trap arguments to the request ID, destination, reply name and descriptor count. Each daemon return address is 4 B past an original `BLRAA X8, X17` instruction. The preceding instruction supplies the discriminator shown for the associated original IOKit import. The framework and libsystem_kernel emission sites below are 4 B before the corresponding shared-region return addresses and match the independently inspected cache. [Current discovery transport](live_iokit_discovery_report.md) [Current open transport](live_iokit_mach_transport_report.md)

| Operation | Request / reply | Daemon return address | Daemon call PC | Original IOKit bind and discriminator | Transport call PC |
| --- | --- | --- | --- | --- | --- | --- |
| Obtain main port | 205 / 305 | `0x100461cc8` | `0x100461cc4` | `IOMainPort`, `0x1010a0988`, `0x6240` | `0x18056b448` |
| Probe server version | 2877 / 2977 | `0x100461cc8` | `0x100461cc4` | Same `IOMainPort` call through the IOKit once block | `0x184ebc3cc` |
| Match FairPlayIOKit | 2881 / 2981 | `0x1003f9598` | `0x1003f9594` | `IOServiceGetMatchingServices`, `0x1010a0d88`, `0xa027` | `0x184ebd3dc` |
| Get next service | 2802 / 2902 | `0x10036c4a8` | `0x10036c4a4` | `IOIteratorNext`, `0x1010a0e38`, `0xd62a` | `0x184ebd59c` |
| Open service, type 0 | 2862 / 2962 | `0x100478bb4` | `0x100478bb0` | `IOServiceOpen`, `0x1010a0b48`, `0xe82b` | `0x184ebdc6c` |
| Release service | Deallocation trap | `0x100478c30` | `0x100478c2c` | `IOObjectRelease`, `0x1010a0240`, `0xbe7e` | Trap instruction `0x180548acc` |
| Release iterator | Deallocation trap | `0x100483cc4` | `0x100483cc0` | `IOObjectRelease`, `0x1010a0240`, `0xbe7e` | Trap instruction `0x180548acc` |

All five request traps report guest PC `0x180548c20` and return zero. The shared transport calls its trap veneer at `0x18055b960`, and the trap instruction is at `0x180548c1c`. The matching, iteration, open and release call PCs differ from the five static selector-26 candidates. The new frames identify the path taken in this run. Six discovery and open packets in the two logs are byte-identical after clearing the namespace-dependent header names and the iterator or service names in replies 2981 and 2902. That equality leaves the archived daemon branch undetermined. [Selector-26 call sites](daemon_selector26_open_report.md) [Selector-26 release sites](daemon_selector26_class_retry_report.md) [Archived exchange and retirement](archived_iokit_open_retirement_report.md)

The outer daemon frames are shared across the five requests and both final releases. Their return addresses are `0x1004c9200`, `0x1005599a4`, and `0x1002089cc`, from inner to outer. The original words at each address minus 4 B are authenticated link branches. Their intermediate data contracts remain unknown. The `IOMainPort` call provides a source-level producer for the matching port cell, which was a fixture in the earlier object-flow analysis. At `0x100461cb8`, X1 receives SP+0x7c as the output address, and the matching block reads the 32-bit name at the corresponding SP+0x7c. The live name is visible in reply 305 and subsequent request headers. The capture contains no direct snapshot of the daemon's stack cell. [Original object-flow premises and widths](daemon_iokit_objects_report.md)

## Rights, packet data and lifetime

Guest and host names occupy separate IPC spaces. The outgoing message header uses `COPY_SEND` for the destination and `MAKE_SEND_ONCE` for the reply. Received right descriptors are `PORT_SEND` (17). All five replies arrive at guest receive name `0x507`.

| Guest request / reply lines | Request width / reply width | Destination role | Guest destination | Host bridge destination | Reply payload |
| --- | --- | --- | --- | --- | --- |
| 16234 / 16238 | 24 B / 40 B | Guest host right | `0xc03` | Guest-side host-object dispatch | IOKit main port `0x1f03` |
| 16253 / 16258 | 24 B / 44 B | IOKit main port | `0x1f03` | `0x2103` | Routine status 0, version `0x134647a` |
| 16285 / 16295 | 100 B / 40 B | IOKit main port | `0x1f03` | `0x2103` | Iterator `0x2003` |
| 16310 / 16315 | 24 B / 40 B | Iterator | `0x2003` | `0x2803` | Service `0x2103` |
| 16330 / 16340 | 80 B / 52 B | Matched service | `0x2103` | `0x2703` | Null connection and application result `0xe00002c2` |

The four forwarded replies arrive at bridge receive name `0x2903`. The matching request contains `IOProviderClass=com_apple_driver_FairPlayIOKit`. Request 2862 carries a separate guest task name `0x203` with `COPY_SEND` at +28 B, a zero-address and zero-length properties descriptor at +40 B and type 0 at +64 B. The equivalent task name in the bridge's host message remains unknown. Reply 2962 contains a port descriptor with name zero at +28 B and the application status at +48 B. The framework's complex-reply path selects that application result as the API return value. The post-call W0 value and the specific provider check responsible for the result remain unrecorded. [Framework reply selection](live_iokit_open_reply_copyout_report.md) [Owning-task translation boundary](archived_iokit_task_translation_report.md)

```text
daemon guest                host bridge
service  0x2103 released -> ID 65 on 0x1c03
iterator 0x2003 released -> ID 65 on 0x1c03
guest exit(0)             -> runner status 0
```

The arrows show log order. Both deallocation traps return zero. The host log records ID 65, 36 B and zero descriptors after each release, at lines 16364 and 16373. A third such receive occurs earlier at line 14228. The ID 65 payloads and the bridge's receive-map entries were unlogged. Among 36 printed guest sends and 34 received messages, there are zero method requests 2865, close requests 2816, corresponding replies or guest ID 65 receives. The emulator logs the exit syscall's argument as zero and reports runner status zero. [Notification emission and limits](archived_iokit_open_retirement_report.md)

## Capture conditions and repeatability

Both runs used the same unmodified daemon image, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`, and the installed `rax-user 0.1.0` on macOS 27.3 build `26C5035r`. The runner flags were `--clear-env --strace --strace-pc --strace-stack=64 --strace-mach-msg=128`. File writes were restricted to each run's own capture directory and writes to the null device. Network egress was denied. The first run inherited the runner's host `TMPDIR`. The second set it to its capture directory while preserving the same confinement rules. The guest environment was cleared in both runs.

| Capture | Startup memory-entry exchange 4817 / 4917 | Endpoint |
| --- | --- | --- |
| Initial, 14,196 lines | A 68 B request specifies 262,144 B and permission `0x00400001` (`MAP_MEM_VM_SHARE | VM_PROT_READ`). The 36 B reply has routine status 6, `KERN_RESOURCE_SHORTAGE`. Mach transport returns zero. | Breakpoint at `0x1855d07f0`, runner status 133. No FairPlayIOKit discovery or open observed. |
| Retry, 16,380 lines | Same size and permission. The 56 B reply returns send right `0x1403` and size 262,144 B. Mach transport returns zero. | Discovery, failed open, releases and runner status zero. |

At inspected RAX revision `47f211fcb131720b0d8bb65e2aa3288371c1274a`, `src/user/darwin/syscall/mach/entry.rs` can create and populate anonymous backing for this share request. `src/user/mm/shared.rs` creates the backing file under the host temporary directory. The observed change is consistent with that path encountering the initial write rule. The initial host file-operation result and the installed runner's exact source revision remain unknown.

The original image and archived input supplied sufficient evidence for the audit. The raw live logs remain local. The published receipt retains selected packet bytes, line numbers, numeric frames and input digests. The auditor runs offline in O(T + B + F) time and space, for total trace bytes T, image bytes B and emitted fixup text F. It uses the macOS toolchain's disassembler and chained-fixup decoder.

```sh
python3 -B triage_evidence/audit_daemon_iokit_callsite_capture.py \
  "$INITIAL_LOG" "$RETRY_LOG" "$ARCHIVED_LOG" "$DAEMON_IMAGE" "$RAX_USER"
```

## Assumption register and bounded follow-up

| ID | Premise and dependent finding | Falsification probe | Impact |
| --- | --- | --- | --- |
| C1 | The emulator frame walk preserves the daemon's saved instruction return addresses and preferred image locations. This supports call-site and shared caller attribution. | Compare executable-region mapping and saved X30 values from the same stock emulated path. The audit already matches the capture's image labels to five distinct original IOKit call words, one main-port call word and their authenticated bindings. | High |
| C2 | Startup memory-entry failure was caused by anonymous backing outside the permitted directory. This explains the effect of the retry configuration. | Record the runner's backing-file open/write result and event order under the same profile, or observe success with the original temp setting. | Medium |
| C3 | The archive could have used the same discovery path. Wire equality also permits another caller using the same framework API. | Recover archived caller frames or a contemporaneous instruction trace for the recorded build and process. | High |
| C4 | The current collected provider path explains the complex reply, but its specific failure gate is undetermined. | Correlate authorized passive open diagnostics with the existing provider result and initializer boundaries on the same build. | High |

The highest-value remaining observation is a stock open that yields a connection, tied to its actual caller, the first method ID and selector, and the final right release. A passive capture would also distinguish the selectors 22/23 query continuation from the separate selector-26 path. The current experiment supplies two run conditions, ten decoded IOKit messages, six normalized byte comparisons, five independently matched framework emission frames, six original IOKit call instructions and three outer link branches. Provenance, packet extents, return-address arithmetic, scope and the unresolved results above were checked against the receipt. The broader interface objective remains active.
