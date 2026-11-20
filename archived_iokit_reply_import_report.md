# Archived FairPlayIOKit reply import and sender metadata

The archived open reply reaches `fairplayd` on guest receive name `0x507` after the bridge records the same reply ID, 2962, on host receive name `0x1603`. The pinned RAX source preserves the 52 B reply's inline status and maps its ordinary port descriptor into the guest IPC space. On that source path the observed zero guest connection implies a null host connection descriptor. The raw historical host packet and exact producer build remain unknown. [Port custody and open retirement](archived_iokit_open_retirement_report.md) [Reply audit receipt](triage_evidence/archived_iokit_reply_import_audit.json.zst)

## Observed replies

| Exchange | Host receive log | Guest receive | Message bytes + trailer bytes | Guest descriptor or inline result |
| --- | --- | --- | --- | --- |
| 205 / 305, get IOKit main | Guest MIG handler at line 1680 | 1681, `0x507` | 40 B + 8 B | Main send name `0x1703` |
| 2877 / 2977, server version | 1691, `0x1603` | 1692, `0x507` | 44 B + 8 B | No descriptor. Routine result zero, version `0x134647a`. |
| 2881 / 2981, match class | 1708, `0x1603` | 1709, `0x507` | 40 B + 8 B | Iterator send name `0x1803` |
| 2802 / 2902, iterator next | 1719, `0x1603` | 1720, `0x507` | 40 B + 8 B | Service send name `0x1903` |
| 2862 / 2962, open | 1735, `0x1603` | 1736, `0x507` | 52 B + 8 B | Null connection, application status `0xe00002c2` |

Each guest trap reports options `0x200000003` and result zero. Its receive capacity equals the exact message plus trailer extent printed above. The receive headers put the consumed send-once disposition 18 in the local bits. Remote and voucher names are zero. Every logged guest trailer is `00 00 00 00 08 00 00 00` and every guest receive has the text `from the kernel`. The trailer bytes encode format 0 and size 8 B. They carry no security or audit token words. [Archived transport](zut_trace_report.md) [Guest header and trailer bytes](triage_evidence/archived_iokit_reply_import_audit.json.zst)

## Host receive and guest delivery

```text
guest reply receive right 0x507
  -> export a host MPO_REPLY_PORT (observed reply name 0x1603)
  -> outbound IOKit call makes a host send-once reply right
  -> host mach_msg2 receives reply on 0x1603 with audit trailer requested
  -> bridge looks up Import::Port and enqueues for guest 0x507
  -> guest copyout remaps rights and materializes the requested 8 B trailer
```

The candidate bridge's `reply_export` keeps a dedicated host reply receive right per exported guest port and records it as `Import::Port`. It creates that reply right with `mach_port_construct` and `MPO_REPLY_PORT` flag `0x1000`. IOKit calls in kernel-object class `0x200000000` with `MAKE_SEND_ONCE` select combined host send and receive on that export. With no send timeout, combining the kernel-object call class, audit element selection `3 << 24` and low option bits `1 | 2 | 4` gives `0x203000007`. The receive buffer is at least 65,536 B. The candidate imports a successful reply from that buffer. Its separate host port-set pump also requests an audit trailer. [Reply export](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/mod.rs#L286-L299) [Host reply port constructor](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/host.rs#L262-L272) [Apple reply port type](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/port.h#L503-L522) [Combined host call](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L381-L437)

For the selected host import, the body copy begins at +24 B. The 52 B packet consists of a 24 B header, 4 B descriptor count, 12 B ordinary port descriptor, 8 B NDR record and 4 B application result. `to_guest` reads the descriptor name at +28 B and disposition at +38 B. A null host name becomes `None` and copies out as guest name zero. A nonzero host name becomes a right, including the explicit dead-right case. On this ordinary descriptor path, a dead or failed guest right insertion yields `MACH_PORT_DEAD`; a successful insertion yields a nonzero guest IPC name. The observed null therefore supports a null host descriptor under the matched bridge and ordinary reply premises. The separate destination copyout consumes the guest send-once right. [Host descriptor import](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L628-L739) [Guest port copyout](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/syscall/mach/kmsg.rs#L873-L952) [Ordinary descriptor rewrite](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/syscall/mach/kmsg.rs#L995-L1005)

Request 2862 lies outside both the bridge's local refusal set and its IOKit memory-fixup set. In the ordinary import and copyout path the single port item rewrites descriptor bytes through +38 B, and the inline status at +48 B is serialized from the copied host body. Under the same premises, the guest's `0xe00002c2` came from the host reply's application field. That narrows the source of the value while leaving the historical kernel branch that produced it unknown. [Routine selection](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/kernel.rs#L16-L53) [Open result channels](live_fairplay_iokit_open_report.md)

## Sender label and trailer scope

The host audit-trailer layout is 52 B. Its type, length and sequence fields total 12 B, followed by an 8 B security token and a 32 B audit token. The bridge computes the trailer base as the four-byte-aligned packet length. Given the full trailer buffer it reads the security and audit words into the message's internal `Sender`. A separately audited Apple XNU reference initializes kernel-object replies with its kernel security token `[0, 1]` and eight zero audit words. Those values equal the candidate guest `Sender::KERNEL` constant. [Apple audit trailer structure](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/message.h#L759-L765) [Apple kernel reply trailer initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_kmsg.c#L5227-L5246) [RAX host sender import](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L772-L798)

Guest receive options select trailer element value zero, so the guest builds only the 8 B minimum trailer. The dumper prints `from the kernel` when the internal sender equals the kernel constant. The locally assembled 305 reply is a control case for this distinction. The guest host handler obtains a proxy for the genuine IOKit main port, then its reply builder supplies the kernel sender constant to the guest envelope. The four subsequent host bridge logs independently corroborate forwarding for their associated replies. The printed guest label alone identifies internal classification, and the raw host audit words and the identity of any FairPlay initializer call remain unknown. [Guest trailer construction](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/mach/msg.rs#L119-L153) [Guest dump classification](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/syscall/mach/dump.rs#L48-L77) [Guest IOKit main handler](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/mig/host.rs#L80-L95) [Guest MIG reply builder](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/mig/mod.rs#L352-L363)

## Assumptions and verification

| ID | Premise and dependent inference | Falsification probe | Impact |
| --- | --- | --- | --- |
| R1 | The corresponding host and guest records took the pinned RAX ordinary import and copyout path. This supplies the null descriptor and inline status inference. | Match the historical producer and compare the raw paired host and guest reply packets at +28 B and +48 B. | High for attributing the failed connection and application status. |
| R2 | The sender metadata came from a complete host audit trailer on the selected host path. | Inspect the archived producer's host receive options and capture the advertised trailer size and token words before translation. | Medium for attributing sender metadata. |
| R3 | The historical kernel used the inspected routine and application status split. | Match the historical build or correlate the task comparison, provider return and reply publication in one original transaction. | High for identifying the failure layer. |

The offline verifier decodes five guest replies, checks their paired trap options and four host receive records, checks 74 anchors across ten RAX files, enumerates the two routine sets from an eleventh file, and checks 11 anchors across three Apple sources. Verification is O(N) in time and space for N input bytes. The audit records only the observed guest message bytes and corresponding host log lines, with the host receive configuration marked as a candidate projection. [Audit generator](triage_evidence/audit_archived_iokit_reply_import.py) [Compressed receipt](triage_evidence/archived_iokit_reply_import_audit.json.zst)
