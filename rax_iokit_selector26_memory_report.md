# FairPlayIOKit selector 26 memory across the RAX bridge

The pinned RAX bridge translates the explicit out-of-line buffer arguments of IOKit request 2865. In the recovered FairPlay selector 26 descriptor form, those arguments are zero and the address of the actual task buffer is embedded inside a 16 B inline structure. The bridge copies that structure without translating its embedded address. The kext uses the address with the task saved at open, which would be the emulator's host task on the candidate bridge path. This identifies a compatibility dependency on the address's host backing. The archived run ended at open, so it establishes no selector 26 request, host mapping, transfer or result. [Recovered daemon request](daemon_selector26_request_bytes_report.md) [Candidate owning task](archived_iokit_task_translation_report.md) [Audit receipt](triage_evidence/rax_iokit_selector26_memory_audit.json.zst)

## Two buffer representations in one method interface

In the ordinary zero-scalar synchronous request, the 24 B Mach header is followed by NDR at +24 B, selector at +32 B, scalar count at +36 B, inline structure count at +40 B and inline structure bytes at +44 B. After the inline structure, the generic MIG layout has two explicit out-of-line address/size pairs with two output-count words between them. All offsets below are from the packed user Mach header. The normal 16 B input and output take the installed framework's inline branches. [Apple MIG method signature](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/device/device.defs#L614-L627) [Installed wrapper and message emission](live_iokit_mach_transport_report.md)

| Field | Offset in the 100 B request | Role in the pinned RAX source |
| --- | --- | --- |
| Embedded task address and extent | +44..51 B, +52..55 B | First 12 bytes of FairPlay's 16 B inline structure. Copied with the message body. |
| Explicit MIG input address and size | +60..67 B, +68..75 B | Zero in the selected inline call. For a populated pair, the bridge reads guest bytes into a temporary host buffer and substitutes its address. |
| Inline and scalar output counts | +76..79 B, +80..83 B | 16 B inline capacity and zero scalars on this route. |
| Explicit MIG output address and size | +84..91 B, +92..99 B | Zero in the selected inline call. A populated pair supplies a temporary host output buffer and a guest copy-back target. |

The bridge's `method_fields` walks past the variable scalar and inline input arrays, rounding each to a four-byte boundary. For 16 B inline input, the first explicit address starts at `44 + align4(16) = 60 B`. The second is `60 + 16 + 8 = 84 B`, and the request ends at `84 + 16 = 100 B`. The older four fixture results provide a cross-check. [RAX offset walk and buffer fixups](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/kernel.rs#L72-L145) [Daemon fixture receipt](triage_evidence/daemon_selector26_request_bytes_audit.json.zst)

| Modeled daemon class and aggregate | Inline input | Explicit input/output address offsets | Request size | Installed fixed input count |
| --- | ---: | ---: | ---: | --- |
| `0x98`, 272 B | 272 B | +316 B / +340 B | 356 B | Fails 16 B comparison |
| `0x98`, 288 B | 288 B | +332 B / +356 B | 372 B | Fails 16 B comparison |
| `0x99`, 272 B | 16 B | +60 B / +84 B | 100 B | Meets 16 B comparison |
| `0x99`, 288 B | 16 B | +60 B / +84 B | 100 B | Meets 16 B comparison |

The source classifies 2865 as a call that names memory. With a valid connection proxy and a send-once reply, the kernel-object call goes through the generic preparation and combined host send/receive. Preparation processes only the two explicit address/size pairs and skips a pair when its address or size is zero. The selected descriptor form has neither a guest input read nor an output-buffer registration in that preparation. The corresponding `finish` returns when no output target was registered. [Bridge dispatch](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L240-L259) [Bridge call and fixup order](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L399-L437) [RAX reply fixup](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/kernel.rs#L148-L176)

## Address-space custody through the method

```text
descriptor-form 2865 -> inline guest address A and extent N
  -> RAX copies inline bytes, explicit address/size pairs are zero
  -> host FairPlay uses A and N in the task retained by open
  -> task-map descriptor -> staging read -> core -> task-map copy-back
  -> 2965 inline output echoes A and N if method succeeds
  -> RAX returns inline bytes, with no registered explicit output buffer
```

The current framework emits request 2865 at `0x184ebe090`. The nominal FairPlay handler reads the address and extent at `0xfffffe000a5451e8` and `0xfffffe000a5451ec`, and reads the saved task at client +224 B at `0xfffffe000a5451f0`. This task is supplied separately from the message data. Provider `uej58Beal` requests the descriptor at `0xfffffe000a546364`. On the ordinary prepared path the descriptor uses that task's VM map at `0xfffffe000c585320`. The provider reads the task range at `0xfffffe000a54647c`, calls the core at `0xfffffe000a54648c` and requests copy-back at `0xfffffe000a5464d4`. These are preferred unslid addresses from the retained installed collection. [Task-to-map provenance](live_iokit_selector26_task_provenance_report.md) [Provider read, core call and copy-back](live_kext_selector26_transfer_report.md)

Task export also arms the candidate RAX memory mirror. Its pre-send path reserves free host address ranges corresponding to guest mappings. The reservation passes a null memory object and zero current and maximum protections. It skips ranges already occupied in the host. The post-receive hook may share a new eligible host region into a free guest range. For the daemon fixtures, the corresponding host backing at the preexisting guest aggregate's address remains unknown. Byte equivalence depends on whether the guest and host task ranges at that address share backing or otherwise stay in sync. [Mirror reservation and adoption](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/mirror.rs#L55-L108) [Host reservation arguments](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/host.rs#L580-L601)

On method success the kext writes the address and extent to the inline output at `0xfffffe000a545240` and `0xfffffe000a545248`. With zero output scalars, the 16 B structure occupies user reply 2965 at +40..55 B inside the 68 B message. The installed framework copies this structure at `0x184ebe200` and stores its extent at `0x184ebe204`. The nested data itself follows the provider's task-memory transfer. The returned address and size therefore cannot establish that the guest aggregate received the host writes. The daemon replay's equal-address and equal-size result copies the existing guest buffer back to itself, so that replay does not supply the missing transfer either. [Inline reply backing and framework copy](live_iokit_selector26_inline_reply_report.md) [Daemon return and buffer ownership](daemon_selector26_pidpath_returns_report.md)

## Assumptions and evidence gaps

| ID | Premise and dependent result | Falsification probe | Impact |
| --- | --- | --- | --- |
| M1 | A valid connection follows the archived candidate bridge's task export, with the nominal class-`0x99` descriptor selected. | Correlate a successful ordinary open, the resulting connection, the method's inline versus out-of-line arguments and the task retained by the receiving client. | High for applying the bridge projection. |
| M2 | The historical transport uses the pinned RAX dispatch, framework ABI and ordinary FairPlay method path. | Compare producer and binary identities and the packed request's inline bytes and explicit argument pairs at both boundaries. | High for attribution of the embedded address. |
| M3 | The guest aggregate has ordinary guest-owned backing. Byte equivalence depends on whether the corresponding host task range names those same bytes. | Compare initial bytes and mapping identity from passive observations of both sides of one ordinary call. | High for input and copy-back equivalence. |
| M4 | The method reaches its normal transfer and inline success reply. | Correlate VM preparation, staging bytes, provider return and reply with the same transaction. | Medium for final status and inline publication. |

The offline verifier reuses six digest-pinned receipts, checks four daemon fixtures and twelve retained handler/provider/framework words, verifies the VM call target, and checks 52 RAX source anchors and seven Apple MIG anchors. It also decodes the archive's failed open and checks the absence of method 2865. Verification takes O(N) time and space for N input bytes. The report establishes a source-level compatibility limit on the selected bridge path. A native or emulated successful exchange and its backing identity remain unknown. [Audit generator](triage_evidence/audit_rax_iokit_selector26_memory.py) [Compressed receipt](triage_evidence/rax_iokit_selector26_memory_audit.json.zst)

```sh
python3 -B triage_evidence/audit_rax_iokit_selector26_memory.py \
  "$RAX_TRACE" "$RAX_CHECKOUT" "$XNU_CHECKOUT"
```
