# Installed selector 26 return to the IOKit stub

The selector 26 replay now crosses the final core register restore and logical `RETAB`. All 32 cases restore the original staging bytes and return one of two nonzero statuses. In the installed provider, the copy-back request precedes the status test. The copy count does not feed the handler result. The nominal continuation of either status reaches the existing MIG short-reply path. [Core cleanup and earlier endpoint](live_fairplay_selector26_core_return_report.md) [Installed transfer ABI](live_kext_selector26_transfer_report.md)

| Modeled allocation at `0xfffffe000a683228` | Cases | Fourth-body bytes read | Core X0 | Nominal kernel RetCode |
| --- | ---: | ---: | --- | --- |
| Null | 16 | 0 B | `0xffff5bd4` | `0xffff5bd4` |
| Fresh 16 B `FPTTLV` | 16 | 10 B | `0xffff5bde` | `0xffff5bde` |

## Core return

The audit reconstructs the previous nested and private-helper states from the archived input digests and matches the earlier receipts field by field. It uses the same sixteen fixtures and two allocation results per fixture. The data-free, typed-free and aligned-free calls are checked against their installed targets, modifiers, argument widths and modeled allocation extents. The first parse and the later cleanup both reach the same typed `FPTTLV` release site and descriptor. The audited dynamic result is the request to retire each object. The generic allocator bodies and allocator metadata updates are outside the replay. [Nested record audit](live_fairplay_selector26_nested_report.md) [Private helper audit](live_fairplay_selector26_helper_report.md)

The restoration loop checks each byte store in descending address order, then hashes the restored buffer. Each case restores 272 B or 288 B, totaling 8,960 checked byte stores. The status calculation uses one u32 XOR, `0xce515bb2 ^ 0x31ae0066 = 0xffff5bd4` or `0xce515bb8 ^ 0x31ae0066 = 0xffff5bde`. The final instruction at `0xfffffe000a6a7484` loads D11 and D10 from the first 16 B of the saved-register area and adds 128 B to SP. At `0xfffffe000a6a7488`, the replay verifies the saved logical link, entry SP, X19–X29 and the low 64-bit D8–D11 values against their entry values. It stops at the link instead of fetching another instruction. The link token is a fixture value. The installed caller independently identifies the real post-call instruction at `0xfffffe000a546490`.

One modeled 19 B allocation remains outside the observed release requests in each case. It is the first fallback reader output that feeds the pathname discriminator. Its replay address also serves as the logical return token. The two uses are distinct in the replay because the token is never fetched. The final owner and native lifetime of those bytes are unknown. [First reader output](live_fairplay_selector26_fallback_report.md) [Pathname discriminator](live_fairplay_selector26_consumer_report.md)

## Provider and reply projection

| Installed instruction | Effect on this path |
| --- | --- |
| `0xfffffe000a54648c` | Call `PRnut72j9` with the kernel staging pointer and extent. |
| `0xfffffe000a546490` | Save the returned X0 in X21. |
| `0xfffffe000a5464d4` | Invoke the task descriptor's `writeBytes` slot with offset 0 B, the staging pointer and the original extent. |
| `0xfffffe000a546510`, `0xfffffe000a546528` | Request staging descriptor `complete(0)` and `release()`. |
| `0xfffffe000a54654c`, `0xfffffe000a546564` | Request task descriptor `complete(0)` and `release()`. |
| `0xfffffe000a546568`, `0xfffffe000a546580` | Restore the status into X0 and return to the selector handler. |
| `0xfffffe000a545224`–`0xfffffe000a545260` | Fall through the nonzero W0 arm, call `IOLog`, skip the two output-descriptor stores and return the saved result. |
| `0xfffffe000be816e4`, `0xfffffe000be816e8` | Fall through the nonzero W0 arm and store the u32 RetCode at kernel reply offset 40 B. |

The source check covers the intervening instruction windows. The provider's two conditional branches in the saved-status interval check descriptor vtable authentication before dispatch. The first instruction that writes X0 after `writeBytes` supplies the staging descriptor to the following `complete` call. The path never reads the copy count for status selection. The low-32-bit word `0xffff5bd4` also occurs on provider setup failures, so observing it at the daemon would leave the originating layer ambiguous. [Provider setup and dispatch](live_kext_selector26_transfer_report.md)

With ordinary reply delivery, request 2865 yields a 36 B short reply 2965 addressed using the request's send-once reply right. Its user-format RetCode is at +32 B. Actual task copy-back counts, reply delivery and task-local numeric port names are unknown. The supplied trace ends after an unsuccessful open and contains no method request 2865. [Mach ports, emitters and message layouts](live_iokit_mach_transport_report.md) [Supplied trace](zut_trace_report.md)

## Verification

The [auditor](triage_evidence/audit_live_fairplay_selector26_return.py) accepts the installed boot collection and an output file. The [compressed receipt](triage_evidence/live_fairplay_selector26_return_audit.json.zst) retains per-case reads, releases, replayed instruction words and the source windows for the conditional handoff. The collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The offline byte restore takes O(N) time and O(1) program working storage for a buffer of N bytes. The auditor also retains O(V + N) evidence per case for V visited instructions and N staged bytes.

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_live_fairplay_selector26_return.py "$CURRENT_COLLECTION" "$RECEIPT"
```

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The pinned image and retained request, workspace and allocator fixtures describe the replay epoch. | The matrix of core results and byte counts. | Compare image identities, staging bytes and fourth-parser inputs in a matched ordinary transaction. |
| The selected allocator returns and releases complete with the normal ABI. | Cleanup, logical return and restored staging. | Check the requested object identities, extents and return state. |
| Pointer authentication succeeds and descriptor methods preserve callee-saved registers under the normal ABI. | The projected provider, handler and MIG status. | Correlate the core return, copy-back call, handler result and emitted reply in one ordinary observation. |

| Impact | Open evidence |
| --- | --- |
| High | Match native selector 26 copy-in, copy-back count and reply, including actual port names. |
| High | Recover the successful descriptor-publication conditions across the core and provider. |
| Medium | Establish the final owner of the 19 B reader allocation on the selected path. |
