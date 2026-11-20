# fairplayd control flow after Mach service registration

The original arm64e daemon takes two observed continuations after it compares the last service registration result. The success continuation reaches a new startup predecessor at `0x10004e594`. The failure continuation tests and releases a previously registered CF object, then reaches `0x1000856ac`. These results come from replay of the daemon image with explicit framework return models. They locate new points for attribution between service registration and IOKit discovery or process exit. [Registration result and caller](daemon_registration_report.md)

| Last service check-in | Main gate at `0x100083974` | Subsequent transfers in the replay |
| --- | --- | --- |
| Success, with all services successful or an earlier modeled failure | Slot `0x101090830`, IA `0x1858`, to `0x10009697c` | `0x10009702c` uses slot `0x1010829c0`, IA `0xb66f`, to `0x1000b73f0`. The branch at `0x1000b74a4` uses slot `0x101060500`, IA `0xf2b9`, to `0x10004e594`. |
| Failure, with the first four services successful | Slot `0x101083118`, IA `0x1858`, to `0x100027310` | `0x10002732c` reads the stored object at registration header +40 B. With that object present, the branch at `0x10002735c` uses slot `0x101067290`, IA `0xbcef`, to `0x1000a7738`. The call at `0x1000a7794` releases the object through slot `0x1010a02e0`, IA `0x1883`, bound to `CoreFoundation/_CFRelease`. The branch at `0x1000a77a4` next reaches `0x1000856ac`. |

Header +40 B is the stored `com.apple.fpsd` CF object. The modeled last check-in failure is for `com.apple.fpsd.sim`. At the release call, X0 held the exact 64-bit reference from the earlier successful `com.apple.fpsd` registration. This is a CF reference release. Native invalidation, Mach receive-right retirement and release of other named objects require additional evidence.

The annotated RAX trace shows five receive-right deliveries, followed by the type-0 IOKit open failure and two discovery-object releases before exit. It supplies no daemon stack attribution for that tail. The modeled failure above is a service registration failure. A continuous path from the traced successful registrations through `0x10004e594` to the IOKit open or exit remains unknown. [Archived wire and port mapping](zut_trace_report.md) [Open and discovery-object retirement](archived_iokit_open_retirement_report.md)

## Assumption register

| ID | Premise and dependent conclusion | Falsification probe |
| --- | --- | --- |
| R1 | The pinned daemon arm64e image and chained fixups govern the named offsets and bindings. | Verify SHA-256, repeat the original-byte checks and compare the original fixup metadata for each slot. |
| R2 | The inherited private startup frame and modeled framework results hold for the replay. The paths and released reference depend on these inputs. | Compare the same reaching frame at the main status gate and correlate its header slot and later CF call with an ordinary matched execution. |
| R3 | The capture covers the historical interval and was produced with the stated trace options. | Rehash the capture and obtain matching user-space caller addresses or return addresses in a separate observation. |

High impact for locating the next startup predecessor after accepted service registration. Medium impact for identifying cleanup of an earlier service's CF object following a later failed check-in. Exact native caller attribution and the complete device-open path remain open.

## Reproduction

The input is the archived arm64e daemon slice, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The audit extends the existing registration replay, compares executed instruction bytes with the original image, and verifies selected targets and a CoreFoundation import against the original fixup catalog. The extension records a bounded number of instructions and branches per case. For B bytes of original image and N recorded source visits, storage is O(B + N) and verification is O(B + N) outside the emulator. [Replay](triage_evidence/audit_daemon_registration_continuation.py) [Compressed receipt](triage_evidence/daemon_registration_continuation_audit.json.zst)

    python3 -B triage_evidence/audit_daemon_registration_continuation.py
