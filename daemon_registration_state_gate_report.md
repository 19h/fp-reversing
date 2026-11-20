# fairplayd post-registration state gate

The successful registration continuation reaches an internal comparison of a process-local generation counter with zero. Under the replay's initial image words, it then attempts to acquire the same 32-bit state gate used by certificate and arena routines. A separate nonzero-counter replay reaches a 227-word update loop over the known generated-stream state. The recovered blocks establish two local control paths between registration and the next startup frontier. A connection to the archived FairPlayIOKit open remains unknown. [Registration continuation](daemon_registration_continuation_report.md) [Generated-stream state](daemon_generated_stream_report.md) [Certificate gate](daemon_record720_fields_report.md)

## Inherited startup state

The original arm64e image has SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` and UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Addresses below are unslid. F denotes the inherited SP at the successful registration continuation. The prior private replay ended at `0x10004e594`. Extending it with the same fixture faults at `0x10004e61c`, the first dereference of the missing X1 lookup pointer. The original startup supplies both words of the missing frame pair. [Registration ABI](daemon_registration_report.md) [Audit generator](triage_evidence/audit_daemon_registration_state_gate.py)

| Operation | Original address and value |
| --- | --- |
| Produce X26 | `0x100413e94..0x100413ea0` reads slot `0x1010a2fb8` with bias `-0x5918054b`, giving `0x100e99a00`. |
| Produce X23 | `0x100413eb4..0x100413ec0` reads slot `0x1010a4000` with bias `-0x62f83f4e`, giving `0x100f4e390`. |
| Preserve the pair | `0x1000a352c` stores X23 at F+0x100 B and X26 at F+0x108 B. |
| Reload the pair | `0x100097024` loads X23 from F+0x100 B and X1 from F+0x108 B. |
| Consume the pair | `0x10004e61c` reads the first bank through X1. `0x10004e624` reads the second through X23. Their composition returns `0xa1` for each of 256 input bytes. |

The fixture supplies the two saved words at its entry `0x100083778`. It inherits the earlier main-frame and registration import models. The original-image walk establishes the producer and consumer instructions. Continuous native execution from LC_MAIN and preservation across every intervening startup helper remain unknown.

## Comparison and local dispatch

The call at `0x10004e71c` passes R=FP−0x98 B in X0 to the 48 B comparison leaf `0x10041a5e0`, through original slot `0x10109fd20`, IA diversity `0xec9d`. The record decodes to mode 0, A=0 and B=zero-extended `u32[0x1010c8258]`. The load at `0x10004e648` supplies B. The record's mask is `0xfd69fa9d`, its true choice is `0xfd69ed95` and its false choice is `0xfd69eced` under the inherited startup phase. The helper writes their XOR selection at R+0x10 B. `0x10004e730` reads the result as a signed 32-bit table index and `0x10004e7ac` branches with IA diversity `0x5e5b`. [Comparison record codec](daemon_context_transfer_report.md)

| Generation counter B | Result | Original slot | Target and next observed operation |
| --- | --- | --- | --- |
| 0 | `0x1708` | `0x101045730` | `0x10002ed44`, shared state gate |
| Any nonzero u32 | `0x1670` | `0x101045270` | `0x1000bb970`, generated-stream table update |

The result rule follows from equality against zero and the fixed choices. Two different frame addresses produced the same decoded record and zero-branch result. The two nonzero samples were 1 and `0xffffffff`. The counter is in `__DATA,__common` with section type `S_ZEROFILL`. Zero is the loader's initial value. Its value after the original startup initializer and at native comparison time remains unknown.

### Shared state gate

`0x10002ed84` executes `CASAL W8,W13,[X9]` on `0x1010b5de0`, with expected `0x5d96` and replacement `0xa94ef`. The original file-backed word is `0x5d96`. Source compares the returned old word with `0x5d96` at `0x10002ed88` and branches at `0x10002eda0` using IA diversity `0x5e5b`.

| Old word | Memory effect | Resulting route |
| --- | --- | --- |
| `0x5d96` | Store `0xa94ef` | Slot `0x101097880` to `0x10008201c`, then branch `0x100082118` through slot `0x101043a68` to `0x10008a6a0`, IA `0xac8a`. |
| Any different u32 | Preserve the old word | Slot `0x101045730` back to `0x10002ed44`. The replay with old word `0xa94ef` stops at the next attempt. |

The audit uses a single-threaded instruction model for the CAS memory/result effect. The native memory ordering, scheduling, contention duration and release reached by this startup caller remain unknown. Prior evidence resolves plain restoration stores in other callers. [Shared gate writer evidence](daemon_seed_material_report.md)

### Nonzero-counter update

`0x1000bb9a8` dispatches through slot `0x101074848` to `0x100024c14`, IA `0x27ae`. Each iteration updates a u32 in place at `0x100024c44`. The original loop covers byte offsets `0x0..0x388` in increments of 4 B, for 227 words or 908 B beginning at `0x1010c784c`. The two nonzero cases verify each written value against the instruction-derived recurrence using the current word, the following word, the word 397 entries ahead, and the two-word frame table selected by the following word's low bit. This is the first 227-word segment of the independently recovered 624-word update. `0x100024c64` then uses slot `0x1010953e0` to reach `0x10000c2cc`, where the replay stops. Only the generation counter was changed to exercise this path. The table remained at its private initial state. [Full recurrence and state layout](daemon_generated_stream_report.md)

## Interface implications

Both recovered continuations consume process-local state. No new Mach message, port name, IOKit import or kext entry is present in the executed extension. The earlier five registrations are framework models. The archived wire trace independently records a type-zero open with return `0xe00002c2` in reply 2962. Linking either recovered continuation to that open still requires original caller attribution. [Archived open and releases](archived_iokit_open_retirement_report.md)

## Assumption register and checks

| ID | Dependent results | Probe or disconfirmation |
| --- | --- | --- |
| S1 | All addresses and original pointer interpretations | Verify the pinned image hash, decode nine chained words from the file and check 295 instructions in six extension ranges against original bytes. |
| S2 | Arrival at the comparison with the inherited startup phase | Remove the saved pair and reproduce the fault at `0x10004e61c`. Move the replay stack by `0x2000` B and decode the same record. To disconfirm native arrival, trace the real reaching frame from LC_MAIN. |
| S3 | Zero-counter route, state-gate acquisition and repeat | Override the counter with 1 and `0xffffffff`, and separately override the gate with `0xa94ef`. Recover the two alternate outcomes. Native initialization could change either word before the compared instruction. |
| S4 | Local branches and table stores in the offline replay | The framework calls return modeled results. Control transfers use decoded pointers with authentication bypassed in private memory. CAS uses a serialized instruction model. Native caller PCs, PAC behavior, an interleaving trace or a successful matching IOKit transaction would test these boundaries directly. |

| Impact | Remaining join |
| --- | --- |
| High | Follow `0x10008a6a0` to the next external API and correlate its original caller with the archived IOKit lookup and open. |
| Medium | Trace the startup writer of the generation counter and the release of the acquired state gate under the same frame. |
| Low | Compare the next nonzero-counter block at `0x10000c2cc` against the remaining 397 update words. |

The audit covers seven replay cases and checks all 256 inputs of each of four bank compositions. For I decoded instructions, V replay visits and B bank pairs, checking costs O(I + V + 256B) time, with O(I + V) retained evidence and fixed-size bank tables. No native IPC result is attributed to this comparison or gate. [Compressed audit](triage_evidence/daemon_registration_state_gate_audit.json.zst)
