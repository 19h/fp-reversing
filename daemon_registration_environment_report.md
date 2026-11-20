# fairplayd post-registration entropy, time and state

On the zero-counter continuation after service registration, `fairplayd` restores its local state gate and calls `arc4random`. It fills a 624-word state array, then builds a private record from a clock read and two further random returns. The nonzero-counter continuation instead refills that same array and reaches a separate cached-table read. Both paths are established under explicit offline startup premises. The archived run still supplies no daemon caller address linking either path to FairPlayIOKit. [Post-registration state gate](daemon_registration_state_gate_report.md) [Archived IOKit exchange](archived_iokit_open_retirement_report.md)

## External calls on the zero-counter path

All addresses are unslid in the arm64e image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Let F be SP on this continuation, G the 624-word array at `0x1010c784c`, and Q=F+0x2a0 B. The source at `0x10008a6c8` stores `0x5d96` back to the same `0x1010b5de0` cell acquired by the earlier CAS. The first imported call follows at `0x10008a710`. A replay checks the restored word at all three random call boundaries. [Original bytes, fixups and replay](triage_evidence/daemon_registration_environment_audit.json.zst)

| Unslid call site | Original slot and IA diversity | Argument or return use |
| --- | --- | --- |
| `0x10008a710` | `0x1010a0050`, `0x2692`, `arc4random` | Zero-argument call. `0x10008a718` stores W0 as G[0]. |
| `0x10008c64c` | `0x10109ff20`, `0x9298`, `gettimeofday` | X0=Q+0x10 B, X1=0. The caller reads the low 32 bits of seconds and the 32-bit microseconds field, and writes their encoded values at Q+8 and Q+4 B. |
| `0x10008c6d0` | `0x1010a0050`, `0x2692`, `arc4random` | W0 supplies Q+12 B at `0x10008c6ec`. |
| `0x10008c738` | `0x1010a0050`, `0x2692`, `arc4random` | W0 supplies Q+0 B at `0x10008c758`. |

The four original bank compositions converge on their respective import slots for all 256 input bytes. The clock ABI uses a 16 B `timeval` with seconds at +0 B and microseconds at +8 B. The source loads the fields after return and discards the integer status in this interval. The status-only replay supplies the same fields with return −1 and produces the same material and next read. It makes no claim about field values left by a native failed call. [SDK layout and parallel clock caller](daemon_clock_record_report.md)

`0x1000b20c8` writes G[i] for i=1 through 623. Taking every operation modulo 2^32, the source rule is `G[i] = 0x6c078965 * (G[i-1] XOR (G[i-1] >> 30)) + i`. The array occupies 624 × 4 B = 2,496 B. `0x1000b20f0` exits the loop through slot `0x101079bf8` to `0x10008c5d8`, IA diversity `0x4c69`. The next block writes 624 at F+0x244 B. The replay checks the entire seeded array before injecting time or the later random values. The loop implements the same seed recurrence as a separately recovered caller. [Previously recovered seed recurrence](daemon_entropy_return_report.md)

At `0x10008c7a4` the four u32 words at Q, in ascending order, are `[random3, microseconds, low32(seconds), random2]` XOR `0x0d875374` word by word. The proof checks the second random path with the startup phase `0x830954`, which gives the same mask as the other three words. This is a local encoding. The clock record in the separate caller has the same field order and uses raw words. No native clock or entropy result, ownership or wire representation is inferred here.

### First pending read after seeding

The path passes the original comparison-helper calls `0x1001cf510 → 0x100444d6c` and `0x1000b78bc → 0x100427514`. It reaches `0x10010dac8` through slot `0x101085f20`, IA diversity `0xa1b5`. All three seed/clock fixtures stop before the 4 B read at `0x10010daf8`, with X11=4. The original instruction at `0x100082020` sets X26 to zero. `0x10008a6a0` saves it at F+0x130 B. The later code adds a 4 B index offset to that saved base before the pending read. The audit preserves the source zero and supplies no memory there. A separate clock caller also computes a low-address demand from a saved zero. The native predicate and its intended optional-input contract remain unknown. [Comparison leaf ABIs](daemon_prng_output_report.md) [Independent clock caller](daemon_clock_record_report.md)

## Nonzero-counter continuation

Two private fixtures start with a generated 624-word array and counters 1 and 7. The original continuation performs a complete in-place refill, which matches the shared twist equation for both arrays. Its phase lengths are 227 + 396 + 1 = 624 words. No time or random import is reached on either retained path. [In-place reference equation](daemon_postseed_output_report.md)

| Operation | Original location and result |
| --- | --- |
| First phase | `0x100024c44` updates G[0..226]. |
| Second phase | `0x10003c988` updates G[227..622], using already updated words in the first part of G. |
| Final word | `0x100080d4c` updates G[623], with the next-word component from the updated G[0]. |
| Extraction | `0x1000a045c` reads G[0] in these fixtures. `0x1000a0464` publishes extraction index 1 at `0x1010c67dc`. |
| Generation | `0x100037f24` publishes the counter increment at `0x1010c8258`: 1 to 2 and 7 to 8. |
| Next read | `0x10002fddc` requests a u32 at `u64(base + (u32(mask) & 0x6f2523cc))`. It reads mask from `0x1010c67d4` and base from `0x1010c8268`. Both cells remain zero in the fixture. The audit stops before the read at address 0. |

The latter two addresses match the cached-table cells in the earlier buffer-publication report. That report proves a 512 B buffer publication and a mask of 255 under its own caller conditions. A same-process startup join to those stores remains unknown. The refill cases varied the array and counter and left the cache cells at their existing values. [Cached-table producer](daemon_buffer_consumer_report.md)

## Archived trace and assumptions

| Observation | Archived line |
| --- | --- |
| Only logged `getentropy` trap | 1185 |
| Last of 29 logged `gettimeofday` traps | 1485 |
| Final observed bootstrap receive-right delivery | 1668 |
| Its port-set insertion | 1675 |
| IOKit main-port request 205 | 1677 |
| Open reply 2962 | 1736 |

The archived trace has no logged clock trap after the final receive-right delivery. Its syscall PCs provide no return address from `gettimeofday` or `arc4random` into the daemon. The record order alone cannot determine whether the reconstructed zero-counter caller executed or whether a library call produced a traced syscall. No Mach or IOKit emission was reached in either replay extension. [Annotated trace evidence](zut_trace_report.md)

| Assumption | Dependent result and stress test |
| --- | --- |
| E1. The pinned original image and trace identify the specimens. | Verify the trace hash, original bytes at two pending reads and 715 decoded extension instructions, 17 chained words and 1,024 input-byte cases. Compare runtime image UUID and caller PCs for a native attribution. |
| E2. The inherited startup frame and serialized gate model apply. | Three seed/clock cases reach the same pending instruction at two stack placements. Disconfirm the replay's native relevance by following the original upstream roots and recording the generation word and actual branch. |
| E3. Imported outputs are declared independently of native libraries. | Change the seed and the later random values, use seconds above the u32 range, and vary clock status without changing its fields. The audit preserves the undefined native values and models no host entropy, clock or IPC. |
| E4. The nonzero cases begin with independent array fixtures and the existing zero cache cells. | Check two differently seeded arrays against the 624-word recurrence, confirm the stored counters, and check that the pending addresses are unmapped. A trace of the original cache publication before this reader would discriminate live cases. |

The high-impact next join is between the archived IOKit exchange and an original daemon caller. Medium-impact continuations are the reaching conditions for the zero saved base and the earlier publication of the cache cells. The audit uses O(V + N + 256B) time and O(V + N) storage, where V is executed source instruction visits, N is trace size in bytes plus array words compared, and B is the number of bank pairs. [Audit generator](triage_evidence/audit_daemon_registration_environment.py)
