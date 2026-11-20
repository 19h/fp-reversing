# Saved continuation and discovery comparison flag

The pinned fairplayd image contains a table load at `0x10085d848` that supplies `0x1005000d4` to the frame cell S+0xc28 B for the examined reaching state. The unequal continuation at `0x1006f6464` reloads that cell and transfers the status in W9 to the consumer. The consumer compares it with `0x8b3dc651`, publishes a one-byte inequality flag at S+0x202f B, and can test the original word again at `0x10053eac0`. Eight split offline replays cover three recovered markers and an equality control against both settings of a second comparison. [Earlier status handoff](daemon_class_marker_frame_report.md) [Audit](triage_evidence/audit_daemon_class_marker_predicate.py) [Receipt](triage_evidence/daemon_class_marker_predicate_audit.json.zst)

## Continuation publication and consumption

S denotes the shared frame SP. The audit scans all 3,712,490 aligned instruction words in the 14,849,960 B `__text` section for the literal 64-bit unsigned-immediate `STR Xn,[SP,#0xc28]` encoding. It locates five sites. This is a census of that encoding. Alias-based writes, paired stores, other access widths and frame equivalence require separate analysis.

| Site | Source of the stored word |
| --- | --- |
| `0x1002b52ac` | Copy from SP+0x1898 B. |
| `0x10085d84c` | Table entry loaded through the base from SP+0x9d8 B. The replay here resolves an IA target. |
| `0x100c24890` | A selected 32-bit value, zero-extended by the W12 assignment. |
| `0x100c6a5f8` | A masked and XOR-derived value in X13. |
| `0x100ce8c54` | A 32-bit XOR result, zero-extended by the W21 assignment. |

With W19=`0xc3e9` at `0x100509ec8`, the source derives W11=`0xe2e` and W24=`0x12a2`. The branch at `0x100509f04` uses table index `0x2a2f`, slot `0x10104f068`, and IA modifier `0xbf7d` to select `0x10085d834`. The target loads slot `0x101041060` at `0x10085d848` using W11, then publishes its 8 B pointer to S+0xc28 B at `0x10085d84c`.

The same producer computes an arena address `A = S + 0xc070 + u64[S+0x16d0]`. It writes A+0x140 B to S+0xb48 B, A+0x150 B to S+0x9938 B, and A+0x181 B to S+0x9940 B. These are also the destination and auxiliary pointer fields read by the earlier discovery builder. The producer advances the cursor by `0x290` at `0x10085d888`. The unequal continuation subtracts the same extent at `0x1006f6468`–`0x1006f646c` and branches through the saved pointer at `0x1006f6478` with IA modifier `0x42bd`.

## Status and dispatch

| Site | Operation |
| --- | --- |
| `0x100500108` | Compare the incoming W9 to the literal `0x8b3dc651` for any phase. |
| `0x10050011c` | Write 1 B at S+0x202f B. The value is 1 for inequality and 0 for equality. |
| `0x100500124`, `0x10050012c` | Copy the word at S+0x3044 B to S+0x7774 B and the word at S+0x1074 B to S+0x4dec B. |
| `0x100500140` | Force the branch selector to 1 when the second comparison is equal. The previously stored flag retains its own comparison result. |
| `0x100500168` | Branch through the table with IA `0xd00d`. W9 retains the incoming status. |
| `0x10053eac0`, `0x10053eb00` | On the selected arm, compare W9 and W8 again and branch through a different table index with IA `0xe10d`. |

For phase `p = low32(u64[S+0x9d0])`, all scalar arithmetic is modulo 2^32. Let `neq` be the indicator for W9 unequal to `0x8b3dc651`. Let `match` be the indicator for the second word equaling `((p + 0xa3d77b07) & 0x5c283b6d) XOR 0x76d8c9e9`. The first index is `(p + 0x3ad1) XOR (0x15 * ((((p XOR 0x6abf) * 5) XOR (match OR neq)) & 1))`.

| W9 at phase `0x6cf4` | S+0x3044 B | Flag | First slot and target | Replay endpoint |
| --- | --- | --- | --- | --- |
| `0x74c29dee`, `0x74c29dba`, or `0x74c29d88` | `0x76d8ea80` or `0x76d8ea81` | 1 | `0x10108dd18` → `0x10053eac0` | `0x1004cb6f4` via `0x101080f48` |
| `0x8b3dc651` | `0x76d8ea80` | 0 | `0x10108dd18` → `0x10053eac0` | `0x1005fac1c` via `0x101049aa8` |
| `0x8b3dc651` | `0x76d8ea81` | 0 | `0x10108dd70` → `0x10051d248` | `0x10051d248` |

## Assumptions and verification

| Assumption | Dependent finding | Falsification probe |
| --- | --- | --- |
| A1. The pinned source image and its format-12 fixups supply the instruction and dispatch evidence. | Site identities, six table entries and authentication modifiers. | Decode the original six fixup words and compare against the source catalog. Native authentication remains unknown. |
| A2. The producer reaches `0x100509ec8` with W19=`0xc3e9` and the original dispatch base in S+0x9d8 B. | Exact source entry for the continuation and derived arena operands. | Independently step the original instructions and verify slot `0x101041060`, the full-width write, and the matching consumer reload. The intervening producer-to-discovery path is unknown. |
| A3. At consumer entry W9 contains the discovery marker, S+0x9d0 B contains phase `0x6cf4`, and the frame contains the producer state and the declared second word. | Concrete branches and local data flow in the eight replays. | Use both second-word outcomes and an equality control, and prove the local flag, word preservation and both dispatch predicates with symbolic 32-bit inputs. Native reach remains unknown. |

The audit runs the producer prefix to `0x10085d890` and then starts the consumer slice with W9 initialized to the declared status. The preceding report independently observed W9 carrying the recovered markers to that boundary. The equality cases here exercise the local consumer and have synthetic reaching status. The earlier complete frame replay sends that equality input to a different initial arm. The receipt records 31 logical edges, six original fixup checks and six bit-vector checks. The census runs in O(n) time for n instruction words and uses O(k) result space for k matches, in addition to the image bytes it reads. Run `python3 -B triage_evidence/audit_daemon_class_marker_predicate.py` in the existing Unicorn, Capstone and Z3 environment.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Same-frame producer-to-discovery path | High | Trace the producer body and its call at `0x10085d9b4` through the later dispatch to the discovery builder. Shared operand offsets and cursor symmetry establish compatibility. |
| Status publication to IPC | High | Find subsequent readers of the 1 B flag and establish the origin of the separate input read at `0x1004cb6f8`. Its connection to any client reply or Mach-port emission is unknown. |
| Native attribution | High | Observe the frame, discovery transport and ultimate result in one native transaction. |
