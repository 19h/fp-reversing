# Discovery inequality, private byte emitter, and flag reader

The original fairplayd inequality arm calls the previously recovered private byte emitter at `0x100add594`. It requests 16 B through an address-coded record, receives a completion word and a separate zero stack adjustment, and resumes at `0x1005fac1c`. The same arm updates a companion word at S+0x6efc B before the call and republishes it at S+0x3d78 B after return. A separate source block reads the discovery flag at S+0x202f B and branches on its value. [Discovery predicate](daemon_class_marker_predicate_report.md) [Existing emitter contract](daemon_generated_stream_report.md) [Audit](triage_evidence/audit_daemon_discovery_emitter.py) [Receipt](triage_evidence/daemon_discovery_emitter_audit.json.zst)

## Unequal path and companion word

S is the enclosing frame SP. The bounded initializer at `0x100790828` forms `0x8b3dc651` and stores that 32-bit word at S+0x6efc B at `0x10079083c`. Two preceding stores in the same slice write the same literal at other offsets. The initializer and consumer slices run in the same scratch frame with a deliberate boundary between them. Native reaching definitions from this initializer remain unknown.

The consumer runs from `0x1005000d4` with each retained discovery status in W9. The retest at `0x10053eac0` selects `0x1004cb6f4` and sets X25=S+0x6000 B at `0x10053eaf8`. The next load overwrites W9 with the companion word from that base plus 0xefc B. Local arithmetic updates the word before constructing the emitter request.

| Site | Address and observed operation |
| --- | --- |
| `0x1004cb6f8` | Load 4 B from S+0x6efc B, value `0x8b3dc651`. |
| `0x1004cb7d8` | Store 4 B at S+0x6efc B, value `0x8b3dc650` in the four replays. |
| `0x1004cb8dc` | Enter the common continuation `0x1005fac1c`, clearing W9 before transfer. The earlier equality control also reaches this continuation through its own edge. |
| `0x1005fac28`, `0x1005fac2c` | Reload the companion word and save it at S+0x3d78 B. |

The transition from `0x8b3dc651` to `0x8b3dc650` depends on the input word and reaching W22=`0x1f77`. The source projection also checks that zero at this phase maps to 3. The new word and the original discovery marker have distinct sources and storage locations.

## Emitter ABI

P is the request at S+0x10cb8 B. The low 32 bits of `(P XOR 0xeaae0ac9) * 0x7398180b` supply address key K. X0=P and X1=S+0xbc90 B at the call. The frame supplies the destination through X19, which the source loads from S+0x3100 B at `0x10053ead8`.

| Site or field | Width | Observed contract |
| --- | --- | --- |
| P+0x08 B at `0x1004cb82c` | 8 B | Destination pointer. The replays use private scratch at S+0xc1b0 B. |
| P+0x10 B at `0x1004cb828` | 2 B | Subtract low16(K) and `0x153b` modulo 2^16 to recover 16 B. |
| P+0x14 B at `0x1004cb83c` | 4 B | Add K modulo 2^32 to recover `0xb399`. |
| `0x1004cb8bc` | Call | Ordered banks from S+0x600 B and S+0x5f8 B collapse key `0x54` to `0xb6` for all 256 input bytes. The index `0xcbf4` selects slot `0x10109fe90` with IA `0x22a0` and target `0x100add594`. |
| `0x100add7d4` | Call | Adapter invokes `0x100acd9c4` through slot `0x1010a0f18`, IA `0x7c25`. |
| `0x100a0ca74` | 1 B per store | Emitter writes all 16 bytes to the declared destination. |
| P+0x00 B and S+0xbc90 B | 4 B and 8 B | The replays observe completion `0x8b3dc651` and a separate zero stack adjustment. The caller applies the adjustment at `0x1004cb8c4` through `0x1004cb8cc`. |

All four replays produced the fixture bytes `0e58f1d2a96715ef3f9210d1f9d78596`. The three discovery status words share the same fixture output. A fourth replay varies the initial generation counter from 9 to 1 under the other fixed inputs and reproduces that output. Those equalities are scoped to the tested inputs. The staged synthetic cache supplies the mask, text-root value and selected cache word observed in the earlier generator receipt. Its private backing is relocated in the replay. Native generator state, the live destination's owner and external meaning of the output remain unknown. [Prior generator receipt](triage_evidence/daemon_generated_stream_checks.json.zst) [Bank producers](daemon_return_bank_origins_report.md)

## Discovery flag consumer

The block at `0x10051fed0` is an original IA `0x7295` target through slot `0x101042fc8`. It reads exactly 1 B from S+0x202f B at `0x10051fee8`. Its dispatch index is `(p + 0x2d3e) XOR (eq * (x - 0xa8))`, where `x = p XOR 0x6de8`, `p = low32(u64[S+0x9d0])`, and `eq` tests the flag against `((2*x - 0x38) & 0xfe)`. The arithmetic is modulo 2^32 and the table load uses a signed 32-bit index. At phase `0x6cf4` the expected flag is zero.

| Flag at phase `0x6cf4` | Index | Slot at `0x10051ff10` | Target at `0x10051ff18`, IA `0x6979` |
| --- | --- | --- | --- |
| 0 | `0x9a46` | `0x101087120` | `0x100546c2c` |
| 1 | `0x9a32` | `0x101087080` | `0x100611520` |

The emitter path preserves the flag through the observed companion-word publication at `0x1005fac2c`. Two separate local replays enter the reader with the declared flag and source phase. A continuous path from that publication to this reader remains unknown.

## Assumptions and verification

| Assumption | Dependent findings | Falsification probe |
| --- | --- | --- |
| A1. The pinned arm64e image provides the instruction bytes and logical chained-fixup entries. | Exact source sites, call identities and table indices. | Verify the image digest, the 23 original fixup words and the ordered-bank identity over 256 inputs. |
| A2. The initialized companion word, phase `0x6cf4`, frame bank roots, destination and cursor input are reaching premises. | The retained unequal route, request fields and updated companion word. | Exercise all three discovery markers, prove the request decoding and check a different scalar input in the word projection. Simultaneous native reach remains unknown. |
| A3. Synthetic generator state and readable cache backing support the original byte loop. | Replay output, completion word and stack delta. | Verify every destination byte against original store events and recheck the final frame and the two separate output channels. Change the initial generation counter within the working fixture. |
| A4. The flag reader receives the same frame offset and the declared phase. | The two precise branch destinations for flag 0 and 1. | Replay both values and prove the index equation over arbitrary 32-bit phase and 8-bit flag. The caller that transfers into the reader is unknown. |

The receipt records four emitter profiles, two flag-reader profiles, six bit-vector checks, and 10,270 logical transfers. No native imports execute in these replays. Run `python3 -B triage_evidence/audit_daemon_discovery_emitter.py` in the existing Unicorn, Capstone and Z3 environment. Replay time is O(n) in emulated instruction visits and receipt space is O(t+b) for t transfers and b destination writes.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Downstream use of the 16 B destination and companion word | High | Continue from `0x1005fac30` and recover the owner reached from S+0x8040 B, plus the gate on S+0x559c B. Establish whether a later read carries the same bytes to a transport boundary. |
| Continuation into the flag reader | High | Recover the reaching indexed load for slot `0x101042fc8` and track the last store to S+0x202f B across that path. |
| Native daemon, driver and reply linkage | High | Correlate a native transaction with the same reaching frame and transport. IPC identity and reply use remain unknown. |
