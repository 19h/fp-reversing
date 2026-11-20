# Discovery status in the enclosing daemon frame

In the pinned fairplayd image, the caller at `0x100585034` builds the parent record and invokes the discovery route through adapter `0x10047d180`. After return it copies the 32-bit status at P+0x28 B to its own frame at S+0xf48 B. The source later uses that word to select a continuation at `0x1005cfc18`. At the tested frame phase `0x6cf4`, all three recovered discovery markers take the unequal branch. A fourth, synthetic control reaches the equality branch. [Parent return](daemon_class_marker_caller_report.md) [Discovery markers](daemon_class_marker_output_report.md) [Audit](triage_evidence/audit_daemon_class_marker_frame.py) [Receipt](triage_evidence/daemon_class_marker_frame_audit.json.zst)

## Record and stack handoff

S is the enclosing SP at `0x100585034`. P is the parent record at S+0x10cb8 B. With W19=`0x10cd` at the builder, the effective parent phase is `0x7b68`. The address key is `u32((P XOR 0xc6d66014) * 0x6b86592f)`. The source writes `(W19 + 0x6a9b) XOR key` to P+0x38 B and `0x54014909 - key` to P+0x24 B. This size word selects a 16 B copy. P+0x18 B receives the destination pointer from S+0xb48 B.

| Site | Observed operation |
| --- | --- |
| `0x1005850cc` | Initialize the cursor cell at S+0xb9d0 B using the value referenced by S+0x1f0 B. |
| `0x100585140` | Call adapter `0x10047d180` with X0=P and X1=S+0xb9d0 B. The ordered banks at `0x100fc4230` and `0x101031fa0` select index `0xce4e` over all 256 byte inputs to the bank transform. Slot `0x1010a1160` uses IA modifier `0x7208`. |
| `0x10047d3c0` | Call parent `0x10046fc5c` through slot `0x1010a1938`, IA `0xdbd5`. The adapter subtracts `0xc0` from the initial cursor in its local cell before the call. The parent prologue adds `0xc0` there. |
| `0x1004ccb5c` | Publish W23 at P+0x28 B after copying the modeled payload in descending byte order and requesting its release. |
| `0x100585144` through `0x100585150` | Apply the returned cursor delta to SP. The delta is zero in these profiles. |
| `0x100585154`, `0x100585158` | Read P+0x28 B and store the same 4 B word at S+0xf48 B. |

## Dispatch and status consumer

The branch at `0x1005851a0` selects `0x1009a1008` through slot `0x101048200`, IA `0xfb72`. At `0x1009a1028` the source loads a target from slot `0x101042558` and saves it to S+0x5990 B at `0x1009a1030`. The replays check the original slot, the saved word and the reload at `0x1005ae1d4`. At `0x1005ae1fc`, IA `0x92a5` selects `0x1005cfbd4` from that saved value.

Let `phase = low32(u64[S+0x9d0])` and `word = u32[S+0xf48]`. The load at `0x1005cfbe4` supplies the comparison at `0x1005cfbf4`. All arithmetic in these formulas is modulo 2^32. The table load sign-extends the resulting 32-bit index.

```text
expected = (0xcbb6 XOR (phase << 1)) + 0x8b3db3f3
index    = (phase - 0x5a96) XOR (0x6a37 * (word == expected))
```

At phase `0x6cf4`, the expected word is `0x8b3dc651`. Both table entries below are read at `0x1005cfc10` and branched through at `0x1005cfc18` with IA modifier `0x7295`.

| Status in S+0xf48 B | Predicate | Index and slot | Target and observed endpoint |
| --- | --- | --- | --- |
| `0x74c29dee`, `0x74c29dba`, `0x74c29d88` | Unequal | `0x125e`, `0x1010431e0` | `0x100606460` reloads the status into W9 at `0x10060646c`. `0x10060647c` then branches to `0x1006f6464` via slot `0x10107d870`, IA `0x3184`, with W9 intact. |
| `0x8b3dc651` | Equal | `0x7869`, `0x101076238` | `0x1007956dc`, where the equality control stops. The first block reads the original destination pointer from S+0xb48 B at `0x1007956e4`. |

## Assumptions and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The pinned arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, supplies the original instructions and chained fixups. | Exact sites, targets and discriminator values. | Check 40 original non-bind fixup words against the source inventory. Check the saved-pointer load, store, reload and branch separately. Hardware authentication remains unknown. |
| A2. The enclosing frame reaches the builder with W19=`0x10cd`, declared operand and bank pointers, and S+0x9d0 B=`0x6cf4`. | The selected record phase, byte extent, and the concrete dispatch indices. | Check the built X0 and X1 addresses, the parent return store and restored SP. Prove the index formula for arbitrary 32-bit phase and status. Simultaneous native reach of these frame values remains unknown. [Earlier frame bank and phase producers](daemon_constructor_bank_origins_report.md) |
| A3. The inherited caller model supplies effects for the helper at `0x100412ebc`, the allocator and deallocator, and the outer discovery routine at `0x100559b7c`. Both adapters execute their original instructions. The model inserts the status at Q+0x10 B and advances the local cursor by `0xe0`. | Original instructions carry the supplied status through the parent, outer frame and predicate. | Vary the three recovered markers and one independent equality control. Verify one 4 B parent status publication, the 4 B frame write and every observed read of the frame slot. |

The receipt records four A64 replays with 331 logical transfers, and three bit-vector checks for the frame copy, phase-derived operand and dispatch index. The reused caller audit reproduces its prior receipt byte for byte. Replay time is O(n) in instruction visits and the receipt uses O(t) space for t recorded transfers with the fixed 16 B copy extent. Run `python3 -B triage_evidence/audit_daemon_class_marker_frame.py` in the existing Unicorn, Capstone and Z3 environment.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Unequal continuation and client reply | High | Recover the producer of the pointer read from S+0xc28 B at `0x1006f6470`, then establish the next consumer of W9. The present boundary has no joined XPC or Mach reply. |
| Native daemon-to-kext attribution | High | Join the same caller frame, parent record and selected transport in one observation. The archived type-0 open failure is a separate transport observation. |
| Additional adapter candidates | Medium | The calls at `0x10072a8f8` and `0x1007f6438` are followed by reads of the same relative record field at `0x10072a90c` and `0x1007f644c`. Resolve their reaching frame and phase before attributing either to this discovery route. |
