# Discovery continuation and decoded owner record

After the private 16 B emitter returns, fairplayd saves its destination pointer at S+0x1ba0 B. Its next dispatch depends on a decoded owner address and a separate 32-bit comparison word. With a nonnull owner and an unequal comparison, the daemon decodes two owner fields, calls an internal helper and forwards the helper's status. The other three cases forward a default status. Four instruction replays trace each outcome through the marker consumer and observe zero accesses to the 16 B output interval after its pointer is saved. [Prior emitter report](daemon_discovery_emitter_report.md) [Audit](triage_evidence/audit_daemon_discovery_owner.py) [Receipt](triage_evidence/daemon_discovery_owner_audit.json.zst)

## Frame inputs and dispatch

S is the enclosing SP. H denotes the object supplied in X20 to the producer at `0x1004ca7b4`. Owner addresses are encoded as `E = O + 0x4aba552460e435c6` modulo 2^64. `0x1004ca7b8` saves H+8 B at S+0x4360 B. `0x10057f7e4` reloads that pointer, `0x10057f7e8` loads E through it and `0x10057f7f0` stores E at S+0x8040 B. The origin of H on the continuous native route is unknown.

`0x1007907bc` loads the comparison word from S+0x43b0 B and `0x1007907c4` copies it to S+0x559c B. The word republished by the emitter at S+0x3d78 B comes from S+0x6efc B. It holds `0x8b3dc650` in all four replays. The two words have separate reaching definitions in the captured slices.

At `0x1005fac30`, W21 is `0xa013` and W23 is `0x6cf4`. Let r be the original 64-bit arena cursor at S+0x16d0 B and A=S+0xc070 B+r. The scratch and pointer stores precede the next transfer.

| Store site | Field | Value |
| --- | --- | --- |
| `0x1005fac48`, `0x1005fac4c` | S+0xad0 B, S+0x7880 B | A |
| `0x1005fac54` | S+0x6a40 B | A+0x40 B |
| `0x1005fac5c` | S+0x7148 B | A+0x181 B |
| `0x1005fac6c` | S+0x16d0 B | r+0x290 B at the recovered phase |
| `0x1005fac70` | S+0x1ba0 B | X19, the 16 B output's destination on this route |

At `0x1005fac84`, `cmp` tests E against the encoding of zero. `0x1005fac98` tests the comparison word against `0x8b3dc651` when E differs from the encoding of zero. Otherwise it sets Z. At `0x1005facc0`, the index is `0xa013 XOR (0x56 * gate)`, where gate is 1 for either equality. The two slots use IA diversity `0xbcd3`.

| Decoded owner | Comparison word | Index | Slot | First target | Status at the marker consumer |
| --- | --- | --- | --- | --- | --- |
| Null | 0 | `0xa045` | `0x10108a118` | `0x10060fe34` | `0x74c29d88` |
| Null | `0x8b3dc651` | `0xa045` | `0x10108a118` | `0x10060fe34` | `0x74c29d88` |
| Nonnull | 0 | `0xa013` | `0x101089f88` | `0x1005c5324` | `0x74c29d8c` |
| Nonnull | `0x8b3dc651` | `0xa045` | `0x10108a118` | `0x10060fe34` | `0x74c29d88` |

## Owner fields and helper request

The nonnull, unequal profile reaches `0x1005a88a4` through `0x1005c538c`, slot `0x101082598`, IA diversity `0x3476`. At `0x1005a88d4`, the daemon recovers O by adding `0xb545aadb9f1bca3a` modulo 2^64. It reads 8 B at O+0 B and 4 B at O+0x18 B. It writes a new private request at P=S+0x10cb8 B and saves O at S+0x61a0 B at `0x1005a89f8`. P was the emitter's request earlier on this route.

| Field | Width | Writer | Observed input or output |
| --- | --- | --- | --- |
| P+0x00 B | 4 B | `0x1005a899c` | Control word derived from the request address and W21. |
| P+0x08 B | 8 B | `0x1005a89b0` | Address O+0x1c B. |
| P+0x10 B | 4 B | `0x100081244` | Helper result, `0x74c29d8c` in the fixture. |
| P+0x18 B | 8 B | `0x1005a89a0` | Address S+0x5a2c B. |
| P+0x20 B | 8 B | `0x1005a89a4` | Pointer read at O+0 B by `0x1005a88d8`. |
| P+0x28 B | 8 B | `0x1005a8984` | Address S+0xaec B. |
| P+0x30 B | 4 B | `0x1005a89ac` | Mix of the request-address key and the word read at O+0x18 B by `0x1005a8904`. |

`0x1005a8a1c` calls `0x10000cd98` with X0=P. The ordered banks at S+0x5f0 B and S+0x5e0 B resolve index `0xcc52` to slot `0x1010a0180`, IA diversity `0x1491`. The helper reads all six input fields between `0x10000cf24` and `0x10000cf38`. The observed call reaches `0x1004350a0` through `0x10003267c`, then returns to the caller after the write at `0x100081244`. The caller reads P+0x10 B into W27 at `0x1005a8a20` and compares it with `W23 XOR 0x8b3daaa5`, equal to `0x8b3dc651` at this phase. The unequal result selects `0x10060fe34` at `0x1005a8a4c`. The general semantics of the helper and its other return values remain unknown.

## Marker consumer and later references

All four profiles pass `0x10060fe50`, which restores the original cursor, and reach `0x1005f3f5c` through slot `0x10106dd30`. `0x1005f3f64` writes W27 to S+0x4804 B and `0x1005f3f6c` clears S+0x2b7f B. With S+0x33e8 B equal to zero, `0x1005f3f94` transfers to `0x1008eb564` through slot `0x101075ea0`. This block reads both published fields at `0x1008eb56c` and `0x1008eb574` and reselects the marker into W22 by `0x1008eb590`.

Through that endpoint the output interval is untouched, S+0x3d78 B retains `0x8b3dc650`, and the earlier discovery flag at S+0x202f B remains 1. The previously identified flag-one successor `0x100611520` has literal loads of O from S+0x61a0 B at `0x100611530`, the field at O+0 B at `0x100611534`, the scratch pointer from S+0x7148 B at `0x100611538` and the emitter companion from S+0x3d78 B at `0x100611544`. These are compatible consumers. The connecting control flow and the destination's first byte consumer remain unknown. The bounded path executes internal code and reaches no Mach or IOKit transport call.

## Assumptions and verification

| Assumption | Dependent findings | Falsification probe |
| --- | --- | --- |
| A1. The pinned arm64e image supplies original instructions and chained-fixup words. | Instruction sites, decoded data flow and transfer targets. | Compare the image digest, original fixup words and bank result across all 256 input bytes. |
| A2. The producer slices, prior emitter fixture and post-emitter branch share a modeled frame at phase `0x6cf4`. | Observed decision, scratch stores and output lifetime within the interval. | Vary the owner and comparison independently. Prove the index over arbitrary 64-bit encoded words and 32-bit comparison words and prove the stores over an arbitrary 64-bit cursor and destination. |
| A3. The nonnull owner has readable backing, with a synthetic child pointer and word `0x12345678` at O+0x18 B. S+0x33e8 B is zero. | The private call's fixture result and the common marker-consumer endpoint. | Check each original reader and the result's store and reload. The report scopes the result to these inputs. |

The receipt uses 11 bit-vector checks and four post-emitter replays, with 21 logical transfers. Each replay checks the exact 16 B interval for reads and writes and compares the final bytes with the emitter's output. Run `python3 -B triage_evidence/audit_daemon_discovery_owner.py` in the existing Unicorn, Capstone and Z3 setup. Replay time is O(n) in instruction visits, and receipt space is O(t+a) for t transfers and a recorded field accesses.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Native source of the encoded owner | High | Recover the incoming X20 object and test the candidate relationship to the earlier record extension. [Record extension](daemon_record_extension_report.md) |
| Continuation to the flag reader and output consumer | High | Follow the marker consumer's next dispatch and recover reaching uses of S+0x1ba0 B, S+0x61a0 B and S+0x3d78 B. |
| Correlation with FairPlayIOKit | High | Match an observed daemon transport event to this same reaching frame and an identified user-client request. |
