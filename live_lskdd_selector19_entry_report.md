# lskdd selector 19 entry-state producer

The installed arm64e image contains a fixed-frame predecessor at `0x1008eda8c` that both computes the selector 19 entry-state register and transfers to the IOKit call block under a matching status. With the previously recovered frame word `0x45b9`, it computes W21 = `0x4fbf`, the value independently derived from the two method-return branches. The origin of the status for this edge and the definition of the connection pointer in X20 remain unknown. [Reply-state derivation](live_lskdd_selector19_reply_report.md) [Large-frame initialization](live_lskdd_large_frame_transaction_report.md)

## Status-gated edge

Let P be the u32 word at S+0x5b94 B, with S denoting the fixed SP. At `0x1008edab0`, W21 becomes `5 * (((P - 0x3db8) OR 0x20ce) XOR 0x273c)` modulo 2^32. The index is `P - 0x2da4`, XORed with `W21 - 0x4f93` if W26 equals `0x2ee02eab`. The load uses the signed 32-bit index, scaled by 8 B, from the table base at S+0x5ff8 B. The branch at `0x1008edae8` uses IA discriminator `0xe28d`. This block itself has an original authenticated entry fixup in slot `0x100e2e148` with IA discriminator `0xb9a3`.

| W26 condition with P = `0x45b9` | W21 | Index | Slot | Target |
| --- | --- | --- | --- | --- |
| Equals `0x2ee02eab` | `0x4fbf` | `0x1839` | `0x100e38ff8` | `0x100474cc4`, selector 19 call block |
| Differs from `0x2ee02eab` | `0x4fbf` | `0x1815` | `0x100e38ed8` | `0x1004decf4` |

The status constant matches the value tested at the earlier recursive-wrapper return. The recursive result is read from context +0x2c B and also tested with a separate frame marker. No continuous trace links that result to W26 at this predecessor. [Recursive return contract](live_lskdd_recursive_parent_state_report.md)

## Other local edges and connection custody

These fixed-frame dispatch formulas can also select index `0x1839`. They leave the required W21 live from an earlier definition.

| Branch | Input constraint for index `0x1839` |
| --- | --- |
| `0x100b5c94c` | P = `0x45a7`, using P − `0x2d6e`. |
| `0x1006eb44c` | The u32 word at S+0x3840 B equals `0x1839`. |
| `0x100ac2684` | P = `0x458b`, using (P − `0x44e8`) XOR `0x189a`. |

All four predecessor windows leave X20 live. The selector 19 block loads its connection name from `[X20]` at `0x100474dcc`. The earlier frame-buffer producer sets W20 to the scalar `0x55d` before its own branch, so a continuous path from there requires an intervening definition of X20. The known selector 18 cell at `0x100e82af8` is named by rebase slot `0x100e77350`. Whether that address supplies selector 19 remains unknown. IDA MCP had no matching daemon database available during this pass. [Selector 18 connection](live_lskdd_selector18_connection_report.md) [Selector 19 application and Mach framing](live_lskdd_selector19_binding_report.md)

## Assumptions and verification

| Premise and dependent result | Falsification check |
| --- | --- |
| The pinned image and original table at S+0x5ff8 B describe the local dispatch. This qualifies target arithmetic. | Recompute the arm64e digest and UUID, then compare the original slots, modifiers, and instruction windows. |
| P retains `0x45b9` when this predecessor executes. This qualifies the computed W21 and both target addresses. | Compare the last writer to S+0x5b94 B with the value loaded at `0x1008eda9c` in a continuous trace. |
| W26 is live on entry. Its value selects the outgoing edge. | Track the status producer into `0x1008edac0` and check whether it was derived from the earlier recursive result or another source. |

High impact for relating an entry-state producer to the IOKit call and its reply decoder. Medium impact for locating the upstream status and connection definitions. Native invocation and port identity remain unknown.

Set `LSKDD_IMAGE` to the original fat executable. The auditor checks slice identity, original fixups and arithmetic and records the disassembly it uses. It takes O(N + F + I) time and storage for N image bytes, F fixups and I selected instructions, excluding system tool costs.

```sh
python3 triage_evidence/audit_live_lskdd_selector19_entry.py "$LSKDD_IMAGE"
```

[Auditor](triage_evidence/audit_live_lskdd_selector19_entry.py) [Compressed receipt](triage_evidence/live_lskdd_selector19_entry_audit.json.zst)
