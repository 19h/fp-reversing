# lskdd selector 19 reply handling

The installed arm64e daemon has one selector 19 entry-state value, W21 = `0x4fbf`, for which both zero and nonzero IOKit returns select original authenticated code fixups under the recovered frame contract. After zero IOKit status, the daemon reads a 32-bit field at output +8 B and compares it unsigned with 3,072 B. The branch for a smaller length derives a pointer at output +12 B. The IOKit connection producer and native reachability remain unknown. [Method binding and frame](live_lskdd_selector19_binding_report.md)

## IOKit status and reply fields

Let S denote the fixed SP and T the function-table base `0x100e2ce30` read from S+0x5ff8 B. The real entry at `0x100474cc4` assigns W8 = W21 XOR `0x4eee` and W9 = W8 shifted left by five bits. The subtraction at `0x100474d84` therefore gives W23 = 31 × (W21 XOR `0x4eee`) modulo 2^32. The index at `0x100474e54` is W21 for nonzero W0, or W21 XOR (W23 − `0x287d`) for zero W0. The load sign-extends the 32-bit index before scaling by 8 B, and the branch at `0x100474e68` uses IA modifier `0x25d2`. Testing the eight original code rebases with that modifier gives one pair whose two indices both have matching fixups.

| IOKit return and subsequent test | Index | Slot | Target and observed operation |
| --- | --- | --- | --- |
| W0 nonzero | `0x4fbf` | `0x100e54c28` | `0x1003b483c` writes W26 = `0x2edf8807` to S+0xf23c B and adjusts the frame cursor at S+0xd7f8 B. |
| W0 zero | `0x4fed` | `0x100e54d98` | `0x10098cbe0` saves output +8 B at S+0xf230 B, loads its u32 value and compares it unsigned with 3,072. It loads W26 from S+0x575c B before the next branch. |
| W0 zero, length ≥ 3,072 B | `0x4fbf` | `0x100e54c28` | Rejoins the status-store block with the W26 value read from the frame and then follows the same cleanup dispatch. |
| W0 zero, length < 3,072 B | `0x7b6a` | `0x100e6a980` | `0x100425608` sets X20 to output +12 B, reloads the length and obtains a second pointer from S+0x6c80 B. |

For nonzero IOKit status, `0x1003b4870` uses W23 = `0x28cf` to select slot `0x100e414a8`. Its target `0x100474944` stores the status at S+0x7f54 B, subtracts 3,072 B from the frame cursor and transfers to `0x10096bb98` through slot `0x100e3a890`. The same dispatch indices apply to the length ≥ 3,072 B case because the length check recomputes W23 = `0x28cf`. The later block reads +12 B from a pointer obtained at S+0x81f0 B. Its object identity remains unknown.

On the length < 3,072 B branch, slots `0x100e39c88` and `0x100e3a3b0` resolve to `0x10072cb44` and `0x1001fac74`, respectively. At `0x1001facc8`, two pairs of additive constants cancel modulo 2^64. The resulting unsigned comparison is between output +12 B and the pointer loaded from S+0x6c80 B. The two targets below follow from that comparison. The later data transfer and ownership of the second pointer remain open.

| Pointer comparison | Index | Slot | Target |
| --- | --- | --- | --- |
| Output +12 B ≤ pointer from S+0x6c80 B | `0x2c05` | `0x100e42e58` | `0x10055d898` |
| Output +12 B > pointer from S+0x6c80 B | `0x2c0b` | `0x100e42e88` | `0x10044fd30` |

The kernel-side interface describes +8 B as the structure length and +0xc0c B as the embedded provider status. The daemon windows above establish the first use of +8 B. The reaching writer of S+0x575c B and any later consumer of +0xc0c B remain unknown. The synchronous IOKit stub writes the returned inline count through X5, which names S+0xaaa0 B at this call. These reply windows do not read that count. [Kernel structure contracts](foundational_triage_report.md) [Mach transport and framework copyout](live_iokit_mach_transport_report.md)

## Connection evidence

The candidate predecessor at `0x100b5c91c` reaches the real entry for a frame state word of `0x45a7`. That predecessor consumes S+0x5b94 B and leaves both W21 and X20 unchanged. The earlier buffer producer ends with W20 = `0x55d` and W21 = `0x7cbe`, so any continuous route from it must establish the later handle pointer and compatible entry state. The separately established selector 18 connection cell at `0x100e82af8` has a rebase at `0x100e77350`. A reaching definition from that cell to selector 19's X20 remains unknown. [Selector 19 frame](live_lskdd_selector19_binding_report.md) [Selector 18 connection provenance](live_lskdd_selector18_connection_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| LR19.1 | The pinned image and table base describe the analyzed dispatch. All indices and targets depend on it. | Recompute the arm64e SHA-256 and UUID, then match original slot targets, keys and modifiers. |
| LR19.2 | Both outcomes take table entries backed by original fixups and the block enters at `0x100474cc4` with the recovered table. The unique compatible W21 depends on these premises. | Enumerate all matching rebases and replay both index calculations. A native sample could establish whether the assumed entry state and unmodified table actually reach the call. |
| LR19.3 | X19 retains the output pointer across the call and the local continuations retain the fixed frame. This qualifies the reply-field offsets. | Compare saved X19 and SP at the method return and later length branch. Correlate the Mach reply count and copied bytes for the same request. |

High impact for separating outer IOKit status from the length field in the returned structure. Medium impact for tracing status storage and data pointers across obfuscated branches. Native port names, the actual return cases taken and the final caller-visible result remain unknown.

Set `LSKDD_IMAGE` to the original fat executable and run the auditor with Python, Capstone and Apple `dyld_info`.

```sh
python3 triage_evidence/audit_live_lskdd_selector19_reply.py "$LSKDD_IMAGE"
```

The auditor verifies the slice identity, records disassembled windows and checks the index arithmetic against original chained fixups. For N image bytes, F fixups and I instructions in the selected windows, it uses O(N + F + I) time and storage, excluding system tool costs. [Auditor](triage_evidence/audit_live_lskdd_selector19_reply.py) [Compressed receipt](triage_evidence/live_lskdd_selector19_reply_audit.json.zst)
