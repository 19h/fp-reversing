# lskdd selector 19 import and frame

The installed `lskdd` arm64e image contains a large-frame initializer that supplies an exact function-table base and byte-bank pair for the selector 19 block. With that frame, the preparatory call resolves to a return-only leaf and the selector 19 call resolves to `IOConnectCallStructMethod`. The static evidence identifies the callee under the recovered frame contract. The complete route into the block and the native provider behind the connection remain unknown. [Earlier lskdd method ABI](live_lskdd_method_abi_report.md) [Live attachment and slice](live_fairplay_additional_clients_report.md)

## Frame publications and consumers

| Frame value | Producer | Selector 19 consumer |
| --- | --- | --- |
| Function table `0x100e2ce30` | `0x1005b3c04` loads the decoded rebase and `0x1005b3c08` subtracts 4 B. `0x1005b3c0c` writes SP+0x5ff8. | `0x100474d94` loads X22 from SP+0x5ff8. |
| Left byte bank `0x100e07090` | `0x1005b39fc` loads pool slot `0x100e74818`, then `0x1005b3a0c` subtracts 12 B. `0x1005b3eac` writes SP+0x5bb8. | `0x100474d68` loads X27 from SP+0x5bb8. |
| Right byte bank `0x100cb47e0` | `0x1005b3a14` loads pool slot `0x100e75f90`. `0x1005b3ec0` writes SP+0x5bb0. | `0x100474d7c` loads X28 from SP+0x5bb0. |
| Two input words for table selection | `0x1005b3c60` and `0x1005b3e98` write pointer cells at SP+0x5fe0 and SP+0x5fe8. | `0x100474d34` and `0x100474d3c` load the pointers. The two call computations subtract or add their contents before reducing to a byte. |

The prologue at `0x1005b3870` allocates 0x1c9c0 B below the register save. The table root uses pool `0x100e73f20`, banks `0x100d06570` and `0x100d3f820`, XOR key `0x50` and addend `0x129`. For every input byte i, `i XOR right[left[i] XOR 0x50]` is `0x7d`. That gives index `0x1a6`, rebase slot `0x100e74c50`, original value `0x100e2ce34`, and final root `0x100e2ce30`.

The selector 19 block at `0x100474cc4` is itself an authenticated target in this table, index `0x1839`, slot `0x100e38ff8`, discriminator `0xe28d`. The entry at `0x100b5c91c` is one table-root consumer that can dispatch to the block. It reads the state at SP+0x5b94, subtracts `0x2d6e`, and uses the resulting index at `0x100b5c93c` before the `0xe28d` branch at `0x100b5c94c`. A state of `0x45a7` selects `0x1839`. This identifies a compatible predecessor and its required state. Derivation of that state on a continuous route from the initializer remains incomplete.

## Authenticated calls

The two calls use the same X22 table base and X27/X28 banks. For key `0xcf`, the 256-input bank equation is `i XOR right[left[i] XOR 0xcf] = 0xaa`. The sign or value of the original two 32-bit words therefore leaves the selected byte unchanged.

| Local call | Index calculation | Original fixup and effect |
| --- | --- | --- |
| `0x100474da4` | `0x8c7b + 0xaa = 0x8d25` | Slot `0x100e73758`, discriminator `0x0199`, resolves to `0x100316938`, whose only instruction is `ret`. |
| `0x100474e38` | `0x8caa + 0xaa = 0x8d54` | Slot `0x100e738d0`, discriminator `0x21c3`, binds to `IOKit/_IOConnectCallStructMethod`. |

The first call leaves the local stack fields unchanged. The second takes W0 from `[X20]`, W1 = 19, and 3,088 B of input via a pointer saved at SP+0x9ae8. It supplies the output pointer saved at SP+0x89f8 and an output-count pointer at SP+0xaaa0. A separate producer initializes that cell to 3,088 B on the frame route described below. The method return is tested for zero at `0x100474e3c`. [Earlier argument and reply audit](live_lskdd_method_abi_report.md)

The exact table and bank loads exclude the other three original fixups sharing `0x21c3`. The selector 18 block uses X28 as table base and its method bank inputs come from SP+0x78 and SP+0x80 with key `0xf2`. Reusing the selector 19 bank pair and root gives byte `0x08` for all 256 inputs and index `0x8d49`. Slot `0x100e73878` then binds to `CoreFoundation/_CFFileDescriptorCreate` with discriminator `0x417d`, incompatible with the selector 18 call's `0x21c3`. The selector 18 bank definitions at its call remain unknown.

## Output-count and buffer producers

At `0x100a35c08`–`0x100a35c1c`, a separate address range builds the selector 19 input pointer from SP+0x10db0 plus an existing cursor, then saves the pointer in the exact cell read by `0x100474db0`. It adds 3,088 B to that pointer and saves the result in the output-pointer cell consumed at `0x100474e0c`. The cursor advances by 6,176 B. The store at `0x100a35c48` writes 3,088 B to SP+0xaaa0, the output-count cell passed as X5. The selected initializer shares the table-root frame slot with the method block. Its continuation and any intervening writers still need correlation with the candidate method entry.

The selector 18 frame candidate sets X20 to SP+0xb0 and X21 to SP+0xcc8 at `0x1005b00c8` and `0x1005b00cc`. The 3,096 B spacing matches that method's stated input extent. It writes 3,096 B to SP+0x90 at `0x1005b00d4`, the exact offset used for the output-count pointer by the selector 18 block. Its table selection at `0x1005b011c`–`0x1005b0120` supplies the same table base to X28. The reaching byte banks and uninterrupted frame continuity to selector 18 remain unknown.

## Cross-layer scope

The running `lskdd` process was observed with a FairPlayIOKit attachment. If the W0 value loaded at `0x100474dcc` names that connection, the matched kernel table maps selector 19 to `GetReEncryptionVault`. With the inspected 3,088 B initial capacity, the framework sends a 3,172 B inline request with ID 2865 at `0x184ebe090`. The connection supplies the COPY_SEND destination and the local reply port supplies the MAKE_SEND_ONCE right. A full-size success reply has ID 2965 and occupies 3,140 B. The request size is 84 B of fixed framing plus 3,088 B of input. The reply size is 52 B of fixed framing plus 3,088 B of output. Actual Mach names and the native method result remain unknown. [Installed method table](live_kext_selector26_report.md) [Mach transport](live_iokit_mach_transport_report.md)

## Reproduction

Set `LSKDD_IMAGE` to the unmodified fat executable. The offline auditor needs Python with Capstone and the Apple `dyld_info` command. The retained receipt includes the Mach-O UUID and SHA-256, the checked instruction words and the original fixup records. The earlier live audit rechecks the loaded slice's CodeDirectory hash, the attached client, and the framework transport instructions. [Static auditor](triage_evidence/audit_live_lskdd_selector19_binding.py) [Compressed receipt](triage_evidence/live_lskdd_selector19_binding_audit.json.zst) [Live slice and transport auditor](triage_evidence/audit_live_lskdd_method_abi.py)

```sh
python3 triage_evidence/audit_live_lskdd_selector19_binding.py "$LSKDD_IMAGE"
python3 triage_evidence/audit_live_lskdd_method_abi.py
```

The audit checks every byte input to each of five table equations. Each equation reads two 256 B banks and runs in O(n) time for a bank of n entries. The distinct results occupy O(n) space in general and one entry for each of these equations.

| ID | Assumption and dependent result | Falsification check |
| --- | --- | --- |
| L19.1 | The original slice SHA-256 and UUID identify the source build. All preferred addresses depend on that image. | Recheck Mach-O identity, raw patch-free instruction words and both chained rebase and binding records. |
| L19.2 | The selected block uses the recovered frame's table and bank cells. The callee pair depends on that reaching state. | Check the allocator prologue, intervening writers and a continuous original route into `0x100474cc4`. |
| L19.3 | The block is entered from the inspected predecessor with the stated state word. This identifies one possible local edge. | Follow the frame's state producer and check the indexed load and branch in the same execution. |
| L19.4 | The loaded connection is the attached FairPlayIOKit client and ordinary inline transfer applies. This qualifies method and Mach interpretation. | Observe the connection object and capacities at emission and correlate them with the matching kernel dispatch and reply. |

High impact for resolving selector 19's two otherwise ambiguous callees. High impact for the newly identified buffer and capacity writes on the selected frame contracts. Medium impact for separating the imported callee from the specific provider and method instance on a running system.

The subsequent large-frame replay identifies an OS transaction acquisition helper. It records an initializer write of `0x45b9` to SP+0x5b94 and establishes a distinct early state from the candidate selector 19 predecessor's `0x45a7`. [Large-frame transaction acquisition](live_lskdd_large_frame_transaction_report.md)
