# lskdd large-frame caller and recursive context

The routine at `0x1006caa30` wraps the large-frame initializer at `0x1005b3870`. It forwards the context in X0, passes a temporary derived from the caller's X1 cell, and publishes a scaled 16-bit difference back into that cell. A block using the large frame's dispatch table and bank layout calls this wrapper at `0x1008d5950`, providing a child context on the parent stack and reading the child status on return. [Large-frame transaction helper](live_lskdd_large_frame_transaction_report.md)

## Wrapper contract

| Operation | Site | Recovered value |
| --- | --- | --- |
| Read the caller cell | `0x1006cab20` | Load 64-bit V through entry X1, preserved in X19. |
| Reserve temporary stack storage | `0x1006cab74`–`0x1006cab94` | Let H be the top four bits of `(0x2ea5 * V + 1) mod 2^64`. Reserve `(H + 1) * 16` B, spanning 16 to 256 B. |
| Initialize the temporary | `0x1006cab98`–`0x1006cab9c` | Store `(V - 0xa0) mod 2^64` through X20. |
| Call the initializer | `0x1006cac14`–`0x1006cac1c` | X0 retains the entry context. X1 is X20. The IA fixup in `0x100e73d00` names `0x1005b3870` with discriminator `0xc295`. |
| Restore the input contribution | `0x1005b39e0`–`0x1005b39e8` | The initializer adds `0xa0` to the temporary through X1. |
| Publish the caller result | `0x1006cac20`–`0x1006cac2c` | Read the low 32 bits of the temporary. Subtract W21, which retains the low 32 bits of V. Store `16 * (difference mod 2^16)` as a 64-bit value through X19. |

The installed Mach-O bytes and chained fixups establish the call targets and offsets. The wrapper selects the adjusted table base `0x100e2ce30` from pool slot `0x100e74c50`, then selects target slot `0x100e73d00`. The table-base lookup uses banks at `0x100d3f720` and `0x100e06f90`, key `0xac` and bias `0x138`. The byte transform gives `0x6e`, yielding pool index `0x1a6`. The call lookup uses banks at `0x100e07090` and `0x100cb47e0`, key `0xcf` and bias `0x8d30`. It gives `0xaa`, yielding table index `0x8dda`. Both byte transforms were checked across 256 inputs.

## Parent frame and child context

The large-frame initializer publishes the table base to SP+0x5ff8 B at `0x1005b3c0c` and the byte banks to SP+0x5800 B and SP+0x5808 B at `0x1005b3d54` and `0x1005b3d74`. The parent block loads those slots at `0x1008d57f8`, `0x1008d5914` and `0x1008d5928`. The original bank pointers are `0x100cb46e0` and `0x100d06478` from the pointer pool. The second pointer is adjusted by -8 B before publication. Key `0xa2` maps every byte input to `0x5f`, so `0x8cd7 + 0x5f = 0x8d36`. The reached slot under this frame contract is `0x100e737e0`, which binds the wrapper with IA discriminator `0x3168`. The original chained fixup for parent block entry `0x1008d5760` is at `0x100e63ef8`, with discriminator `0xa11f`. The exact incoming parent branch remains unverified.

Let S be the parent SP in the call block and C be `X29 - 0xe8`, passed in X0. For the fixed frame from the prologue, `X29 = S + 0x1ca50`, so `C = S + 0x1c968`. Let R be `((low32(C) XOR 0x113ef3f5 XOR 0xc86cc8b9) * 0x58fbd727) mod 2^32`.

| Parent site | Child field | Transfer |
| --- | --- | --- |
| `0x1008d5898` | C+0x00 B | Stores `load32(S+0x9574) XOR R`. |
| `0x1008d586c` | C+0x08 B | Stores X19, computed from the pointer at S+0xb330 B plus 0x50 B. |
| `0x1008d5880` | C+0x10 B | Stores the pointer read from S+0x54d0 B. |
| `0x1008d5868` | C+0x18 B | Stores the pointer read from S+0x8ae0 B. |
| `0x1008d5878` | C+0x20 B | Stores pointer S+0x9f48 B. |
| `0x1008d5890` | C+0x28 B | Stores `(W20 + 0x2a03 + R) mod 2^32`. W20 comes from S+0x3b8c B at `0x1008d5760`. |
| `0x1008d58fc`, `0x1008d5948` | Separate X1 cell | Initializes the 64-bit cell at S+0x10c88 B and passes its address through X1. |
| `0x1008d5964`–`0x1008d596c` | X1 result | Reads the published 64-bit value and adds it to SP. This consumer identifies the result as a stack adjustment in bytes. |
| `0x1008d5970`–`0x1008d597c` | C+0x2c B | Reads the child status and compares it with `0x2ee02eab`. |

The mask, addition and subtraction at `0x1008d583c`–`0x1008d5844` compute XOR with the low 32 bits of the immediate in X12. The resulting residue agrees with the decoder in the initializer. This identifies the sources of the recursive entry's decoded words. The upstream producers of S+0x9574 B and S+0x3b8c B remain unknown.

## Offline verification

Two wrapper-entry runs used the pinned installed arm64e slice, UUID `28d510e5-3b91-3916-97ab-b765a3a7ba21`, SHA-256 `a8c3110a3e5f3f4d7d64295218e3a966644c84d2a8c375c7a7b042b6629780c6`. Both encoded the previously verified W21 value `0x45b9`. One began with no transaction and reserved 16 B for the wrapper temporary. The other began with a transaction and reserved 32 B. Both returned through the original wrapper, stored a zero stack adjustment and wrote `0x2edf880f` at context +0x2c B. The model supplied the stack-probe return and successful transaction imports. Both traces ended without visiting the selector 19 predecessor or method block. The parent path above is established by static data flow under the recovered frame contract.

The selector 19 method binding and its inline Mach transport remain independently established. The native dispatch into the recursive caller, selector 19 connection producer and selector 19 Mach port names remain unknown. [Selector 19 binding](live_lskdd_selector19_binding_report.md) [Mach transport](live_iokit_mach_transport_report.md)

The offline run uses Unicorn with the original instruction stream and matches each taken indexed transfer against its original fixup. The recorded parent transfer is a static calculation using the parent frame slots and does not represent a replay of the parent entry.

| Assumption and dependent finding | Falsification check |
| --- | --- |
| C1. The preferred addresses name the same arm64e image throughout. | Verify the slice UUID, SHA-256, chained fixups and instruction bytes. |
| C2. The parent block uses the published large-frame slots and fixed-frame SP relation on the analyzed epoch. | Check the producer loads and stores, consuming offsets, child addresses, and all 256 byte inputs. An intervening SP epoch or overwrite would change the parent linkage. |
| C3. The replay starts at the wrapper with synthetic context, stack and OS transaction state. | Repeat both wrapper-entry cases and verify their original target, temporary writes, published value and separate status. |
| C4. The recursive path has a caller status consumer. Its native route before the block is unknown. | Trace the incoming transfer to the parent block and check the two frame words and status under that execution. |

High impact for distinguishing the recursive daemon-local ABI from an IOKit invocation. Medium impact for establishing the status consumer and the use of the wrapper result as a stack adjustment.
