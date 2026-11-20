# lskdd recursive marker and frame staging

The installed arm64e `lskdd` image contains a fixed-frame write to the 64-bit slot read after recursion. The block at `0x100720018` copies S+0xce10 B to S+0xa4c0 B and stages a pointer used by the parent copy call. That store is a candidate reaching definition for a zero stack adjustment. The last writer to the address read at runtime remains unknown. [Recursive return dispatch](live_lskdd_recursive_parent_state_report.md)

## Frame transfers

S denotes SP in each analyzed window. Matching offsets identify candidate data flow across windows under a common frame epoch.

| Site | Source | Destination or consumer |
| --- | --- | --- |
| `0x100720038`–`0x10072003c` | Pointer at S+0x9d08 B | Pointer slot S+0x9d80 B. The parent reads this slot into X0 at `0x1008d5798` for its 32 B copy. |
| `0x100720048`–`0x10072004c` | 64-bit word at S+0xce10 B | S+0xa4c0 B. The parent reads S+0xa4c0 B plus the returned stack adjustment at `0x1008d5988`. |
| `0x100720080`–`0x1007200f0` | 32 B through the pointer at S+0x9df0 B | Copies to the pointer loaded from S+0x9d08 B. The original fixup resolves to the same X0-source, X1-destination helper used before recursion. |
| `0x1007200f4`–`0x100720118` | A = S+0x10db0 B plus the 64-bit value at S+0xd7f8 B | Stores A at S+0xb330 B and S+0x65b0 B. Stores A+0x20 B at S+0x8ae0 B. These slots feed child-context preparation. |
| `0x100720148`–`0x100720158` | Zero and `0x2ee02eab` | Initializes A+0x00, +0x08, +0x10, +0x18 and +0x1c B. The writes cover 28 B and leave the 4 B interval at A+0x0c B outside their coverage. |
| `0x1004a9ff4`–`0x1004aa000` | 64-bit word at S+0xa4c0 B | Copies it to S+0xb5a8 B. |
| `0x10075960c`–`0x100759620` | 64-bit word at S+0xa4c0 B | Carries it in X8 through the authenticated transfer indexed by the word at S+0x3028 B. |

At `0x1007200f0` the banks at `0x100d3f720` and `0x100e06f90` yield `0x13` for every byte under key `0xf2`. Adding `0x8d17` gives `0x8d2a`. The slot at `0x100e73780` resolves to the local copy routine at `0x10034e248` with IA discriminator `0x81d1`. Combined with the parent copy, this gives a candidate 32 B lineage through two copy operations. The order and surviving buffer contents require a continuous trace.

## Additional control uses

The predicate at `0x10098c290`–`0x10098c2b4` combines W28, the marker at S+0xb5a8 B, and the 32-bit field at S+0xa580 B. Let P be the 32-bit value at S+0x5b94 B. Its marker comparator is `0x7c36115800000001 + u32(P - 0x3a2a) - 0xb8f`, with the outer arithmetic modulo 2^64. For P = `0x45b9` this gives the same constant read by the recursive return. The final EQ predicate is true if W28 differs from `0x2ee02eab`, if the marker comparison fails, or if the 32-bit field equals `0x2ee02eab`. In particular, the immediate NZCV value of 4 in the final conditional compare sets Z when the prior predicate fails.

The earlier matching recursive-return fixture preserves W21 = `0x45b9` into `0x1009a7a48`. The next transfer at `0x1009a7a88` has two fixup-supported cases.

| X28 at `0x1009a7a48` | Index | Slot | Target |
| --- | --- | --- | --- |
| Zero | `0x699f` | `0x100e61b28` | `0x1008bfc60` |
| Nonzero | `0x6a06` | `0x100e61e60` | `0x1008bf4c4` |

Both use IA discriminator `0xca3f`. The nonzero continuation reads one byte at X28+0x30 B at `0x1008bf4d0`. The zero continuation next selects index `0x2e9c` and slot `0x100e44310`, which resolves to `0x100ac1a48` with discriminator `0x88ba`. At `0x100ac1a6c` W9 is compared as signed with the threshold formed from W21. There are two compatible targets for the fixture, `0x100743a34` via `0x100e6ecf8` when W9 is below the threshold and `0x1009b3a90` via `0x100e6ee48` otherwise, both with discriminator `0xdbbf`. Neither local continuation map supplies an observed selector 19 request.

## Verification and assumptions

The primary evidence is the original instruction bytes and `dyld_info` fixups in arm64e slice UUID `28d510e5-3b91-3916-97ab-b765a3a7ba21`, SHA-256 `a8c3110a3e5f3f4d7d64295218e3a966644c84d2a8c375c7a7b042b6629780c6`. The byte lookup was checked over all 256 inputs. The branch destinations were evaluated statically under the earlier offline state. No matching `lskdd` database was active in the available IDA sessions.

| Assumption and affected result | Falsification check |
| --- | --- |
| M1. The compared windows use the pinned image. Applies to all addresses and bindings. | Recheck slice identity, instruction words and fixup records. |
| M2. Same-offset linkage requires a common SP epoch and a surviving store. Applies to all candidate frame flows. | Record SP and effective addresses from the producer through the load. Check intervening writes including any child-frame writes. A nonzero return adjustment moves the recursive marker load away from S+0xa4c0 B. |
| M3. The continuation table evaluates the earlier W21 fixture. Applies to all listed destinations. | Measure W21 and the loaded table base while following each actual transfer. Check the pointer predicate and discriminator at the branch. |

High impact for separating the frame's marker, status, staged buffer pointer and IOKit connection. The original producer of S+0xce10 B, the continuous route into the recursive parent, and selector 19's connection and Mach port identities remain unknown.
