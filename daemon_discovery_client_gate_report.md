# Discovery client-state gate after scratch cleanup

The continuation at `0x1004ccbe4` tests the saved u64 at S+0x3650 B. A nonzero address enters a status check at object offset +0x18 B. The exact status word initialized by the earlier 32 B client-object constructor passes this check and leads to reads at offsets +0x10 and +0x0c B. A null saved value and a mismatching status both take the same saved continuation. These joins use separately entered producer slices. The live producer and daemon–kext attribution remain unknown. [DG1–DG4]

```text
S+0x3650
  +-- present --> object[0x18] == 0x8b3dc651 ?
  |                +-- match --> consume object[0x10] and object[0x0c]
  |                +-- mismatch --+
  +-- null -----------------------+
                                   v
                    continuation saved at S+0x7738
                                   |
                    test u64 at S+0x58d0
                      +-- zero --> 0x1004de1d4
                      +-- nonzero --> pending malloc(16)
```

| Evidence | Primary artifact |
| --- | --- |
| DG1 | Pinned daemon SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Original instructions and chained fixups supply the address map. |
| DG2 | [Discovery scratch cleanup](daemon_discovery_pointer_cleanup_report.md) reaches `0x1004ccbe4` under the compatible saved-continuation premise. |
| DG3 | [Client-object report](daemon_client_object_report.md) establishes the original 32 B allocation and initializer through the original source. [Identity cache publication](daemon_cache_publication_report.md) establishes a separate CF result writer at the same numeric offset. |
| DG4 | [Replay](triage_evidence/audit_daemon_discovery_client_gate.py) and [receipts](triage_evidence/daemon_discovery_client_gate_audit.json.zst) check the source effects, successor slots, and alternate allocation request. |

## Reaching the object field loads

The continuation loads S+0x3650 B at `0x1005e604c` and copies the full value to S+0x1cf0 B at `0x1004ccc04`. The source at `0x1005596c4` initializes 28 B of a declared 32 B allocation and publishes its address at `0x1005596e4` into S+0x3650 B. The replay executes those writes in a detached slice, supplies that address to the captured continuation entry, and verifies the exact field accesses. The final four bytes of the allocation remain outside the initializer write extent and outside the checked read footprint. [DG2–DG4]

| Site | Source effect |
| --- | --- |
| `0x1004ccc40` | In phase `0x6cf4`, zero selects index `0x9ebf` and target `0x100713fd8`. Nonzero selects `0x9ed4` and `0x10081a354`. Both branches use IA `0x7afa`. |
| `0x10081a36c`, `0x10081a370` | Save object+0x18 B at S+0x3730 B and load its u32. |
| `0x10081a380`, `0x10081a39c` | Compare against `0x8b3dc651` in this phase. Match selects index `0x82b2` and target `0x1004ba468`. Mismatch selects `0x82d9` and `0x100713fd8`. Both branches use IA `0x2e12`. |
| `0x1004ba498` through `0x1004ba4a4` | Save object+0x10 B at S+0x7238 B and copy its u32 unchanged to S+0xa648 B. |
| `0x100836664` through `0x10083666c` | XOR that u32 with `0x8b3dc651`, subtract the result from W11, and store u32 12 at S+0x4ee4 B for the original initializer profile. |
| `0x10082a7fc` | Read the u32 at object+0x0c B as the next local operand. The matching replay stops immediately afterward at `0x10082a800`. |

There are three literal unsigned-immediate u64 stores to S+0x3650 B in the examined text. `0x1005596e4` saves the initialized client object. `0x100592ff8` writes zero. `0x100ad6fd0` saves the formatted CF object in the identity-cache route. Only the first two slices are entered in these controls. The common frame offset gives an address correspondence across these routines. Native type and ownership require a reaching definition on the selected route. Computed-address or different-width stores fall outside the literal census. [DG1, DG3–DG4]

## Saved continuation and alternate allocation

Source at `0x1004ccbf0` loads index `0xdfb` from slot `0x101040ec8` and saves `0x1004d7f48` at S+0x7738 B. On either the null or mismatch route, `0x100713fd8` reloads it and `0x100713fe0` branches with IA `0xaec3`. The u64 read from S+0x58d0 B at `0x1004d7f58` controls the next dispatch with IA `0x12f4`. Zero gives index `0x7ac1` and target `0x1004de1d4`. The zero control executes the sole literal u64 zero writer found at `0x100592f94`. A separately supplied nonzero word gives `0x7b24` and `0x100618538`. [DG4]

The latter block uses the recovered bank values `0x101031da0` and `0x100e99900` at S+0x5f0 and S+0x5e0 B. Across all 256 input bytes, key `0x9a` and addend `0xcb28` select index `0xcc0d`, slot `0x10109ff58`. At the pending call `0x1006185ac`, X0 is 16, IA diversity is `0x6aa4`, and the binding is `libSystem/_malloc`. This call site is distinct from the 16 B allocation previously analyzed at `0x100699858`. No allocation return is supplied at the new boundary. [Constructor bank origins](daemon_constructor_bank_origins_report.md) [DG3–DG4]

## Assumptions and check limits

| Premise | Dependent result | Falsification control |
| --- | --- | --- |
| DG-A1. Original image and logical fixups identify the daemon build. | Instruction addresses and branch bindings. | Verify the pinned image hash and all selected original fixups. A different build requires rederivation. |
| DG-A2. Detached 32 B backing and producer slices apply to the captured continuation. | Client field meanings and memory accesses. | Compare initialized and one-bit-modified status, use the original zero store for null, and check the full read footprint. Native frame identity and owner provenance remain unknown. |
| DG-A3. The detached saved-continuation producer and phase apply. | Concrete indices and match/mismatch targets. | Retain CPU context at entry, track the exact S+0x7738 save/reload, and check fixup metadata. Hardware PAC remains unobserved. |
| DG-A4. The alternate u64 and the two bank roots are explicit premises. | Pending 16 B allocation. | Vary the alternate word between zero and nonzero, enumerate the 256 bank selections, and stop at the exact pending call. |

The bounded replay scales linearly with executed instructions. The bank check uses 256 iterations and bounded storage. Validation covers the stated widths, exact field flow, branch targets and API request size. The high-impact unresolved joins are the live producers for S+0x3650 and S+0x58d0 B and the downstream path to a transport boundary. The checked slice contains no observed Mach or IOKit emission.
