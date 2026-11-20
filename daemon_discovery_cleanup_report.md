# Discovery cleanup dispatch and output-pointer references

The first branch after the discovery marker consumer tests the pointer in S+0x8878 B. A nonnull value reaches `free` with that pointer in X0. The null arm reaches a separate owner-state check. Neither bounded arm accesses the 16 B output. A scan of the original daemon text locates four byte readers and one byte writer through the same literal SP-relative pointer slot, S+0x1ba0 B. Their reaching definitions remain unknown. [Owner record](daemon_discovery_owner_report.md) [Audit](triage_evidence/audit_daemon_discovery_cleanup.py) [Receipt](triage_evidence/daemon_discovery_cleanup_audit.json.zst)

## Marker and pointer dispatch

S is the enclosing SP. At `0x1008eb590`, W22 is the marker from S+0x4804 B except when that marker equals `0x8b3dc651` and the byte at S+0x2b7f B equals 1. In that case W22 is `0x74c29db1`. The original initializer at `0x100790824` clears S+0x8878 B. The consumer loads the full pointer into X0 at `0x1008eb598`. At `0x1008eb5c0` the signed 32-bit table index is `(W23 + 0x3520) XOR (0x3d * (X0 != 0))`, with the addition taken modulo 2^32.

| S+0x8878 B at phase `0x6cf4` | Index | Fixup slot, IA `0x149f` | Next block | Observed boundary |
| --- | --- | --- | --- | --- |
| Null | `0xa214` | `0x10108af90` | `0x1005bb048` | `0x10080a4d4`, before a load through the pointer in S+0x6fb8 B. |
| Nonnull | `0xa229` | `0x10108b038` | `0x10079dc3c` | `0x10079dca0` calls `free` with X0 equal to the pointer. |

On the nonnull arm, the byte banks at S+0x5d0 B and S+0x5d8 B, key `0x61` and base `0xcbef`, resolve the call to slot `0x10109ff30`, IA `0x46a2`, and the original `libSystem/_free` import. The replays stop at the import entry. The post-return table load at `0x10079dca4` uses index `W23 - 0x45be`, saved in W19 before the call. At phase `0x6cf4` this resolves to slot `0x10104d8a0`, IA `0x8dec`, and the same block `0x1005bb048`. Native allocation provenance and return remain unknown. [Bank producers](daemon_constructor_bank_origins_report.md)

On the null arm, `0x1005007d8` loads X20 from S+0x5670 B. The prefix ending at `0x10057f804` initializes that field with the encoded null address `0x4aba552460e435c6`. With this reaching definition the replay takes `0x1006c3eb8 -> 0x1006902e4`. The former block loads an authenticated continuation at `0x1006c3e6c` and saves it at S+0x3aa8 B at `0x1006c3e70`. The latter reloads it and transfers to `0x1005840bc` at `0x1006902ec`. Two more transfers reach `0x10080a4b8`, whose pointer load at `0x10080a4d0` uses S+0x6fb8 B. Its reaching definition is required to extend the replay. The full branch sequence and original fixups are in the receipt.

## Literal destination uses

The census covers scalar unsigned-offset 64-bit `LDR` and `STR` with base SP and displacement `0x1ba0` in the original `__text`. It finds seven loads and four stores to the slot. Each byte reader loads the pointer, reads byte zero and stores the byte zero-extended into a 4 B frame field.

| Pointer load | Byte access | Local effect |
| --- | --- | --- |
| `0x100986634` | `0x100986638` read | Store at S+0x5e4 B. |
| `0x100a145b4` | `0x100a145b8` read | Store at S+0x1360 B. |
| `0x100a44f98` | `0x100a44f9c` read | Store at S+0x170 B. |
| `0x100b52810` | `0x100b52814` read | Store at S+0xaa4 B. |
| `0x100bbde58` | `0x100bbde60` write | Store `0xe9` to byte zero. |

The other literal loads are `0x10038553c` and `0x100518d24`. At `0x100518d24`, the frame has just been restored from a local call and the pointer is reloaded into X19. A common displacement alone cannot identify a logical field across frames. The four literal stores include `0x1005fac70`, which saves the discovery emitter output pointer, and three other sites whose same-frame applicability is unknown. Base aliases, pointer escapes and pair instructions are outside this encoding census.

## Trace and verification

The archived RAX log records a FairPlayIOKit class match, iterator result and a type-0 open with request ID 2862 and reply ID 2962. The syscall PC for the open is `0x180547c20`. The reply contains a null connection name and IOKit result `0xe00002c2`. The trace has syscall PCs and decoded messages. The internal call edges and any association with the output pointer remain unknown. [Archived request and cleanup](archived_iokit_open_retirement_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The pinned arm64e image supplies the instructions and chained-fixup words. | Address map, literal census and API binding. | Check the image digest, original fixup words and bank output across all 256 byte inputs. |
| A2. The prior emitter and owner fixtures share the scratch frame with the declared separate initializer slices. | Contiguous continuation to the two observed boundaries. | Cross both owner settings with both values of the cleanup pointer. Check the actual saved and reloaded continuation and the X0 value at the import. |
| A3. The detached byte-access slices receive a readable or writable pointer in the named frame slot. | Local byte and word effects. | Prove the load projections over an arbitrary byte and the writer's resulting byte using the original instructions. |

The audit reads the image once for the literal census and performs eight bit-vector checks and four instruction replays. Time is O(w+n) for w text words and n replay instructions, excluding solver work. Receipt space is O(t+s) for t recorded transfers and s matched sites. Run `python3 -B triage_evidence/audit_daemon_discovery_cleanup.py` in the existing Unicorn, Capstone and Z3 setup.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| First byte use of the emitted output | High | Recover the reaching pointer at each candidate load and resolve S+0x6fb8 B at the null arm boundary. |
| Reach to the saved discovery flag | High | Recover the predecessor load of slot `0x101042fc8` and check the last store to S+0x202f B. |
| Cross-layer attribution | High | Match a daemon caller PC and the same frame to a traced IOKit request and its reply. |
