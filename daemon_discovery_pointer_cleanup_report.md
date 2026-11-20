# Discovery pointer cleanup and scratch continuation

With the recovered bank roots, the nonzero pointer loaded from S+0x17a0 B reaches `libSystem/_free` unchanged in X0 at `0x1005bfaf0`. Zero takes the direct branch to `0x10083ea7c`. Both paths reach the same local cursor rewind of 2,032 B. A separately entered source component identifies a compatible continuation producer and also reserves 2,032 B. Which producer reaches the live discovery frame remains unknown. [DP1–DP4]

```text
S+0x17a0 --> X0
             |
             +-- zero -------------------+
             +-- nonzero --> free(X0) ---+
                                         |
                       S+0x16d0 -= 2032 B
                       branch via S+0x57a8
```

| Evidence | Primary artifact |
| --- | --- |
| DP1 | Pinned daemon image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Source ranges and format-12 fixups identify the addresses below. |
| DP2 | [Discovery cache sealing](daemon_discovery_cache_codec_report.md). The parent replay reaches the pointer load before introducing a value for the missing stack slot. |
| DP3 | [Constructor bank origins](daemon_constructor_bank_origins_report.md). The original initializer writes S+0x9b0 at `0x1004c2584` and S+0x9a8 at `0x1004c349c`. |
| DP4 | [Replay](triage_evidence/audit_daemon_discovery_pointer_cleanup.py) and [receipts](triage_evidence/daemon_discovery_pointer_cleanup_audit.json.zst). Three cleanup controls, two 256-input bank enumerations, and detached allocation and continuation-source checks. |

## Pointer lifetime and converging branches

| Site | Effect in the selected phase `0x6cf4` |
| --- | --- |
| `0x100577fc0` | Load the u64 at S+0x17a0 B into X0. |
| `0x100577fec` | Branch directly to `0x10083ea7c` for zero or via `0x1005bfa84` for nonzero. |
| `0x1005bfaf0` | Nonzero arm calls the import bound through slot `0x10109ff30`, IA `0x46a2`. X0 equals the full loaded pointer. |
| `0x1005bfb00` | Upon modeled return, branch through index `0x327`, slot `0x10103b828`, IA `0x1910`, to `0x10083ea7c`. |
| `0x10083ea7c` through `0x10083ea84` | Subtract `0x7f0` B from the u64 cursor at S+0x16d0 B, modulo 2^64. In the replay the signed interpretation changes from -240 B to -2,272 B. Live SP stays fixed. |
| `0x10083ea88` | Load the saved continuation at S+0x57a8 B. The main cleanup replay stops before the read. |

The two 256-byte bank arrays come from `0x100fc4230` and `0x101031fa0`. Let i be the low byte of `u32(((controller1 - controller0) XOR 0xa6) * 0x0a5cd4cf)`. For every i, `0xcbc5 + (i XOR right[left[i] XOR 0xf3])` selects `0xcc08`, the `free` import. Both modeled post-call X0 words, zero and `0xffffffff`, reach the same rewind. The chosen phases, source arithmetic and logical fixups establish the call. Native allocation ownership, deallocation and pointer authentication are unknown. [DP1–DP4]

A detached allocator component at `0x10077b058` uses the same bank roots with key `0x6c` and addend `0xcb86`. All 256 byte inputs select index `0xcc0d`, slot `0x10109ff58`, IA `0x6aa4`, binding `libSystem/_malloc`. X0 is 164 B at that call. The original store at `0x10077b05c` saves the return at S+0x1998 B. A separately entered slice at `0x1002aa0dc` copies that exact word to S+0x17a0 B. This is a specific allocator-to-cleanup candidate with matching slot and value flow. The intervening branches and frame identity required to make it a reaching definition are unknown. [DP1, DP4]

## Saved continuation

At `0x10058bc40`, W22=`0xe0a` is a conditional input derived from the downstream slot, `0x76aa - 0x68a0`. The original source uses that W22 to select the setup block and then save a second table entry. The analogous reservation and rewind each use 2,032 B. The detached pairing restores the starting cursor and reaches `0x1004ccbe4` through the saved pointer.

| Site | Effect under the detached premises |
| --- | --- |
| `0x10058bca0` | Index `0x76aa`, slot `0x101075440`, IA `0xc77e` selects `0x1007cfa3c`. |
| `0x1007cfa48` / `0x1007cfa4c` | Load index `0xe0a` from slot `0x101040f40` and save `0x1005e6020` at S+0x57a8 B. |
| `0x1007cfae4` / `0x1007cfaf8` | Reserve 2,032 B in the local cursor and branch to `0x10053b8a8`. |
| `0x10083ea90` | After the separately entered rewind, reload and branch to `0x1005e6020` with IA `0x8ac1`. |
| `0x1005e6084` | Index `0x3c55`, slot `0x101058198`, IA `0x08f3` selects `0x1004ccbe4`. |

## Assumptions and verification bounds

| Premise | Dependent result | Falsification probe |
| --- | --- | --- |
| DP-A1. The pinned image and recovered bank roots apply to this path. | Import targets and address mappings. | Recompute both banks over every u8 index and check the original chained fixups. |
| DP-A2. The pointer and API returns are declared model inputs. | Forwarding to `free`, cursor convergence and candidate allocation origin. | Vary nullness and the post-call value. Require a source-linked predecessor and same owner before attributing a native allocation. |
| DP-A3. The detached setup enters with W22=`0xe0a` and declared scalar frame inputs. | Continuation identity and matched scratch extent. | Verify the branch slots, save/reload and inverse cursor effects. A different reaching W22 or an intervening overwrite can invalidate the pairing. |
| DP-A4. Discovery phase `0x6cf4` and the prior frame state are inherited from the pinned replay. | Specific post-free and downstream branch targets. | Check the restored register context and the initial cursor at the parent stop. A different phase requires recomputing the indices. |

The bank enumeration is O(256) per call site with bounded storage. Replaying the paths costs O(executed instructions). The checks establish pointer width, exact argument forwarding, modular byte extents and source provenance. High-impact unresolved joins are the live writer for S+0x17a0 B and whether the compatible S+0x57a8 B writer reaches the same frame. Medium-impact unresolved evidence is a continuous path from the new continuation to a native transport call. No Mach or IOKit emission was observed in this bounded replay.
