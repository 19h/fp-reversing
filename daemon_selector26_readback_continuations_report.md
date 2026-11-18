# fairplayd selector 26 allocation readback continuations

The two audited `fairplayd` class profiles take the mismatch branch after comparing the decoded first four bytes of the 14 B allocation with a 32-bit frame reference. A separate offline replay sets the reference equal to the decoded word and follows the equality branch. The mismatch clears a frame pointer and reaches a private helper. Equality saves the allocation's owner pointer and reads all 14 bytes before reaching a different allocator call. [Preceding readback and comparison](daemon_selector26_allocation_readback_report.md)

## Comparison and owner pointer

Addresses are unslid in the arm64e daemon image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

The original comparison runs at `0x1009d12e4` against the reference at SP+0xa14 B. The authenticated branch at `0x1009d131c` selects the continuation. Both outcomes reach `0x10065467c`, which loads the destination address from SP+0xa18 B. The store at `0x100654680` writes 8 B to SP+0x418 B. At comparison entry, SP+0xa20 B holds the 32 B owner pointer and owner+0x18 B holds the 14 B child pointer.

| Outcome | First table slot | First target | Value stored at SP+0x418 B | Next allocation call |
| --- | --- | --- | --- | --- |
| Mismatch in both fixtures | `0x1010737e8` | `0x100641ec4` | Zero, set in the block at `0x100a2d86c` | `_malloc(32)` at `0x100948dd0` |
| Modeled equality | `0x101073728` | `0x10065467c` | Owner pointer | `_malloc(32)` at `0x100a17948` |

Both outcomes then pass through `0x100981570` and `0x10064b71c`. At `0x10064b75c`, the mismatch takes slot `0x10104ffa0` to `0x100641f84`. Equality takes slot `0x101067928` to `0x100751f64`.

## Mismatch path

The call at `0x100645f40` resolves to `0x100444dfc` through slot `0x1010a01b0`, with X0 set to FP−0xa0 B. It uses the previously recovered 16 B frame record. The replay resumes with an opaque 64-bit result at FP−0x98 B using the prior helper return model. It takes 15 authenticated edges from the comparison dispatch through the `_malloc(32)` call at `0x100948dd0`, including the helper call. Over that span it makes zero further reads of the child allocation. [Private helper and consumers](daemon_selector26_helper_consumers_report.md)

## Equality path

After the initial four-byte read and comparison, the equality continuation reads the child from byte 0 through byte 13 in order. The same four byte-load PCs occur in each four-byte group. The two-byte group uses the separate decoder at PCs `0x1006a0e44` and `0x1006a0ff0`.

| Child byte offsets | Load PCs in order | Decoder exit PC | Exit slot | Exit target |
| --- | --- | --- | --- | --- |
| 0–3 | `0x100973934`, `0x100973998`, `0x100973cf4`, `0x100973ea0` | `0x100973ed0` | `0x10103d8a0` | `0x10063fc4c` |
| 4–5 | `0x1006a0e44`, `0x1006a0ff0` | `0x1006a119c` | `0x10103aca8` | `0x10063f740` |
| 6–9 | `0x100973934`, `0x100973998`, `0x100973cf4`, `0x100973ea0` | `0x100973ed0` | `0x10103d8b0` | `0x10099ae54` |
| 10–13 | `0x100973934`, `0x100973998`, `0x100973cf4`, `0x100973ea0` | `0x100973ed0` | `0x10103d658` | `0x10090a944` |

The two-byte decoder's continuation writes W19's low halfword at SP+0x82e B (`0x10063f748`) and W19 at SP+0x200 B (`0x10063f75c`). The final group's continuation stores W14 at SP+0x67c B (`0x10090a950`) and reloads the halfword from SP+0x82e B (`0x10090a958`). The path takes 32 authenticated edges through the call at `0x100a17948`. That `_malloc(32)` is the only call on the audited equality path.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Class fixtures `0x98` and `0x99` retain the predecessor's frame staging and allocation identities. Their original modeled reference values select mismatch. | Rebuild both fixtures and check the comparison operands, owner link, and address of the common store. A different reaching definition of SP+0xa14 B in a native invocation would change the recorded predicate. |
| A2 | The equality replay replaces only the compared frame word. Its path and 14 reads apply to that offline state. | Independently lift the equality continuation with the reference constrained equal and check the branch, effective addresses, and allocator arguments. Native equality reachability is unknown. |
| A3 | The mismatch helper is modeled with an opaque 8 B output, ABI register clobbers, and the caller's frame intact. The mismatch continuation depends on that call model. | Lift the helper at this call site and compare its actual writes and preserved registers with the modeled effects. |

The audit checks the original daemon SHA-256, all 39 distinct chained fixups, the common pointer store in both outcomes, and the load order and widths for both class profiles. It verifies that the owner+0x18 B link still points to the same child and that no stores overlap the child before either allocation call. The replay stops at those calls, before their results. No IOKit call, Mach send, or release occurs within either audited span. [Reproducible audit](triage_evidence/audit_daemon_selector26_readback_continuations.py)

Run from the repository root with the same pinned image inputs as the preceding audit.

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_readback_continuations.py
```

| Impact | Open evidence |
| --- | --- |
| High | Follow both allocator returns to the next transfer or release of the original 14 B child. Native lifetime is unknown. |
| High | Correlate an ordinary successful daemon request with the kext method. The native exchange is unknown. |
| Medium | Establish the reaching producer of SP+0xa14 B and the helper's actual effects at `0x100645f40`. |
