# CoreFP selector-gated slot reset and preparation-field retirement

Original CoreFP routine `0x1f530c` implements a selector-gated reset under decoded operation `0xf7a5`. It acquires the same token at image+`0x1d33108` used by the protected root, tests selector image+`0x1d44409` for equality to 1, and walks 88 B slots starting at image+`0x1d32dd0`. Each selected slot can request `_free` of its +8 field. The routine resets the other 80 B, clears the selector at `0x1f5650`, restores the token and returns. Eleven private profiles are independently replayed.

This identifies a selector-clear writer and a reset writer for the root's preparation field at image+`0x1d32e18` (first slot+`0x48`). That field is separate from the free argument at slot+8. The routine does not establish a selector-set-to-1 producer or a valid preparation-object initializer. Native callers, object ownership, successful protected processing and daemon/kext pairing remain unknown. The full investigation remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_optional_reset.py), [checks archive](triage_evidence/corefp_optional_reset_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_optional_reset.py), [audit archive](triage_evidence/corefp_optional_reset_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_optional_reset_publication.py) retain the evidence. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; offsets are hexadecimal, extents are bytes (B), and arithmetic widths are explicit. Original file bytes and decoded chained-fixup rows are primary evidence. A current read-only MCP request reports no matching authenticated IDA bridge worker; live database contents and knowledge-store results are unknown. No new live corroboration is claimed.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OR1 | The pinned image, compiler bounds, import/fixup reader and retained source identify this routine. All source results depend on them. | Compare the complete 1400 B body, every executed instruction, original authenticated-edge rows and eight independently enumerated byte-table banks. Preserve the three supplied inputs. |
| OR2 | An aligned private record with decoded operation `0xf7a5` is the analyzed entry configuration. Source continuity is conditional on this entry. | Reconstruct all initial CPU/RAM states independently. Check the address-key reduction over all u32 addresses and verify original dispatch row `0x1cfd668`. A real incoming caller has not been established. |
| OR3 | Sequential CASAL and PAC models preserve the recorded selected edges. Token behavior depends on these models. | Check exact before/after CPU and RAM, reaching pointer loads, IA modifiers and original fixup rows. Busy-token input follows the original retry edge and stops before a second CASAL. Native atomic ordering, signing and concurrency are unknown. |
| OR4 | Selector/count/slot changes are explicit diagnostic inputs. Reset coverage depends on their bounded backing. | Test selectors 0,1,2,255; counts 0,1,3; null, backed and mixed slots. Distinct 64 B private allocations support positive free controls. These fixtures do not establish native capacity, initialization or external control. |
| OR5 | The `_free` model retires only declared private allocations and retains their mapped bytes. Lifetime observations depend on this model. | Check four matching-pointer retirements, no model RAM changes, caller-register clobber and a distinct residual X0. The original raw field reaches a stop before the import effect; no native free executes. |
| OR6 | Source reset bytes describe encoded state without assigning unknown semantic types. The field join to the root is structural. | Independently lift all 33 literal-reset instructions, compare each field width/value, replay every store and check root load `0x8eadfc`. Reset at +0x48 is not an initialized pointer. Native object types and owners remain unknown. |

## Entry, pointer banks and token flow [OR1-OR4]

For record address `R`, all operations below are modulo 2^32:

```text
K(R) = (low32(R) XOR 0x341dc0b1) * 0xdb676c6f
decoded_operation = load_u32(R) XOR K(R)
```

The original OR-minus-AND expression reduces to the XOR above. Three UNSAT obligations establish that identity, its XOR-constant reduction and tag round-trip. Equality is preserved by multiplying both reduced operands by the same u32 constant. The operation record is read, remains unchanged and receives no result store on any retained path. Residual X0 does not establish a semantic return type.

An authenticated original pointer row at `0x1d04f48` targets entry `0x1f530c` with IA diversity `0x30ae`. This row alone does not identify an incoming caller. The entry updates two u64 obfuscation-state cells before dispatch and token acquisition; even the busy-token prefix has those stores. The selected operation row `0x1cfd668`, IA diversity `0xeadc`, reaches `0x1f54c0`.

Every bank below independently checks all 256 values of the source's low-byte index `x`, using `x XOR B[A[x] XOR c]`. The resulting constant selects the original pointer row. This removes the current mutable state value from each bank identity; it does not prove arbitrary whole-function paths.

| Bank | XOR c | Constant | Original pointer row | Selected destination |
| --- | --- | --- | --- | --- |
| First state | `0x58` | `0x7e` | `0x1d0c100` | image+`0x1d353b8` |
| Second state | `0x89` | `0x77` | `0x1d120a8` | image+`0x1d37f68` |
| Dispatch base | `0x8c` | `0xa3` | `0x1d108e8` | image+`0x1c81944`, then subtract4 |
| Token | `0x0b` | `0x09` | `0x1d065d0` | image+`0x1d33108` |
| Selector | `0xc8` | `0xc0` | `0x1d0fe78` | image+`0x1d44409` |
| Slot count | `0x89` | `0x77` | `0x1d0bd18` | image+`0x1d36090` |
| Slot base | `0x27` | `0x18` | `0x1d133e0` | image+`0x1d32dd8`, then subtract8 |
| Free import | `0x27` | `0x18` | `0x1d03570` | `_free`, IA diversity `0x7c9f` |

```text
entry -> update two obfuscation-state cells -> decode operation0xf7a5
      -> CASAL at0x1f54fc: compare0x5d96, replacement0x0a94ef
          mismatch -> original retry edge -> STOP before second CASAL
          match -> selector read/compare
              !=1 -> restore token0x5d96 -> return
              ==1 -> read count -> zero count skips slots
                    -> slot+8 nonzero? -> free boundary -> sentinel store
                                      -> null bypass
                    -> common80 B reset -> increment index -> unsigned bound
                    -> clear selector -> restore token -> return
```

The selector lies in `__DATA,__common`, a Mach-O `S_ZEROFILL` section. The pinned mapping starts it at zero; physical segment padding is not a file-backed section initializer or evidence of its live value. The original slot count is 1. Count-zero is a sensitivity control; count-three supplies three explicitly backed diagnostic slots and establishes no native allocation extent. The loop retains its count across null-slot iterations and reloads it after `_free`. Concurrent count changes are outside the model.

## Exact slot fields and reset effects [OR1,OR4-OR6]

Let `S = image+0x1d32dd0 + 88*i`. Original `0x1f57c4` reads u64 at `S+8`, and `0x1f5854` calls `_free` with that value when nonzero. Source `0x1f586c` then stores zero-extended u32 constant `0x614a2fa7` into the same eight-byte cell. A null cell bypasses both free and sentinel store and remains null. The common block writes exactly 80 B per slot.

| Offset from S | Store width B | Stored integer | Original store site |
| --- | --- | --- | --- |
| `0x00` |8 | `0x29acdb77` | `0x1f56b0` |
| `0x08` |8 | `0x614a2fa7` after free; null preserved otherwise | `0x1f586c` |
| `0x10` |4 | `0xfb394ce9` | `0x1f56c4`, first element |
| `0x14` |4 | `0x3f74e630` | `0x1f56c4`, second element |
| `0x18` |8 | `0x99960b5a` | `0x1f56d0` |
| `0x20` |4 | `0xeb152103` | `0x1f56e4`, first element |
| `0x24` |4 | `0xcbc97b7d` | `0x1f56e4`, second element |
| `0x28` |8 | `0x20a6b15dcc57f527` | `0x1f5700`, first element |
| `0x30` |8 | `0xeb20c546` | `0x1f5700`, second element |
| `0x38` |8 | `0x44710b16` | `0x1f5714`, first element |
| `0x40` |8 | `0x058aaa16` | `0x1f5714`, second element |
| `0x48` |8 | `0x0176cb4e` | `0x1f5728`, first element |
| `0x50` |8 | `0x6c426f1a` | `0x1f5728`, second element |

Eight-byte stores sourced by W-register definitions zero their upper 32 bits. The common-reset sum is `8 + 4 + 4 + 8 + 4 + 4 + 6*8 = 80 B`; adding the conditional pointer-cell store gives 88 B. A fourth UNSAT obligation checks the original index increment at observed W24=`0x79b8`; replay checks that phase and every successive slot index. The original unsigned comparison is against the zero-extended u32 count.

The earlier [preparation route](fpsd1201_key_routes_report.md) loads the slot base at `0x8eadf8`, then reads its +`0x48` field at `0x8eadfc`. That address is exactly image+`0x1d32e18`. Its pinned original value is `0x176cb4e3`; this reset writes `0x0176cb4e`, a different value. Neither number is established as a valid native object address. The optional pointer remains unresolved in the [coherent caller-to-cold continuation](corefp_caller_cold_report.md); this increment does not resume that root past its stopped read or compose reset with a native lifetime.

| Shared field | New established writer / effect | Still unknown |
| --- | --- | --- |
| Selector image+`0x1d44409` | `0x1f5650`, one-byte clear after selected reset, including count0 | Writer of 1, admission and actual live epoch |
| Preparation field image+`0x1d32e18` | `0x1f5728`, eight-byte reset in first slot | Valid object producer, full schema and ownership |
| Free field image+`0x1d32dd8` | Read at `0x1f57c4`; conditional post-free sentinel at `0x1f586c` | Actual allocated-object producer and native lifetime |
| Count image+`0x1d36090` | u32 read; no source write on retained paths | Count producer, native capacity and mutation policy |
| Token image+`0x1d33108` | Sequential modeled CASAL, then original restore at `0x1f5664` | Native atomic ordering and cross-thread behavior |

## Profiles, ABI and cross-level bounds [OR1-OR6]

| Profile | Selector | Count / slots | Original visits | Outcome |
| --- | --- | --- | --- | --- |
| Original zero |0 | Original |185 | Immediate post-gate return |
| Selector two |2 | Original |185 | Same bypass |
| Selector255 |255 | Original |185 | Same bypass |
| Empty |1 |0 |223 | Clear selector, restore token, return |
| One null |1 |1 null |315 |80 B reset, null preserved, return |
| Three null |1 |3 null |499 |240 B reset, return |
| One backed |1 |1 backed |350 | One private retirement,88 B reset, return |
| Backed/clobber |1 |1 backed |350 | Same effects with volatile registers and residual X0 changed |
| Mixed three |1 | Null, backed, backed |569 | Two private retirements,256 B reset, return |
| Original-slot frontier |1 | Original raw slot |270 | Stop before `_free(0x614a2fa7)` effect; token held |
| Busy token |0 | Original |147 | One failed CASAL model, stop before retry; token held |

Only `_free` is reached as an external call in this routine's retained configurations. Arm64e SDK syntax-only assertions verify `void free(void *)`, eight-byte pointers and four-byte u32. A declared residual X0 is an execution fixture for the void import, not an API result. The original-slot control does not execute native free, simulate reclamation of the raw value or reproduce a native fault.

No Mach send, receive, port allocation, descriptor transfer or daemon child is reached or newly identified. The shared token and holder establish a CoreFP state interface with the earlier protected-root analysis; they do not establish a native daemon/kext exchange. No incoming external control origin has been established for the selector, count, slots or operation record.

Independent replay checks 11 initial CPU frames, 1261568 B of initial touched RAM and the same final extent; 3278 original instruction visits,717 reads,311 writes,73 authenticated-edge models,15 declared effects and54 checkpoints. Four private allocations are retired, with their mapped bytes retained. Eight banks cover2048 inputs. Four symbolic obligations are UNSAT;32 exact instruction assertions,33 independently lifted literal-reset instructions and8 additional root-reference bytes pass. One complete 1400 B reset body is retained. Native target/API/IPC and IDB mutation remain absent.

Conservative replay/enumeration cost is `O(C*(B+P*F+V*J+R)+256*K)` time/space, including inherited per-page fixup and reaching-load scans. C denotes profiles, B source bytes, P touched pages, F fixups, V visits, J journal size, R retained state and K=8 banks. Each source execution is capped at4000 visits. Symbolic solver cost is separate, capped at30 s/query. These finite paths do not establish universal native termination or memory safety.

| Impact | Bounded continuation / discriminating evidence |
| --- | --- |
| High | Resolve a complete incoming caller to `0x1f530c`, including its operation-record producer and frame epoch. An IA modifier or pointer row alone is insufficient. |
| High | Recover the selector-set-to-1 producer and valid slot+0x48 preparation-object construction. The reset writer closes only the clearing/retirement side. |
| High | Establish count/slot allocation extent and matching object lifetimes, then join prepared input to successful root processing and a matched daemon/kext epoch. |
| Medium | Determine whether slot+8 and slot+0x48 refer to related ownership domains. Their field addresses and reset effects are distinct; common allocation identity is unknown. |
| Medium | Resolve wider/adjacent selector writes and additional operation routes. The current literal/table search is a lead generator, not an exhaustive alias or writer census. |

**QG1** passes: factual technical analysis. **QG2** passes: OR1-OR6 register assumptions and probes. **QG3** passes for this report; the full objective remains incomplete. **QG4** passes: widths, extents, reset sums and bounded costs are explicit. **QG5** passes: initialization versus reset, +8 versus +0x48, count reloads, busy-prefix effects, raw-import stop and native ownership remain distinct. **QG6** passes: pinned bytes/fixups, independent CPU/RAM replay, table enumeration, byte-layout oracle, symbolic checks and SDK assertions support the bounded claims; live IDA is unavailable. **QG7** passes: impact-ranked continuation covers admission, initialization, aliases, environment and cross-level identity.
