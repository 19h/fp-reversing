# fairplayd selector 26 error record

The pinned daemon has a conditional path from the selector 26 cleanup tail to a 4 B result-record store. At `0x100092578`, W22 takes the saved word from SP+0xe8 B. At `0x1000acc50`, `str w22, [x0, #8]` writes that word verbatim to the record whose address was saved at SP+0x90 B. The recovered path requires `W28 = 0x8934` at `0x1000242f8` and a null pointer in the second cleanup cell at FP−0xb8 B. The reaching definition of W28 for the selected selector 26 callers and the runtime value of the second cell remain unknown. [Prior cleanup path](daemon_selector26_cleanup_report.md)

## Control flow and ABI

| Source location | Check or transfer | Original destination |
| --- | --- | --- |
| `0x1000242f8`–`0x100024310` | With W16=`-0x7e42` and W1=`0x38c0`, W28=`0x8934` gives W23=`0x0af2` and index `0x3232`. X12 becomes FP−0xb8 B. | `0x101053080`, IA `0xca53`, to `0x100008f88` |
| `0x100008f94` | Loads X2 using W23=`0x0af2`. This pass checks the second cleanup cell at `0x100008f98`. | `0x10103f680`, IA `0xf2d5`, resolves to `0x100092550` |
| `0x100008fb8` | A null second cell selects the common tail. | `0x101082518`, IA `0x8e7b`, to `0x100026478` |
| `0x100026484` | Tail-branches through X2. | `0x100092550` |
| `0x100092574`–`0x100092578` | Loads the record pointer from SP+0x90 B and the status from SP+0xe8 B. The separate pointer at SP+0xa8 B controls the branch. | Null pointer selects index `0x63e2` and slot `0x10106be00`. Nonnull selects index `0x6414` and slot `0x10106bf90`. Both use IA `0x49be`. |
| `0x1000dda2c`–`0x1000dda98` | On the nonnull path, the code saves the output pointer in X20, supplies the SP+0xa8 B pointer as X0 to the call at `0x1000dda88`, restores X0 from X20, then branches using W19=`0x63e2`. | On normal return the same record store is selected at `0x1000acc50`. |
| `0x1000acc50` | Stores W22 at record+8 B. The following canary-gated epilogue restores the frame and returns through `retab` at `0x1000acc88`. | Caller of the containing routine, still unidentified for this path |

For the previously recovered inputs `0xffff5bbc` and `0xffff5a87`, the conditional store takes `0x74c29ded` and `0x74c29cd6`, respectively, encoded little-endian as `ed 9d c2 74` and `d6 9c c2 74`. Four solver queries verify the reload and store for every 32-bit word on the two SP+0xa8 B branches under their entry and return premises. The local handoff takes O(1) time and O(1) space, excluding the indirect callee. [Upstream error encoding](daemon_selector26_callers_report.md) [Audit script](triage_evidence/audit_daemon_selector26_status_publication.py) [Compressed evidence](triage_evidence/daemon_selector26_status_publication_audit.json.zst)

The nonnull call at `0x1000dda88` uses byte-bank pointers at SP+0xb8 B and SP+0xc0 B, XOR key `0xa3`, and an index in `[0xcb96, 0xcc95]`. Four original slots in that range match IA `0x46a2`. The `_free` import is one candidate. Call identity remains unknown until the bank bases are recovered. The record receiver and any later Mach or XPC publication also remain unknown.

## Assumption register

| Assumption | Dependent claim and falsification probe |
| --- | --- |
| R1. The original daemon and format-12 fixup catalog match the upstream report. | Source addresses and slot targets. Independently decode original words and compare the imported symbol for each compatible bind. |
| R2. The first cleanup tail enters `0x1000242f8` with W28=`0x8934`, the recorded phase registers and the same SP. | Reentry at `0x100008f88` with W23=`0x0af2`. Invert the index expression for all six in-table IA `0xca53` rebase entries, then trace the original producers of inherited W28 and SP+0x124 B. |
| R3. FP−0xb8 B is null, SP+0xe8 B is live and SP+0x90 B supplies a valid output record. | The direct second tail, exact status reload and 4 B store. Compare both pointer tests and verify the saved status and output pointer in the matched caller frame. |
| R4. The nonnull SP+0xa8 B callee returns normally and preserves X19–X22 under the ordinary ABI. | Convergence after the call. Test with independent X0 return values and verify the final field and both preserved inputs. Establish the bank origins and call identity separately. |

| Impact | Open join |
| --- | --- |
| High | Identify the reaching definitions for W28 and the output pointer, then trace consumers of record+8 B. |
| Medium | Establish whether `0x1000dda88` retires the SP+0xa8 B object and whether a nonnull second cleanup cell reaches the same publication. |

QG1–QG7 apply to the conditional static handoff. The source trace establishes local record publication under the stated premises. Native reachability and the external receiver remain open.
