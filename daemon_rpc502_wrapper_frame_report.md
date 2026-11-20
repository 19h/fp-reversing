# fairplayd RPC 502 wrapper stack and helper dispatch

The outer wrapper at `0x100de7d7c` forwards its input record and creates a separate stack displacement cell for the inner wrapper at `0x100de574c`. A private replay from the outer entry reached original instructions that wrote all three dispatch pointers. A second interval reused the same stack and reached the local environment helper `0x100de1430` from `0x100de7a8c`. The call remains conditional on the incoming continuation state. Both intervals use the original thin Mach-O identified by SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` and UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Addresses are preferred virtual addresses. [Prior authenticated-dispatch audit](daemon_rpc502_dynamic_dispatch_report.md)

## Outer wrapper ABI

| Site | Data flow |
| --- | --- |
| `0x100de7e6c` | Read 8 B input word `q` through the original X1. |
| `0x100de7e78–0x100de7ec8` | Compute `v = (q * 0x2edd + 1) mod 2^64` and reserve `16 * (1 + (v >> 60))` B. The exact range is 16–256 B in steps of 16 B. |
| `0x100de7ee4–0x100de7ef0` | Lower SP by the calculated allocation and store `q - 0xb0` modulo 2^64 at the new SP. |
| `0x100de7f7c` | Call `0x100de574c` through slot `0xeb` with the original X0 and the address of the displacement cell as X1. |
| `0x100de586c–0x100de5874` | The inner prologue adds `0xb0` to the cell, recovering `q` modulo 2^64. |
| `0x100de7f80–0x100de7f8c` | On normal return, the outer wrapper reads the cell's low 32 bits and subtracts the original low 32 bits of `q`. It writes the low 16 bits of the difference shifted left four bits as an 8 B value through the original X1. This is a static epilogue result. |

The allocation formula is dimensionless until the instruction applies its result as a byte displacement. The outer replay exercised the 16 B and 256 B endpoints and checked the inner prologue's compensating store. The outer epilogue was disassembled. The replay stopped inside the inner wrapper before that epilogue ran.

## Dispatch pointer custody

| Slot, relative to inner SP | Original producer | Observed value |
| --- | --- | --- |
| `+0x28` | `0x100de5938` forms the right lookup pointer. `0x100de6bac` stores it through X26. | `0x101032c70` |
| `+0x30` | `0x100de57f4` loads the left lookup pointer. `0x100de6bac` stores it through X28. | `0x101032b70` |
| `+0x58` | `0x100de5984` stores the table base. | `0x1010ab1a0` |

The first interval entered `0x100de7d7c` with a synthetic carrier and stopped at `0x100de6bb0` after the pair store. The second interval started at `0x100de7878` in the same mapped frame. It inherited the three dispatch slots and supplied W19 = `0x25`, the saved context at SP+`0x78`, and the readable image-cell pointers in X23 and X24. Those inputs define a model of the continuation entry. The natural path from the first interval to that continuation is unknown.

The second interval followed the local displacement wrapper from `0x100de7958` to `0x100de9cd8`, then deeper into `0x100de7fa4`. The nested wrapper returned an observed zero displacement at SP+`0xd0` and the parent retained its original SP at `0x100de7968`. The three pointer slots retained their original contents. At `0x100de7a8c`, X8 held `0x100de1430`, X17 held `0x19ad` and X0 addressed the parent frame at X29 minus `0x78` B. The replay entered the helper. A longer exploratory run reached the modeled read-only query for `kern.hv_vmm_present` and stopped in a later comparison continuation. The helper's output word was unobserved for this call site.

| Continuation | Matching original table index and IA modifier |
| --- | --- |
| `0x100de7878` | `0x02 / 0x900e`, `0x4d / 0x36b3`, `0xb4 / 0xf57a` |
| `0x100de79c8` | `0x75 / 0xf57a` |
| `0x100de1430` via the call at `0x100de7a8c` | `0xe7 / 0x19ad` |

The nearby linear predecessor at `0x100de7744` cannot supply the fixture's W19 value through its straight-line path. It masks W24 with `0xa6c41f37` before setting W19 to W24 plus `0xc`. The necessary W24 value `0x19` requires the cleared bit `0x08`. A follow-up derives the distinct state carried by the early slot 2 branch. The other branch sites still require reaching-definition evidence. [Early continuation selector](daemon_rpc502_predecessor_report.md) This gives a concrete constraint on any attempt to join the intervals.

## Assumption register and verification

| Assumption | Impact and dependent result | Falsification probe |
| --- | --- | --- |
| F1. The pinned daemon and its original fixups describe this build. | High. Dispatch slots and instruction addresses are build-specific. | Rehash the image and compare the raw slot words, decoded targets and modifiers. |
| F2. The carrier, later inherited registers and saved-context pointer describe finite private replay inputs. | High. Continuation dispatch and preserved pointers are observed for those inputs. Native reachability is unknown. | Recover the earlier writers for W19, X23, X24 and SP+`0x78` on an original path into the continuation, then replay from before those writers. |
| F3. The private runner normalizes chained pointers and models stack probing in mapped memory. | High. The observed control flow validates referents and argument transfer in the model. | Compare original chained words independently and use an ordinary native observation to establish hardware authentication and production reachability. |
| F4. The nested wrapper returns a zero displacement for the observed continuation. | Medium. Custody across a nonzero parent-relative shift remains unknown. | Obtain a complete earlier continuation that produces a legitimate nonzero displacement and locate the three slots relative to its subsequent SP. |

The bounded architectural finding is local stack-mediated control flow, with a high-impact distinction for RPC 502 transport attribution. The helper edge itself transfers a local frame pointer. The modeled intervals provide no native Mach port observation or FairPlayIOKit linkage. The transport census remains the basis for actual emission sites. [Daemon Mach transport census](daemon_iokit_retirement_report.md) [Repeatable offline checkpoint receipt](triage_evidence/daemon_rpc502_wrapper_frame_audit.json.zst)
