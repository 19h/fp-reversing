# fairplayd selector 26 caller records and status gate

Two caller fragments prepare different selector 26 records in the same stack location. On return, each reloads its own result field into W16 and branches to the same comparison. In the recovered phase, the two documented IOKit errors take the same continuation and remain distinguishable in a caller stack cell. [Selector 26 callee returns](daemon_selector26_return_report.md)

| Stage | Direct structure | Stack descriptor |
| --- | --- | --- |
| Caller entry | `0x1000f20f4` | `0x100111684` |
| Local call | `0x1000f2204` | `0x100111754` |
| Code pointer | Slot `0x1010a0ab8`, IA `0xe047`, entry `0x10043a018` | Slot `0x1010a0ca8`, IA `0x7833`, entry `0x10043ee28` |
| IOKit call | `0x1002069c4` | `0x100293074` |
| Result read | `0x1000f220c`, u32 at record+24 B | `0x10011175c`, u32 at record+8 B |
| Shared status gate | `0x1000745f4` | `0x1000745f4` |

## Selecting the record ABI

The dispatch fragment at `0x1000c62f0` loads a byte through X6 and subtracts the low byte of its companion word at SP+0x38. In the selected phase W10=`0xa4c7`, adjusted byte `0x2d` selects index `0xa4c7` and the stack descriptor caller. Every other u8 value selects index `0xa4cb` and the direct structure caller. The original table words at `0x10108c528` and `0x10108c548` carry IA discriminator `0x705d`. This establishes how the local fragment uses the byte. The upstream origin and reachability of the selected frame and phase remain unknown.

Both callers set X0 to record address FP−0x80. They read the connection context from SP+0x88 and use X7 as the structure pointer or payload destination. The u64 extent input at SP+0x130 contributes its low u32 to either record through the address-derived codec. The selected direct structure record decodes to control `0xbf1d`, and the descriptor record decodes to `0xb469`.

| Record field | Direct structure | Stack descriptor |
| --- | --- | --- |
| Data address, u64 | +0 B | +24 B |
| Connection context, u64 | +8 B | +16 B |
| Encoded extent, u32 | +16 B | +0 B |
| Encoded control, u32 | +20 B | +4 B |
| Result written by callee, u32 | +24 B | +8 B |

The direct caller resolves its banks through original pool words and signed biases. For all 256 byte inputs, key `0x61` gives `0x19`, which combines with `0xcd60` to give table index `0xcd79`. The stack descriptor caller loads the bank addresses from SP+0x70 and +0x68. With original bank bases `0x101031da0` and `0x100e99900` in those cells, key `0x86` gives `0x58`, which combines with `0xcd5f` to give index `0xcdb7`. Those exact cell values at this call are a premise. Both call targets and IA fields are independently decoded from original fixup words.

The modifier `0x7833` alone is insufficient to identify the selector 26 helper. The call at `0x1000b3a94` uses the same modifier and a different original bank pair, which selects slot `0x1010a0be8` and target `0x100454f60`.

## Return classification and propagation

After either local call, the caller restores the table base from FP−0xd0, loads the u32 result into W16 and branches through index `0x7ef7`, slot `0x1010796a8`, IA `0xa27c`. The selected W19 phase is `0x4d3f` in both fragments. The shared gate derives the comparison word as `u32((W19 xor 0x462e) + 0x8b3dbb40)`, which evaluates to `0x8b3dc651`. The gate tests the record field. The callee's X0 is immaterial to this comparison.

| Record result | Gate slot and destination | Subsequent effect in the audited range |
| --- | --- | --- |
| `0x8b3dc651` | Index `0x8c08`, slot `0x10107ff30` to `0x1000acd3c` | Takes the zero-status continuation. |
| `0x74c29ded` from `0xffff5bbc` | Index `0x4d3f`, slot `0x1010608e8` to `0x100013334` | Stores `0x74c29ded` at SP+0xe8 at `0x1000c3178`, then branches to `0x100008f88`. |
| `0x74c29cd6` from `0xffff5a87` | Index `0x4d3f`, slot `0x1010608e8` to `0x100013334` | Stores `0x74c29cd6` at SP+0xe8 at `0x1000c3178`, then branches to `0x100008f88`. |

The mismatch path moves W16 into the low word of X10 before storing W10. The same paired store saves a separate companion word at SP+0xec. The symbolic check covers all raw words other than the comparison marker. The two error cases therefore share control flow while retaining distinct values. Their later translation, retry behavior and propagation to an external response remain unknown. This increment follows local calls, loads and stores. No additional Mach emission site or native transaction identity was established. [Mach transport and rights](iokit_sync_error_reply_report.md#from-kernel-reply-to-the-framework-return)

## Evidence and assumptions

The [auditor](triage_evidence/audit_daemon_selector26_callers.py) checks the pinned image, three exhaustive 256-input bank selections, original chained pointer words, six symbolic obligations and six selected profiles. The [compressed receipts](triage_evidence/daemon_selector26_callers_audit.json.zst) contain original instructions and the resolved branches. Each selected caller fragment and status gate takes O(1) time and extra space. Source replay is O(I) in the number of lifted instruction visits, with O(I) evidence storage and separate solver costs.

| Assumption | Dependent result and falsification probe |
| --- | --- |
| C1. Original daemon image and pointer metadata match the pinned SHA-256 in the receipt. | Both code-pointer joins. Compare original slices and format-12 words with the report. Resolve the same-modifier call at `0x1000b3a94` as a collision control. |
| C2. The local split enters with W10=`0xa4c7` and the recovered table base. | Caller selection and record controls. Sweep the adjusted byte and compare both table slots. Model the extent cell symbolically and recover its full u32 projection through each codec. |
| C3. The descriptor branch's stack bank cells hold the two listed original bank addresses. | Descriptor caller target and all downstream joins for that branch. Observe the two reaching cells at `0x100111720` and `0x100111734`, or recover their producers through the preceding dispatch. |
| C4. Calls return normally with valid stack and record backing, ordinary preserved registers and the prior callee's selected record store. | Both status loads and their continuation. Vary X0 independently, test the zero marker and both errors, and compare the reloaded word with the final SP+0xe8 value. |

| Impact | Open join |
| --- | --- |
| High | Confirm both bank-cell origins and correlate either caller to a native request 2865 and reply 2965 with their observed port rights. |
| Medium | Follow SP+0xe8 through `0x100008f88` to determine which later call or response consumes the raw error. |

QG1–QG7 pass for this increment. The report provides factual scope, explicit premises and falsification probes, both record layouts, exact widths and complexity, positive and collision controls, original-byte provenance and ranked remaining joins.
