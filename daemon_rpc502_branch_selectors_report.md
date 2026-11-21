# RPC 502 continuation predecessor census

The original inner wrapper has three chained fixups that name `0x100de7878`. A scan of its 2,444 instructions found 23 authenticated branches with adjacent loads of the corresponding modifiers. Under the original table and block-entry assumptions below, 19 branches cannot both select `0x100de7878` and deliver the `W19 = 0x25` used in the prior private environment-helper replay. Four branches survive the register and selector checks. Their incoming values and frame custody remain unknown. [Wrapper and replay provenance](daemon_rpc502_wrapper_frame_report.md)

The thin `fairplayd.arm64e` is 17,668,912 B, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The scan covers preferred virtual addresses `[0x100de574c, 0x100de7d7c)`. It inspects adjacent `mov x17, #imm` and `braa …, x17` pairs and checks immediate branch destinations separately. No immediate branch in that interval names the continuation or enters the audited predecessor block interiors. The chained-fixup destination census also identifies the entry points for the register-writer checks.

| Table index | Fixup address | IA modifier | Matching branch sites |
| --- | --- | --- | --- |
| `0x02` | `0x1010ab1b0` | `0x900e` | 5 |
| `0x4d` | `0x1010ab408` | `0x36b3` | 11 |
| `0xb4` | `0x1010ab740` | `0xf57a` | 7 |

## Branch-local constraints

Address columns use the common prefix `0x100de`. Table indices are unitless, with 8 B entries and base `T = 0x1010ab1a0`. Arithmetic on W registers is modulo 2^32. `E` denotes the Boolean comparison result at the named site. Where a row depends on a block-entry writer, it assumes normal return from intervening local calls with the pertinent nonvolatile registers preserved.

| Branch suffix | Required index | Original constraint or remaining evidence for W19 = `0x25` |
| --- | --- | --- |
| `5b40` | `4d` | Open. `(W19 + 0x7701b75c) XOR (E * (W20 + 0x50))` requires equality and W20 = `0x7701b77c`. Recover the arriving W19/W20 and the frame comparison at `5b14`. |
| `5c98` | `4d` | The block at `5b44` sets X19 to `0x5033434b8db07d76`. |
| `5ed4` | `4d` | `5e68` sets W19 to W25 + `0xc`. W25 = `0x19` then yields index `0xb` or `0x65`. |
| `6180` | `b4` | Open. `6048` copies X20 into X19. The byte B at X25 and the loaded W14 and W27 must satisfy `B * ((W14 XOR 0xfffffffa) + W27) = 0xe2`. The byte load at `6158` allows 0–255. |
| `6408` | `02` | The selector is `0x16 XOR (E * 0x2a)`, giving `0x16` or `0x3c` for any W19. |
| `655c` | `4d` | Open. `((W21 XOR 0x88fe48f3) + W20) OR (E << 3)` requires the sum to be `0x4d` for E=0 and `0x45` or `0x4d` for E=1. Recover the reaching values and `6534` comparison. |
| `66a8` | `4d` | `65f4` sets X19 to SP+`0xe8`. Aligned SP places its low nibble at `8`. |
| `6804` | `b4` | `6790` masks W19 with `0x705cf1b1`, clearing the bit `0x04` required by `0x25`. |
| `6858` | `02` | The selector ORs in `W19 + 0x7701b73b`, which is `0x7701b760` for W19 = `0x25`. |
| `6924` | `b4` | `68b8` adds `0x818f4aaf` to a word with the `0x886208d2` bits set. The required pre-add word `0x7e70b576` lacks mask bits `0x80020880`. |
| `698c` | `b4` | Open. The fixup at `0x1010ab400` enters at `6960`, after the W10 definition at `6940`. On the fixup-entry path, the branch requires arriving W10 = `0xb4` or `0xa5` because it XORs that value with `0x11 * E`. An immediately preceding iteration through the same branch and slot `0x4c` would require W10 = `0x4c` or `0x5d`, and the body preserves W10. Recover other incoming writers to that entry. |
| `6c30` | `02` | The two slot-2 solutions are W19 = `0x88fe48c7` or `0x88fe4948`. [Early selector derivation](daemon_rpc502_predecessor_report.md) |
| `6d98` | `02` | The block at `6c34` sets X19 to `0x5033434b8db07d76`. |
| `6ebc` | `b4` | `(W20 + 0x5f) XOR W20 XOR (E * 0xf8)` is odd. |
| `6fcc` | `02` | `6f64` ORs `0x11` into W19. The result requires bit `0x10`. |
| `7150` | `4d` | `711c–7120` set W19 to `0xd1c48a3f`. |
| `72a8` | `4d` | `(W20 AND 0x43bfce51) XOR (E * 0x33)` would require masked output `0x4d` or `0x7e`. Both require bits excluded by the mask. |
| `73e0` | `4d` | `72b8` ORs `0x11` into W19. The result requires bit `0x10`. |
| `75bc` | `b4` | The only slot-`0xb4` solution has W19 = `0x88fe48d5`. See derivation below. |
| `7740` | `4d` | `(W21 AND NOT 0x0d5c695e) OR (E * 0x4e)`. E=0 clears index bit `0x08`. E=1 sets bit `0x02`, which `0x4d` lacks. |
| `7874` | `4d` | `7750` sets W19 to W24 + `0xc`. The needed W24 value `0x19` contains bit `0x08`, cleared by the mask at `774c`. |
| `79c4` | `b4` | The self-edge requires W19 = `0xe4` or `0x3f`, depending on the stage word. |
| `7b9c` | `4d` | The branch uses `(W27_in XOR 0xd) OR (E * 0x5a)`, where W27_in is the value before `7b84`. The entry at `79c8` sets W19 to W27_in minus `0xb`. W19 = `0x25` implies W27_in = `0x30` and gives `0x3d` or `0x7f`. |

## Second bank producer and continuation handoff

The block at `0x100de73e4` has another original bank-pair store at `0x100de7528`. It transfers the incoming X12 and X14 through X24 and X26 to SP+`0x28` and SP+`0x30`. It also writes stage 6 at SP+`0x64` at `0x100de7458` and stores the X29−`0xf8` context pointer at SP+`0x78` at `0x100de7540`. These offsets refer to the producer's SP. The later SP adjustment at `0x100de7574` means subsequent custody of those bytes depends on the local displacement result.

At `0x100de75bc` the index is `(W19 + 0x7701b7df) XOR (E * (W19 XOR 0x88fe48dd))`, with equality formed at `0x100de7588`. For E=0, subtracting the additive constant from `0xb4` gives `0x88fe48d5`. For E=1 the equation is `W19 + 0x7701b7df = W19 XOR M`, where `M = 0x88fe48dd XOR 0xb4 = 0x88fe4869`. Writing the XOR as `W19 + M - 2 * (W19 AND M)` gives possible AND results `0x08fe4845` and `0x88fe4845`. Both contain bit `0x04`, which M clears. Thus the second bank producer cannot feed the replay directly through its terminating branch. The sole slot-`0xb4` solution instead forms address `0xfffffffd48fcf848` at `0x100de788c` when T is reloaded, outside the pinned image.

The branch at `0x100de79c4` uses `W19 XOR 0x50 XOR (E * 0xdb)`, where E=1 iff the 32-bit stage at SP+`0x64` after the displacement is 5 or 6. This yields two W19 candidates per destination.

| Destination index | Stage 5 or 6 | Other stage |
| --- | --- | --- |
| `0x75` to `0x100de79c8` | `0xfe` | `0x25` |
| `0xb4` to `0x100de7878` | `0x3f` | `0xe4` |

Before this branch, `0x100de788c` reads the entry indexed by W19 and stages it as the nested continuation. For the nested route from the private replay, `0x100de816c` consumes that entry as an IA pointer with modifier `0x83fd`. Only the `0x25` candidate has the corresponding original fixup.

| W19 | Earlier slot address | Original slot contents |
| --- | --- | --- |
| `0x25` | `0x1010ab2c8` | IA `0x83fd` to `0x100de8170` |
| `0x3f` | `0x1010ab398` | IA `0x36b3` to `0x100de6560` |
| `0xe4` | `0x1010ab8c0` | IA `0x0d9c` to `0x100de9cd8` |
| `0xfe` | `0x1010ab990` | Plain rebase to data at `0x1010c5440` |

## Assumptions and falsification probes

| Assumption | Impact and dependent result | Falsification probe |
| --- | --- | --- |
| B1. The branch uses T and the chained fixups from the pinned image. | High. The index and pointer mappings depend on table identity. | Rehash the image, check the raw fixup words and trace each arriving table-base register. |
| B2. The writer-to-branch checks start at the mapped block entries and use ordinary returns with nonvolatile values preserved and SP aligned at the frame formation site. | High. The 19 exclusions include these register-writer premises. | Check direct and indirect entry targets in a complete original-code trace, and compare X19, X27 and frame alignment across calls. |
| B3. The nested wrapper consumes the staged entry at `0x100de816c` on the replay route. | Medium. The four-slot comparison is conditional on this nested consumer and the original fixups. | Track the staged slot and X14 through the nested wrapper for a separately observed call target or displacement. |

An independent Z3 check of the recovered expressions used 32-bit bit vectors and returned 19 unsatisfiable and four satisfiable site queries for W19 = `0x25`. Three additional unsatisfiable queries checked the unique local requirement at `5b40`, the sole unrestricted slot-`0xb4` solution at `75bc`, and the same-branch predecessor exclusion at `698c`. The `75bc` solution was also evaluated directly. Satisfiable queries allow unconstrained reaching values and are limited to the local expressions. The instruction and fixup census is linear in the number of instructions and fixup records inspected. Per-site arithmetic uses fixed-width integer operations and constant space.

The second bank writer is a medium-impact alternative source for the local frame fields. The four open branch sites are a high-impact evidence gap in joining the wrapper entry to the environment helper. A reaching frame and a native Mach or IOKit transaction remain unknown.
