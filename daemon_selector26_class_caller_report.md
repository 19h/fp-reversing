# fairplayd caller of the FairPlayIOKit class-selection routine

The original call at `0x100636dfc` reaches the class-selection routine `0x1004382b4` under a recovered lookup-table and phase state. Its caller writes the encoded phase `0xe8d`, then reads the result from the same private record after return. Three offline compositions carry that record through primary lookup, Avp-to-primary fallback, or a context-based skip. The primary-open failure returns a daemon-local status distinct from the IOKit return supplied to the call model. [Class-selection routine](daemon_selector26_class_gate_report.md) [Audit generator](triage_evidence/audit_daemon_selector26_class_caller.py)

## Frame roots and entry condition

Addresses are unslid in the arm64e image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Let S be caller SP and P=caller FP−0xa0 B. A separate original span produces the following values. The local replay composes this span with the following branch under a shared-frame premise.

| Frame location | Original writer | Value and provenance |
| --- | --- | --- |
| S+0x298 B | `0x1005303dc` | `0x101031da0`, from original slot `0x1010a44b0` plus bias `-0x0fd31782`. |
| S+0x2a0 B | `0x1005303ec` | `0x100e99900`, from slot `0x1010a4a58` minus `0x00d45667`. |
| S+0x2f8 B | `0x100530434` | Saves incoming X24. It provides a pointer to one u32 used in the caller's byte-index computation. |
| S+0x300 B | `0x100530438` | Saves incoming X7. The composition uses the common table base `0x101039ef0`. |

`0x10047e0fc` reads P+4 B after an earlier helper call and compares it with W22 at `0x10047e100`. For inherited W20=`0x219a`, equality selects index `0x219a` through slot `0x10104abc0` to `0x100636d60`. Inequality selects `0x21d4` through slot `0x10104ad90` to `0x1006340c8`. The branch at `0x10047e128` uses IA diversity `0xe6b8` on both paths. The audit supplies the prior helper result and W22 as separate inputs. The native producer of this result and the uninterrupted route from the discovered frame writers remain unknown.

## Local call ABI

`0x100636d60..0x100636da8` changes W20 to `0x21d4` and writes at P+4 B. For the inherited coefficient W25=`0xba209ef7`, its source equation is:

`u32[P+4] = u32(0xe8d - (low32(P) XOR 0xe732d262) * 0xba209ef7)`.

The coefficient is materialized at `0x10047e084..0x10047e088`. A bit-vector check lifts the original caller instructions and proves phase `0xe8d` for all 2^32 possible low address words under these inherited register premises. The replay's aligned P is `0x12000` and the caller produces `0x5d08b5ff` at P+4 B. The callee consumes that exact word before the class selection. P+0 B is the 4 B return field written by the callee and reloaded at `0x100636e04`; the caller does not take its result from W0.

The target selection reads the two array pointers saved at S+0x298 and S+0x2a0 B. Key `0x0a` yields constant `0xea` for all 256 input byte values. `0x100636df0` reads the table at index `0xceea`, slot `0x1010a1640`, which the original chained word binds to `0x1004382b4` with IA diversity `0x31e8`. The call sets X0=P. The audit checks this full load-to-call join with the source-produced frame cells.

The aligned exact instruction pair `MOVZ X17,#0x31e8; BLRAA X8,X17` occurs six times in 14,849,960 B of original `__text`. The other sites are `0x1003845e0`, `0x1006e3fd8`, `0x10076e160`, `0x100829c60`, and `0x100829d14`. Four original authenticated slots share that diversity. The modifier identifies a candidate group. Only the target of `0x100636dfc` is resolved here. Other modifier registers, computed values and nonadjacent definitions lie outside this scan. The compiler-start metadata brackets the resolved call between `0x10061a2d0` and `0x10065ffd8`. An independent XPC path reaches `0x10061a2d0`; that alone supplies no reaching frame or request-family attribution for this call. [Independent shared-core entry](daemon_xpc_core_bridge_report.md)

## Return and IOKit correspondence

In the three composed profiles, the exact caller-produced P enters the class routine. The calculation of the helper byte is covered by the prior audit. Here its two projections are used as explicit API-model inputs. When lookup occurs, the original source reaches `IOMainPort` at `0x100281684`, `IOServiceMatching` at `0x100079bf0` for FairPlayIOKit or `0x100281890` for Avp, and type-zero `IOServiceOpen` at `0x100176a0c`. The two returning open-failure paths use service release at `0x1001dcab8` and iterator release at `0x100205980` for each attempt. [Matching and open arguments](daemon_selector26_match_entry_report.md) [Release provenance](daemon_selector26_class_retry_report.md)

| Modeled conditions | Lookups in order | Return field P+0 B | Caller successor from `0x100636e34` |
| --- | --- | --- | --- |
| Helper byte `0x99`, primary byte `0x70`, open returns `0xe00002c2` | FairPlayIOKit | `0x74c29dee` | Slot `0x10104ad90` → `0x1006340c8` |
| Helper byte `0x99`, primary byte `0x00` | None | `0x8b3dc651` | Slot `0x101059650` → `0x10053ec30` |
| Helper byte `0x98`, both context bytes `0x70`, both opens return `0xe00002c2` | Avp, then FairPlayIOKit | `0x74c29dee` | Slot `0x10104ad90` → `0x1006340c8` |

The callee's store at `0x1002bffa8) writes the return field. For inherited W20=`0x21d4`, the caller compares with `0x8b3da47d + 0x21d4 = 0x8b3dc651`. Both resulting slots use IA diversity `0xe6b8`. The match in the context-skip profile demonstrates that this status describes the private caller contract. An IOKit connection is unnecessary for that local status. The archived trace shows the FairPlayIOKit class, failed open and release order, consistent with the first model. It supplies no return PC, private record bytes or evidence of this caller's execution. The existing startup and wire exhibits therefore remain separate at this boundary. [Archived open and retirement](archived_iokit_open_retirement_report.md) [Startup environment](daemon_registration_environment_report.md)

## Assumption register

| ID | Dependent scope | Stress test or disconfirmation |
| --- | --- | --- |
| C1 | Original image, lookup bytes, chained words and compiler metadata | Recompute the exact instruction census, check 48 chained words, and exhaust the 256 bank inputs. A runtime pointer or modifier with a different reaching value invalidates the corresponding call attribution. |
| C2 | Local frame continuity, W20 admission and inherited coefficient | The mismatch control skips the class routine. The independent address-codec check covers every u32 projection. Native frame snapshots at the stores and the call would test the unresolved intervening path. |
| C3 | Modeled helper, IOKit results and ordinary saved-register behavior | Reuse the verified class/release source evaluator. Vary the helper and context bytes across three cases and carry the caller's P through the exact callee return. Native port names and authentication remain unknown. |
| C4 | Correlation with the archived exchange | Compare class, status and releases to the archived packet evidence. Confirm any identity with a caller PC and the selected class and IOKit result in the same ordinary run. |

The audit retains 111 original instruction spans, three complete conditional class-call profiles and one preceding branch control. The extraction and replay take O(N + I + 256) time and O(N + I) space for N scanned bytes and I source instruction visits, excluding the bit-vector solve. The high-impact remaining join is the actual route from startup or a native request to `0x10047e128` and the matching IOKit caller. Medium-impact work is to resolve the prior helper's result producer and attribute the return state at `0x1006340c8`. [Compressed audit](triage_evidence/daemon_selector26_class_caller_audit.json.zst)
