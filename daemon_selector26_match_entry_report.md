# fairplayd class matching and the selector 26 control word

Two source-backed predecessors write the 32-bit control word inherited by the selector 26 caller. In the selected entry states, `0` accompanies a match for `com_apple_driver_FairPlayIOKit`, and `1` accompanies a match for `AvpFairPlayDriver`. Both enter the same service matching, iteration and type-0 open fragment. After a successful open, the caller reads the value written by the corresponding predecessor. The prior byte proof associates those values with the descriptor and direct structure helper paths, respectively. [VMM query and initial class selection](daemon_selector26_class_gate_report.md) [Open handoff](daemon_selector26_open_report.md) [Selector 26 dispatch byte](daemon_selector26_constructor_join_report.md)

Addresses are unslid in the original arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. F is the shared SP and R is FP−0x78 B. [Audit generator](triage_evidence/audit_daemon_selector26_match_entry.py) [Compressed evidence](triage_evidence/daemon_selector26_match_entry_audit.json.zst)

## Source and ABI joins

| Entry and premise | Control-word write | Class, C-string address and call PC | Later helper |
| --- | --- | --- | --- |
| `0x100289e64` with W8=`0xe5e` | `0x100289e64` writes WZR to F+0x4c B and the block sets W24=1. | `com_apple_driver_FairPlayIOKit` at R−31 B, called at `0x100079bf0`. | Descriptor, conditional on the successful constructor path. |
| `0x1002765f8` with u32[F+0x6c B]=`0xe8d` and context at F+0x10 B | `0x100276610` writes 1 to F+0x4c B and the block sets W24=0. | `AvpFairPlayDriver` at F+0x97 B, called at `0x100281890`. | Direct structure, conditional on the successful constructor path. |

Both predecessors enter `0x100281608` with W9=`0xe8d`. The block zeros the 8 B pair at F+0x78 B and calls `IOMainPort(0, &F[0x7c])` at `0x100281684`. On success, the continuation enters `0x1001a1eb4` through slot `0x101094350`. Here W19 and W23 both become `0x5a55`. W24 bit 0 selects index `0x8fe6` for the FairPlayIOKit class decoder and `0x8fce` for the Avp class decoder. [Compressed evidence](triage_evidence/daemon_selector26_match_entry_audit.json.zst)

| Field | Source producer | Value and first audited consumer |
| --- | --- | --- |
| F+0x28 B | First half of `STP X0, X16, [SP,#0x28]` at `0x1001a1f3c`. Rebase at `0x1010a2fb8` biased by `-0x5918054b`. | `0x100e99a00`, iterator's first byte bank. |
| F+0x30 B | Second half of the same store. Rebase at `0x1010a4000` biased by `-0x62f83f4e`. | `0x100f4e390`, iterator's second byte bank. |
| F+0x7c B | `IOMainPort` output argument at `0x100281678`. | Main-port name read at `0x1002b7b78`. |
| F+0x4c B | Branch-specific 4 B store listed above. | Read at `0x1001f50c0` after success on each modeled IOKit call. |

The class source pointers come from original rebases at `0x1010b5f58` and `0x1010b7818`. They point to encoded arrays at `0x100f981f0` and `0x100f8a201`. The first decoder emits 31 B including its NUL, using subtraction by `0x6e` except at byte 1. In the selected phase that byte uses addition by `0x92` modulo 256. The second decoder emits 18 B including its NUL. In the selected phase all 18 effective masks are `0x58`, including two computed from the phase registers. Both calls use the original `IOServiceMatching` binding at `0x1010a0c28` with IA diversity `0x083b`. A nonnull dictionary becomes X1 and selects `0x1002b7b08` with W24=`0x5dee`. Both a null dictionary and a nonzero main-port status select `0x1000bd85c` in the audited states. [Compressed evidence](triage_evidence/daemon_selector26_match_entry_audit.json.zst)

## Cross-layer evidence

The annotated RAX request 2881 contains `IOProviderClass = com_apple_driver_FairPlayIOKit`. The iterator then returns a service right, and request 2862 receives reply 2962 with a null connection and `0xe00002c2`. These messages establish the class criterion and failed open in that run. The exact daemon call-site correlation remains unknown. The supplied kext contains the FairPlayIOKit class metadata. The independent ADID analysis has call sites for both class names, with separately recovered caller predicates. The native provider identity on each path and a successful matched native 2865/2965 exchange remain unknown. [RAX trace](zut_trace_report.md) [Kext metaclass association](daemon_iokit_class_report.md) [ADID class paths](adid_iokit_report.md)

## Assumption register and checks

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Original bytes and fixups identify logical call and branch targets. Read-only tables and file-initial class pointer cells retain their values. | Check original chained words, all five 256-case bank rules and every emitted string byte. Hardware PAC remains unknown. |
| A2 | Entry W8, F+0x6c B and the incoming context have the stated values. The incoming banks at F+0x60/+0x58 B and F+0x40/+0x38 B match their fixture pairs. | Compare the incoming slots against the recovered prologue stores and the F+0x28/+0x30 B iterator bank pair against the source stores on both profiles. [VMM query and initial class selection](daemon_selector26_class_gate_report.md) |
| A3 | F, FP and C enable disjoint storage for the live scalar, string and ABI output cells. IOKit calls return normally with the declared opaque results and preserve callee-saved state. | Check live-slot widths, clear volatile registers and test each prefix with main-port failure, null dictionary and nonnull dictionary. |
| A4 | The earlier aligned-record and constructor premises apply to the handoff. | Compare the measured word at the caller load with the established low-byte theorem. Correlate the class request, successful open, connection and method exchange in one native capture. |

The audit checks six profiles, 82 original instruction spans, 26 original chained fixups and 1,280 byte-bank inputs. The two successful profiles continue from their source write to the control-word load in the same frame. The modeled API returns supply opaque port names and pointers. The four negative controls stop at the shared failure continuation. For I instruction visits and B byte-bank inputs, source evaluation uses O(I+B) time for the fixed class extents and O(I) retained space plus the fixed-size banks. QG1–QG7 cover factual scope, the four premises, the success and failure joins, byte widths, original provenance and the following open interfaces.

| Impact | Remaining evidence |
| --- | --- |
| High | Extend the now-recovered initial class decision through the later continuations and resolve native service identity. [VMM query and initial class selection](daemon_selector26_class_gate_report.md) |
| High | Establish which native service and UserClient each matching dictionary resolves to, then correlate a successful open and method transaction. |
