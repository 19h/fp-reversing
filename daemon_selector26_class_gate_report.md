# fairplayd VMM query and initial IOKit class selection

In phase `0xe8d`, `fairplayd` uses a cached `kern.hv_vmm_present` result and two separate context bytes to choose its initial class lookup. With both contexts at their file-initial value `0x70`, a zero cache selects `com_apple_driver_FairPlayIOKit`, and a cache of one selects `AvpFairPlayDriver`. The paths write `0` and `1`, respectively, to the word later read by the selector 26 caller. The selector split remains conditional on successful matching, open and construction. [Class matching](daemon_selector26_match_entry_report.md) [Selector 26 dispatch byte](daemon_selector26_constructor_join_report.md)

Addresses are unslid in the original arm64e image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. F is SP after the `0x150` B allocation at `0x1004382b8`. FP is F+0x140 B and R is the private record at F+0xc8 B. The entry `0x1004382b4` has an original authenticated rebase at `0x1010a1640`. X0 is the incoming record pointer P. At `0x10043842c`, W27 becomes `((u32(P) XOR 0xe732d262) * 0xba209ef7 + u32[P+4]) mod 2^32`. The audit uses an input record that yields `0xe8d`. [Audit generator](triage_evidence/audit_daemon_selector26_class_gate.py) [Compressed evidence](triage_evidence/daemon_selector26_class_gate_audit.json.zst)

## Query and cached byte

| Stage | Original address | Observed semantics in the static replay |
| --- | --- | --- |
| Private record adapter | Call `0x100438530` → `0x1004156b4` | Passes R. The adapter reads the encoded u32 at R+4 B, constructs a second private record and calls `0x10044f9c8` at `0x100415910`. It copies that record's output byte back to R at `0x100415918`. |
| Once or cached route | `0x10044fba0` and `0x10044fc30` | Reads the 8 B control at `0x1010c8248`. A value of all ones selects `0x10035a43c`. Other values in this phase select `0x10032f5f0`, whose call at `0x10032f688` is `dispatch_once(&control, block)`. Both paths join at `0x100360938` on normal completion. |
| Block and read-only query | Block `0x1010399d8`, invoke `0x10043dd24`, query `0x10043df88` | The block's invoke field at +16 B resolves to `0x10043dd24`. X0 points to the original 20 B NUL-terminated `kern.hv_vmm_present` literal. X1 and X2 point to a zero-initialized u32 and an 8 B size initialized to 4 B. X3 and X4 are zero. |
| Cache publication | `0x100130b30` | Query status zero stores the byte `u32_result != 0` at `0x1010c5740`. Nonzero status branches directly to the block epilogue, preserving the cache. Both cache and once control are in the zero-fill `__DATA,__common` section. |
| Cache projection | Read `0x1003609ac`, store `0x1003609bc` | Writes `(cache & 0x89) XOR 0x99` to the private record. The ordinary cache values `0` and `1` yield `0x99` and `0x98`. |

## Initial class decision

The original rebase and byte-bank expressions identify two distinct context records. The Avp context is `0x1010b5d90`, saved at F+0x10 B by `0x1004385ac`. The primary context is `0x1010b63a0`, saved at F+0x50 B by `0x100438614` and passed in X20 to the fallback check. Each starts with byte `0x70` in the image. The Boolean below uses the current bytes loaded during selection. [Compressed evidence](triage_evidence/daemon_selector26_class_gate_audit.json.zst)

| Predicate in execution order | Original branch and successor | Initial class / control word |
| --- | --- | --- |
| `u8[R] != 0x99` and `u8[Avp] == 0x70` | `CCMP` at `0x1004385bc`, dispatch at `0x10043861c`; index `0x409d` → `0x1002765f8`. | `AvpFairPlayDriver` / `1`. The successor loads its context from F+0x10 B. |
| Previous conjunction false and `u8[primary] == 0x70` | Initial index `0xe8d` → `0x10014ebf0`; dispatch at `0x10014ec24`; index `0x3e46` → `0x100289e64`. | `com_apple_driver_FairPlayIOKit` / `0`. The successor retains the primary context in X20. |
| Previous conjunction false and `u8[primary] != 0x70` | `0x10014ec24` uses index `0xe5e` → `0x1002bfecc`. | Return fragment reached before a class lookup on this path. |

The prologue derives the remaining inherited bank pairs from four original pool rebases. Stores at `0x100438498` and `0x1004384bc` put `0x100fc4130` and `0x101031ea0` in F+0x60/+0x58 B. The pair store at `0x1004385e4` puts `0x101031fa0` and `0x100fc4230` in F+0x38/+0x40 B. The common dispatch base comes from rebase `0x1010a6230` plus its instruction bias. The same frame carries the phase from the write at `0x1004385cc` to the selected successor. [Compressed evidence](triage_evidence/daemon_selector26_class_gate_audit.json.zst)

## Trace correspondence and remaining interfaces

The annotated RAX log records matching request 2881 for `com_apple_driver_FairPlayIOKit` and type-0 open reply 2962 with a null connection and `0xe00002c2`. Its `sysctl` lines do not decode the returned u32 or attribute the call to `0x10043df88`. The matching string is consistent with the recovered primary path. The live byte values, call-site attribution and successful native method exchange remain unknown. The independently analyzed ADID provider uses the same sysctl name and has evidence for an Avp stage followed by a primary stage. Here the recovered decision determines the first lookup, and a second lookup in the same daemon invocation remains unknown. [RAX trace](zut_trace_report.md) [ADID extended caller](adid_iokit_caller_report.md)

## Assumption register and verification

| ID | Premise and dependent results | Falsification probe |
| --- | --- | --- |
| A1 | The selected method runs with phase `0xe8d` and valid aligned stack and record extents. Other phases and the provenance of the original caller record remain unknown. | Recover the caller of the authenticated entry. Check incoming record+4 B, the decoded phase and the live FP-relative pointers in the same invocation. |
| A2 | Original fixups and immutable bank bytes identify logical targets. The audit models ordinary ABI returns and stack guard equality. | Recompute the original chained words and inspect the edge modifiers. Check native fixups, canary behavior and PAC in a matched run. |
| A3 | The cache and once control begin zeroed. On the first ordinary call, `dispatch_once` invokes the indicated block and completes normally. Cached cases use a completed control. | Check initial section flags, then correlate cold and warm reads with the block call and cache store. Other writers and concurrent transitions remain unknown. |
| A4 | The two context reads use their sampled bytes. The file-initial bytes give a cold-image prediction. | Observe each context byte immediately at its load and identify its prior writer. Continue past the open to test whether a second match occurs in the same frame. |

The audit checks four modeled query outcomes through both helper routes and the eight combinations of the branch predicates. It uses original instruction bytes and independently verifies chained fixup words and the import names. Ten bank rules enumerate 2,560 byte inputs. For I audited instruction visits and B bank inputs, the bounded replay uses O(I+B) time and O(I) retained evidence plus the fixed-size banks. QG1–QG7 cover factual scope, the premises, both class joins, register and byte widths, replay provenance, and the unresolved lifecycle and native exchanges below.

| Impact | Evidence frontier |
| --- | --- |
| High | Follow the selected Avp and primary continuations after matching failure or method return to establish whether either can enter the other lookup in the same invocation. |
| High | Correlate the actual sysctl result, matching dictionary, service identity and successful IOKit connection and method exchange on one matched system. |
| Medium | Attribute other writers of both context-state bytes and the VMM cache, including teardown or initialization on concurrent routes. |
