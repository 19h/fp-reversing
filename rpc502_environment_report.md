# RPC502 environment boundary: scheduling, CSR and BootPolicy

The protected RPC502 path reaches two further architectural interfaces: `csr_get_active_config` and `/usr/lib/libbootpolicy.dylib`'s `bootpolicy_get_security_mode`. On the recovered guarded-global path, the CSR result reduces to an indicator with values 0, 1 or 2; it is not itself the final FairPlay authorization/decryption result.

Original bytes establish the call targets, guarded branches, imported data bindings and arithmetic. Ten bounded synthetic fixtures corroborate selected paths with explicit PAC bypasses and import models. No native daemon, host IPC or target file/system API was executed. The subsequent [BootPolicy backend report](bootpolicy_backend_report.md) resolves the local-cache implementation's default values, user-client/Mach/SEP interfaces and daemon mode partition. The later [sidecar report](rpc502_sidecar_report.md) connects those markers and the CSR indicator to a mutable global and filename scan start. Actual runtime values/selection, full global lifetime and final context policy remain unknown; this report's original ten fixtures still stop at their scoped unmodeled boundaries.

## Provenance and assumption register

Analysis date: 2026-11-01. Original arm64e daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred static VAs. [Native contracts](triage_evidence/rpc502_environment_contracts.json) retain 22 instruction ranges, seven exhaustive selector-bank checks, two nonzero-addend import bindings, 14 branch slots and four full-domain SMT results. The [probe implementation](triage_evidence/daemon_rpc502_probe.py) and [fixture runner](triage_evidence/run_rpc502_probe_profiles.py) retain the finite execution method and its model boundary.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| E1: original image/fixups/read-only selector banks match the intended build | Call identities and constant reductions | Recheck hashes, original bind words/import table, branch slots and bank identities. Runtime memory/PAC/protection are separate. |
| E2: the prior private-frame/register protocol remains intact | PID-zero continuation, CPU/origin roles and scheduling flag | Trace all predecessors, writes, custom stack-check preservation and aliases. Valid isolated seeds do not establish native reachability. |
| E3: the guarded global has the inspected initial four-byte prefix | The recovered path through CSR inquiry | Observe runtime bytes, initialization and repeated/concurrent calls; cover every mismatch predecessor. The original file is an initial-state profile, not runtime attestation. |
| E4: runtime APIs implement the documented/expected argument contracts | QoS and CSR interpretations | Match loaded libraries or inspect them. Original import names and native argument registers remain independently established. |
| E5: encoded comparison frame is valid, four-byte aligned and unmodified | Comparator cancellation and compact CSR reduction | Misalign/change frame words, exercise aliases, or capture native input/output. Proofs explicitly constrain pointer alignment. |
| E6: synthetic seeds/models explain only their finite fixtures | Probe routes, local stores and end points | Vary PID/CPU/status/configuration, remove a model or alter globals. Models bypass PAC, skip stack probing, use a zero-filled private stack and map private image pages permissively. They do not establish native permissions or useful failure outputs. |

The prior [RPC502 report](daemon_rpc502_report.md) supplies the private 120-byte record and PID gate. Current daemon IDA availability remains separately recorded; no fresh daemon IDA result is used in this increment.

## Scheduling join and CPU/origin interface

```text
audit PID zero
    |
query current pthread QoS
    +-- failure ------------------------> changed_flag=0
    |
    +-- success -> request class 0x21, relative 0
                      +-- success ------> changed_flag=1
                      +-- failure ------> changed_flag=0
                                             |
                      common continuation 0x1005be85c
                                             |
                           compare CPU field to 0xabcd
                                             |
                        guarded global / CSR / BootPolicy
```

The flag is stored as a byte at protected SP+0x344f. The native path tracks whether the class-setting operation returned 0, rather than treating the request alone as a successful scheduling change. The queried prior class and relative priority remain available at SP+0xcec and +0xab0. Complete restoration and every exit path remain unresolved.

The later [mapping/cleanup report](rpc502_mapping_report.md) recovers a concrete use of this flag on selected error exits: bit0 selects a late setter that reloads saved class from SP+0xcec and explicitly requests relative0. The saved relative-priority value is not forwarded by that call. Query-failed and initial-set-failed fixtures skip it. Complete exit coverage, setter-failure behavior and actual scheduling remain unknown.

At `0x1005be894`, the observed 64-bit comparison value reduces to 0xabcd. This is the CPU scalar previously copied from private R+0x10, not origin or subtype. Equality selects `0x100547604`; other values select `0x1005806fc`. Both finite CPU profiles tested here eventually reached the CSR boundary, but complete equivalence of their processing is not established. The sentinel correlates with a private distinction seen in the kext; it is not assigned a public CPU enumeration.

On the ordinary branch, origin at protected SP+0x990 is transformed and stored at SP+0x8d28. Its mixed arithmetic is exactly `origin + 0x7d4e7336e158c61a mod 2^64`, proven across all 64-bit origin words. This is recovered data marshalling, not an identified cryptographic algorithm.

The ordinary path prepares a private arena region of 0x880 bytes and checks a nonnull filename pointer; the sentinel branch prepares a different region of 0xa80 bytes. This later pointer check does not replace the earlier wrapper's readable-NUL precondition: filename scanning already occurred before the PID gate.

## Guarded global and CSR call

Original slot `0x1010a6e48` plus its native bias resolves global address `0x1010b5f70`. The original first four bytes are `56 a0 54 c0`. The inspected route checks those bytes through continuations `0x10056fca8`, `0x10058781c`, `0x10049b2c0` and `0x100520a64` before reaching the CSR path.

The object is not established as a C string. Its checked header, subsequent byte writes and unknown remainder are retained as a guarded binary global. Native mismatch paths and warm/reentrant/concurrent semantics are not assigned a complete contract here.

| External call | Native emission | Original slot / identity | Observed ABI |
| --- | --- | --- | --- |
| CSR inquiry | `0x100616094` | `0x1010a1390` -> `_csr_get_active_config`, `/usr/lib/libSystem.B.dylib` | X0 points to a zero-initialized u32 at protected SP+0x4134; low-32-bit return compared with 0 |
| BootPolicy inquiry | `0x1004cfe24` | `0x1010a1070` -> `_bootpolicy_get_security_mode`, `/usr/lib/libbootpolicy.dylib` | X0/X1 are values loaded from two imported data cells; X2 points to SP+0x11e4; low-32-bit return compared with 0 |

These are daemon-level call sites, not the deeper system-call or IPC emission sites inside the libraries. The original authenticated bind modifiers are 0x99fc and 0x9218, respectively; static metadata does not validate runtime authentication.

The [pinned XNU declaration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/csr.h#L35) defines a 32-bit CSR configuration and names bit 0x10 `CSR_ALLOW_APPLE_INTERNAL`. This is separately versioned context; the exact running-library/source relationship remains unestablished. [Local source hashes](triage_evidence/rpc502_environment_sources.json) retain that provenance.

## Compact CSR result and encoded comparison helper

For successful CSR inquiry, the protected code compares the returned configuration with 0 through local helper `0x10041a5e0`, then reduces the relevant branches. With c the full u32 configuration, the value carried into `0x1004cfcec` in W23 is:

```text
getter return != 0 : indicator = 2
getter return == 0 : indicator = (c & 0xffffffef) != 0
```

Thus configuration 0 and configuration 0x10 give indicator 0. Any set bit outside 0x10 gives indicator 1, including bit 0 and reserved high bits in the mathematical domain. This describes this local indicator; no complete security-mode or FairPlay acceptance rule follows.

The recovery initially used an incorrect mask 0xffffffee. The CSR bit 0 fixture contradicted it. Rechecking the native signed-comparison threshold changed the formula to 0xffffffef, and the corrected source-derived expression passed a full 32-bit SMT equivalence check. The current artifact contains the corrected result.

The comparison helper has compact semantics despite its arithmetic encoding. Let p be its frame pointer and:

```text
E = (p xor 0x4de3a292f9d49974) * 0xda51a827 mod 2^64
k = u32(frame[0x00]) - low32(E)
a = u64(frame[0x08]) - E
b = u64(frame[0x20]) xor E
predicate = (k & 1) ? (a > b, unsigned) : (a == b)
yes = u32(frame[0x2c]) xor low32(E)
no  = u32(frame[0x28]) + low32(E)
frame[0x10] = (predicate ? yes : no)
                xor (u32(frame[0x14]) - low32(E))
```

All widths wrap at their stated bit sizes. The CSR caller constructs the matching E with a different mixed expression; SMT proves equality for every four-byte-aligned 64-bit frame pointer. In this caller, k=0 and the decoded right side is 0, so the helper performs an equality partition. It is an encoded comparator/continuation selector, not an established crypto primitive.

CSR getter success enters `0x100607ec4`; its failure enters `0x1004cfcec` with indicator 2. Both observed paths continue toward the BootPolicy boundary. This does not establish that a failed inquiry is ignored by later policy.

## BootPolicy imported values and nonzero binding addends

| Imported data cell | Original slot | Import-table addend | Native adjustment |
| --- | --- | --- | --- |
| `_bootpolicy_default_policy_volume_path_value` | `0x1010a3c30` | +0x7bed81d2 | -0x7bed81d2 at `0x1004cfd98` |
| `_bootpolicy_root_volume_uuid_value` | `0x1010a6818` | +0x4677e24f | -0x4677e24f at `0x1004cfde0` |

Both imports belong to original load-command ordinal 9, `/usr/lib/libbootpolicy.dylib`. Their format 12 chained words reference format 2 import entries; the addends above come from the original import table, not a nearest-symbol guess or the printed annotation alone. Pointer-local addends are 0 for these words. Each native adjustment cancels the import-table addend modulo 2^64, yielding the actual symbol-cell address.

At `0x1004cfd9c`, the daemon loads the first cell's value into X0. At `0x1004cfe00`, it loads the second into X1. These are **values stored in imported data cells**, not the symbol addresses themselves. Their runtime values and concrete high-level types are unknown. The symbol spelling does not establish a literal filesystem path, UUID string or object representation.

The next authenticated call is exactly `_bootpolicy_get_security_mode`. On a zero return, target `0x100592a00` reads a u32 at SP+0x11e4; a nonzero return selects `0x1005bbb20`. These observations establish the caller's result-width/status expectations, not the library's full C prototype, returned enum meanings, internal IPC service or final policy effect.

The initial private probe omitted nonzero import-table addends and faulted on the adjusted first-cell load. Correcting the bind model changed that end point to a deliberate stop before unknown imported data is read. That unmapped-read error was a model defect; it was not evidence of a daemon fault or missing daemon startup initialization.

## Finite synthetic checks and their boundary

| Profile | Explicit model change | Observed finite result |
| --- | --- | --- |
| PID123 | Audit word 5=123 | Returns 0xffff5bbf, corroborating prior static early-return reduction |
| PID0 | CSR is unmodeled | Stops before `_csr_get_active_config` |
| CPU0xabcd | Alternate CPU scalar; CSR unmodeled | Also reaches CSR in this fixture; does not establish full branch equivalence |
| CSR0 | Getter 0/config 0 | Indicator 0; stops before first BootPolicy data-cell read |
| CSR0x10 | Getter 0/config 0x10 | Indicator 0; same deliberate stop |
| CSR4 / CSR1 | Getter 0/config 4 or 1 | Indicator 1; same deliberate stop |
| CSR error | Getter 5; no output write | Indicator 2; same deliberate stop |
| QoS query failure | Query 5, CSR 0 | No class-set request; same BootPolicy data boundary |
| QoS set failure | Query 0/set 5, CSR 0 | Class request occurs; change flag remains 0; same boundary |

All ten runs use private image/stack memory, normalized chained pointers, explicit PAC bypasses, a modeled stack-probe preservation contract, an audit-output model and synthetic pthread results. They execute no target host IPC, file or system API. The imported BootPolicy data and API remain unmodeled; the probe stops before consuming the first unknown cell. A zero-filled model stack is not evidence that native error outputs are initialized.

The probes corroborate finite translations and expose model mistakes. Native bytes, exhaustive byte-bank identities and full-domain arithmetic proofs support different, explicitly bounded claims. Neither source provides a native end-to-end RPC transaction, actual QoS change, SIP state, successful PAC or complete context lifetime.

## Reproduction, bounded findings and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/run_rpc502_probe_profiles.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_rpc502_environment.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/rpc502_environment_layouts.c
```

Native extraction is O(B+F+D+P) time/space for image bytes B, fixups F, retained instructions D and fixture evidence P; SMT cost is solver-dependent. The private probe has a 200,000-instruction budget per fixture, stops at every unmodeled import/data/system instruction and uses at most three concurrent independent processes in the runner. This is a bounded analysis budget, not a claim about native operation latency. Compile assertions cover the 48-byte comparison prefix only.

| Impact | Additional finding / remaining boundary |
| --- | --- |
| High | CSR configuration and BootPolicy security mode are concrete external inputs to RPC502 processing. Their final policy effects and library/internal-service behavior remain unknown. |
| High | Nonzero chained-binding addends are part of the daemon ABI; omitting them can produce false synthetic faults at valid imported-data references. |
| High | A compact full-domain CSR indicator replaces a trace-only description; bit 0 validation caught and corrected a premature reduction. |
| Medium | CPU sentinel 0xabcd and ordinary origin marshalling connect this application path to prior kext-side distinctions. |
| Medium | Scheduling-change success is tracked independently from the request; restoration remains a lifecycle requirement. |
| Medium | Guarded-global mutation and warm/reentrant/concurrent behavior remain unproved; the bytes are not assigned unsupported string/cache semantics. |

QG1 factual technical scope. QG2 E1-E6 and probes explicit. QG3 this increment covers scheduling convergence, CPU/origin marshalling, CSR and BootPolicy caller interfaces, import addends and bounded synthetic corroboration; the full original objective remains active. QG4 widths, wrap rules, frame alignment, partial layout and complexity are explicit. QG5 corrected mask/addend discrepancies, model/native distinctions, opaque imported values and incomplete policy/lifetime are separated. QG6 original ranges, exact imports/load paths, import-table words, exhaustive banks, SMT, pinned source hashes and model artifacts are retained. QG7 bounded impact-labeled findings and remaining interfaces are listed above.

[Machine-readable delivery checks](triage_evidence/rpc502_environment_quality_gates.json) retain the current validation counts and evidence boundaries.
