# Kext close-wrapper token and shared-record interfaces

The text-session close entry `_oh70aLVr`, at `0xfffffe000a5bff88`, now has a recovered record boundary. It saves incoming X0 but marshals only its low32 bits. A shared record dispatcher receives an address-keyed base index `0xc18`, an encoded biased token, and a context pointer; it returns a byte at record+12. The wrapper explicitly returns X20 through X0, despite the supplied C export's apparent no-argument/void form.

Four complete private prefix executions with a declared flag1 and null global pointer return `0xffff5b36`. The shared dispatcher writes byte `0x22` before any token-field read. This is a conditional failure path: flag1 plus a file-initial null global pointer is not established as a consistent initialized native state. Successful close, context removal and send-reference release remain unknown. A separate flag0 execution stops before `_IOMallocTypeImpl` executes.

This continues the [text-pager close association](text_pager_interface_report.md). The investigated extra operation tag `0x85150332` remains unassigned to a wrapper. It does not establish an alternate-mode app-context caller or RPC700 receiver.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| K1 | The original normalized kext and matching collection are the intended implementation | Addresses, opcodes, pointer banks and allocator identity | Rehash original files and UUIDs; compare actual loaded bytes/PAC separately |
| K2 | File-defined data plus the explicit flag/stack-guard/guest entry values define only the stated private fixture | Complete prefix executions and fixed return | Reject other external calls and unmapped accesses; execute original initialization before claiming native warm-state reachability |
| K3 | The recorded warm-path W21/W28 values and ordinary frame/nonaliasing preconditions apply | Token bias and record construction | Check source literal/state operations and all source-defined byte epochs; other caller/global/register states remain separate |
| K4 | The local GPR lift preserves ARM32/64 widths and shifted operands | Three source scalar identities | Retain original spans and width-aware lift; rerun the full stated scalar domains |
| K5 | Proven key equivalence composes with independent word-codec identities | Bias-preserving token decode and index `0xc18` | Check source lifts first, then all-word XOR/addition identities; this does not prove arbitrary record acceptance |
| K6 | Source-defined input fields and byte output are considered independently from observer padding | Partial record ABI and output validity | Reconstruct last original writes; exclude unwritten bytes; compare actual source read/store sites and call/return windows |
| K7 | Current IDA responses identify only the queried databases/ranges | Live daemon readback and kext-connection visibility | Compare requested bytes against original thin image; unavailable kext target does not prove its IDB/process is absent |
| K8 | Five private executions and four byte-bank identities support the stated bounded behavior | Branch/call bindings and cold/warm distinctions | Review real initialized registry state, other callers, successful token processing, cleanup and concurrency independently |

[Original contracts](triage_evidence/kext_close_contracts.json) retain five source spans, four exhaustive byte-bank reductions and five scoped proofs. [Retained prefixes](triage_evidence/kext_close_profiles.json), [distinct fresh replays](triage_evidence/kext_close_replays.json) and [independent checks](triage_evidence/kext_close_checks.json) retain native instruction visits, source byte epochs, nested call/return records, external boundaries and partial input/output observations. No native target, kernel API or IDB mutation occurs. [K1-K8]

## Wrapper and conditional control context

The original prologue saves X0 at wrapper SP+`0x30`. Let S be SP after the `0x140`-byte prologue; FP=S+`0x130`. The later record pointer is P=FP-`0x88`=S+`0xa8`. It is reused for several different records across the wrapper. Its contents at one call must not be assigned a permanent whole-function type. [K3,K6]

| Boundary | Original site / target | Established behavior |
| --- | --- | --- |
| Public close entry | `0xfffffe000a5bff88` | Saves incoming64-bit X0; source callers associate this entry with session close |
| Global byte read | `0xfffffe000a5c00c0` | Reads the selected initialization byte at `0xfffffe000ccca078` |
| Selected flag0 branch | `0xfffffe000a5c0178` | Reaches `_IOMallocTypeImpl` before further initialization in the retained fixture |
| Selected flag1 branch | `0xfffffe000a5c0868` | Builds the private records described below |
| Preparation helper | Call `0xfffffe000a5c0958` -> `0xfffffe000a66acb0` | Receives P; complete semantic role remains unresolved |
| Shared record dispatcher | Call `0xfffffe000a5c0a48` -> `0xfffffe000a5b07f4` | Decodes the address-keyed base index and gates on a registry pointer |
| Return | `0xfffffe000a5c16d4` | Explicitly moves X20 to X0 before register/frame restoration |

The flag1 branch follows from index `0xddc XOR0x2f =0xdf3`; flag0 selects index `0xddc`. These statements concern the selected byte values0 and1. The full byte's other values and the registry/initialization lifecycle are not classified here. [K2,K8]

## Record at the shared-dispatch call

Let p=`low32(P)`, T=`low32(incoming X0)`, and M=`0xf87ec353`. Arithmetic in these field codecs is modulo `2^32`:

```text
K(P) = (p XOR 0x280834b2) * M
B(T) = T + 0x7a2abb13

record+8  = K(P) + 0xc18
record+16 = B(T) XOR K(P)
```

| Record offset | Extent, bytes | Source construction / consumer | Established role at this call |
| --- | ---: | --- | --- |
| +0 | 8 | Store `0xfffffe000a5c09dc` | Pointer S+`0x70`; deeper context meaning unknown |
| +8 | 4 | Store `0xfffffe000a5c09e4`; read `0xfffffe000a5b08e0` | Encoded base dispatch index; consumer subtracts its address key |
| +12 | 1 | Store `0xfffffe000a5b0ad4`; later caller load `0xfffffe000a5c0a50` | Defined byte output on the observed null-pointer path |
| +13..15 | 3 | No input-definedness claim | Unassigned padding/other data |
| +16 | 4 | Store `0xfffffe000a5c09e8`; non-null continuation has load `0xfffffe000a5b09a8` | Encoded biased low32 token |
| +20 onward | Unknown | Observer prefixes extend beyond input fields | No complete extent/type or input guarantee inferred |

The accessed input prefix reaches20 bytes; surrounding stack alignment supplies a24-byte analytical view. Only16 input bytes are established by original stores:8 pointer bytes,4 index bytes and4 token bytes. Fresh checks reconstruct all64 such bytes across four flag1 cases. The output byte has its own later source-store epoch. [K3,K6]

The native token transformation before XOR with K is:

```text
(T XOR 0xfa7eff33) + 0x7fabbbe0 + ((T << 1) AND 0xf4fdfe66)
```

Its source lift proves equality to B(T) for all64-bit incoming X0 values, given the recorded W28 seed `0x34d9d269`; only low32(T) contributes. Inputs1 and `0x100000001` consequently produce the same defined index/token/context fields at the same P, although the earlier64-bit saved argument differs. This is a marshalling identity, not proof that all tokens resolve to the same object or that the dispatcher has processed a token. [K3-K5]

The shared dispatcher computes a64-bit address expression from P, then uses its low32 word as the field key. A separate source lift proves equality to K(P) for every64-bit P. Unlike the preceding [daemon cleanup codec](rpc502_cleanup_report.md), this scalar identity requires no additional algebraic8-byte-alignment constraint; readable/native ABI prerequisites remain separate. [K4,K5]

The final two proof obligations establish XOR cancellation for all32-bit codec words and additive cancellation for the operation field. Composed with the source-key identity, the decoded index is `0xc18`, and token-field XOR produces B(T). An initial expanded round-trip query reached its timeout; the final checked obligations explicitly separate source equivalence from word-codec composition. No complete dispatcher or finalization equivalence is claimed. [K4,K5]

## Global pointer gate and failure-byte path

| Resolved reference | Exhaustive-bank result / original target |
| --- | --- |
| Preparation call | Selected index `0xf3e`, slot `0xfffffe000847a910` -> `0xfffffe000a66acb0` |
| Shared record call | Selected index `0xf26`, slot `0xfffffe000847a850` -> `0xfffffe000a5b07f4` |
| Global pointer cell | Pool index `0x157`, slot `0xfffffe00084729b8` -> `0xfffffe000cccca58` |
| Shared dispatch table | Pool index `0x33`, stored value minus12 -> table `0xfffffe0008472f20` |

Each byte-bank identity is checked for all256 byte inputs against original arrays and pointer slots. A reversed pair of arrays can identify a different callee; the native saved-register flow is therefore retained with the bindings. PAC discriminators alone are not target evidence. [K1,K3,K8]

In all four flag1 fixtures, the global pointer at `0xfffffe000cccca58` is null because the original file-defined state was retained. The source gate preserves base index `0xc18`, selecting table target `0xfffffe000a5b0ad0`. That continuation stores W12=`0x22` at P+12 and returns. During this dispatcher call, the only recorded access to the argument's input fields is the4-byte operation read at P+8. The token load at `0xfffffe000a5b09a8` is not executed. [K2,K6]

```text
declared flag1
  -> construct keyed index and biased token fields
  -> shared dispatcher reads operation
  -> registry pointer is null
  -> write output byte22 -> return
  -> caller selects local return value ffff5b36
  -> record storage reused for later cleanup helper
  -> wrapper returns X20 in X0
```

Evidence-field names containing `registry` are locator labels; the pointed object's complete role and type remain unknown.

The four observed wrapper returns are zero-extended `0x00000000ffff5b36` (signed32 interpretation -42186). The symbolic/business error name is unknown. The text-session close caller's earlier role association does not prove that it consumes this return value. These fixtures establish neither successful token lookup nor context removal, memory/VM retirement, send-right release, or a native port reference balance. [K2,K8]

The flag0 fixture reaches external target `0xfffffe000c4ba154`, exactly bound to kernel `_IOMallocTypeImpl`, at call `0xfffffe000a5c01f4`. X0 is type-descriptor address `0xfffffe000847b460`. Execution stops before that API; no allocation, OOM behavior or initialized object is supplied. Allocation extent and the complete cold initialization protocol remain unknown. [K1,K2,K8]

## Extra tag and current IDA availability

Under the previously recovered local dispatcher state, extra operation `0x85150332` selects `0xfffffe000a607294` for a non-null argument record and `0xfffffe000a60ec64` for a null record. The first branch contains a32-bit argument-word read; this does not assign a filename/context-construction role. No named-wrapper association is established. The four completed flag1 close fixtures use the different shared entry `0xfffffe000a5b07f4` and never visit core entry `0xfffffe000a606728`. Other close states and tag callers remain open.

The [read-only IDA availability/facts snapshot](triage_evidence/kext_close_ida_availability.json) currently reaches daemon target `6b117c693e3b`, whose recorded original-input hash matches the known universal daemon. The recorded kext target `a90cf8ec0d88` cannot be resolved by the current connection. This is connection visibility, not proof that a database file or process is absent. No knowledge-store read API was exposed in the discovered tool surface; retained analysis artifacts remain locators rather than new memory evidence.

Four fresh daemon [IDB byte ranges](triage_evidence/kext_close_daemon_readback.json),64 bytes each, match the original thin source at MIG502 validation/application return, the common receive callback and daemon cleanup-helper entry. This refreshes256 selected bytes, not whole-IDB/native executable integrity. No IDB changes were made. [K7]

## Validation and continuation

Five distinct fresh private replays reproduce four flag1 returns and one flag0 allocator boundary, covering4316 original-source visits. Twenty actual source call/return pairs are closed in the flag1 cases. Five scoped proof obligations pass; four byte-bank identities cover1024 byte inputs. The verifier also checks source-defined record epochs, output bytes, absence of token-field reads on the selected failure path, original source spans and the four live daemon ranges. Exact counts and pins are in the checks artifact.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_close.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_close.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_close.py
```

Token/index codecs are O(1) local word work. Prefix observation/verification is O(B+V+E+S) for source bytes, visits, events and state; space is bounded by the source and retained journals. Each fixture has a20000-instruction cap; each solver has a60000 ms timeout. Extents are bytes and arithmetic widths are explicit. Instruction counts do not establish native timing or full processing cost.

[Preservation](triage_evidence/kext_close_preservation.json) checks1181 prior artifacts with only the six permitted reporting/index/aggregator changes. [Scoped quality gates](triage_evidence/kext_close_quality_gates.json) retain final source/readback checks. Other published analytical files remain frozen; the full interface investigation remains active.

| Impact | Remaining requirement | Evidence needed |
| --- | --- | --- |
| High | Real initialized close/finalization | Original registry/flag initialization, valid context identity, lookup/removal, VM/heap and send-reference release |
| High | Alternate-mode/RPC700 callers | Resolve extra-tag or computed callers independently; current close-prefix evidence does not establish them |
| Medium | Shared dispatcher semantics | Non-null global pointer format, key/capacity/status rules, all caller record epochs and token consumers |
| Medium | Native pairing and lifetime | Actual kext/daemon/port objects, PAC/locking/concurrency and complete acquisition-to-close balance |

QG1: factual analysis. QG2: K1-K8 assumptions and probes. QG3: close-prefix/record increment covered; broader goal active. QG4: u32/u64 formulas, record epochs, proof domains and complexity explicit. QG5: declared flag state versus valid initialization, marshalling versus token processing, register return versus business error name, and source versus live IDB/native behavior distinguished. QG6: original instructions/banks/slots, fresh private replay, source epochs, scoped proofs and fresh selected daemon bytes. QG7: impact-bounded continuation above.
