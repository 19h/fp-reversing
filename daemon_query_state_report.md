# Daemon version/capability query state and local record ABI

The query22/23 sequence feeds a 20-byte, address-dependent local record into `0x100013AC0`. Its inspected source decodes the record, stores encoded version components and capabilities at state base `0x1010B6380`, and selects a separate continuation when capabilities are zero. A normal helper return permits caller marker `0x0A` to be stored at state+0. These are conditional source roles; native entry, actual queried values, fallback effects and final state lifetime remain unknown. [QS1-QS12]

The increment contains 264 fresh private source replays, 111616 instruction visits, 11 source proof pairs over 142 lifted instructions, seven exhaustive byte-bank rules, 25 original fixup checks, two independent bind decodes and 78 live IDB instruction comparisons. All 256 preceding query prefixes agree after the declared frame/register and connection-cell alias adjustments. No native Mach, IOKit, stack-guard or fallback operation executed.

[Original-source contracts](triage_evidence/daemon_query_state_contracts.json), [retained cases](triage_evidence/daemon_query_state_profiles.json), [fresh replays](triage_evidence/daemon_query_state_replays.json), [independent checks](triage_evidence/daemon_query_state_checks.json), [source proofs](triage_evidence/daemon_query_state_proofs.json), [live IDB source](triage_evidence/daemon_query_state_live_ida.json), [source identity](triage_evidence/daemon_query_state_source_identity.json), [preservation](triage_evidence/daemon_query_state_preservation.json) and [scoped gates](triage_evidence/daemon_query_state_quality_gates.json) retain the evidence. The [preceding query/census report](daemon_iokit_census_report.md) establishes the API guards and compatible kext counterparts. The full interface objective remains active.

```text
conditional open -> state+4 connection output cell [native result unknown]
  -> selector22: version V32 -> source status/size guard -> V or 0
  -> selector23: capabilities C32 -> source status/size guard -> C or 0
  -> 20 B local record at caller FP-0x78
  -> helper 0x100013AC0
       -> controller A/B updates
       -> state+0x08/+0x0C/+0x10 encoded version bytes
       -> state+0x14 encoded capabilities
       -> C == 0 ?
          yes: 16 B local fallback record
               -> STOP before call 0x10043BD18
          no:  guard equality -> helper return
               -> source writes state byte0 = 0x0A
               -> STOP before saved iterator read at SP+0x68
               -> source prepares IOObjectRelease [unexecuted]
```

Addresses are preferred file virtual addresses. B denotes bytes. u32/u64 arithmetic below is modulo 2^32/2^64. V and C denote the words after the daemon's status/extent guards, including their source-zero fallback. They are not observed getter values.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| QS1 | Pinned thin source and selected IDB identify the inspected instruction bytes | Address/role correspondence | Rehash thin source; compare 78 current IDB rows; distinguish original chained words from loader pointer representations |
| QS2 | Entry at `0x100364398` has W21=0x9376, X24=0x101039EF0 and the declared saved frame cells | Query and helper composition | Recover the native predecessor; current private cases do not establish complete entry reachability |
| QS3 | Caller FP=F+0x120, incoming X19=0x101031EA0 and saved left bank F+0x20=0x100FC4130 | Record address and helper dispatch | Original prologue establishes the FP relation; compare all preceding prefixes with only X28/X29 differences at the query boundary |
| QS4 | F+0x58 points to state `0x1010B6380`; F+8 points to state+4 | Connection/cache alias and marker store | Original `0x100478B98..0x100478BB0` prepares state+4 and saves the pointer; fixture/native pointer origin remains conditional |
| QS5 | Incoming state byte09, connection0x5804 and opaque guard value are explicit private fixtures | Finite paths and normal guard comparison | Inspect fixture/provenance masks; no fixture is a native observation or original-file state claim |
| QS6 | Two returning API summaries preserve callee-saved state and supply declared status32/size64/word32 outcomes | Source query outputs | Retain all prior 256 combinations; add eight accepted-zero-capability controls; API return values remain unknown natively |
| QS7 | Original byte banks/fixups and selected root biases retain their pinned values | Helper, controller, state, table, fallback and release targets | Exhaust all 256 byte inputs for seven rules; decode 25 original fixups and two import bindings |
| QS8 | Private A64 execution with explicit PAC/return abstraction matches the declared local model | Fresh instruction traces | Verify all source bytes/edges and every read/write epoch; no hardware authentication claim |
| QS9 | Record cells persist across the helper's controller/root instructions; source phases use their declared aliases | Universal record-to-cache formulas | Audit record preservation in 264 replays and inspect intervening source stores; native concurrent writes/lifetime remain unknown |
| QS10 | Helper normal return and unchanged opaque guard are premises for caller continuation | Byte0 publication and iterator frontier | Source marker follows the call; zero-capability paths stop before fallback and do not claim marker publication |
| QS11 | Unknown private bytes remain unknown | Saved iterator boundary | Stop before `0x100483CA8` loads F+0x68; its four bytes retain known-mask00000000 in all cases |
| QS12 | Static kext query compatibility does not identify a live connection or provider value | Daemon/kext association and IPC limits | Establish actual connection ownership, provider dispatch and a transaction separately; no new Mach emission is established |

QS1-QS12 qualify all dependent claims. The earlier query-only fixtures used an arbitrary FP and a private connection cell. This increment explicitly changes FP/incoming bank and rebinds the connection cell to state+4. It does not claim raw equality of all old/new registers or reads.

## Source roles and exact touch points

| File VA | Source role established in this increment | Boundary |
| --- | --- | --- |
| `0x1003C39B0` | Packs guarded version/capability words into five u32 cells | Caller continuation, not a standalone semantic function boundary |
| `0x1003C3AE8` | Calls original target `0x100013AC0`, X0=FP-0x78, IA diversity0xF08F | Target follows original slot0x1010A01D0 |
| `0x100013AC0` | Initial record unpack/cache publication and capability-dependent continuation | Zero-capability callee effects remain unknown |
| `0x1000898D8` | Guard equality test and helper register/frame restoration | Normal-return source, with private guard fixture |
| `0x1000115A0` | Builds a 16 B fallback record for capabilities-zero path | Stops before `0x100011674` |
| `0x10043BD18` | Resolved fallback callee | Function and effects unknown; unexecuted |
| `0x1003C3AF4` | Writes caller state byte0=0x0A following helper return | Later state transitions/lifetime unknown |
| `0x100483CA8` | Reads saved u32 iterator candidate at caller F+0x68 | Unknown source value; instruction unexecuted |
| `0x100483CC0` | Source prepares `_IOObjectRelease(W0)` using that saved value | Call and actual object ownership unexecuted |

The live IDB's retained comments include earlier conditional bank/slot analyses. Current source arithmetic, original fixups and exhaustive banks corroborate those particular roots. No knowledge-store search tool is exposed in this session; no IDB annotation or stored memory was changed.

## Connection/state schema at the initial publication epoch

The source at `0x100478B98` loads the saved state pointer from F+0x58, computes X3=state+4, saves X3 at F+8 and prepares the previously established IOServiceOpen call. The query sequence subsequently loads its u32 connection argument through that saved pointer. Thus the connection field and metadata cache share a state base under QS4; the private connection value is not proof of a Mach right or successful native open.

| Offset from `0x1010B6380` | Width | Initial publication role | Source store |
| --- | --- | --- | --- |
| +0x00 | 1 B | Caller marker; private incoming09, source0A only after normal return | `0x1003C3AF4` |
| +0x01..+0x03 | 3 B | Role unknown | No store in inspected sequence |
| +0x04 | 4 B | Conditional IOServiceOpen output / query connection cell | Open output is external; fixture5804 here |
| +0x08 | 4 B | `(V >> 24) + 0x0BFD3DA4` | `0x100013CA0` |
| +0x0C | 4 B | `((V >> 16) & 0xFF) + 0x0E62359A` | `0x100013CA8` |
| +0x10 | 4 B | `((V >> 8) & 0xFF) + 0x0DA54C41` | `0x100013CB0` |
| +0x14 | 4 B | `C XOR 0xC49697F0` | `0x100013CC8` |

These are encoded component bytes. Major/minor/patch nomenclature, capabilities bit meanings and final fallback-produced state are unknown. The stores precede the zero-capability test. A zero query value therefore yields an encoding offset/constant rather than all-zero cache bytes. Two accepted-version pairs differing only in byte0 (`0x12345678`/`0x123456FF`) produce identical records/cache fields at each of the two frame placements. The universal source proof establishes this independence for all V32/C32 values under QS2-QS9.

## Twenty-byte record and source composition

Let F be caller SP, FP=F+0x120, R=FP-0x78=F+0xA8, and

```text
K32 = u32((low32(R) XOR 0xC6D66014) * 0x6B86592F)
b3 = V >> 24
b2 = (V >> 16) & 0xFF
b1 = (V >>  8) & 0xFF
```

| Record offset | u32 source value | Meaning on initial helper consumption |
| --- | --- | --- |
| +0x00 | `0x2757 - K32` | Recovers control word0x2757 |
| +0x04 | `K32 + b2 + 0x0E62359A` | State+0x0C after subtraction |
| +0x08 | `(C XOR 0xC49697F0) - K32` | State+0x14 after addition |
| +0x0C | `K32 + b3 + 0x0BFD3DA4` | State+0x08 after subtraction |
| +0x10 | `K32 + b1 + 0x0DA54C41` | State+0x10 after subtraction |

Stores at `0x1003C3A58`, `0x1003C3A7C` and `0x1003C3A90` cover exactly20 B through F+0xBB. The helper derives the same K32 from X0, loads these exact cells and preserves the record during the inspected continuation. The source call does not expose a five-argument C API: X0 points to this local packed object.

The helper's intermediate pointer arithmetic establishes state base `0x1020C48B3 + 0xFFFFFFFFFEFF1ACD = 0x1010B6380` modulo2^64. Its recovered phase is `0x2757 XOR (C==0 ? 0x7FAB : 0)`, selecting index0x58FC for C=0 and0x2757 otherwise.

| Selection | Original slot | Decoded target | Source discriminator |
| --- | --- | --- | --- |
| Record helper | `0x1010A01D0` | `0x100013AC0` | 0xF08F |
| Capabilities nonzero | `0x10104D9A8` | `0x1000898D8` | 0xFDE4 |
| Capabilities zero | `0x1010666D0` | `0x1000115A0` | 0xFDE4 |
| Caller after normal helper return | `0x101061690` | `0x100483C6C` | 0x9A6D |
| Zero-capability fallback call | `0x1010A1078` | `0x10043BD18` | 0xB61A |
| Iterator release call | `0x1010A0240` | IOKit `_IOObjectRelease` | 0xBE7E |

The release binding has original format12 word0xC008BE7E0000007D, import ordinal125, IOKit library ordinal4 and total addend0. The guard cell0x1010B1E18 is an unauthenticated bind to `___stack_chk_guard`, ordinal229, `/usr/lib/libSystem.B.dylib`, total addend0. Its private value is opaque; the import is not executed.

## Controller state and fallback boundary

The helper reads and replaces two global u64 controller cells. Their values influence obfuscated indexing, while exhaustive byte-bank rules make the selected roots constant over every byte input. Their broader lifecycle and concurrent access are unknown.

For A=[0x1010B9028], B=[0x1010C4670], helper SP H=F-0x60, M=0x0A5CD4CF and T=0x73D046208EAED1A6:

```text
D = u64(B - A - (H + 8))
[0x1010B9028] <- u64((D * M) XOR T)   at 0x100013BEC
[0x1010C4670] <- u64((D XOR T) * M)   at 0x100013BF0
```

A separate source proof covers all u64 A/B/H values in this local arithmetic phase. Replays check528 concrete controller stores; this is not a native synchronization or lifetime model.

For C=0, the fallback builds a16 B record at Q=H+0x14, then prepares X0=Q at `0x10001166C`. Let `J32=u32((low32(Q) XOR 0x8515CFBD) * 0xC7F6DCA7)`:

| Offset from Q | u32 value |
| --- | --- |
| +0 | `J32 + 0x50EBC19F` |
| +4 | `J32 XOR 0x7B3D5095` |
| +8 | `0x6D25 - J32` |
| +0x0C | `J32 XOR 0x0862CC88` |

Record operation semantics remain unknown. Three source lemmas cover its pointer-derived prekey, multiplication and field packing. Source selection resolves the call target to0x10043BD18 for all256 byte-bank inputs. The private run stops before that call; it does not supply a return or infer whether marker0A would eventually be published.

## Validation, reproduction and preservation

The base256 cases independently vary two API outcomes: status in{0,0xE00002C7}, returned size64 in{4,3,0,0x100000004}, two frame placements and two word pairs. Eight further cases use accepted status0/size4, capabilities0 and four version words at each placement. API output writes have provenance2; source stores1; incoming fixtures3. Original image bytes have provenance0. A5-filled private backing remains unknown until initialized.

| Verification | Result |
| --- | --- |
| Fresh cases / original instruction visits | 264 /111616 |
| Fresh cases reaching normal-return/unknown-iterator frontier | 32 |
| Fresh cases reaching zero-capability fallback-call frontier | 232 |
| Preceding query prefixes with explicit alias/register adjustments | 256 |
| Source read/write epochs independently reconstructed | 18504 /6688 |
| Source capacity resets / retained API models | 528 /528 |
| API write epochs | 608 |
| Packed-record/cache formula checks | 264 /264 |
| Record-preservation checks | 264 |
| Source proof pairs / lifted instructions | 11 /142 |
| Exhaustive banks / byte inputs | 7 /1792 |
| Original fixups / import bindings / direct dispatch slots | 25 /2 /3 |
| Current live IDB instruction rows matching original source | 78 |
| Prior artifacts checked / unchanged | 2300 /2294 |
| Original analysis/C/calls inputs preserved | 3 |

The fresh replays use the same A64 engine as the retained cases. Independent validation reconstructs byte epochs, reads, source/API provenance, formulas, controller stores and declared prefix differences. This is not an independent native execution engine. SMT obligations are built from original opcode spans; both original and simplified query files are hashed and rechecked. All obligations are source-local and compose under the stated phase/alias premises.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_query_state.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_query_state.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_query_state.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_query_state.py
```

These commands regenerate only this increment's outputs; a new seal requires rerunning preservation/delivery validation. Probe each case with at most3000 instruction visits. With B image bytes, C cases, V visits/case, E memory/API events/case, J demand pages, F fixups, I lifted instructions and R bank rules: time O(B+C*(V+E+J*F)+I+256R), retained space O(B+C*(V+E)+I+F+4096J), plus solver cost bounded to30 s/query. Original inputs, binaries, IDB and prior evidence remain preserved. Six permitted historical file edits are the four consolidated reports, investigation status and aggregate manifest validator.

## Bounded continuation and scoped quality gates

| Impact | Next bounded question | Completion evidence |
| --- | --- | --- |
| High | What does zero-capability callee0x10043BD18 do to its16 B record and shared state? | Source record consumer, status/state stores and returning continuation; do not presume fallback success |
| High | Which readers decode state+8/+0x0C/+0x10/+0x14, and which capability bits affect later calls? | Exact read/decoder provenance and selected call contracts |
| High | What produces caller F+0x68 and connects that iterator to the original service match/open? | Source store/return aliases, iterator lifetime and cleanup ordering |
| Medium | Are controller A/B and state marker updates serialized across concurrent entry? | Concrete lock/once ownership and native state-transition evidence |
| Medium | Does selector18 originate in another computed call form or linked module? | Bound target, selector definition, connection lineage and arguments; modifier-only candidates remain insufficient |
| Low | Do component bytes correspond to named version fields? | Consumer semantics or matching primary type/schema evidence; byte positions alone do not establish names |

No new incoming Mach endpoint, emitted message, transferred right or native port name is established by this local continuation. It adds the source connection-cell/cache relationship and an unexecuted iterator-release preparation. Actual transaction identity remains unknown.

| Gate | Result / evidence |
| --- | --- |
| QG1 | Pass: factual technical analysis |
| QG2 | Pass: QS1-QS12 list dependent results and falsification probes |
| QG3 | Pass for this increment: record, cache, controller and continuation contracts covered; full_goal_complete=false |
| QG4 | Pass: explicit B/u32/u64 widths, modular formulas, cardinalities and reproduction |
| QG5 | Pass: fixture/native values, initial/final state, normal/fallback paths and raw/adjusted prefixes distinguished; unknowns explicit |
| QG6 | Pass: original bytes/fixups/imports,78 live source rows,264 fresh byte audits and11 source proof pairs |
| QG7 | Pass: impact-labeled bounded continuation table |
