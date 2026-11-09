# Constructor rejection, candidate retirement and status return

Original source resolves the constructor cleanup frontier at `0x1008c3528`. Under core phase `0x6cf4` and a valid candidate node, it saves the full incoming X6 status, conditionally releases the candidate buffer, releases the candidate node, restores X6 and selects the saved constructor continuation. The two original `_free` call sites are `0x10078c3f0` and `0x1006b79a4`, under the recorded bank-root/call premises. These are source contracts; the 12 retained successful private profiles contain no cleanup occurrence. [CF1-CF8]

The same source identifies two boundaries: cleanup reads node+`0x18` before testing the buffer, so a valid node is required; and cleanup does not clear the freed candidate-pointer scratch at frame+`0x38a0`. Neither observation proves a native fault, later invalid access or executed allocator failure. No such fixture or execution occurred.

One earlier report label is corrected: the record allocator's left bank pointer comes from frame+`0x968`, not `0x5f0`. The actual source at `0x100948bbc` is `LDR X10,[SP,#0x968]`. The prior numeric bank-selection theorem remains conditional and unchanged; its frozen JSON/generator retain the historical label. The new ledger explicitly supersedes that one metadata field, and the human report now gives the correct slot.

Evidence: [source, banks, liveness, original pointers and erratum](triage_evidence/daemon_constructor_failure_source.json), [14-query certificate](triage_evidence/daemon_constructor_failure_checks.json), [extractor](triage_evidence/recover_daemon_constructor_failure.py), [validator](triage_evidence/validate_daemon_constructor_failure.py), [preservation](triage_evidence/daemon_constructor_failure_delivery.json), [scoped gates](triage_evidence/daemon_constructor_failure_quality_gates.json). Adjacent contracts: [entry/allocation](daemon_constructor_inputs_report.md), [type/extent](daemon_typed_scalar_report.md), [lookup/replacement](daemon_constructor_lookup_report.md). Reference data sufficed; no additional IDA access/mutation, target execution, emulation, native API or IPC request occurred.

| Evidence | Exact scope |
| --- | --- |
| Original thin image | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh capture | 12 fragments, 366 instructions, 1464 B; 15 original pointer records |
| Prior source recapture | 44 ranges, 11220 B |
| Cleanup selection | Two bank calculations, all 256 byte inputs each: 512 cases |
| Static certificate | 14 UNSAT queries; 260 translated instruction instances, 239 SSA definitions |
| Liveness | Four source intervals establish specific status/argument/phase/bank-register preservation; native calls require normal saved-register behavior separately |
| Frozen corpus | 12 private send profiles; 60 nonnull node and 60 nonnull buffer results; zero cleanup entries/calls |
| Altered controls | Nine source/bank/slot/erratum/fixup/liveness/occurrence/native-label/result alterations rejected |

Addresses are original unslid VAs. Hexadecimal offsets/constants have `0x` prefixes; extents use B. K denotes the shared frame, N the candidate 32 B node, and B its buffer pointer. X6 is a full u64 transfer channel; W6 observes its low 32 bits. These are private flattened continuation interfaces, not a recovered public C return prototype. [CF1-CF4]

```text
constructor checks / lookup status
                 |
                 v
           save X6 in X25
           load N; load B=N.buf
                 |
                 +-- B!=0 --> free(B) --> N.buf=0 --+
                 |                                 |
                 +-- B==0 -------------------------+
                                                   |
                                                free(N)
                                                   |
                                             restore X6=X25
                                                   |
                                          saved constructor continuation
```

## Entry and failure categories [CF1-CF4]

The selected entry/core epoch is `0x6cf4`. Raw markers below are exact source values, not assigned public error names. Gate assignments also execute on some successful branches; branch selection determines the failure path.

| Source category | Raw W6 carried on that failure edge | Original route / bound |
| --- | --- | --- |
| Null collection operand C | `0x74c29d88` | Entry index0xab69 -> early return0x10076de60, before allocation |
| Decoded payload P exceeds0xfffffff5 | Entry marker, ordinarily `0x74c29d88` | Guard index0x79f1 -> early return, before allocation |
| Node allocation result | `0x74c29d85` on the selected null-result edge | Index0xa1c8 -> cleanup entry; valid-node cleanup premise is not established by a null result |
| Record-buffer allocation returns zero with valid N | `0x74c29d85` | Zero stored at N+0x18; index0xc766 -> cleanup, which skips buffer release |
| Unaccepted internal discriminator | `0x74c29d88` | Intermediate0x100544fd0 -> index0x3c99 -> cleanup |
| Incorrect scalar payload extent | `0x74c29d8f` | U32 intermediary or direct u64 index0xa1c8 -> cleanup |
| Lookup status other than exact success/miss | The lookup's raw status | Signed classifier plus exact gates -> index0x3c99 -> cleanup |

Here `P=E XOR 0x8b3dc651`, with E/u32 saved at entry. The guard's accepted bound ensures the mathematical P+10 B allocation fits u32. The early-return proof retains arbitrary incoming X6 across the guard; the preceding entry supplies the stated marker on the selected ordinary route.

The lookup composition holds for every u32 status: only `0x8b3dc651` selects matched replacement, and only `0x74c29ded` selects append. Every other low32 status selects common cleanup under the compatible phase. The proof uses the actual signed classifier and exact gate table-address expressions, not an unsigned reinterpretation or finite status examples.

At entry to cleanup, `0x1008c3548` loads N from K+`0x38a0`; `0x1008c354c` unconditionally reads B=[N+0x18]. Only afterward does the source test B. There is no preceding N==0 predicate in this captured entry. Accordingly, the valid-N cleanup certificate cannot be extended to graceful handling of a null node-allocation result. Actual native allocator failure, fault behavior and reachability remain unknown; no target failure was reproduced.

## Cleanup ABI, banks and ordered calls [CF1-CF5]

| Source location | Exact effect / value under phase0x6cf4 |
| --- | --- |
| `0x1008c3528` | Saves X25=X6, preserving all 64 bits |
| `0x1008c3548`, `0x1008c354c` | X20=N=[K+0x38a0]; X0=B=[N+0x18] |
| `0x1008c3544`, `0x1008c355c` | W19=0x79f1; W21=0xa7fb |
| `0x1008c3580`, `0x1008c3584` | X23=[K+0x5e0], right bank; X24=[K+0x5f0], left bank |
| Cleanup dispatch | B!=0: index0xa7f7 ->0x10078c384; B=0: index0xa7fb ->0x1006b794c; IA0x8809 |
| `0x10078c3f0` | Conditional `_free(B)`, IA0x46a2 |
| `0x10078c3f4` | After normal return, stores zero/u64 at N+0x18 |
| `0x1006b7988` | Reloads X0=N from K+0x38a0 |
| `0x1006b79a4` | `_free(N)`, IA0x46a2 |
| `0x1006b79ac` | After normal return, restores full X6=X25 |
| `0x1006b79b4` | Transfers through index0x79f1 ->0x10076de60, IA0x9b18 |
| `0x10076de60`, `0x10076de68` | Loads continuation from K+0x6ed0, transfers with IA0x151e |

The two cleanup calls use the same conditional bank roots: left `0x101031da0`, right `0x100e99900`. These are the original C-family byte arrays, not an assertion about the actual native contents of K+0x5f0/+0x5e0.

| Call role | Byte key | Source additive index constant | Exhaustive collapsed byte | Original binding |
| --- | --- | --- | --- | --- |
| Candidate buffer | 0x86 | 0xcbb0 | 0x58 | Table0xcc08 / slot0x10109ff30 / libSystem `_free` |
| Candidate node | 0x9a | 0xcb23 | 0xe5 | Table0xcc08 / slot0x10109ff30 / libSystem `_free` |

For each input byte i, the concrete arrays satisfy `i XOR right[left[i] XOR key]=collapsed_byte`. The source-to-SMT components separately establish the exact left/right byte addresses, keys, controller arithmetic, table index and call argument. Under those roots, all 512 input cases therefore select `_free`; original binding metadata gives IA diversity0x46a2, address diversity zero and total addend zero. Actual frame-root production, hardware authentication and native allocator effects remain premises/unknowns.

The buffer preamble preserves X0=B until its call. Both branches supply N to node release, and W19 is0x79f1 on either branch. X25 carries the full incoming status through both call sites, requiring normal preservation of the saved registers used by the source. The buffer's zero case has no buffer call or explicit field-clear store; it proceeds directly to node release. No list unlinking occurs in the captured cleanup instructions. Interpreting N as an exclusive uncommitted candidate is an owner/list-state premise, not a consequence of the two `_free` bindings alone.

## Scratch lifetime and separate retirement domains [CF3-CF6]

| Frame/object cell | Failure cleanup | Successful matched replacement |
| --- | --- | --- |
| K+0x38a0 | Holds the candidate N; no explicit clear after node release | Holds NEW, which becomes reachable in the list |
| K+0x80b8 | No explicit write in these cleanup fragments | Holds OLD from lookup; cleared after old-node retirement |
| Candidate/old node+0x18 | Candidate buffer field cleared after the optional nonnull-buffer call | OLD buffer field cleared after its buffer call |
| K+0x6ed0 | Supplies enclosing constructor continuation | Supplies the same enclosing continuation contract |

The successful replacement calls are separate sites, `0x1006c10ac`/`0x100747e84`, with separate bank-root premises in the lookup report. The candidate cleanup calls must not be relabeled as old-record retirement. Source instruction-store checks cover all captured cleanup fragments: their only explicit store is zero/u64 to N+0x18 on the buffer-release branch. They neither clear K+0x38a0 nor update collection head/tail or neighboring links. With disjoint owners, that gives a local store footprint; it does not prove complete allocator side effects, synchronization or future scratch-cell uses.

## Prior metadata erratum [CF1,CF6]

The historical [constructor-input source ledger](triage_evidence/daemon_constructor_inputs_source.json) contains `/allocation_banks/1/frame_bank_pointer_slots/0 = "0x5f0"`. Its generator also hard-codes that label. In the same ledger's original record-allocation instructions, `0x100948bbc` is already `LDR X10,[SP,#0x968]`. Fresh bytes and a separate all-frame-address query confirm0x968.

The [human constructor-input report](daemon_constructor_inputs_report.md) now gives K+0x968/+0x960 for the record allocator and links this erratum. The frozen prior JSON/generator remain unchanged as historical evidence; the new source ledger's `metadata_erratum` explicitly supersedes that one label. This correction does not alter the bank bytes, 512 prior allocation-selector cases, `_malloc` binding or their conditional-root premise. K+0x5f0/+0x5e0 belong to the cleanup bank-pointer inputs described here. Conflating these two interfaces would incorrectly assign a bank family to a source load.

## Evidence limits and computational scope [CF7-CF8]

The frozen successful corpus contains 60 nonnull node results and 60 nonnull buffer results, across five constructor calls in each of 12 profiles. No profile enters the three cleanup fragments or reaches either cleanup call PC. Thus the corpus supplies a positive normal-allocation occurrence boundary and a negative cleanup count for this corpus; it supplies no dynamic failure/retirement example. Historical PAC bypasses and private allocation results remain private-model evidence.

No new allocation-failure input, malformed record, emulation or native FairPlay request was run. The annotated trace remains preserved; it does not supply successful native daemon-kext pairing. The source contracts identify no new Mach port, message emission or right transfer.

Cleanup has a fixed number of source operations and at most two original release calls: O(1) source control/scalar space. Allocator-internal cost is unknown and excluded from that bound. Extraction/recapture cost is O(source bytes + fixup catalog + frozen profile bytes); exhaustive bank checking costs512 constant-size byte cases. Translation is linear in selected instruction instances. Solving uses a15000 ms per-query timeout and separate solver complexity.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CF1 | Pinned original thin image/fixups and recorded conditional bank roots; source roles and import selection | Rehash/recapture bytes and fixups; establish actual bank-root producers before native selection claims |
| CF2 | Compatible core phase0x6cf4 and saved continuation/frame epoch; branch and return joins | Recover actual incoming phase and table base; another phase is outside these selected contracts |
| CF3 | N is valid, exclusive, uncommitted and suitably sized; frame, collection and buffer owners are stable/disjoint | Establish allocation/list lineage and aliases; cleanup reads N+0x18 before any buffer-null branch, and does not unlink N |
| CF4 | Normal call completion and preservation of the saved registers/frame fields used across `_free` calls; ordered retirement/status restore | Independently establish native call target, preserved state and ownership; static source call arguments alone do not prove effects |
| CF5 | Concrete bank-collapse lemma is instantiated at the source-proved byte addresses under the recorded roots | Recheck all256 inputs per key, source key/addend and frame slots; pointer-root mismatch invalidates the composition |
| CF6 | Explicit store footprint is scoped to captured instructions, and the erratum supersedes one historical label only | Recapture all stores, compare0x968 source load with historical JSON, and audit candidate/old-node scratch separately |
| CF7 | Frozen profiles retain the named successful private corpus; counts describe that corpus only | Recount results and cleanup site/target occurrences; source/observation/native-label alterations are rejected |
| CF8 | Continuation/source contracts do not imply native authorization, PAC, fault behavior or daemon-kext transport | Requires independent native endpoint/right identity and matching message/selector evidence; none is added here |

## Bounded continuation

| Impact | Remaining interface question |
| --- | --- |
| High | Actual frame-bank-root, phase and candidate ownership producers before native retirement/return claims |
| High | Upstream typed caller roots and outer continuations: how raw constructor markers become higher-level response fields |
| High | FairPlayIOKit selector26/RPC502/700 native caller/receiver pairing and concrete Mach rights |
| Medium | Lifetime of retained candidate scratch across subsequent frame epochs; no later-use conclusion follows from an uncleared cell alone |
| Medium | Distinguish normal allocator-result interfaces from valid-node cleanup premises without inferring native failure/fault behavior |
| Low | Apply exact instruction-address checks to future frame-slot annotations; arithmetic bank proofs do not validate metadata labels |

## Scoped quality gates

QG1: No normative conclusion is required; the report concerns source contracts and evidence scope.

QG2: CF1-CF8 enumerate assumptions, dependent results and falsification probes.

QG3: Early rejection, allocation-result joins, cleanup input/bank/owner ABI, optional buffer/node calls, status restore, saved return, scratch footprint and the specific prior metadata error are covered. Native interfaces remain incomplete.

QG4: Widths, B extents, modulo-u32 controller arithmetic, full-u64 status preservation, exact branch domains and computational bounds are explicit and reproducible.

QG5: Gate markers on successful branches, unconditional node-field read, absent cleanup observations, two retirement domains and the conflicting historical frame label are reconciled. Native fault behavior and future scratch uses remain explicitly unknown.

QG6: Original source/fixups, source-address and selector queries, concrete bank cases, prior recapture, frozen result counts and nine altered controls provide scoped primary provenance. Memory is build/evidence-boundary guidance only.

QG7: Bounded high/medium/low continuations preserve upstream status, owner/bank/phase and native endpoint obligations. No new execution, port identity or full-goal completion is claimed.
