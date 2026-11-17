# Schema scalar to shared-table lookup: holder, packet and status interfaces

The decoded schema u32 V becomes the key32 of a private token-0x541 hash-table lookup. Before consuming V, the caller requests the same global-holder facility used by UIDList replacement, saving its own callback. A ready holder returns to that callback, which reads the actual scalar output and constructs the original 48-byte lookup record. Under the independently recovered decoder/probe contract, the occupied-entry key is `0x1ee45f68039f9913 + zero_extend32(V)`. The exact synthetic ADID field with V=0 reaches this pending lookup request.

This extends [the protected scalar result](userclient_schema_scalar_report.md) through its actual consumer, rather than assigning a command name from the field value. The helper call and allocator request are not executed. Native holder coherence, table contents/results, application identity of the key and matched daemon/kext transport remain unknown. The original stopped continuous guest is unchanged. The artifact name "registry" denotes this recovered shared-table operation; it assigns no platform service identity.

## Custody and claims

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original `_PRnut72j9` container | `[0xfffffe000a635208, 0xfffffe000a666930)`, 202536 bytes / 50634 words |
| Container SHA-256 | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Additional helper codec | `[0xfffffe000a5ae3c8, 0xfffffe000a5ae418)`, 80 bytes; outside the above container, compared separately against both pinned images |
| Decoded checks SHA-256 | `8e32cec6eec4718c2699fc97189b15c574f9bdce395d9bd55ce4dbf74f20cc72` |
| Decoded audit SHA-256 | `c476c63e75e118210b73cda2052a0a756e5947b794bcb81722543989fdf899b1` |
| New selected source | 17 spans, 313 words, 75 original table pointers; all 313 words covered |
| New source obligations | 13 nonvacuous UNSAT queries; 11602 lifted instruction instances |
| Retained proof rechecks | Six formulas re-solved: two scalar codec identities, actual u32 result/caller, lookup codec closed form and token541 nonnull/null-array contracts |
| Prefix custody | Ten cells / 76 bytes per original prefix; 300 cells / 2280 bytes across 30 retained prefixes |
| Derived evaluations | 30 explicit key substitutions; 498 numeric field values plus twelve symbolic environment-field relations |
| Environment and controls | 31 SAT premise checks and 31 conditional UNSAT checks; three rejected copied-source mutations; zero concrete native holder/capacity/array values supplied |
| New bank certification | Four source bank rules, 1024 input cases; original arrays, slots, fixups, targets and diversity retained |

The [generator](triage_evidence/recover_userclient_schema_registry.py) rebuilds the preceding scalar receipt, compares each new word against both pinned images, verifies all selected bank compositions and original pointers, checks the allocation descriptor/adapter and reconstructs every additional cell from overlapping original stores. The [auditor](triage_evidence/audit_userclient_schema_registry.py) composes the actual serializer/decoder/output stores into the new consumer. The [delivery verifier](triage_evidence/verify_userclient_schema_registry_delivery.py) rebuilds both receipts and checks exact publication custody. Frozen [checks](triage_evidence/userclient_schema_registry_checks.json.zst) and [audit](triage_evidence/userclient_schema_registry_audit.json.zst) are compressed JSON; displayed hashes refer to decoded bytes. Reference data sufficed; no IDB was required or modified.

| Claim | Established result |
| --- | --- |
| RG1 | The original prefixes retain the new bank, result, packet and default-status roots; all 300 cell reconstructions match their original stores. |
| RG2 | Actual u32 success requests the global holder at `0xfffffe000ccceac0` and saves this caller's callback `0xfffffe000a6367b4`. |
| RG3 | A ready holder returns to the exact scalar consumer, which reads V from S+0xbc4 and forwards its internal encoding with the caller's own output roots. |
| RG4 | The original packet matches the token541 decoder contract, including key32=V, capacity/array inputs, found/index outputs, callback roots and pending call target/modifier. |
| RG5 | An initial NULL holder selects a pending 16-byte typed FPHashTable allocation while preserving this caller's callback. Its allocator result and subsequent constructor return are not composed here. |
| RG6 | Arbitrary saved status32 is restored at the holder callback; its holder predicate selects the scalar consumer or caller error block. The caller error block stores the raw status before requesting cleanup. |
| RG7 | Actual u64/span schema type errors reach that status publication; the four source-built domains retain their qualified continuations and the u32 path preserves protected record/container state. |
| RG8 | The exact synthetic ADID field reaches a pending lookup for key32=0. Native table admission/content, lookup success, payload identity, field business meaning and transport pairing remain unknown. |

## Caller-specific holder and scalar consumer

F is the retained frame base, C the context, S the workspace, H/J/Z the first early container/node/protected record. V is the raw u32 already published at S+0xbc4. G is the independently symbolic value read from the global holder cell. The ready path requires a readable separated 16-byte G header; its capacity32 M at G+4 and array64 A at G+8 remain arbitrary source inputs. They are not bound to native values. The pending call does not dereference A.

| Channel / original site | Exact result |
| --- | --- |
| `0xfffffe000a636794` / terminal `0xfffffe000a6367b0` | Original index 0x5b7 -> shared holder entry `0xfffffe000a65abf8`, modifier 0x8d40. |
| W8=0x37 at that request | Selects this caller's saved callback `0xfffffe000a6367b4`. The replacement caller's index 0xa9 selects a different callback. |
| F+0xa50 / F+0xa58 | Original V-bank roots `0xfffffe0007941f60` / `0xfffffe000794a0d0`. |
| `0xfffffe000a65ac54` / `0xfffffe000a65ac58` | Certified holder rule selects the original pool pointer; its minus-four address is `0xfffffe000ccceac0`. Read G there, with writeback of that cell address. |
| `0xfffffe000a65ac5c` | Save the global cell address, not G, at F+0x9e0. |
| `0xfffffe000a65ac80` | G=0 -> `0xfffffe000a65ac84`; G!=0 -> `0xfffffe000a65affc`; modifier 0xa830. |
| `0xfffffe000a65b004` | Ready path resumes through X19=`0xfffffe000a6367b4`, modifier 0xcb79. |
| `0xfffffe000a6367e8` | Restore W23 from F+0x9ec. In this original prefix epoch the source-fixed default is `0xce515bb2`. |
| `0xfffffe000a6367f8` | G!=0 selects `0xfffffe000a6367fc`; G=0 selects `0xfffffe000a641c1c`; modifier 0x0d4c. |
| `0xfffffe000a636818` / `0xfffffe000a63681c` | Load F+0x648 -> S+0xbc4, then read the actual raw V stored by the preceding decoder. |
| `0xfffffe000a636838` | Produce W8=`V XOR 0x31ae0066`. |
| F+0x658 / F+0x610 | Load found-byte destination S+0x10 and retained payload destination C+0x440. |
| `0xfffffe000a636850` | Request common lookup entry `0xfffffe000a65b16c`, modifier 0x44f9, with private callback index W10=0x128. |

The callback's holder predicate is independently proved over all G64 and saved status32. A nonzero G selects the scalar consumer regardless of the restored status value; that consumer computes a new internal phase W23=0x160. The saved default is therefore not a completed lookup failure. The NULL-holder allocation path has not returned to this callback in the new composition; the all-G callback cut does not assert that every G value is natively reachable there.

```text
actual protected record -> raw V at S+bc4
                               |
                     shared global holder cell
                      /                     \
                   G != 0                  G == 0
                     |                       |
            own callback a6367b4       typed allocation request
                     |                 16-byte FPHashTable
            actual V read/re-encoded         |
                     |                  [call not executed]
            common lookup packet
                     |
            pending a5ae354 call
            token541; key32=V
            found / index / status channels
```

The shared absolute holder cell and shared source implementation establish architectural convergence with [UIDList replacement](userclient_uidlist_replacement_report.md) and [its constructor](userclient_replacement_bootstrap_report.md). They do not establish the same native object epoch, synchronization or ownership in both callers.

## Private lookup request and field roles

The record pointer R=S+0x968 is retained at F+0x998. Its companion F+0x6f0 value is `R OR 0xd9d0ab468c12f4cb`, produced by the original saved-root instructions. All thirty retained prefixes independently preserve both cells; the recorded source X16 at the R store equals S+0x968. F+0x940 retains the index-output address S+0xa28.

The original helper codec has K64=`((R XOR 0xec7859d5734a22b2)*0x8c229611) mod 2^64`; K32=low32(K64). The retained closed-form proof is re-solved. The new auditor independently proves the caller/helper pre-multiply expressions equal for every record64, executes the actual helper codec words and checks the caller expression/multiplier shape before transporting that equality through the common multiplier. V remains the value obtained from the actual protected body bytes.

| Record offset | Width | Exact original caller value / role |
| --- | --- | --- |
| R+0x00 | 8 bytes | Adding K64 yields `0x652019cc00000000 OR zero_extend32(V XOR 0x6a48ac59)`; token541 decodes key32=V. |
| R+0x08 | 8 bytes | Found-byte destination S+0x10. |
| R+0x10 | 8 bytes | Index32 destination S+0xa28; this caller clears it before the request. |
| R+0x18 | 4 bytes | Helper's raw status-output slot; the new caller does not initialize it. |
| R+0x1c | 4 bytes | Padding/unaccessed slot in the retained helper contract; the new caller does not initialize it. |
| R+0x20 | 8 bytes | A, loaded from G+8. |
| R+0x28 | 4 bytes | K32+0x541 modulo 2^32. |
| R+0x2c | 4 bytes | `(M+0x4f950919) XOR K32`, modulo 2^32; M loaded from G+4. |

Six actual stores initialize 40 bytes. Every new store is proved disjoint from the R+0x18..R+0x20 gap. No previous bytes or modeled outputs are supplied to fill that gap. The status slot remains an output channel of the pending helper rather than an assumed success value.

| Caller channel / transfer | Exact binding |
| --- | --- |
| C+0x30 | Saved outer callback `0xfffffe000a636854`, selected by index 0x128. |
| C+0x680 | Saved common trampoline `0xfffffe000a65b5f8`, selected by index 0x160. |
| X19 at pending call | C+0x440, the retained caller payload destination; its eventual store is not executed here. |
| X0 | R=S+0x968. |
| Call instruction | BLRAA at `0xfffffe000a65b52c`; target `0xfffffe000a5ae354`, IA modifier 0x6a0f. |
| Nominal link register | X30=`0xfffffe000a65b530`; target execution and native authentication remain unknown. |
| Original target slot | `0xfffffe000847a7e8`, inherited fixed-up authenticated pointer. |

The [table-probe contract](userclient_hash_table_lookup_report.md) establishes that a matching occupied entry compares its key64 against `0x1ee45f68039f9913 + zero_extend32(key32)`. The packet join therefore gives this expression with key32=V. Its largest value is `0x1ee45f69039f9912`, below 2^64; this addition does not wrap for any V32. Record codec operations remain modular u64/u32.

The same retained contract distinguishes an occupied-key hit from an available insertion candidate: both can return SUCCESS and an index; the optional found byte separates them. No lookup result follows from the pending request in this increment. Arbitrary capacity32/array64 packet formation does not establish an admissible table, positive capacity, readable entries or a matching key.

## NULL-holder allocation and error-status publication

| Source branch / effect | Established ABI or result |
| --- | --- |
| Initial G=0 | Select the original shared construction block at `0xfffffe000a65ac84`. |
| Allocation descriptor | `0xfffffe000847b960`: `site.FPHashTable`, signature `21`, flags32=0x64, requested size 16 bytes. Original and normalized descriptor bytes match the prior capture. |
| Pending allocation call | BLRAA `0xfffffe000a65ad50` -> typed adapter `0xfffffe000c4ba154`, modifier 0xd0c8; X0=descriptor. |
| Caller continuation across this request | X19 remains this caller's `0xfffffe000a6367b4`; nominal link X30=`0xfffffe000a65ad54`. |
| Error entry `0xfffffe000a641c1c` | Under the original caller phase W24=0x25, store raw W23 at S+0x1c. |
| Error terminal `0xfffffe000a641c5c` | Request `0xfffffe000a66229c`, modifier 0xb23e; W25=TOKEN and X19=C+0x418. Cleanup body is not executed here. |
| Complete source-built u64 / span variants | Publish the preceding type error `0xce515ae1` at S+0x1c; retain zero scalar output and cursor L+10 before that cleanup request. |

The earlier replacement-constructor evidence describes allocation, initialization, publication, rollback and reload for its own caller. The shared source and new allocation request do not replace a proof of those returns with this caller's saved callback. Native allocator effects and complete NULL-holder continuation remain open.

The selected spans contain no new Mach trap, port-right transfer, message send or incoming endpoint. New external resolution here is the pending typed-memory adapter; the other pending call uses a private in-image record ABI. Existing Mach emission sites and endpoint identities retain the separate evidence in [Mach ports](mach_ports_report.md) and [interface ABI](interface_abi_report.md).

## Evaluations, controls and costs

Thirty evaluations explicitly substitute raw tag `0xfa834112` into retained predecessor inputs. Six u32 projections reach the ready-holder lookup request, while twelve u64 and twelve span projections reach error-status publication. They check 498 numeric field values and twelve remaining symbolic array/capacity relations. For every projection and the separate ADID witness, all storage/branch/table premises are jointly satisfiable and the qualified output/call contract has an UNSAT counterexample query: 31 SAT and 31 UNSAT checks. G, M and A are never replaced by concrete native values. These are conditional derived projections, not new retained guest execution prefixes.

The ready composition uses four additional independent controller reads and two additional abstract certified-bank bytes, on top of the preceding serializer/search's four reads and two bank bytes. The NULL allocation request uses four additional controller reads and three additional bank bytes. No equality of controller observations across calls is required. The four new finite bank relations are independently checked over 256 inputs each. The eight unrelated setup cells remain symbolic; no missing cell is filled.

The ADID witness retains the exact field `fa83411297770000000400000000`, checks all fourteen actual protected bytes, decodes V=0 and proves the pending packet/call contract with environment inputs still symbolic. Under the rechecked helper interpretation, its requested occupied-entry key64 is `0x1ee45f68039f9913`. The twelve identical frozen 320-byte packet fixtures remain source-built evidence, not twelve independent native captures. The full packet is not submitted, its nested layer is not identified with H, and no native lookup or successful transaction is observed.

| Copied-source mutation | Contract violation / boundary |
| --- | --- |
| Change SUB immediate at `0xfffffe000a63678c` from 0x3a to 0x3b | Callback index becomes 0x36 rather than 0x37; stop before consuming that index. |
| Change result-root ADD at `0xfffffe000a635c54` from 0x10 to 0x14 | Ready caller forwards the wrong found-byte address; stop before packet construction. |
| Change entry-array STR offset at `0xfffffe000a65b4c8` from 0x20 to 0x18 | Array store reaches the status slot instead of R+0x20; stop at the pending call without executing the malformed record. |

All three controls have satisfiable premises and satisfiable violations. Only copied symbolic source is modified. The stopped continuous guest remains before `0xfffffe000a654ae4`; no native target, allocator, private lookup or fault path executes.

This selected holder/packet preparation uses O(1) work and auxiliary storage. The private helper's general probe cost, lifecycle and results retain their separate contract; they are not measured or executed here. Preceding span construction retains its finite O(L) copy proof. Evidence construction is linear in selected instruction/query DAGs, dependency bytes and original prefix stores, plus 1024 finite-bank cases. Solver search is separate: 60 seconds per new query and 120 seconds per retained-formula recheck in a fresh solver context. No native latency follows from these proofs.

## Assumption register

| Assumption | Dependent claims / stress test or falsification probe |
| --- | --- |
| RG-A1: Pinned images, original tables and dependency closure | RG1-RG8. Rehash the complete core envelope and both full images; compare all new words, helper codec, bank arrays, original slots, allocation descriptor/adapter and frozen predecessor receipts. |
| RG-A2: Original root/caller epochs and record address | RG1-RG8. Reconstruct all 300 cells from overlapping original stores, check X16 at the original R producer and execute the selected alias/default producers. Intervening writes or another R epoch invalidate the join. |
| RG-A3: Inherited separated storage and first-record scalar/span domains | RG2-RG8. Check original F/C/S/H/J/Z extents, capacity and pointer guards; preserve actual protected bytes and result/cursor cells. Native allocation/lifetime and full incoming admission remain unknown. |
| RG-A4: Explicit global-holder/header inputs | RG2-RG5, RG8. G is an observed symbolic global-cell input; only the ready path assumes a valid separated 16-byte G header. M/A are arbitrary field inputs. Check all G64 gate outcomes and conditional environment SAT/UNSAT queries; no native value or stable cross-call object epoch is supplied. |
| RG-A5: Fixed-width lift, certified banks, codec identities and nominal transfer semantics | RG2-RG8. Check 1024 new bank cases, independent controller symbols, the universal pre-multiply identity, every source-shape assertion, thirteen source queries and three mutations. Re-solve both inherited scalar codec identities. Native PAC/BTI/call effects are outside the model. |
| RG-A6: Private token541 interpretation applies to the newly proved packet shape | RG4, RG8. Re-solve original codec and token541 nonnull/null-array formulas; compare all actual caller fields, output roots and call metadata. Another token/record epoch or mutated field falsifies the join. No native table admission or result is inferred. |
| RG-A7: Explicit synthetic tag/scalar substitution and phase-qualified status joins | RG6-RG8. Check all derived bindings, fourteen ADID-compatible bytes, arbitrary saved-status/holder cuts and actual non-u32 error compositions. Full ADID layer/transport pairing, table contents and business identity need independent evidence. |

## Bounded continuation

| Impact | Interface / falsification target |
| --- | --- |
| High | Compose this actual token541 record with the helper's source execution and caller-specific result/payload/status consumers. Preserve the distinction between occupied-key hit and available candidate. |
| High | Trace producers of this shared table's keys/payloads and correlate the schema-read and replacement epochs. A common global cell alone does not identify an object lifetime or key business meaning. |
| High | Bind the ADID nested container and native daemon/Avp-to-primary26 transaction to H before claiming protocol-level handling. |
| Medium | Continue this caller's NULL-holder allocation/initializer/rollback returns with callback `a6367b4`; test the independent holder reload rather than assuming publication succeeds. |
| Medium | Follow the raw S+0x1c status and C+0x418 cleanup request, retaining separate early, schema and table-helper error phases. |
| Low | Apply the certified caller/decoder pre-key congruence to other packets only after checking their original source expression and saved-root epoch. |

## Quality gates

- **QG1**: Pass. Factual source contracts and evidence boundaries require no normative judgment.
- **QG2**: Pass. RG-A1 through RG-A7 identify dependencies and explicit stress/falsification probes.
- **QG3**: Pass for this increment. Actual scalar consumer, shared holder, ready packet/call, NULL allocation request, output channels and error-status publication covered; full interface goal remains active.
- **QG4**: Pass. Exact byte widths, 40/48 initialization coverage, u32/u64 modular arithmetic, nonwrapping key range, counts and complexity are reproducible.
- **QG5**: Pass. Ready versus NULL holder, saved status versus phase registers, initialized input fields versus untouched output slots, pending calls versus executed source and derived versus retained states remain distinct.
- **QG6**: Pass. Original code/pointers/descriptor/adapter, prefix stores, source formulas and independent private-decoder evidence provide primary provenance; no semantic reference is fabricated.
- **QG7**: Pass. Impact-ranked continuation identifies specific remaining data, control, lifecycle and transport joins.
