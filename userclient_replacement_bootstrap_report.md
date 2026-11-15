# Replacement-caller shared-table construction and continuation

The selected existing-node replacement caller constructs a missing shared `FPHashTable`, publishes it only for initializer output `0x7cb541a6`, and sends any other initializer output through typed rollback. Allocation failure and ordinary rollback return independently reload the global holder and rejoin the original processing continuation. A null reload subsequently consults the saved replacement status; it does not itself determine the final update/failure outcome. These are conditional source contracts. Native holder coherence, ownership, serialization, full incoming reachability and correspondence to a successful fairplayd transaction remain unknown.

This extends the [replacement report](userclient_uidlist_replacement_report.md), [table bootstrap](userclient_hash_table_bootstrap_report.md) and [initializer report](userclient_hash_table_initializer_report.md). Original kernel-collection instructions and chained pointers are the primary evidence; the associated C export supplies context. The supplied references suffice for this increment; no IDB change or native target execution was performed.

## Evidence and reproducibility

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Original-byte comparisons for all selected code and descriptors |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instructions, pointer-chain membership and authenticated-pointer diversity |
| [Checks](triage_evidence/userclient_replacement_bootstrap_checks.json.zst) | `2e1d5733decedc4660bf373bd17e7fafc1a2469ab4be1de9db7ac052c6d1e5b3` | 24 spans, 354 selected instructions, 15 terminal transfers, 8 bank rules |
| [Audit](triage_evidence/userclient_replacement_bootstrap_audit.json.zst) | `c25989647b89033df33cb52c2797697c6434fb3db5252cd8f3a680700253e44c` | 22 new nonvacuous UNSAT obligations; 26 predecessor queries re-solved |

The [extractor](triage_evidence/recover_userclient_replacement_bootstrap.py), [source model](triage_evidence/audit_userclient_replacement_bootstrap.py) and [delivery verifier](triage_evidence/verify_userclient_replacement_bootstrap_delivery.py) reconstruct the evidence and proof queries. The audit covers 2,966 instruction instances across the 354 distinct selected PCs, all 2,048 bank-input cases, both fallback routes and four altered-evidence comparisons. Those controls detect a changed instruction, bank byte, descriptor size or unsupported native-coherence claim through fresh-evidence inequality; they are not native mutation experiments.

The complete 275-instruction initializer and both complete kernel adapters are freshly compared with original and normalized bytes and with their prior captures. Twenty-one initializer queries and five replacement queries are re-solved from their frozen SMT formulas. This is full byte custody and predecessor-query revalidation, with a fresh caller-to-decoder/header join; it is not a fresh replay of the complete initializer or a native run. The separate 181-instruction bank-root def-use envelope overlaps selected root spans and is not added to the distinct-PC count.

| Claim | Established result | Principal dependency |
| --- | --- | --- |
| RB1 | Initial holder load, zero/nonzero gate and original processing continuation | RB-A1, RB-A2 |
| RB2 | Null-holder typed 16 B allocation request and nullable return gate | RB-A1-RB-A4 |
| RB3 | Token0xabd caller record, decoder equality and header count/capacity stores | RB-A1-RB-A4 |
| RB4 | Exact initializer-output publication/rollback predicate | RB-A1-RB-A4 |
| RB5 | Success publication and restoration of the saved continuation | RB-A1-RB-A5 |
| RB6 | Typed rollback request, ordinary return and independent holder reload | RB-A1-RB-A5 |
| RB7 | Both null-reload routes reach the saved-status update/failure gate | RB-A1-RB-A6 |
| RB8 | Original bank roots, raw saved-status default and ancillary FPTTLV allocation ABI | RB-A1, RB-A2, RB-A4 |
| RB9 | Interface, complexity and external-control boundaries | RB-A1-RB-A8 |

## Control and data flow

Here H is the global holder at `0xfffffe000ccceac0`, B is the allocator return, R is the private record at S+968 B, C is caller scratch, J is the matched 16 B list node and M is the new u32 marker. Initial h0 and later h1 are independent holder observations. The saved SP/cell epoch is an explicit premise.

```text
initial holder h0
  +-- nonzero: resume(h0)
  +-- zero: typed FPHashTable allocation -> B
       +-- B == 0: reload H -> h1 -> resume(h1)
       +-- B != 0: initializer(R)
            +-- output == 0x7cb541a6: H = B -> resume(B)
            +-- other: typed rollback -> ordinary return
                         -> reload H -> h1 -> resume(h1)

resume(selected holder): original processing continuation
  C+0x420 = selected holder; W23 = saved status32
  +-- holder != 0: first lookup
  +-- holder == 0: saved status == 0x31ae0066 ?
       +-- yes: store_u32(J+4, M) -> matched-node continuation
       +-- no: failure continuation
```

No success-path holder recheck is present in the selected publication block. Diagram offsets are hexadecimal.

| Site | Width / action | Exact selected behavior |
| --- | --- | --- |
| `0xfffffe000a65ac58` | load64 initial holder | Save holder address at SP+0x9e0; h0=0 selects index0x526 -> `0xfffffe000a65ac84`, otherwise index0x539 -> `0xfffffe000a65affc` |
| Holder phase | saved continuation64 | X19=`0xfffffe000a65b0e0`, obtained through table index0xa9 |
| `0xfffffe000a65ad50` | authenticated typed allocation call | X0=`0xfffffe000847b960`; adapter `0xfffffe000c4ba154`, IA modifier0xd0c8 |
| `0xfffffe000a65ad54`..`0xfffffe000a65ad78` | allocation return gate | B=0 -> index0x837 -> `0xfffffe000a65afa8`; B!=0 -> index0x81b -> `0xfffffe000a65ad7c` |
| `0xfffffe000a65ad80` / `0xfffffe000a65ad84` | retain B / continuation | X22=B; SP+0x9d0=X19 before X19 is reused for R |
| `0xfffffe000a65adc4` / `0xfffffe000a65adc8` | record stores32/64 | R+4=encoded token; R+8=B |
| `0xfffffe000a65ae1c` | authenticated initializer call | X0=R; target `0xfffffe000a627400`, IA modifier0x2bbe |
| `0xfffffe000a65ae24` | load32 R+0 | Output==0x7cb541a6 -> index0x59b -> `0xfffffe000a65ae58`; other -> index0x57a -> `0xfffffe000a65af10` |
| `0xfffffe000a65ae60` | store64 through saved holder address | H=B on initializer success |
| `0xfffffe000a65aea4` | restore64 | X19=SP+0x9d0, then index0x539 -> `0xfffffe000a65affc` |
| `0xfffffe000a65af90` | authenticated typed rollback call | X0=`0xfffffe000847b9a0`, X1=B; adapter `0xfffffe000c4ba368`, IA modifier0x4d6a |
| `0xfffffe000a65af98` / `0xfffffe000a65af9c` | ordinary rollback return | Index0x4e3 -> `0xfffffe000a65afa8`; restore X19 from SP+0x9d0 |
| `0xfffffe000a65afb0` | load64 holder again | X22=h1, independent of h0 and B |
| `0xfffffe000a65b004` | authenticated resume | BRAA through X19=`0xfffffe000a65b0e0`, modifier0xcb79 |
| `0xfffffe000a65b10c` / `0xfffffe000a65b120` | processing stores/loads | C+0x420=selected holder; W23=load32(SP+0x9ec) |
| Processing holder gate | nonzero / zero | Index0xaf9 -> `0xfffffe000a65b12c` first lookup / index0xac9 -> `0xfffffe000a65e6cc` status gate |
| Null-holder status gate | saved status32 predicate | 0x31ae0066 -> index0xc0e -> `0xfffffe000a65e710`; other -> index0xf4 -> `0xfffffe000a65ef14` |
| `0xfffffe000a65e734` | store32 through matched J+4 address | Write M; retained nonzero J selects `0xfffffe000a65e890` afterward |

The null-allocation route preserves the original continuation directly in callee-saved X19. The initializer/rollback route preserves it in SP+0x9d0 and restores it after the call. Separate source obligations establish X19, the resume register, modifier and selected holder before processing overwrites X19. Restored processing roots include C, S, the controller pointer, token `0x886a1ca3` and phase `0x7795e642`.

## Private initializer and typed memory interfaces

The new caller's low32 codec is:

```text
k32 = (low32(R) XOR 0x7abbf985) * 0xded29631  (mod 2^32)
store_u32(R+4, k32 XOR 0x00000abd)
store_u64(R+8, B)
call initializer(R)
output32 = load_u32(R+0)
```

| Record offset | Width | Meaning |
| --- | --- | --- |
| +0 | 4 B | Initializer's raw output status |
| +4 | 4 B | Pointer-dependent encoded token0xabd |
| +8 | 8 B | Allocated header B |

The 16 B count describes the accessed prefix of the previously established private record, not a newly inferred complete record allocation size. The source proof equates the caller pre-multiply value at `0xfffffe000a65adb0` with the decoder value at `0xfffffe000a627538`, then applies congruence through the same low32 multiplier and XOR. The reconstructed header slice proves decoded token0xabd, X20=B, store_u32(B+0,0) and store_u32(B+4,128). Valid disjoint aligned 16 B B storage is required for this memory composition.

The predecessor initializer contract, whose queries are re-solved here, requests 128 entries with 24 B stride: 128*24 B=3,072 B of entry storage, plus the separate 16 B header, totaling 3,088 B of requested object/entry storage on that path. Allocator overhead is excluded. Its success output is `0x7cb541a6`; its null-entry-buffer output is `0x7cb49d7a`. The later replacement gate's `0x31ae0066` is a different raw status channel. This increment preserves that distinction and does not infer native allocation success.

| Descriptor / use | Address | Name / signature | flags32 | size32 |
| --- | --- | --- | --- | --- |
| Missing-holder allocation | `0xfffffe000847b960` | `site.FPHashTable` / `21` | 0x64 | 16 B |
| Initializer-failure rollback | `0xfffffe000847b9a0` | `site.FPHashTable` / `21` | 0x64 | 16 B |
| Earlier bank-root envelope call | `0xfffffe000847bb60` | `site.FPTTLV` / `11` | 0xe4 | 16 B |

The two FPHashTable descriptors have distinct addresses and identical normalized 64 B contents. Their original 64 B contents and original name/signature pointer chains are separately retained and checked. The complete allocation/free adapters match the bootstrap capture. These descriptors identify requested typed-memory operations; native allocation identity, exclusive ownership and actual deallocation remain unknown. FPTTLV16 B, FPHashTable16 B, UIDList16 B and FPTTLVNode32 B are separate recovered type labels despite overlapping sizes.

## Bank roots and earlier call context

Each rule checks all 256 byte inputs against original arrays and compares the actual selected chained-pointer slot. Controller reads are independent arbitrary u32 values at each selected PC.

| Pair | Left array | Right array |
| --- | --- | --- |
| E | `0xfffffe0007949ed0` | `0xfffffe000792fec0` |
| V | `0xfffffe0007941f60` | `0xfffffe000794a0d0` |
| T | `0xfffffe0007949dd0` | `0xfffffe000792fbc0` |
| F | `0xfffffe000792fcc0` | `0xfffffe00079391f0` |

| Rule | Pair / key / composition constant | Index | Slot | Resolved target after bias |
| --- | --- | --- | --- | --- |
| Holder | V / 0x6d / 0x13 | 0x1ac | `0xfffffe0008472c60` | `0xfffffe000ccceac0` (minus4) |
| Allocation | E / 0x92 / 0xa2 | 0xf13 | `0xfffffe000847a7b8` | `0xfffffe000c4ba154` |
| Allocation descriptor | V / 0x05 / 0x2d | 0x31 | `0xfffffe0008472088` | `0xfffffe000847b960` (minus4) |
| Initializer | T / 0xb4 / 0x6e | 0xf77 | `0xfffffe000847aad8` | `0xfffffe000a627400` |
| Rollback | F / 0x87 / 0xdf | 0xf2b | `0xfffffe000847a878` | `0xfffffe000c4ba368` |
| Rollback descriptor | F / 0x87 / 0xdf | 0x4f | `0xfffffe0008472178` | `0xfffffe000847b9a0` (minus4) |
| Earlier allocation | T / 0x5c / 0xd2 | 0xf13 | `0xfffffe000847a7b8` | `0xfffffe000c4ba154` |
| Earlier descriptor | E / 0x32 / 0xf9 | 0x200 | `0xfffffe0008472f00` | `0xfffffe000847bb60` |

The 724 B/181-instruction envelope `0xfffffe000a6363c8`..`0xfffffe000a63669c` has one ordinary call, `BLRAA X11,X17` at `0xfffffe000a636404`, and no other transfer. The relevant source ranges do not overwrite X24/X26/X28 before their saved-root uses. Ordinary callee-save preservation across that call remains an ABI premise. The call is independently resolved to the typed allocation adapter, with X0 pointing to the 16 B FPTTLV descriptor and modifier0xd0c8. Its returned object's use/lifetime is not closed here.

The earlier W12=0x5c/W15=0x32 assignments occur before an unclosed `BRAA` at `0xfffffe000a636334`. The selector proof is conditional on those phase values at its entry; the envelope does not prove the intervening incoming branch or whole dispatcher reachability. Source stores subsequently establish E roots at SP+0x9f8/SP+0x9f0 and F roots at SP+0xa00/SP+0xa20.

The same selected source establishes the initial u32 default at SP+0x9ec as `0xce515bb2`. It differs from the later first-found-gate value `0xce515bbf` documented in the replacement report. The full intervening native write/admissibility domain of SP+0x9ec is unknown. Accordingly, both fallback routes prove the universal saved-status predicate, plus the conditional saved-success marker update. They do not prove that a native failed allocation always fails, always updates, or admits every modeled status value.

## Architectural scope and cost

The holder is a module-global memory cell; its original collection bytes are zero and the normalized file does not back that cell. Those facts do not establish a current runtime value. Publication and reload expose distinct observation epochs. No selected success block serializes an additional holder observation; native locking, barriers, other writers and lifetime protection require wider incoming/caller evidence before assigning a concurrent lifecycle interpretation.

No new incoming Mach endpoint, outgoing message, transferred port or emission site is established. The new calls are typed allocation, internal initialization and typed rollback. Existing endpoint/emission evidence remains in the [Mach-port report](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [context/task flow](context_descriptor_task_flow_report.md). This source closure does not bind a fairplayd request to a kext object epoch.

Excluding allocator/initializer internals, this selected caller uses O(1) time and O(1) auxiliary storage. Under the predecessor initializer's bounded contract, initialization uses O(N) time and O(N) requested entry storage, N=128 here. The complete dispatcher and native allocator costs are outside that bound. Extraction/model construction is O(B+I+256R+query DAG) time/space for captured bytes B, selected instruction instances I and bank rules R; SMT search cost is separate, with 30 s per-query limits. All 22 new premises are satisfiable before the counterexample predicates are added.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RB-A1: Pinned images, original pointer chains and predecessor receipts | RB1-RB9 provenance | Fresh full-function/adapter/descriptor bytes, dependency hashes, 2,048 bank cases and four altered-evidence comparisons |
| RB-A2: Selected matched-node phase, saved SP epoch and root values at slice entry | RB1-RB9 caller composition | Recover full incoming dispatcher, the branch at a636334, SP adjustments and all intervening saved-cell writes; current phase cuts do not prove native reachability |
| RB-A3: Valid nonwrapping separated frame, S4096 B, C2048 B, J16 B, context24 B, candidate120 B and conditional B16 B; SP aligned16 B, R/J/B aligned8 B | RB2-RB7 memory composition | Satisfiable separation from all five image VM regions; aliasing, invalid storage or a different frame epoch invalidates this composition |
| RB-A4: Ordinary returning authenticated calls preserve X19-X29, SP and the specified saved cells | RB2-RB8 call joins and bank-root survival | X0-X18/X30 become arbitrary at each return; recapture exact target/modifier and 181-instruction def-use envelope; native PAC and nonreturning outcomes remain unknown |
| RB-A5: h0, h1, B and initializer output are independent call/observation seams until native lifecycle closure | RB4-RB7 publication/reload predicates | Universal pointer64/output32 obligations; recover all holder writers, synchronization and object identity before restricting native combinations |
| RB-A6: Saved status32 and matched J+4/M survive in the assumed cell/object epoch | RB7 conditional marker update | Universal status gate plus selected saved-success update; trace all SP+0x9ec writers and actual marker producer before asserting native admissibility |
| RB-A7: Predecessor initializer's valid-storage and bounded ordinary helper premises | RB3/RB9 128-entry initialization and cost | Re-solve all 21 initializer obligations and compare complete callee bytes; allocation failure, retag path and frame/canary conditions remain distinct |
| RB-A8: Whole lifecycle, native ownership, lock discipline and daemon correlation remain separate requirements | RB9 architectural scope | Close input producers, holder/table writers and correlated provider transactions; recovered type names and local cuts alone do not establish them |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | S+0xc90 discriminator and original new-marker producer | Establish externally influenced input identity, collision interpretation and native marker domain |
| High | Incoming dispatcher, a636334 branch and SP+0x9ec writer chain | Close phase/cell epochs and actual saved-status admissibility |
| High | All holder/table writers and caller synchronization | Establish publication/reload lifetime and which observation combinations are native |
| Medium | Returned FPTTLV object and saved prior payload allocation identity | Connect typed requests to concrete producer/consumer lifetimes |
| Medium | Correlated fairplayd selector26/context/connection evidence | Bind static private fields to a successful daemon-kext exchange |
| Low | Other users of the distinct initializer and replacement status channels | Map reuse of the private-record ABI without merging raw statuses |

## Quality gates

- **QG1**: Factual instruction, ABI and control/data-flow claims require no normative conclusion.
- **QG2**: RB-A1-RB-A8 register dependencies, stress tests and explicit unknowns.
- **QG3**: Selected null-holder allocation, decoder/header join, exact initializer gate, publication, rollback, both reload routes and original continuation are covered; the larger investigation remains active.
- **QG4**: u32/u64 widths, modulo2^32 arithmetic, 16 B prefix/header, 24 B stride, 3,072 B entry request, 3,088 B combined request and bounded construction costs are reproducible.
- **QG5**: Initial/reloaded holder, original/saved continuation, initialized/replacement status, initial/later saved-status values and type labels remain distinct. Null and nonnull fallback gates are separately checked.
- **QG6**: Original instructions/fixups, fresh full-byte custody, 22 nonvacuous source obligations, explicit codec/bank certificates, 26 predecessor query rechecks and four evidence-comparison controls support the bounded claims.
- **QG7**: Ranked continuation includes input identity, incoming phase, saved-status writers, synchronization, ownership and daemon correlation.

The [discriminator-origin report](userclient_discriminator_origin_report.md) recovers the selected hash and exact null/empty/zero-result behavior. Its complete bounded literal-base inventory preserves the distinction between the saved-status initial default and unknown native effects through aliases/calls.

## Shared input-reader increment

The [shared input-reader analysis](userclient_input_reader_report.md) distinguishes encoded payload length at source+0xaa8 from primary status W23 and saved status at SP+0x9ec. It closes the selected hash-input publication path but does not restrict the native saved-status domain or complete holder ownership.

## Container-staging increment

The [shared input-parser report](userclient_container_staging_report.md) captures another16 B `site.FPTTLV` descriptor at0xfffffe000847b620 and its two-field initialization. The common site name does not identify this allocation with the replacement holder/root envelope or establish common native object lifetime.

## Record-node construction increment

The [nonempty-parser node constructor](userclient_record_nodes_report.md) identifies a separate 32 B FPTTLVNode descriptor, two allocation-result gates and shared writer setup. This conditional node path does not establish identity or ownership relationships with the replacement bootstrap's FPTTLV allocation.

## Protected record-writer increment

The [record-writer analysis](userclient_record_writer_report.md) establishes selected protected header/payload construction in the nonempty parser. This does not establish runtime identity with replacement-bootstrap objects or close their intervening ownership/list epochs.
