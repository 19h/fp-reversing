# Schema lookup results: actual helper execution and caller consumers

The actual schema token-0x541 packet now feeds the lookup routine at `0xfffffe000a5ae354` in the source model. A successful status permits the caller to copy entry+16 before its outer callback tests the found byte. An empty candidate therefore returns helper SUCCESS and an index, copies its declared payload, and then fails the caller's found-byte gate. An occupied-key hit with payload zero passes that gate and fails the subsequent payload-NULL test. A NULL entry array returns a distinct helper error and skips the payload read.

This composes the [original schema packet](userclient_schema_registry_report.md), [table-probe implementation](userclient_hash_table_lookup_report.md) and this caller's own callback. All business outputs come from executed source words. The authenticated return has an explicit normal-return ABI premise. Native authentication, coherent table epochs, real key/payload contents, pointee validity, complete operation and daemon/kext transport remain unknown. The historical continuous guest remains stopped before its undefined load.

## Evidence custody

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original helper envelope | `[0xfffffe000a5ae354, 0xfffffe000a5ae88c)`, 1336 bytes / 334 words |
| Helper envelope SHA-256 | `8d1690c80943159be246aa40e0f962fa2d92831f0fa4504f163f0fe8856e6d28` |
| Decoded checks SHA-256 | `b5a623be2bbd10b22c15187c624997375d0cd0c703e773ff6dcba9b87eb2374f` |
| Decoded audit SHA-256 | `a715d19afc150fe6e385f787a8bf78fd2534bff52d04ef1ee1626bd97faeae81` |
| New selected source | 29 spans / 433 words; 96 original branch-table pointers; every selected word covered |
| Source obligations | 298 nonvacuous UNSAT partitions across eleven semantic contracts; 626580 lifted instruction instances, including repeated prefixes |
| Retained formulas re-solved | Seven: two scalar codecs, caller/helper pre-key equality, actual packet formation, positive-capacity initial probe bound, empty-candidate index/status, constructor entry defaults |
| Additional prefix custody | Two cells / 16 bytes per original prefix; 60 cells / 480 bytes across 30 prefixes |
| Conditional evaluations | Six retained u32 inputs times four declared profiles, plus four exact ADID-field projections: 28 SAT/UNSAT pairs and 224 numeric fields |
| Controls | Three satisfiable copied-source violations; one bank relation checked over all 256 byte inputs |

The [generator](triage_evidence/recover_userclient_schema_lookup_result.py) rebuilds the predecessor receipt, compares selected words and the whole helper envelope against both pinned images, verifies original fixups/pointers/banks and reconstructs saved roots from original stores. The [auditor](triage_evidence/audit_userclient_schema_lookup_result.py) executes the existing protected serializer, reader, scalar output and packet constructor, then the helper and exact caller. The [delivery verifier](triage_evidence/verify_userclient_schema_lookup_result_delivery.py) rebuilds the results and verifies publication custody. Frozen [checks](triage_evidence/userclient_schema_lookup_result_checks.json.zst) and [audit](triage_evidence/userclient_schema_lookup_result_audit.json.zst) are compressed JSON; hashes above concern decoded bytes. Existing reference data sufficed; no IDB or original input was modified.

| Claim | Established result |
| --- | --- |
| LR1 | Original stores supply F+0xa30=`0xfffffe000ccc30d0` and F+0xa60=TABLE in all thirty prefixes. |
| LR2 | The real packet, token, capacity/array inputs and output addresses enter the actual helper; the probe uses `V AND (M-1)` and occupied-key comparison uses `0x1ee45f68039f9913 + zero_extend32(V)`. |
| LR3 | The helper's 112-byte frame preserves X19-X29, restores SP and reloads its opaque signed return token. Its two 64-bit controller stores have exact source formulas. |
| LR4 | Under the first occupied-match profile, source stores produce index p, found=1 and helper SUCCESS. The caller copies the declared raw payload to C+0x440. |
| LR5 | Under the first empty-candidate profile, source stores produce index p, found=0 and helper SUCCESS. With the constructor-compatible payload=0 input, the caller copies zero before publishing `0xce515bc4`. |
| LR6 | A NULL array produces helper `0xce515bbf`; no entry, found-byte or payload access occurs, and the caller publishes that status. An occupied hit with payload zero instead publishes `0xce515bda`. |
| LR7 | Separate source cuts establish the outer gate for every status32, every found-byte value and every raw payload64. Only found bit 0 matters; non-NULL payload selects the next unexecuted block. |
| LR8 | All four declared environments compose with the exact synthetic ADID field V=0. This establishes conditional source behavior, with no native content, whole-packet admission or transport identity inferred. |

## Data and control interfaces

F is the retained caller SP/frame base; C/S/H/J/Z retain their previous meanings. G is the nonzero shared-holder value with readable 16-byte header. M32=load32(G+4), A64=load64(G+8), R=S+0x968 and V32 is the actual decoded scalar at S+0xbc4. For non-NULL-array profiles, M is an arbitrary positive u32 and the complete readable array extent is `24*zero_extend32(M)` bytes, separated from private roots, the extended frame, header and image. It is not restricted to a power of two. The initial probe `p=V AND (M-1)` is below M for every M>0.

Selected entry inputs describe an explicit synthetic table environment. An occupied-match profile supplies state `0x629f8777` and key64=`KEY_BIAS+V` at the first probe; its payload is an arbitrary raw nonzero u64 or zero. An empty-candidate profile supplies state `0x629f8775` and payload zero. These are assumptions about table contents, not recovered native observations or injected helper outputs. Every input load has an address/width obligation. Unread entries are not materialized. The NULL-array profile supplies A=0 and needs no readable array extent.

| Location | Width / role | Source writer or reader |
| --- | --- | --- |
| R+0x18 = S+0x980 | 4 bytes, helper status | STR at `0xfffffe000a5ae868`; caller LDR at `0xfffffe000a65b53c` |
| R+0x08 -> S+0x10 | 1 byte, found output | Clear at `0xfffffe000a5ae524`; hit store at `0xfffffe000a5ae834`; outer read at `0xfffffe000a6368d4` |
| R+0x10 -> S+0xa28 | 4 bytes, index output | Store at `0xfffffe000a5ae84c`; caller read at `0xfffffe000a65b578` |
| Entry+0 | 4 bytes, state input | First-probe read at `0xfffffe000a5ae718` |
| Entry+8 | 8 bytes, occupied-key input | Read at `0xfffffe000a5ae778`; no key read on the selected empty path |
| Entry+16 | 8 bytes, raw payload input | Caller read at `0xfffffe000a65b598`; helper does not read it |
| C+0x440 | 8 bytes, caller payload output | Copy at `0xfffffe000a65b59c`; outer read at `0xfffffe000a636928` |
| S+0x1c | 4 bytes, caller error output | Store at `0xfffffe000a641c38`, before cleanup request |

The original lookup call at `0xfffffe000a65b52c` is BLRAA with target `0xfffffe000a5ae354`, IA modifier 0x6a0f and nominal link `0xfffffe000a65b530`. The source prologue executes PACIBSP, subtracts 0x70 from SP and saves X19-X30. The model uses a fresh opaque signed-return token, stores and reloads it through the actual frame instructions, proves token/SP/register preservation, and interprets RETAB under an explicit successful authenticated-return ABI premise. It supplies no PAC bits, keys, successful hardware authentication or native call evidence. The IA call modifier and B-key/SP return boundary remain distinct.

| Source transfer | Exact result |
| --- | --- |
| Helper RETAB `0xfffffe000a5ae888` | Conditional nominal return to `0xfffffe000a65b530`; original SP F and X19-X29 restored |
| Caller BRAA `0xfffffe000a65b560` | Status=SUCCESS and X19!=0 -> `0xfffffe000a65b564`; otherwise `0xfffffe000a65b5ac`; modifier 0x73ed |
| Payload address / copy | A+24*zero_extend32(index), normal pointer branch; read +16 and store through restored X19=C+0x440 |
| Common restore `0xfffffe000a65b5e8` | `0xfffffe000a65b5ec`, modifier 0x9599; restore C, S, TOKEN and PHASE |
| Inner / outer trampolines | BRAA through saved C+0x680=`0xfffffe000a65b5f8`, then C+0x30=`0xfffffe000a636854`, modifier 0x78f4 |
| Outer status branch `0xfffffe000a6368ac` | SUCCESS -> `0xfffffe000a6368b0`; other status -> `0xfffffe000a641c1c`; modifier 0x64d8 |
| Found branch `0xfffffe000a636900` | `(found&1)!=0` -> `0xfffffe000a636904`; otherwise error entry; W23=`0xce515bc4`, modifier 0x09fa |
| Payload branch `0xfffffe000a636954` | Payload!=0 -> `0xfffffe000a636958`; otherwise error entry; W23=`0xce515bda`, modifier 0x09fa |
| Error terminal `0xfffffe000a641c5c` | Pending cleanup request `0xfffffe000a66229c`, modifier 0xb23e; cleanup body unexecuted |

W23 at the non-NULL-payload frontier equals `0xce515bda`, but that value has not been published as an error there. It is assigned before the conditional transfer. A register value at that frontier is not a completed operation status. Payload!=0 proves only the NULL predicate; payload type, ownership, validity and lifetime are unknown.

```text
actual protected field -> V -> original token541 packet
                                     |
                              source lookup helper
                    +----------------+------------------+
                    |                |                  |
              occupied match    empty candidate        A=0
              SUCCESS,found1    SUCCESS,found0       ce515bbf
                    |                |                  |
                    +------ copy entry+16 ------+       |
                                  |            |       |
                          outer status gate    |       |
                                  |            |       |
                          outer found-bit gate |       |
                              /          \     |       |
                          found1       ce515bc4 |       |
                            |                  |       |
                       payload NULL?           |       |
                        /         \            |       |
                       0          !=0          |       |
                   ce515bda    a636958          |       |
                       |     [unexecuted]      |       |
                       +----------- raw status at S+1c-+
                                      |
                              pending cleanup request
```

| Declared profile | Helper status | Index / found | Payload copy | Caller result |
| --- | --- | --- | --- | --- |
| First occupied match; raw P!=0 | `0x31ae0066` | p / 1 | P -> C+0x440 | Next unexecuted block `0xfffffe000a636958` |
| First occupied match; P=0 | `0x31ae0066` | p / 1 | 0 -> C+0x440 | S+0x1c=`0xce515bda`, pending cleanup |
| First empty candidate; declared P=0 | `0x31ae0066` | p / 0 | 0 -> C+0x440 | S+0x1c=`0xce515bc4`, pending cleanup |
| A=0 | `0xce515bbf` | Index retains caller's preclear; found untouched | No payload read/store | S+0x1c=`0xce515bbf`, pending cleanup |

An arbitrary empty entry need not have payload zero. The zero-payload profile is compatible with the recovered [constructor defaults](userclient_hash_table_initializer_report.md): 128 entries, 24-byte stride, EMPTY state, KEY_BIAS key and zero payload. The per-entry source formula is re-solved. No constructor-to-this-call native allocation epoch is established. Because the payload copy precedes the found check, an empty-candidate selection would copy its actual payload input under the same status/output-pointer gates; this increment's complete empty profile supplies zero explicitly.

Both the helper key address and caller payload address test `(A XOR entry_address) AND 0xffc0000000000000`. Complete compositions use their normal-pointer branches as explicit premises. Separate source cuts prove each alternate MOVK replaces the upper 16 bits with 0xc8a2; they do not establish native usability of the resulting pointer.

## Controller effects, preservation and validation

The helper reads u64 g0 at `0xfffffe000ccc3158` and u64 g1 at `0xfffffe000ccc32f8`. Let `t=(F-0x68+g0+g1) mod 2^64`, multiplier B=0x4d08a3fb and K=0xa41a4d891208c018. Its original stores are:

| Store PC | Destination / exact u64 value |
| --- | --- |
| `0xfffffe000a5ae3c0` | `0xfffffe000ccc3158 = (t*B) XOR K` |
| `0xfffffe000a5ae3c4` | `0xfffffe000ccc32f8 = (t XOR K)*B` |

Multiplication/addition are modulo 2^64. These are private image-global effects in the model. They are not port operations. Observations remain independently symbolic; no equality with earlier 32-bit caller reads is assumed. The certified helper B-bank relation fixes the table pointer for all 256 byte inputs despite these controller values.

New source stores are proved disjoint from the protected fourteen-byte record, H/J objects, scalar-output cell and committed-cursor cell. The complete array remains read-only. Earlier scalar/packet values are reused through their re-solved original proof, with preservation checked against their actual pre-helper expressions. No decoded business output or missing private cell is replaced. The helper frame extends ownership down to F-0x70, with explicit nonwrapping/separation premises.

Twenty-four derived evaluations use the six retained u32 predecessor inputs and four explicit table profiles. They substitute the requested raw tag `0xfa834112`; the original tags remain recorded. Four additional projections use the exact fourteen-byte ADID field `fa83411297770000000400000000`, V=0 and key64=KEY_BIAS. All 56 protected-byte comparisons pass. Capacity128 is a declared constructor-compatible finite projection, not a native observation; the source contracts use arbitrary positive capacity on the non-NULL paths. Holder, array and nonzero raw payload remain symbolic. No native values are supplied.

The twelve frozen ADID field records are identical source-built fixtures. The certificates do not submit a full packet, identify its nested object with H or establish daemon/kext pairing. The continuous guest is not extended beyond `0xfffffe000a654ae4`; its eight unrelated unknown setup cells remain symbolic.

| Copied-source control | Detected violation / stop boundary |
| --- | --- |
| Change hit STRB at `0xfffffe000a5ae834` to store WZR | Actual found output becomes zero; reject before caller found-byte consumption |
| Change payload STR at `0xfffffe000a65b59c` from offset 0 to offset 8 | Store misses C+0x440; stop before reading the intended output cell |
| Change ADD immediate at `0xfffffe000a6368f8` from 0xc to 0xd | Empty-candidate error publication differs from `0xce515bc4`; stop at pending cleanup |

All three controls have satisfiable premises and satisfiable violations. Source obligations partition a disjunction of possible counterexamples into bounded groups; UNSAT of every partition proves the complete conjunction. SAT premise checks prevent vacuity. The partition count is not a count of independent native observations.

For these first-probe profiles, helper and caller processing take O(1) time and auxiliary space. The general prior probe contract has O(M) bounded visits for positive capacity; arbitrary collision/tombstone tables are not newly composed here. Evidence construction is O(I+C*I+256+query-DAG size) time/space, excluding bounded SMT search. New-query limits are 60 seconds per partition; retained formulas use 120 seconds in fresh contexts. No native timing follows.

No new incoming/outgoing Mach port, right disposition, message or emission site is established. All new transfers use private in-image records/callbacks or controller storage. Existing [Mach-port evidence](mach_ports_report.md) and [external interfaces](interface_abi_report.md) retain their separate native-identity limits.

## Assumption register

| Assumption | Dependent claims / stress test or falsification probe |
| --- | --- |
| LR-A1: Pinned images and retained dependency custody | LR1-LR8. Rehash both images and helper envelope; compare every selected instruction, original pointer/fixup, bank array and predecessor receipt. |
| LR-A2: Saved-root and packet epochs match the retained source | LR1-LR8. Reconstruct sixty additional cells from original stores; execute their producers, whole scalar/packet construction and actual helper decoder. Intervening writes or another callback/record epoch invalidate the join. |
| LR-A3: Readable, separated, nonwrapping storage and normal pointer branches | LR2-LR8. Check complete array extent, positive capacity, G header and F-0x70 frame separation; SAT-check every profile and compare all table-load addresses. Alternate pointer transforms have separate bit-only proofs. |
| LR-A4: Explicit first-probe table input profiles | LR4-LR6, LR8. Mutate occupied state/key, empty state or payload input and re-evaluate. Matching key/content and constructor-compatible defaults are declared environments, with no native producer/epoch supplied. |
| LR-A5: Fixed-width source lift, certified bank and inherited codec identities | LR2-LR8. Check all 256 bank inputs, seven retained formulas, all new UNSAT partitions, address/width obligations and three source mutations. Controller observations are independent; all new business outputs are source-derived. |
| LR-A6: Opaque PAC signing token and successful authenticated-return ABI | LR3-LR8. Verify actual frame stores/reloads, all X19-X29, SP and signed-token preservation; compare IA call modifier and B-key/SP return boundary. A native PAC failure invalidates the caller-return composition. Native PAC remains unknown. |
| LR-A7: Derived tag/ADID substitutions and phase-qualified result interpretation | LR4-LR8. Verify exact field/protected bytes, all 28 conditional environments, raw output stores and the next unexecuted block. Native transport, pointee validity, command meaning and whole-operation status require independent evidence. |

## Bounded continuation

| Impact | Specific interface / falsification target |
| --- | --- |
| High | Follow `0xfffffe000a636958` using the copied raw payload; recover its first dereference, object type/layout and subsequent status contract before attributing service meaning. |
| High | Trace producers of matching shared-table keys/payloads and correlate constructor, replacement and schema-consumer epochs; the common holder cell alone does not establish lifetime or synchronization. |
| High | Join the ADID nested container and actual daemon/Avp-to-primary26 transport to H and the same table epoch. Source-compatible fields do not establish end-to-end admission. |
| Medium | Extend this caller's NULL-holder allocation, initializer, publication/reload and rollback using callback `0xfffffe000a6367b4`. |
| Medium | Compose collisions, tombstones and exhausted probing from actual table inputs, preserving separate helper SUCCESS and caller found-byte semantics. |
| Low | Reuse the frame/PAC boundary model only after checking each routine's exact frame layout, signing key and SP modifier. |

## Quality gates

- **QG1**: Pass. Factual source contracts require no normative judgment.
- **QG2**: Pass. LR-A1 through LR-A7 identify dependent claims and explicit falsification probes.
- **QG3**: Pass for this increment. Actual helper/frame/controller outputs, four caller outcomes, error publication and exact ADID-field projections are covered; the full interface goal remains active.
- **QG4**: Pass. Widths, byte extents, u32/u64 modular arithmetic, 24-byte indexing, counts and algorithmic bounds are reproducible.
- **QG5**: Pass. Helper status, found byte, raw payload and published caller error remain separate; native PAC, table admission and whole-operation completion remain unknown.
- **QG6**: Pass. Original bytes, fixups, prefix stores, source queries, inherited formulas and rejected mutations provide primary provenance.
- **QG7**: Pass. Impact-ranked continuation identifies concrete payload, lifecycle, table-producer and transport joins.
