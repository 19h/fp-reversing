# Existing UIDList match: old-marker removal, payload retirement and replacement

For the selected existing-node phase of `_PRnut72j9`, an unequal old marker enters the module-global FPHashTable holder path. With a nonnull shared header, two token0x541 lookup requests use the old marker's key. The first saves entry+16 as a prior payload; the second gates tombstone/reclamation requests with status and a found bit. A successful retirement status conditionally requests typed free of the saved payload, then writes the new marker into the existing UIDList node. Zero saved payload skips the free and reaches the same marker update. These are conditional source contracts, not native ownership or deallocation evidence. [UR1-UR9; UR-A1-UR-A8]

This refines the [publication report](userclient_uidlist_publication_report.md): the existing-match resource continuation is no longer wholly unknown. Its selected nonnull-holder lookup/removal/free/update path is established below. The null-holder constructor at `0xfffffe000a65ac84`, complete incoming dispatcher reachability, saved-frame epochs, all producers and serialization remain unknown. The raw old marker `0x31ae0066` selects a different direct path that reaches the failure continuation under the captured phase; it does not take this replacement path.

## Provenance and verification

| Evidence | Identity / verified scope |
| --- | --- |
| Normalized kext | SHA256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection | SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Original compiler envelope | `0xfffffe000a635208`..`0xfffffe000a666930`; SHA256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`; full byte custody, partial semantics |
| [Extractor](triage_evidence/recover_userclient_uidlist_replacement.py) / [checks](triage_evidence/userclient_uidlist_replacement_checks.json.zst) | Decoded SHA256 `02169372dbf37cf1a8807ed2dcf3ce74a93ed4f20e7f2d77d96c4d145d88e174`; 48 source spans, 734 selected instructions, 33 separate terminal transfers |
| [Auditor](triage_evidence/audit_userclient_uidlist_replacement.py) / [receipt](triage_evidence/userclient_uidlist_replacement_audit.json.zst) | Decoded SHA256 `8b94deb2ddf686f660bce197f87aeaf32cb143b6647ac42dc9c14e4d3fd20b51`; 34 nonvacuous UNSAT source obligations, 18 predecessor obligations, 2219 proof instruction instances |
| Static data / evidence controls | Six 256 B bank arrays, seven composition rules / 1792 byte-input cases, original branch/call/data fixups; four altered-evidence comparisons reject instruction, bank, branch-target and unsupported native-deallocation changes |
| [Delivery verifier](triage_evidence/verify_userclient_uidlist_replacement_delivery.py) | Fresh extraction/audit reconstruction, canonical SMT comparison and re-solving, exact manifest delta, original-input custody and decoded path hygiene |

Every selected PC appears in the source obligations. `734*4=2936 B` of selected source plus `33*4=132 B` of transfers are captured separately. A further `134*4=536 B` linear codec gap is checked for X8/X16 preservation and absence of control transfer. Original and normalized code agree. The complete envelope hash does not establish complete control flow. Files suffice for this increment; no new IDA query, native execution, API call or IDB mutation is performed.

## Objects, fields and saved record roots

Let C be the current scratch base in X2, S the current source base in X4, J the matching 16 B UIDList node, H the shared 16 B table header, A its entry array, R=S+0x968 the 48 B private record, M the new marker retained at S+0xd8c, and O=load_u32(J+4) the old marker. The [insertion report](secure_tunnel_table_insertion_report.md) establishes the affine R root; frame identity and interference remain premises. SUCCESS below denotes raw u32 `0x31ae0066`, without assigning an errno meaning.

| Claim | Original source | Established field / interface |
| --- | --- | --- |
| UR1 | `0xfffffe000a65ee70`..`0xfffffe000a65ee88` | Save J at C+0x410 and J+4 at C+0x2c8; copy O into S+0xc84; clear C+0x7a8 and S+0xb68 |
| UR2 | `0xfffffe000a65eef4`; `0xfffffe000a65ac54`..`0xfffffe000a65ac5c` | Unequal marker enters shared-holder dispatch; load u64 holder at `0xfffffe000ccceac0`, save its cell address at SP+0x9e0 |
| UR3 | `0xfffffe000a65b10c`; `0xfffffe000a65b120` | Save H at C+0x420 and reload a separate raw status32 from SP+0x9ec; this reload replaces W23's earlier default |
| UR4 | `0xfffffe000a65b4c4`..`0xfffffe000a65b52c` | First old-marker lookup: found byte S+0xb68, index32 S+0xa28, raw status R+0x18; first call at `0xfffffe000a65b52c` |
| UR5 | `0xfffffe000a65b598`..`0xfffffe000a65b59c` | Read entry[index1]+16 and save u64 payload at C+0x7a8; source tests the first found byte later |
| UR6 | `0xfffffe000a65b780`..`0xfffffe000a65b7e4` | Second old-marker lookup: separate found byte S+0xc80, index32 S+0xbe0, same R+0x18 status channel; call at `0xfffffe000a65b7e4` |
| UR7 | `0xfffffe000a65b874`..`0xfffffe000a65ba24` | Request tombstone/KEY0/zero payload through the entry writer, then backward reclamation; consume raw reclaimer status R+0x20 |
| UR8 | `0xfffffe000a65e598`; `0xfffffe000a65e664`; `0xfffffe000a65e698` | Load saved payload through C+0x7a8, conditionally request typed free, then clear the saved payload cell after ordinary return |
| UR9 | `0xfffffe000a65e6b4`..`0xfffffe000a65e734` | Success join explicitly writes W23=SUCCESS; status gate admits the existing-node marker store through C+0x2c8 |

The entry setup derives SP+0x940=S+0xa28, SP+0x5d8=C+0x7a8, SP+0x650=S+0xb68, SP+0x428=S+0xbe0 and SP+0x398=S+0xc80. Separate original-source obligations recapture these address-producing stores. The source's first payload-output pointer is C+0x7a8; its nonzero test is a pointer test, not a test of the saved payload or found byte.

The saved writer pre-key at SP+0x2c8 is `R XOR 0x2a4f38d70e12cee6`. SP+0x998 contains R, SP+0x6f0 contains `R OR 0xd9d0ab468c12f4cb`, and SP+0x3a0 contains the lookup codec key. Their original producers are checked under the supplied affine R identity. The original gap `0xfffffe000a635928`..`0xfffffe000a635b40` contains 134 instructions, no control transfer and no write to X8/W8/X16/W16; it preserves the pre-key and R before their saved use. Caller/helper pre-multiply equalities and multiplication congruence are explicit proof certificates; they do not assume a fixed numerical stack address.

## Exact control flow and status boundaries

```text
matching J -> capture old marker O and marker-address J+4
  O == SUCCESS -> status gate with W23=0xce515bbf -> failure continuation
  O != SUCCESS -> global holder
    zero    -> constructor frontier at a65ac84 (not closed here)
    nonzero -> saved processing continuation -> first lookup
      first status != SUCCESS -> failure continuation
      first status == SUCCESS -> save entry[index1].payload
        first found bit0 clear -> force 0xce515bbf -> failure continuation
        first found bit0 set   -> second lookup
          status == SUCCESS AND second found bit0 set
            -> tombstone writer -> backward reclaimer -> reclaimer status
          otherwise -> second lookup status
          tested status != SUCCESS -> failure continuation
          tested status == SUCCESS -> saved payload gate
            nonzero -> typed free request -> ordinary return -> clear saved cell
            zero    -> skip free
          -> force SUCCESS -> node+4 = new marker -> a65e890 continuation
```

| Predicate / local stage | Index | Original target |
| --- | --- | --- |
| Old marker O differs from SUCCESS | 0xbc1, then 0x5b7 | `0xfffffe000a65eee4`, then `0xfffffe000a65abf8` |
| Old marker O equals SUCCESS | 0xbc9 | `0xfffffe000a65e6cc`; captured W23 causes failure at `0xfffffe000a65ef14` |
| Initial holder zero / nonzero | 0x526 / 0x539 | `0xfffffe000a65ac84` / `0xfffffe000a65affc` |
| Saved processing H zero / nonzero | 0xac9 / 0xaf9 | `0xfffffe000a65e6cc` / `0xfffffe000a65b12c` |
| First status success / other; output pointer nonnull | 0x2f5 / 0x2ed | `0xfffffe000a65b564` / `0xfffffe000a65b5ac` |
| First status success / other after trampoline | 0x988 / 0x146 | `0xfffffe000a65b64c` / `0xfffffe000a65e6cc` |
| First found bit0 set / clear | 0x2b9 / 0x146 | `0xfffffe000a65b6ac` / `0xfffffe000a65e6cc`; this gate installs W23=0xce515bbf |
| Second header nonzero / zero | 0xea2 / 0xeab | `0xfffffe000a65b6fc` / `0xfffffe000a65e6cc` |
| Second status success AND found bit0 set / other | 0xcb8 / 0xc95 | `0xfffffe000a65b820` / `0xfffffe000a65ba34` |
| Retirement status success / other | 0xdcb / 0x146 | `0xfffffe000a65ba98` / `0xfffffe000a65e6cc` |
| Saved prior payload nonzero / zero | 0xd72 / 0xd46 | `0xfffffe000a65e5dc` / `0xfffffe000a65e6a8` |
| Success join's status gate | 0xc0e | `0xfffffe000a65e710`, marker update |

These are phase-specific internal indices, not external IOKit selectors. The processing, first-header and second-header zero cases are separately proved local cuts. This does not close the actual null-holder constructor's continuation or equate independently observed holder epochs.

The second lookup's alternate route retains its raw status. Therefore raw SUCCESS with found bit0 clear bypasses mutation but still satisfies the later retirement-status comparison. The selected source does not retest that found byte there. A coherent stable table containing the previously confirmed key constrains which cross-call combinations can occur; that coherence and native admissibility are unknown. The model deliberately keeps the call outputs independent. No native resource imbalance or failing transaction is inferred.

## Lookup, writer, reclaimer and free contracts

Both lookup records decode the old-marker value as:

```text
U32 = O XOR 0x31ae0066
entry_key64 = 0x1ee45f68039f9913 + zero_extend_64(U32)  (mod 2^64)
```

The actual lookup input is encoded with the existing token0x541 codec, capacity and entry-array pointer; the audit checks the original packet shape, both output pointers, status channel, target and IA modifier. The [lookup report](userclient_hash_table_lookup_report.md) distinguishes candidate-success from an occupied-key hit. First status success permits the payload read before the first found-bit gate; the later first found-bit gate is required to proceed to the second request.

| Interface | Call location | Original target / slot | IA modifier |
| --- | --- | --- | --- |
| First lookup | `0xfffffe000a65b52c` | `0xfffffe000a5ae354` / `0xfffffe000847a7e8` | 0x6a0f |
| Second lookup | `0xfffffe000a65b7e4` | Same helper / slot | 0x6a0f |
| Entry writer | `0xfffffe000a65b90c` | `0xfffffe000a5aec24` / `0xfffffe000847aa08` | 0x3936 |
| Backward reclaimer | `0xfffffe000a65ba14` | `0xfffffe000a616860` / `0xfffffe000847a9d0` | 0xaf1c |
| Typed payload free | `0xfffffe000a65e664` | `0xfffffe000c4ba368` / `0xfffffe000847a878` | 0x4d6a |

| Bank rule | Pair / key / constant | Index | Resolved value |
| --- | --- | --- | --- |
| Holder | V / 0x6d / 0x13 | 0x1ac | Pool slot `0xfffffe0008472c60`, pointer minus4 -> `0xfffffe000ccceac0` |
| First lookup | F / 0x87 / 0xdf | 0xf19 | Lookup helper |
| Second lookup | T / 0x16 / 0x88 | 0xf19 | Same lookup helper |
| Entry writer | T / 0xb4 / 0x6e | 0xf5d | Entry writer |
| Reclaimer | F / 0x87 / 0xdf | 0xf56 | Backward reclaimer |
| Typed free | T / 0x73 / 0x47 | 0xf2b | `_IOFreeTypeImpl` adapter |
| Free descriptor | V / 0x98 / 0x95 | 0x117 | Pool slot `0xfffffe00084727b8` -> `0xfffffe000847bf60` |

F is the original array pair `0xfffffe000792fcc0`/`0xfffffe00079391f0`; T is `0xfffffe0007949dd0`/`0xfffffe000792fbc0`; V is `0xfffffe0007941f60`/`0xfffffe000794a0d0`. Each rule checks all 256 byte inputs, both original array addresses and its actual selected pointer slot. Controller reads are independent arbitrary u32 values at each selected source PC; target resolution does not require frozen controller values across calls.

The 48 B writer record requests state TOMBSTONE=`0x629f8776`, key word KEY0=`0x1ee45f68039f9913`, payload zero and header H for entry `A+24*index2`. The writer has no status output. The following 40 B token0x559 record carries H, index2, capacity N, A and raw output status at R+0x20. Its low32 pre-multiply codec equality is proved under 8 B R alignment before applying the common multiplier. The [reclamation report](userclient_hash_table_reclamation_report.md) establishes the writer transitions and bounded backward policy; 18 selected predecessor queries are re-solved here. This increment establishes the new caller records, not a new interpretation of those helpers.

At typed free, X0 is the original descriptor `0xfffffe000847bf60`, X1 the saved entry+16 word, X10 the exact `_IOFreeTypeImpl` adapter and X17=0x4d6a. The descriptor is `site.FPSecureTunnel`, empty signature, flags32=0x6c, size32=120 B. Original descriptor bytes and the complete adapter match the prior capture. They identify the requested free ABI, not the allocation identity, exclusive ownership, liveness or actual deallocation of X1.

Ordinary call-return cuts make X0-X18 and X30 arbitrary; X19-X29, SP and the documented saved cells persist. Following free return, the source restores roots, clears C+0x7a8 and enters a join that assigns W23=SUCCESS without consulting W0. The zero-payload route bypasses free and reaches that same join. The original status gate then admits `0xfffffe000a65e734`, which writes u32 M through the pointer captured as J+4. The matched-node presence cell retains J and selects `0xfffffe000a65e890` afterward. No UIDList node free or head replacement is performed by these selected update blocks.

For a stable coherent table with capacity N and ordinary bounded helper returns, two lookups and one backward reclamation cost O(N) time and O(1) auxiliary storage apart from fixed records/frames. Including the preceding discriminator search over L nodes gives O(L+N) for this selected composition. This is not a bound for the complete obfuscated function or native allocator/free costs.

## Architectural and external-control boundaries

The global table holder, per-context list head, matching node, new candidate tunnel and saved prior payload are distinct channels. The new marker flows through the [publication contract](userclient_uidlist_publication_report.md); the old marker supplies both lookups here. The recovered names and u32 fields do not identify a user, PID, Mach-port name, entitlement or cryptographic key.

No selected instruction establishes a new incoming endpoint, Mach trap, outgoing message or port transfer. All newly bound calls are internal private-record helpers or typed memory retirement. Existing emission sites remain in the [Mach-port report](mach_ports_report.md) and [interface ABI report](interface_abi_report.md). The [context/task flow](context_descriptor_task_flow_report.md) connects the provider arguments conditionally; a successful fairplayd-kext transaction in the same object/marker epoch remains unknown.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UR-A1: Pinned original/normalized image, pointer fixups and predecessor receipts | UR1-UR9 provenance | Fresh source and full-envelope comparison, descriptor/adapter equality, dependency hashes and four altered-evidence controls |
| UR-A2: Current matching-node dispatcher phase, saved SP epoch and stable C/S/R roots | Existing-node resource composition | Recapture node/marker-address stores, all saved roots and exact branch slots; recover full incoming dispatcher and SP adjustments before asserting native reachability |
| UR-A3: Valid nonwrapping disjoint frame, source4096 B, scratch2048 B, node16 B, context24 B, candidate120 B, header16 B and array24*N B; 16 B SP and 8 B R/header/array/node alignment | Memory/record claims and address composition | Nonvacuous separation premises against all image VM regions, positive N and index<N; invalid objects/aliasing exclude composition |
| UR-A4: Ordinary authenticated calls and saved-cell/callee-save persistence | Record outputs, payload retention and update after free | Arbitrary X0-X18/X30 at every selected call-return cut; exact modifiers, restored roots and predecessor frame rechecks; native PAC and nonreturning paths unknown |
| UR-A5: Each lookup/reclamation output is an explicit independent call seam until table coherence is proved | All raw status/found predicates and miss/success edge case | Universal status32/found8/payload64 obligations; close table serialization and inter-call mutation before assigning native combinations |
| UR-A6: Original marker/tunnel/context identity persists across insertion, match and update | New marker replaces the intended existing tracking field | Recheck publication's matching-address/marker premises and trace actual producer/lifetime epochs; descriptor names alone do not prove identity |
| UR-A7: Coherent positive-capacity table and stable bounded helper execution | O(N) composition and occupied-to-tombstone interpretation | Re-solved helper queries and existing independent replays; concurrent mutation, invalid index, nonordinary tag path or inconsistent entry state falsifies composition |
| UR-A8: Native ownership, deallocation, null-holder construction and daemon correspondence are separate open requirements | Scope and external-control conclusions | Recover constructor at a65ac84, table/list locking and actual correlated provider transactions; do not promote this local source path to a completed native lifecycle |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Null-holder constructor at `0xfffffe000a65ac84` through the saved processing continuation | Complete this caller's allocation, initialization, publication, rollback and saved-status behavior |
| High | Source+0xc90 discriminator producer and original new-marker producer | Input identity, collision behavior and actual admissible marker values |
| High | Full incoming dispatcher, SP/cell interference and native table/list serialization | Establish which local joins coexist in one valid lifecycle |
| Medium | Saved payload allocation identity and all global holder/table writers | Resource ownership and producer/remover relationships |
| Medium | Correlated fairplayd selector26 and context/connection records | Bind the recovered fields to a successful daemon-kext exchange |
| Low | Additional users of the saved first-payload and independent found/index channels | Broader reuse of the private-record interface |

## Quality gates

- **QG1**: Factual source, ABI and control/data-flow analysis; no normative conclusion is required.
- **QG2**: UR-A1-UR-A8 identify dependencies and falsification probes, including ordinary ABI and cross-call coherence.
- **QG3**: Selected match gate, shared-holder/nonzero path, both lookup packets, exact found/status gates, payload capture, deletion/reclamation records, nullable typed free, ordinary return and marker update are covered. Null-holder construction and the full investigation remain active.
- **QG4**: u32/u64 widths, modulo arithmetic, 24 B stride, 48 B/40 B records, 120 B type, source/transfer byte counts and algorithmic bounds are explicit. Extraction/audit construction is O(B+I+256R+query DAG), with SMT search separate and30 s/query limits.
- **QG5**: Old versus new marker, first versus second outputs, success versus occupied hit, writer versus reclaimer status, request versus native deallocation, and complete bytes versus complete reachability remain distinct. Both zero and nonzero saved-payload joins pass.
- **QG6**: Original code, pointer chains, descriptor/adapter, 34 nonvacuous obligations, explicit codec congruence certificates, 18 predecessor rechecks and four evidence-comparison controls provide reproducible provenance.
- **QG7**: Ranked continuation preserves constructor, input identity, epochs, synchronization, ownership and daemon correlation as outstanding requirements.

The [replacement bootstrap report](userclient_replacement_bootstrap_report.md) now closes the selected null-holder constructor and both fallback continuations. The earlier constructor gap is superseded within those stated premises; native reachability and coherence remain unknown.

The [discriminator-origin report](userclient_discriminator_origin_report.md) recovers the discriminator algorithm and records one literal SP+0x9ec write with 47 reads. Aliases/callees/SP epochs remain open, so the saved-status native domain is not established.

## Shared input-reader increment

The [hash-input reader](userclient_input_reader_report.md) extends discriminator provenance to a decoded tagged-node payload and exact-L allocation/copy. It preserves the separate tunnel-marker channel; original marker generation, upstream termination and replacement serialization remain open.
