# Conditional FPSecureTunnel-to-table insertion

The original `_PRnut72j9` instructions establish a conditional pointer chain from the initialized tunnel alias to an occupied table entry's +16 payload. The caller derives the lookup/insertion key from a u32 at source+0x20, passes no optional found-byte output, and gates the occupied-entry writer only on lookup status0x31ae0066. After the writer returns, it stores the raw source marker into tunnel+0x6c. Native reachability, allocation identity, ownership, serialization and daemon transaction correlation remain unknown.

## Evidence and verification

| Evidence | Identity / coverage |
| --- | --- |
| Normalized kext | SHA256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original kernel collection | SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Original function container | `0xfffffe000a635208`..`0xfffffe000a666930`, `_PRnut72j9`; SHA256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| [Extraction](triage_evidence/recover_secure_tunnel_table_insertion.py) / [checks](triage_evidence/secure_tunnel_table_insertion_checks.json.zst) | Decoded checks SHA256 `2a02b7cad33072f3790125634f6d8d0deacd690f978df65a76b3939688b7e9df`; 23 spans, 388 selected instructions, four terminal transfers |
| [Audit](triage_evidence/audit_secure_tunnel_table_insertion.py) / [receipt](triage_evidence/secure_tunnel_table_insertion_audit.json.zst) | Decoded audit SHA256 `51a55c97d7989c6bc57b48b0c77301aeb11bf52eb5b3bc4871c0c4e88a9e9f02`; 15 nonvacuous obligations, including one unsigned integer extent lemma; eight predecessor obligations rechecked |
| [Publication verifier](triage_evidence/verify_secure_tunnel_table_insertion_publication.py) | Fresh extraction/audit reconstruction, canonical query comparison, solver reruns, decoded path scrub and manifest/input custody |

The audit covers all 388 selected instruction locations in 465 proof instruction instances. A separate original-byte def-use scan checks 354 intervening instructions. The two literal byte-bank identities are independently checked over 256 inputs each. The complete 50,634-word dispatcher is not semantically recovered. No target executes and no IDB is changed; existing binary evidence suffices without a new IDA query.

## Pointer and record lineage

Let C denote the current scratch-record base X2, S the current source-record base X4, P the initialized tunnel alias, H the table header, A its entry array, N its u32 capacity and I the u32 lookup index. Register roles are local; their business meaning and complete incoming provenance are unknown.

| Claim | Original location | Recovered transfer |
| --- | --- | --- |
| TI1 | `0xfffffe000a6355c4`, `0xfffffe000a635b50` | X16=S+0x968; save the private record R at SP+0x998. The intervening 354 instructions neither write X16/W16 nor transfer control |
| TI2 | `0xfffffe000a65b080`..`0xfffffe000a65b088` | P=load_u64(C+0x48); copy P to C+0x218 and C+0x5d8 |
| TI3 | `0xfffffe000a65b0c8`, `0xfffffe000a65bb98`..`0xfffffe000a65bba4` | Store H at C+0x200; reload H, load raw marker M from S+0x20 into W22, reload P from C+0x5d8 into X28 and clear S+0xcb4 |
| TI4 | `0xfffffe000a65bd0c`, `0xfffffe000a65be00` | Save payload X28 at SP+0x9e0 around a separate growth-call region, then restore it before that slot is reused as a token word |
| TI5 | `0xfffffe000a65c1ac` | Encoded token0x541 lookup request, X0=R, IA modifier0x6a0f |
| TI6 | `0xfffffe000a65c1f8`, `0xfffffe000a65c318` | Lookup status-only branch, then token0xc28 occupied-entry request with P as payload; IA modifier0x3936 |
| TI7 | `0xfffffe000a65c344`, `0xfffffe000a65c34c` | After ordinary writer return, store M at S+0xd0 and at the pointer reloaded from C+0x48, offset +0x6c |
| TI8 | Caller storage obligations and predecessor writer/lookup contracts | Conditional composition of record codecs, index/entry extent and entry state/key/payload updates; whole dispatcher and native lifetime remain outside the proof |

[The allocation report](secure_tunnel_allocation_report.md) establishes the earlier P publication at C+0x48/C+0x6e8 from the 120 B typed-allocation result. Joining that publication to TI2 requires stable scratch identity and preserved cells across intervening dispatcher paths. The current proof establishes the subsequent local transfer under that explicit premise; it does not execute or identify a native allocated object.

```text
allocation return P -> C+0x148 -> initialization -> C+0x48
                                                  |
                             C+0x218, C+0x5d8 <-----+
                                      |
                                      v
                                     X28
                                      |
                  SP+0x9e0 saved pointer -> restore X28
                  SP+0x9e0 then reused as u32 token0x5cc
                                      |
                                      v
               writer record R+0x10 -> entry I +0x10
                                      |
                          ordinary writer return
                                      v
                raw M -> S+0xd0 and reloaded P+0x6c
```

SP+0x9e0 carries different data at different times. The pointer is restored before `0xfffffe000a65be98` writes the u32 token. Treating the later token word as the saved pointer would break the source data flow.

## Exact key and lookup ABI

The source key domain is:

```text
M = load_u32(S+0x20)
U = M XOR 0x31ae0066
entry_key64 = 0x1ee45f68039f9913 + zero_extend_64(U)  (mod 2^64)
```

The original key-basis span proves X27=zero_extend(U)-0x31ae0066 and X25=X27+0x68aa65787ec20240 for every M. The caller's lookup key mixer then builds the exact representation consumed by [the recovered probe helper](userclient_hash_table_lookup_report.md). This is an XOR codec, not subtraction of the raw marker. No UID, PID, task identity or Mach-port interpretation is established.

R=S+0x968 occupies 48 B. Define K_L=((R XOR 0xec7859d5734a22b2)*0x8c229611) modulo 2^64. The caller's original pre-multiply expression is independently proved equal to the helper's, then transported through the common multiplier.

| R offset | Width | Lookup request |
| --- | --- | --- |
| +0x00 | u64 | Word whose addition to K_L equals `0x652019cc00000000 OR zero_extend(U XOR 0x6a48ac59)` |
| +0x08 | u64 | Zero: optional found-byte output absent |
| +0x10 | pointer | S+0xcb4: required u32 index output |
| +0x18 | u32 | Raw helper status output |
| +0x20 | pointer | A=load_u64(H+8) |
| +0x28 | u32 | Encoded token; subtract low32(K_L) to recover 0x541 |
| +0x2c | u32 | XOR low32(K_L), then subtract 0x4f950919 to recover N |

The lookup preparation is conditional on W20=W26=0x886a1ca3 and W13=0x7795e642. It derives token0x5cc in SP+0x9e0 and W20=0x91e for the return gate. These incoming dispatcher values and the saved TABLE/bank roots are premises; their native reachability is unknown.

Both call selectors use L=`0xfffffe0007949dd0`, Rbank=`0xfffffe000792fbc0`, with the exhaustive identity `x XOR Rbank[L[x] XOR key] = constant`:

| Call | Key / constant | Index | Original slot | Target / original diversity |
| --- | --- | --- | --- | --- |
| Lookup at `0xfffffe000a65c1ac` | 0xd8 / 0x20 | 0xf19 | `0xfffffe000847a7e8` | `0xfffffe000a5ae354` / 0x6a0f |
| Writer at `0xfffffe000a65c318` | 0x5c / 0xd2 | 0xf5d | `0xfffffe000847aa08` | `0xfffffe000a5aec24` / 0x3936 |

The original slot pointers have verified chained-fixup membership and authentication metadata. Native PAC authentication is unexecuted. Finite bank lemmas are explicit dependencies of the symbolic source-address checks.

## Status gate, occupied-entry request and counter

| Lookup status | Index selected by caller | Actual original target |
| --- | --- | --- |
| 0x31ae0066 | 0x91e XOR 0x4bf = 0xda1 | `0xfffffe000a65c1fc`, occupied-entry request |
| Any other u32 | 0x91e | `0xfffffe000a65e4bc`, continuation outside this increment |

The caller does not request or inspect a found byte. Under the existing helper contract, successful lookup can identify an insertion candidate or a matching occupied entry. This local branch therefore permits an occupied-entry write in either case. It does not independently prove the slot was empty, or establish the disposition of a prior payload.

The entry address is E=A+24*zero_extend(I). Original code tests `(A XOR E) AND 0xffc0000000000000`: a nonzero result replaces the top 16 bits with 0xc8a2. The ordinary-tag branch is an explicit premise of the entry-store composition. The alternate retag transformation is proved separately; its native dereference is unknown.

Define K_W=((R XOR 0x2a4f38d70e12cee6)*0x91c952ff) modulo 2^64. The original caller/helper pre-multiply expressions are independently equal. The writer request is:

| R offset | Width | Decoded writer value |
| --- | --- | --- |
| +0x00 | pointer | E |
| +0x08 | u32 | Encoded token minus low32(K_W) = 0xc28 |
| +0x10 | pointer | P, loaded through C+0x5d8 and the saved/restored X28 |
| +0x18 | pointer | H |
| +0x20 | u32 | Encoded state minus low32(K_W) = 0x629f8777, occupied |
| +0x28 | u64 | Encoded key plus K_W = 0x1ee45f68039f9913+zero_extend(U) |

Applying [the verified writer contract](userclient_hash_table_reclamation_report.md) under the proved storage implication gives state at E+0, key at E+8 and P at E+16; bytes E+4..E+7 are untouched. Header+0 increments modulo 2^32 only for an old empty state0x629f8775. An old tombstone0x629f8776, occupied state0x629f8777 or any other old state does not increment for this request. The global counter invariant remains unknown because all producer/growth paths are not closed.

The writer has no status output. After its ordinary return, the caller writes M to S+0xd0 and to the tunnel+0x6c field. Thus the earlier allocation-stage 0x31ae0066 at tunnel+0x6c is not a permanent constant: it becomes the raw source marker on this path. The source order publishes the pointer through the entry writer before this field writeback; native visibility/atomicity and a lock protecting this interval are unknown.

Cleanup derives its key from `UIDList node+4 XOR 0x31ae0066`. Consequently the keys agree if that node marker equals M, but this increment does not establish the node producer. P is not established as a Mach port name, and these local transfers emit no newly identified Mach message or endpoint. Existing IPC contracts remain in [the Mach-port report](mach_ports_report.md) and [interface ABI report](interface_abi_report.md).

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TI-A1: Pinned original/normalized bytes and actual fixup chains | TI1-TI8 provenance | Fresh original extraction, function-container hash, pointer metadata and decoded receipt comparison |
| TI-A2: Stable C/S roots, saved cells and P alias across the selected blocks | Conditional allocation-to-entry chain | Exact affine producers, 354-instruction X16 def-use scan, pointer-save/restore proof; resolve intervening paths/calls before asserting native identity |
| TI-A3: Stated dispatcher tokens and ordinary authenticated transfers | Lookup/writer ABI and return gate | Full-width codec equalities, all-M key proof, exact original selectors and both status branches; incoming native reachability/PAC unknown |
| TI-A4: Positive N, I<N, nonwrapping array and ordinary entry-tag branch | Entry indexing and stores | Explicit unsigned extent lemma for all u32 N/I, original stride/tag guard, separate alternate-tag transformation |
| TI-A5: Disjoint storage outside loaded image VMs; aligned SP/R/H/A and intact frame | Lookup/writer composition | Nonvacuous owned extents: caller plus 112 B callee frame, source4096 B, scratch2048 B, header16 B, payload120 B and array24*N B; exact implications into predecessor storage predicates |
| TI-A6: Exhaustive literal bank identities are valid at the original load addresses | Call binding | 512 finite checks and per-application address obligations; shared PAC diversity alone is insufficient |
| TI-A7: Earlier helper contracts apply to these decoded records | Candidate-or-match success and writer effects | Eight predecessor SMT queries rerun; no-found-byte request, exact token/key/capacity/state fields and explicit storage implications |
| TI-A8: Raw marker equivalence is distinct from business identity and ownership | Cleanup correlation, native lifetime and IPC interpretation | Recover UIDList node+4 producer, synchronized epochs and correlated daemon/userclient records; those claims remain unknown |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | UIDList node+4 producer and source+0x20 origin | Close marker/key correspondence and establish external source influence |
| High | Incoming dispatcher tokens and source/scratch roots | Establish reachability of the conditional allocation/insertion chain |
| High | Growth helper, other writers and context/table serialization | Establish counter invariants, stable epochs and payload ownership across replacement/free |
| Medium | Post-insertion context/list publication | Join table insertion with per-client tracking and teardown |
| Medium | Correlated fairplayd userclient transactions | Bind local marker/payload construction to existing IPC records |
| Low | Alternate retag dereferences and retained object bytes | Extend native pointer/layout domains with separate evidence |

## Quality gates

- **QG1**: Technical evidence only; no normative judgment is required.
- **QG2**: TI-A1-TI-A8 list assumptions, dependent results and falsification probes.
- **QG3**: Current pointer lineage, source-key derivation, lookup/write ABI, exact call sites, counter delta, post-write marker, environment/ownership boundaries and IPC scope are covered for this increment. The full investigation remains active.
- **QG4**: u32/u64 arithmetic, 24 B entry stride, 48 B record and 120 B payload are explicit. Exact modular arithmetic has no rounding term. Model/extraction construction is O(B+I+256R+query DAG), excluding SMT search; query limit30 s. The extent lemma uses unsigned integer ranges and proves nonwrapping before transport to bit-vector addresses.
- **QG5**: Candidate success versus match, raw marker versus identity, pointer-save versus token-slot reuse, local counter delta versus global invariant, ordinary versus alternate tag, and conditional lineage versus native ownership are distinguished.
- **QG6**: Original bytes/fixups, complete selected-source coverage, explicit finite/congruence/extent dependencies, storage-implication obligations and predecessor rechecks provide reproducible provenance. No native execution or new IDA evidence is claimed.
- **QG7**: Ranked continuation identifies remaining marker origins, reachability, growth, serialization, tracking and daemon correlation without claiming completion.

## UIDList search and publication follow-up

[The UIDList publication report](userclient_uidlist_publication_report.md) recovers the separate node+0 discriminator and node+4 tunnel marker, exact search/successor gates, typed 16 B allocation and ordered node-fill/context-head stores. Candidate tunnel+0x6c flows into node+4 under the recorded frame/object premises, joining the insertion and cleanup key codecs conditionally. Seventeen new obligations, six predecessor obligations, 232 selected instructions and 512 bank cases pass. Existing-match resource/status completion, discriminator/input identity, native reachability, ownership, serialization and daemon correlation remain unknown; no new Mach endpoint is established.

## Existing UIDList marker replacement follow-up

[The replacement report](userclient_uidlist_replacement_report.md) establishes the selected nonnull shared-holder path from an existing discriminator match through two old-marker lookup records, prior entry+16 payload capture, tombstone/reclamation requests, conditional 120 B typed payload free and status-gated node+4 replacement. Thirty-four nonvacuous obligations, 18 predecessor obligations, 734 selected instructions and 1792 bank inputs pass. Zero saved payload skips free and reaches the same marker-update join; raw success and found outputs remain separate. Null-holder construction, complete incoming reachability, native ownership/deallocation, serialization and daemon correlation remain unknown. No new Mach-port emission site is established.

The [replacement bootstrap report](userclient_replacement_bootstrap_report.md) extends shared-table construction evidence to the existing-node replacement caller, including its ordinary rollback and independent holder reload.
