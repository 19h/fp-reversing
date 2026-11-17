# Early scalar and plaintext-span payload serialization

Subsequent early-publication evidence: The [first early record publication report](userclient_early_publication_report.md) composes all four scalar/span variants through empty-container lookup, exact first-node head/tail stores, saved callback and parser cursor selection. Eighteen source proofs, four payload rechecks, 30 partial-state evaluations, 480 reconstructed prefix cells, 270 resulting fields and three rejected mutations pass. The certified bank leaves controller values arbitrary. All retained fixtures select exhausted input; the universal cursor gate also covers a remaining suffix. Continuous guest extension, native ownership/PAC, nonempty early replacement and matched daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

The early record path conditionally serializes all three recovered payload domains: four-byte scalars, eight-byte scalars and plaintext byte spans. Combined with the [early header](userclient_early_writer_report.md), the selected source produces a complete protected record of `L+10` bytes and transfers to `0xfffffe000a655cb4`. The u32 and u64 gates require exactly L=4 and L=8. A zero-length span bypasses payload access; a nonzero span copies exactly L plaintext bytes in reverse index order and applies destination-address protection.

This is an original-instruction composition under storage, epoch and normal-pointer premises. All eight unrelated setup cells remain symbolic. The stopped continuous private guest remains stopped before `0xfffffe000a654ae4`; its missing cells have not been filled. Native allocator/admission/PAC/ownership, actual record publication and a matched daemon/kext transaction remain unknown. The broader interface investigation remains active.

## Primary evidence and reproduction

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Complete `_PRnut72j9` container | `[0xfffffe000a635208, 0xfffffe000a666930)`, 202536 bytes / 50634 words |
| Container SHA-256 | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Decoded checks SHA-256 | `6ed7378f51320046bf9d7ffea2470759ddbaf0b08dd290571147a7ba7fe504d0` |
| Decoded audit SHA-256 | `422eb0a76e182e8870f0870adfcea3de534268d178b9a77a0c383c29625d27d4` |
| New capture | 14 spans, 352 original words, 16 original table-pointer records, three direct type branches |
| New proofs | 15 nonvacuous UNSAT obligations, 5204 lifted instruction instances; all 352 new words covered |
| Prior rechecks | Two early-header obligations independently re-solved UNSAT |
| Partial-state evaluation | 30 predecessor cases, 468 serialized bytes, 120 saved-control values |

The [generator](triage_evidence/recover_userclient_early_payload.py) compares selected words with both images and rehashes the full container. It reconstructs seven retained cells per case from every overlapping source store, checks their final bytes, and checks the relevant producer-register values. The [auditor](triage_evidence/audit_userclient_early_payload.py) lifts original instructions independently and evaluates source-derived expressions against raw input fixtures. The [delivery verifier](triage_evidence/verify_userclient_early_payload_delivery.py) rebuilds both receipts, canonicalizes SMT formulas and checks exact publication custody. Receipts are [checks](triage_evidence/userclient_early_payload_checks.json.zst) and [audit](triage_evidence/userclient_early_payload_audit.json.zst); receipt hashes refer to decoded JSON. No IDB was required or modified.

## Claim register

| Claim | Established result |
| --- | --- |
| EP1 | Original source produces two fixed frame controls, the workspace scalar-cell pointer and the table-cell store under its incoming register premise; all 30 predecessor prefixes agree. |
| EP2 | Direct type branches classify raw types `0x9777`, `0x8485` and `0x50db`; scalar size gates require exactly four/eight bytes. |
| EP3 | The u32 path produces the exact 14-byte protected header-plus-scalar record and selects the common continuation. |
| EP4 | The u64 path produces the exact 18-byte protected header-plus-scalar record and selects the common continuation. |
| EP5 | The span gate recovers exact L, bypasses payload access for zero and loads the current buffer/plaintext source/count for nonzero L. |
| EP6 | A universal source step and finite-index certificate cover exactly L plaintext reads and protected payload stores, with exact backedge/exit selection. |
| EP7 | Thirty premise-checked partial-state evaluations agree with 468 independently encoded bytes; three copied-source mutations are rejected. |
| EP8 | Complete conditional serialization is distinguished from native admission, continuous guest execution, record publication and external IPC correlation. |

## Typed channels and source selection

`F` is the frame base, `C` the context, `S` the workspace, `J` the current 32-byte node and `Z` its retained data buffer. `D`, `V` and `L` are raw tag32, wire-type16 and length32. `B` and `Q` denote raw scalar32 and scalar64; `P` denotes the plaintext span source. These symbols are report notation; they do not assert new recovered business names.

| Domain | Raw wire type V | Early transformed type `V XOR 0xa2e3` | Width gate | Payload source |
| --- | --- | --- | --- | --- |
| u32 | `0x9777` | `0x3594` | L=4 | `S+0x110 = B XOR 0x31ae0066`, retained through `F+0x480` |
| u64 | `0x8485` | `0x2666` | L=8 | `S+0xad0 = Q XOR 0x8f98c6acce5848ca`, addressed through `F+0xf8` |
| span | `0x50db` | `0xf238` | L=0 bypass; L>0 copy | `C+0x168 = P`, plaintext bytes |

The first comparison is at `0xfffffe000a654dd4`, followed by the u64 comparison at `0xfffffe000a6551c8` and span comparison at `0xfffffe000a6551e8`. Other types branch to `0xfffffe000a664074`. Scalar width failures select the same target. This report establishes those source selections, not the complete failure body or its native return status.

The u32 comparison uses the actual live W1 left by header writing, `0x31ae0062`, against `L XOR 0x31ae0066`; equality means L=4. The u64 comparison uses `0x31ae0066+8 = 0x31ae006e`; equality means L=8. Substituting the generic success token for live W1 would misidentify the u32 width gate.

## Source-produced saved controls

| Cell | Source producer | Exact source result | Consumer |
| --- | --- | --- | --- |
| F+0x104, 4 bytes | `0xfffffe000a635ae4` | `0x802218a3` | u64 writer index reduction at `0xfffffe000a655ae0` |
| F+0x560, 8 bytes | `0xfffffe000a635af4` | `0x886a1ca0` | Span address-shift arithmetic at `0xfffffe000a6553f8` |
| F+0xf8, 8 bytes | `0xfffffe000a635bb0` | `S+0xad0` under incoming X4=S | u64 cell selection at `0xfffffe000a655af8` |
| F+0xa60, 8 bytes | `0xfffffe000a6362fc` | Table base under incoming X7=table | Scalar/type table reloads |

The two incoming register premises are checked at their actual producer visits in every retained prefix. Every overlapping source write to these cells, S+0xad0, S+0xca8 and C+0x168 is replayed into a byte-level reconstruction; all 210 resulting cells agree with the retained source contracts. This is finite prefix custody, not a universal no-alias theorem or native epoch guarantee. The composed proof explicitly retains these epochs through the selected paths.

The saved span value XOR the loop's token `0x886a1ca3` reduces to shift count 3, which selects the destination byte's address-mask lane. The u64 saved values select table index `0x684` and the scalar-cell address. Their producers are included in the source lift rather than introduced as unexplained concrete setup values.

## Protected records and scalar contracts

The established mask is:

```text
K0 = 0x02e859d27e491464
K1 = 0x4dae26df20976138
mask8(a) = low8(((ROR64(a AND ~7, 8) + K0) XOR K1)
                >> (8 * (a AND 7)))
```

All address arithmetic is unsigned modulo `2^64`; nonwrapping storage extents are separate premises. Each stored byte at address a is its plaintext byte XOR mask8(a).

| Path | Complete plaintext representation before masking | Protected output extent | Final transfer modifier |
| --- | --- | --- | --- |
| u32 | `BE32(D) || BE16(V) || BE32(4) || BE32(B)` | Z[0..13], 14 bytes | `0x3aa3` |
| u64 | `BE32(D) || BE16(V) || BE32(8) || BE64(Q)` | Z[0..17], 18 bytes | `0xc4bd` |
| span | `BE32(D) || BE16(V) || BE32(L) || P[0..L-1]` | Z[0..L+9], L+10 bytes | `0x4bb5` if L=0; `0xd76c` after copying |

The u32 request at `0xfffffe000a654e34` loads the saved scalar channel, selects phase index `0x129`, and reuses the common word writer through the length bridge. Its four payload stores are the common word-store PCs already used for the header, now at offsets 10..13. The selected continuation is `0xfffffe000a655cb4`.

The u64 request at `0xfffffe000a655acc` selects the saved cell and writer `0xfffffe000a655b14`. The eight payload store PCs are `0xfffffe000a655b50`, `0xfffffe000a655b80`, `0xfffffe000a655bb0`, `0xfffffe000a655be0`, `0xfffffe000a655c0c`, `0xfffffe000a655c34`, `0xfffffe000a655c60` and `0xfffffe000a655c98`. The universal proof reduces its scalar XORs and exceptional final-byte key expression to BE64(Q) protected by the same destination mask. It does not assume those expressions equivalent in advance.

## Plaintext-span count and reverse copy

The inherited source store is `S+0xca8 = zero_extend32(L)+0x622f763938943e93`. The gate beginning at `0xfffffe000a6551fc` reduces its obfuscated arithmetic to `W10 = L XOR 0xc76bc16d`, including low32 wrapping cases. Equality with `0xc76bc16d` means L=0. Zero selects `0xfffffe000a655cb4` without executing the payload request or byte load. It requires no readable P payload region.

For L>0, `0xfffffe000a65538c` loads Z through the current `J+0x18`, loads P from C+0x168, and widens the exact u32 count. For every old counter `1 <= c <= zero_extend32(L)`, the original step establishes:

```text
read_address  = P + c - 1                  [PC 0xfffffe000a6553d0]
write_address = Z + c + 9                  [PC 0xfffffe000a655410]
stored_byte   = plaintext8 XOR mask8(write_address)
next_counter = c - 1
next_target   = 0xfffffe000a655cb4          if c == 1
                0xfffffe000a6553b0          if c > 1
modifier      = 0xd76c
```

Initial counter L, exact decrement, exact exit/backedge and the finite certificate `i=L-1-j`, `0<=j<L`, establish coverage of all source indices 0..L-1 and destination indices 10..L+9. Source bytes are read once; no source-address mask is removed. Header bytes 0..9 are outside the payload store extent. No extra terminator byte is added.

```text
early header -> type gate ---- u32 / L=4 -> word writer -----+
                    |-------- u64 / L=8 -> eight stores ----+--> common continuation
                    +-------- span / L=0 ------------------+    0xfffffe000a655cb4
                                 L>0 -> reverse copy ------+
```

The [later record writer](userclient_record_writer_report.md) instead reads protected source bytes and rebases source protection to destination protection. Its different source domain must be preserved when relating these phases. No encryption-purpose or external wire-format identity follows from these internal memory representations.

## Evaluation and controls

The 30 retained states comprise six u32, twelve u64 and twelve span evaluations, including six zero-length spans. The two u64 profiles include a high32 declared-size variant inherited from the predecessor. All storage, branch and lookup premises are checked after substitution. No unknown setup cell receives a concrete binding. Zero spans use a separate bypass composition. Nonzero span fixtures evaluate every reverse-copy step against their declared plaintext bytes. Results match independent big-endian encoding and mask arithmetic for 468 bytes, with 120 saved-control values checked.

These are partial-state expression evaluations, not a repaired guest replay, native writes or a new allocation experiment. Original input fixtures and full predecessor receipts remain unchanged. Earlier zero-tag span success may bypass node construction; a conditional node-path theorem does not establish that every raw tag reaches this path.

| Copied-source mutation | Normal oracle rejection |
| --- | --- |
| NOP scalar load at `0xfffffe000a654e64` | A satisfiable path violates the complete u32 byte contract. |
| NOP first u64 payload store at `0xfffffe000a655b50` | Complete 18-byte store contract fails. |
| NOP span byte store at `0xfffffe000a655410` | Universal span step lacks its required payload store. |

All mutated paths have satisfiable storage, selected-branch and lookup premises. Original files/IDBs are unchanged. The new span alternate-MOVK proof establishes only replacement of pointer bits 63..48 with `0xc8a2`; alternate alias validity and native pointer authentication remain unknown. Previously checked header retag sites retain their earlier scope.

Scalar serialization takes O(1) selected work and writes 14 or 18 bytes. Span serialization takes O(L) work, L byte reads and L payload stores, O(1) auxiliary loop state and L+10 bytes of serialized output. Allocator, publication and native synchronization costs are excluded. Evidence construction is linear in source bytes/instructions, query-expression DAGs and retained fixture evaluations; solver search is separate with 30-second query limits.

## Assumption register

| Assumption | Dependencies and falsification probe |
| --- | --- |
| EP-A1: Pinned image and predecessor custody | EP1-EP8. Rehash collection/container/normalized words, table records and dependencies; rebuild all receipts. Any mismatch invalidates reuse. |
| EP-A2: Stable live frame/context/workspace/node/control epochs | EP1-EP7. Check producer registers and every overlapping prefix store; inspect later native aliases, calls and epoch changes before claiming native retention. |
| EP-A3: Valid separated nonzero F/C/S/J/Z storage | EP2-EP7. Require F alignment of 16 bytes, nonwrapping extents, pairwise separation and separation from image segments; require `L<=0xfffffff5` and Z extent L+10. Native admission remains unknown. |
| EP-A4: Readable stable plaintext span P for L>0 | EP5-EP7. Require a separated nonwrapping P extent L; vary every byte/counter symbolically. Overlap, protection of source bytes or a shorter input falsifies applicability. L=0 bypass has no readable-P premise. |
| EP-A5: Normal pointer branches and logical authenticated-table semantics | EP3-EP7. Check satisfiable branch premises and original table membership; separately validate native retag/PAC/BTI behavior before generalizing. |
| EP-A6: Fixed-width lift and loop composition | EP1-EP7. Check all 352 new words, universal scalar/count/byte formulas, induction indices, prior header obligations and three source mutations. |
| EP-A7: Selected serialization scope | EP7-EP8. Check zero bypass separately, leave eight setup cells unbound, and follow the common continuation before asserting publication, cleanup, complete operation or daemon/kext identity. |

## Bounded continuation

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | `0xfffffe000a655cb4` and its incoming state | Recover early node publication/lookup/cleanup; shared continuation target alone does not prove identical phase contracts. |
| High | Native caller epochs, input capacity and allocator effects | Establish whether the conditional serialization premises hold in a live operation. |
| High | Matched daemon request, user-client selector and kext record flow | Link internal field provenance to an actual cross-layer transaction. |
| Medium | Remaining setup-cell consumers and S+0x20 marker producer | Recover phase-specific roots and external state/control transitions; current serialization does not initialize them. |
| Medium | Failure target `0xfffffe000a664074` | Establish exact failure status/retirement effects beyond the selected type/width branches. |

## Quality gates

- **QG1**: Instruction, data-flow and ABI claims require no normative conclusion.
- **QG2**: EP-A1-EP-A7 enumerate assumptions, dependencies and falsification probes.
- **QG3**: Three payload domains, exact gates, source controls, protected bytes, loop coverage, evaluations and interface limits are covered; full objective remains active.
- **QG4**: u16/u32/u64 widths, big-endian scalars, modular arithmetic, exact byte extents/counts and scoped complexity are reproducible.
- **QG5**: Plaintext versus protected source, zero bypass versus nonzero copy, conditional serialization versus native admission/publication and partial-state evaluation versus continuous replay remain distinct.
- **QG6**: Original dual-image words/pointers, overlapping-store custody, 15 nonvacuous proofs, two prior rechecks and three rejected mutations support the bounded claims.
- **QG7**: Ranked continuation retains native ownership, publication, failure, marker and matched IPC questions without treating this increment as whole-goal completion.
