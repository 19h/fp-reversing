# Mode1 encoded XOR and natural digit maps

Follow-up: [Post-table size fork and source passes](daemon_mode_one_post_table_passes_report.md) establishes the selected LEN32 gate,two additional32-byte source walks,two retained four-word banks and a35-store shared initializer. All611 captured nonbranch sites are translated;23 UNSAT and two distinct SAT results pass. The initializer preserves816 arithmetic-table cells,leaves F+0x424 untouched and saves a F+0x8348 view whose native extent is unknown. Next routine0x100bdba34,caller output and native daemon-kext exchange remain unknown.

Three source-backed routines extend the local sum/carry contract.0x100c9589c builds a256-entry encoded XOR table.0x100c6ff08 saves the inverse natural-digit map into sixteen separate scratch cells.0x100d17960 then overwrites the former permutation-inverse cells with the forward natural-digit map. The ordering preserves the old inverse until its last required read. These results establish explicit encoding/decoding maps for the recovered arithmetic tables. Caller-visible output,whole return and native daemon/kext linkage remain unknown. [DM1-DM8]

Evidence: [original source,data and pointer records](triage_evidence/daemon_mode_one_digit_maps_source.json), [SSA and finite certificates](triage_evidence/daemon_mode_one_digit_maps_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_digit_maps.py), [validator](triage_evidence/validate_daemon_mode_one_digit_maps.py), [preservation](triage_evidence/daemon_mode_one_digit_maps_delivery.json), [quality gates](triage_evidence/daemon_mode_one_digit_maps_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_digit_maps_publication.py). Parent: [encoded sum/carry tables](daemon_mode_one_carry_table_report.md).

| Evidence | Verified scope |
| --- | --- |
| Artifact |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New routines |167 instructions/668 B;all164 nonbranch sites translated |
| With incoming carry seed |Four ranges,292 instructions/1168 B;all288 nonbranch sites translated |
| Recapture |Four parent ranges/980 B;944 B immutable fixed-data region |
| Pointer metadata |Six records; six branch/modifier matches across five distinct branch slots |
| SMT |17 new plus19 replayed UNSAT certificates;three SAT abstract-domain checks |
| Finite algebra |256 XOR pairs,256 sum/carry pairs rechecked,256 packed-encoding identities,16 inverse-map and16 forward-map cases |
| Memory |816 distinct identified scratch cells;288 new dynamic byte writes |
| Controls |Four altered source/data/target/native-claim records rejected by fresh original-source comparison |
| Execution boundary |No target execution,emulation,API/IPC request,hardware PAC or IDB mutation |

## Shared digit coordinates and table representations

Keep the parent notation E(j)=0xd4 XOR j,H(j)=0xd4 XOR(j<<4),with byte truncation for H. The seeded shuffle gives a permutation pi. The fixed natural-digit labels are:

`M = [9, 4, a, d, 0, 5, 7, c, 1, 3, 8, f, b, e, 2, 6]`

Define R(a)=pi(M[a]). All indices a,b are digits0..15. The three binary tables satisfy:

```
C[R(a)+16*R(b)] = E(R((a+b) mod16))
D[R(a)+16*R(b)] = H(R(floor((a+b)/16)))
Q[R(a)+16*R(b)] = E(R(a XOR b))
```

The two new16-entry maps satisfy U[t]=E(R_inverse(t)) and,after the final rewrite,B[j]=E(R(j)). Thus both directions of the same label mapping exist as explicit tables. This follows from the source inverse/permutation relations and exact finite fixed-data decoders;it does not enumerate16! permutations or assume that every permutation is reachable. [DM2-DM6]

There is also a byte-packing identity: E(s) XOR H(c)=s OR(c<<4) for any two nibble labels s,c. Consequently C[x+16*y] XOR D[x+16*y] packs the encoded sum label into its low nibble and encoded carry label into its high nibble. All256 encoding pairs are checked. This is an algebraic consequence;these three routines do not perform that C/D combination. The presence of encoded addition and XOR alone does not identify a complete cipher or standard algorithm.

Let F be the protected-core frame and T=F+0xd00. Every physical address below is T plus the stated offset.

| Table | Offset | State after the three new routines |
| --- | --- | --- |
| A[j],16 cells |(84784+757*j) mod963 |E(pi(j)),unchanged raw permutation |
| B[j],16 cells |(12869+757*j) mod963 |E(R(j));previously E(pi_inverse(j)) |
| C[t],256 cells |(534442+757*t) mod963 |Encoded digit sum,unchanged |
| D[t],256 cells |(137774+757*t) mod963 |Encoded digit carry,unchanged |
| Q[t],256 cells |(333080+757*t) mod963 |Encoded digit XOR |
| U[j],16 cells |(757*j) mod963 |E(R_inverse(j)) |

All816 positions are pairwise disjoint within the963 B scratch address domain. B's physical cells are deliberately reused in the final routine. After that rewrite,using B as the old pi inverse is invalid. U is complete before B's first overwrite. The new path preserves A,C,D,the saved scratch/branch/word-cell roots,the second-bank spills and the8 B budget cell at F+0x1210 through0x100d17a24. Q and U remain intact after their respective construction. No invariant here extends into0x100daee68. [DM3,DM6]

## Source routines,indices and loop state

All three routines use X21=T and the fixed-data base X23=0x100f715a0. The preceding carry loop's full source is translated again to bind the XOR writer's incoming constants,including W10=0 and phase W11=0xa648. Fixed-data addressing uses the same944 B original image region as the sum/carry path. Each selected byte and its decoded result is retained in the finite evidence. [DM1,DM4-DM5]

The XOR writer reads the old B[t&15] and B[t>>4]. For their decoded inverse labels u,v,the source packs argument (u+16*v) XOR0x06. It reads the fixed byte at0x100c95924 with offset (156519+527*argument) mod944. Decoding that byte by XOR0x5e yields a nibble k. It reads A[k] at0x100c95960 and stores the unchanged byte to Q[t] at0x100c9596c. Independently decoding all256 source-selected bytes proves M_inverse(k)=M_inverse(u) XOR M_inverse(v),which establishes the Q relation above. W10 advances from0 to256;the routine sets W1=0,W4=0xa79db846 and W8=0xa659 for the next loop.

The inverse-digit-map writer at0x100c6ff08 runs sixteen times. Its input numerator is u32((0xa79db846+t)*757+0x4b47),whose base is0xa5623245. The source computes a quotient from the low16 bits and narrows the final address offset to16 bits. This makes the actual read B[t],not an access using the large full numerator. The source SSA checks this narrowing explicitly. For a byte E(j) read at0x100c6ff44,it selects fixed offset (143344+527*(E(j) XOR0xd1)) mod944. The byte loaded at0x100c6ffa8 combines with E(j) XOR0x49 to give E(M_inverse(j)). The store at0x100c6ffc4 therefore writes U[t]=E(M_inverse(pi_inverse(t)))=E(R_inverse(t)).

The inverse-map loop starts W4=0xa79db846,W1=0 and ends after W4 reaches0xa79db856. Its source recurrence keeps W1=t before each store and sets it to t+1. It also sets W13=0 and phase W14=0x4def for the final routine. W13 is reset to zero in every inverse-map round;the next routine receives zero on the exit edge.

The forward-digit-map writer at0x100d17960 runs with W13=j from0 to15. It reads the fixed byte at0x100d1798c with offset (325159+527*(j XOR7)) mod944. Combining it with ((((j XOR0xd)-(j XOR0x41)) mod256) XOR0x52) yields exactly M[j] in all sixteen cases. The source's phase arithmetic also reduces its address multiplier to757. It reads A[M[j]] at0x100d179f0 and writes that byte into B[j] at0x100d17a08. Thus the new B is the forward R map,while U retains its inverse. [DM4-DM6]

| Routine / terminal branch | Private selector and original target | IA diversity |
| --- | --- | --- |
|XOR,0x100c95990 |0xa648 repeats0x100c9589c;0xa659 exits to0x100c6ff08 |0xa035 |
|Inverse map,0x100c6ffe0 |0xa659 repeats0x100c6ff08;0xb395 exits to0x100d17960 |0xa035 |
|Forward map,0x100d17a24 |0x4e26 repeats0x100d17960;0x4def exits to0x100daee68 |0xec8e |

The branch table is loaded from F+0x740. The six edge records match original IA-authenticated rebases and their source modifiers. Successful hardware PAC,valid native mappings and actual traversal remain unknown. The captured routines contain private authenticated branches and byte loads/stores,with no call,trap or Mach emission. No new incoming/outgoing Mach port,name,right or message ABI is established. These selectors are private branch indices. [DM7-DM8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| DM1 |Pinned original image,unslid source/data and original fixups |Rehash image,recapture ranges,compare pointers and all944 fixed bytes |
| DM2 |Selected mode1 path and the parent equal-shuffle/inverse/sum/carry contract |Recheck admission,stable source bytes and equal seeds;other paths do not inherit this result |
| DM3 |Valid nonwrapping private frame,coherent memory and no outside writes |Check actual mappings,owner lifetime and intervening writes;native validity is unknown |
| DM4 |Saved roots and fixed image data remain stable through the local loops |Recheck root rebases,source liveness and all selected fixed-data indices |
| DM5 |SSA widths,low16 narrowing,SUBS/CMP roles and division shapes match source |All288 captured nonbranch sites are translated;bounded reciprocal and finite-case checks reject alternate arithmetic |
| DM6 |Compositional use of bijective pi and M,with the B lifecycle respected |Verify all256 XOR and sum/carry pairs,the32 map cases,disjoint cells and U-before-B overwrite ordering |
| DM7 |Authenticated pointer metadata supplies static target selection |Hardware authentication,exceptions and native authorization are not executed or proved |
| DM8 |Caller output,whole operation and daemon/kext pairing remain unknown |Trace0x100daee68 and subsequent C/D/Q/U/B reads through output and serialization |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Trace0x100daee68 and actual arithmetic-table consumers |A source chain showing how C/D/Q and the explicit R maps transform state |
|High |Connect transformed state to caller output and cross-layer messages |Buffer ownership,extents,publication and serialization evidence |
|Medium |Track the overwritten inverse region through later aliases |Reads interpreted using B's new E(R(j)) meaning;stale inverse interpretations must be rejected |
|Low |Evaluate algorithm hypotheses after wider behavior is recovered |Independent operation-level structure;encoded addition/XOR is insufficient for attribution |

The new loops have fixed256/16/16 rounds and perform288 byte writes. The address domain is963 B,with816 identified cells. Source extraction/hashing is linear in bytes;finite binary-operation checks take O(n^2) time and retained evidence for n=16. SMT runtime is solver-dependent,with15000 ms per query;unknown or timeout is rejected. All extents use bytes and source arithmetic uses explicit8/16/32/64-bit widths.

QG1: Factual source,metadata and algebraic results are reported.

QG2: DM1-DM8 record assumptions,dependent results and falsification probes.

QG3: Routine roles,local memory ABI,data/control flow,environmental premises and Mach-emission scope are covered for this increment. The full objective remains active.

QG4: Byte extents,widths,narrowing,recurrences,division bounds and finite cases are reproducible.

QG5: B's old and new roles,U-before-overwrite ordering,and the purely algebraic C/D packing consequence are distinguished. Native and downstream unknowns remain explicit.

QG6: Original bytes/data/fixups,all288 captured nonbranch sites,36 UNSAT certificates,three abstract SAT checks,finite table/map cases and four alteration controls establish scoped provenance.

QG7: Four impact-ranked continuation questions bound the expansion. Whole cipher,caller output and native exchange are not claimed.
