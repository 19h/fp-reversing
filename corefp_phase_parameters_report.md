# CoreFP paired scalar mixers and source-produced workspace encodings

Subsequent source join: the [scan-entry report](corefp_scan_entry_report.md) derives common u64 initializers and earlier field encodings, and proves the final-fold carrier equations feeding the shared downstream seed under the scan and writer-free-interval premises. Earlier arithmetic-pass pairing and native control/admission remain unresolved.

The six preparation-scan accumulator outputs feed two copies of the same scalar mixer. With equal mixer seeds and a pairwise bank XOR of `0xeb3e515b`, the original source produces coherent workspace index and word encodings for arbitrary u32 scalar inputs. The previously retained five parameter classes are concrete instances of this conditional source contract.

Five reported workspace parameters reduce to three fields: a seven-bit mask m, a three-bit rotation r and a u32 value Z. Their descriptions require at most `7+3+32=42` bits. This is a representation bound, not a key size, native entropy estimate or proof that every combination is reachable. Establishing the shared seed and bank relation for arbitrary admitted raw inputs remains open.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_phase_parameters.py), [checks archive](triage_evidence/corefp_phase_parameters_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_phase_parameters.py), [audit archive](triage_evidence/corefp_phase_parameters_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_phase_parameters_publication.py) retain original instructions, complete phase entries/ends, a core checkpoint, memory journals, dispatch metadata, compact parameters and solver queries. Ten parent receipts and thirteen frozen dependencies are SHA-256 pinned. The three originally supplied inputs are unchanged.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. All source addresses below are preferred-base-zero offsets. B denotes bytes; unsigned u8/u32/u64 widths are explicit. The new interval `[0x1b66ac,0x1b69c4)` contains 198 instructions/792 B, within the retained 59120 B caller/allocator/retirement coverage. The following 36-instruction/144 B constructor retains its earlier source proof.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PP1 | Original source/fixups, ten parent receipts and thirteen dependencies identify the image. All source results depend on those bindings. | Compare all 198 instructions, the normalized five-instruction slice, dependencies, original dispatch row and the three supplied inputs. |
| PP2 | Existing private caller/context/pool/malloc/PAC/sequential-CASAL fixtures apply. Complete replay continuity depends on these premises. | Freshly reconstruct six initial CPU/RAM states and independently replay 488136 source visits. Native admission, synchronization and actual ownership remain unknown. |
| PP3 | FP=SP+`0x520`, the 1312 B frame is backed, and the tail's six loads have their declared typed pointer interfaces. Memory contracts depend on these bindings. | Prove each store/load address; compare full frames and memory journals. Core arithmetic has no memory read. Aliasing arbitrary native objects is outside this contract. |
| PP4 | W5=W12 and the three incoming bank pairs XOR to `0xeb3e515b`. Coherent common encoding depends on these premises. | Prove preservation through the common mixer, check all six retained entries, exercise all 1024 mask/rotation pairs per domain and retain counterexamples when each premise is omitted. A universal upstream producer proof is still missing. |
| PP5 | Tail W8=`0x4208`, the original dispatch-table binding/cell and source-produced backing/table pointers apply. Constructor continuity depends on these bindings. | Prove generic control-dependent addresses and scratch value; check original cell `0x1cbdd78`, target/modifier and original constructor stores. Native cryptographic PAC authentication is not executed. |
| PP6 | The frozen constructor/table/consumer contracts apply at their declared epochs. Canonical workspace interpretation depends on them. | Recheck their retained obligations, fixed complete tables, all source-produced workspace words in six whole callers and component constructor stores. This does not establish a whole transform or native transport handoff. |

## Scalar interfaces and compact common mixer [PP1-PP4]

| Scalar input at `0x1b66ac` | First bank | Second bank |
| --- | --- | --- |
| Three accumulator words | W26, W30, W22 | W15, W10, W11 |
| Mixer seed | W5 | W12 |
| Mixed words U,V,C | W23, W21, store at SP+`0x450` | store at SP+`0x3f8`, W22, W12 |

The first mixed U is also stored at SP+`0x400`. The second mixed C exists in W12 at `0x1b6898` and subsequently supplies the rotation selector; later uses overwrite temporary registers. These are scalar/stack interfaces, not field names in a recovered native structure.

Define `A_n(x)=x+(x>>n)` and `S_n(x)=x-(x>>n)`, with every addition/subtraction reduced modulo 2^32 before its result is reused. Right shifts are logical. One mixer seed s gives:

```text
a = A_6(A_14(s + d01d67d8))
b = S_1(A_11(a XOR 8df2987e))
c = A_8(S_11(b + f1b810a4))
d = S_8(S_9(c XOR 24880a0e))
e = S_3(A_13(d + d20cac36))
f = A_5(A_11(e + 088e8841))
g = S_4(A_9(f + d95b0f59))
h = S_5(A_13(g XOR 62167b51))
j = A_8(S_15(h + 5e588794))

T(s) = (a XOR d XOR g,
        b XOR e XOR h,
        c XOR f XOR j)
mixed_bank = incoming_bank XOR T(s), componentwise
```

All literals in this pseudocode are hexadecimal u32 values. The first source chain starts at `0x1b66c4`; the second at `0x1b67fc`. Their syntactic difference at `[0x1b6854,0x1b6868)` is exactly:

```text
x - ((2*c mod 2^32) AND (x<<1)) + c = x XOR c
c = 62167b51
```

The original instructions load `c42cf6a2=2*c mod 2^32`, AND it with x shifted left once, subtract and add c. A separate source-lifted universal obligation proves this five-instruction identity. The complete core lift composes that lemma at the same W5 lifetime; the actual-byte tests execute all original instructions without replacing the arithmetic.

For any common seed s and incoming triples L,R with `L_i XOR R_i=D`, applying the same T(s) preserves every pairwise XOR D. This requires no restriction on the individual accumulators or seed. In all six retained entries, the seeds agree and D=`eb3e515b` for all three pairs. The preceding [scan report](corefp_preparation_scans_report.md) separately establishes common preparation-dependent XOR deltas; it does not by itself prove the upstream seed/bank premises for arbitrary raw inputs.

## Three-field encoding and universal rotations [PP3-PP6]

Let the first mixed triple be `(U1,V1,C1)` and the second `(U2,V2,C2)`. Under PP4, corresponding words XOR to D. Let P(x) be the XOR of the four bytes of a u32 word; let `REP(b)=b*0x01010101` for a u8 byte b. The five canonical workspace parameters become:

| Parameter | Exact source-derived expression | Width |
| --- | --- | --- |
| m | `(U2 AND 0x7f) XOR 6` | 7 bits |
| M | `REP(m)` | u32 |
| r | `(C2 XOR 6) AND 7` | 3 bits |
| Z | `U2 XOR V2 = U1 XOR V1` | u32 |
| b | `P(Z) XOR 0x2e` | u8 |
| K | `Z XOR 0x7631365f` | u32 |
| Q | `Z XOR 0x8b95e221` | u32 |

Consequently `K XOR Q = 0xfda4d47e`; b is determined by either K or Q. First-path mask `(U1 AND 0x7f) XOR 0x5d` equals m because `low7(D)=0x5b`. First rotation `(C1 AND 7) XOR 5` equals r because `low3(D)=3`.

The source byte folds at `0x1b68ec..0x1b6930` combine biased lower bytes with an unmodified high byte. Treating all four bytes as biased gives the wrong b. The source obligations prove `digest_U=REP(P(U2) XOR 0x7f)`, `digest_V=REP(P(V2) XOR 0x51)` and their XOR `REP(b)` at `0x1b694c`.

The exact temporary masks also contain data-dependent terms. For common r, put `k=(-r) AND 7`, and q=0 when r=0, otherwise `q=low8(0xff<<k)`. The right-word mask in W24 is `REP(q) XOR low8(U1 AND NOT(0xff<<k))` for nonzero r, and zero for r=0. Its extra low-k bits leave the word when shifted right by k. The corresponding index mask in W27 has U2 in place of U1 and the same discard property.

The left-word mask W20 is:

```text
REP(q) XOR NOT((q*0xf5000000 mod 2^32) AND V2)
```

Its extra term occupies only the top r bits of the u32 word and leaves the word when shifted left by r. This remains true for arbitrary U1/V2, including r=0. Eight word obligations and eight index obligations, one per r, prove:

```text
((x AND W20)<<r) + ((x AND W24)>>k) = BR_r(x)
low8((y<<r) OR ((y AND W27)>>k))   = ROL8(low8(y),r)
```

The first equation is u32 modular arithmetic; BR rotates each byte lane independently. The second quantifies an arbitrary u8 y, zero-extended before the source operations. These are universal operator results under PP4, rather than five constant-parameter checks. Rotation plus XOR and the triangular map `phi_M(x)=x XOR ((x AND M)<<1)` retain the inverses established in the [workspace report](corefp_workspace_report.md).

Composing the unchanged constructor's universal load/store contract and complete fixed table identities yields:

```text
pi(i) = ROL8(phi_low8(M)(i),r) XOR b
workspace1[pi(i)] = BR_r(phi_M(L(G(i)))) XOR K
workspace2[pi(i)] = (G(i)<<8) XOR 65 XOR Q
```

Here i ranges over all 256 u8 values, literal 65 is hexadecimal, and G/L are the previously established fixed substitution/affine expansion. This extends the encoding normalization to all scalar inputs satisfying PP3-PP6. It does not prove those premises for arbitrary original caller inputs or identify the algorithm using the tables.

## Memory, control flow and constructor handoff [PP1-PP3,PP5]

The first 169 instructions/676 B, `[0x1b66ac,0x1b6950)`, have no memory read and perform eleven u32 stores/44 B. The final 29 instructions/116 B read six u64 interfaces/48 B, write one u32 scratch/4 B and branch into the constructor. One region therefore has six reads and twelve writes. Six complete callers give 1188 visits, 36 reads/288 B, 72 writes/288 B and six modeled authenticated branches.

| Source store PC | SP-relative offset | Stored value |
| --- | --- | --- |
| `0x1b6794` | `0x450` | C1 mixed scalar |
| `0x1b67b0` | `0x48` | first byte mask m |
| `0x1b67b8` | `0x410` | REP(m) |
| `0x1b67bc` | `0x458` | first r |
| `0x1b67dc` | `0x1c` | first q |
| `0x1b67e8` | `0x400` | U1 |
| `0x1b67f4` | `0x24` | REP(first q) |
| `0x1b68b0` | `0x44` | second m |
| `0x1b68f8` | `0x3f8` | U2 |
| `0x1b6948`, first/second word | `0x6c` / `0x70` | digest_U / digest_V |
| `0x1b6978` | `0x348` | control scratch, `0x40f6` under PP5 |

The C1 storage reuses FP-`0xd0`; this u32 store does not replace the entire previous u64 stack lifetime.

| Read PC | Typed interface | Retained value or role |
| --- | --- | --- |
| `0x1b6980` | SP+`0x488` | dispatch-table base image+`0x1c81940` |
| `0x1b6984` | table+8*sign_extend_u32(W8+`0x367f`) | original cell at `0x1cbdd78` under PP5 |
| `0x1b69a0`, first/second word | SP+`0x428` / SP+`0x430` | two workspace backing pointers |
| `0x1b69a4` | SP+`0x328` | original u32 table image+`0x166f4e0` |
| `0x1b69b8` | SP+`0x2b8` | original u16 table image+`0x1af3fc0` |

The tail source proves the generic scratch `((W8+0x367f) XOR 0x7885)*0x207b`, modulo 2^32, and the signed-index cell address. Under W8=`0x4208`, its index is `0x7887`. Original authenticated chain word `0x80082c2a001b69c4` has target `0x1b69c4`, key IA, diversity `0x2c2a`, no address diversity and no bind. Source `0x1b69c0: braa x2,x17` emits this local control transfer, not an IPC message or Mach right. The private PAC model checks target/modifier and advances PC without cryptographic authentication.

```text
six scan-output words + two scalar seeds
                   |
       paired common mixer T(s)
                   |
          U1,V1,C1 / U2,V2,C2
                   |
       m,r,Z + typed table/backing loads
                   |
      original authenticated local branch
                   |
   unchanged 256-iteration workspace constructor
```

## Validation and remaining boundaries

The independent audit does not import the new producer. It reconstructs six initial CPU frames and 3313664 B of initial RAM, freshly replays 488136 visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM. The phase entries match the preceding second-scan ends. All five canonical parameters match the six retained workspace oracles, including the clobber control.

An independent concrete instruction interpreter checks all six complete phase CPU frames, the core checkpoints, memory journals and 7872 B of final stack snapshots. Independent integer arithmetic reconstructs both mixed triples and all parameters. Original-byte component tests separately vary all four byte positions of each of eight u32 inputs: `8*4*256=8192` cases per domain, or 49152 cases across six domains. These component inputs need not satisfy the paired coherence premises.

Each domain additionally synthesizes all `128*8=1024` coherent mask/rotation pairs with varied seed/Z values, giving 6144 cases. Each executes the original phase and then the original 36-instruction constructor at a declared u8 counter cut; both stored words are checked against G/L and the source-derived encoding. These are component interface cuts, not original-loop counter progression or native admission proofs. The complete caller replay separately checks all 256 constructor iterations per retained profile.

Together, 55296 finite phase cases produce 10948608 phase source visits and 55296 PAC models; 6144 constructor cases add 221184 source visits, for 11169792 finite source visits. Aggregate digests cover full ending CPU frames and stack snapshots; the finite corpus is not asserted to contain 55296 distinct inputs. Each domain retains counterexamples showing that omitting either the bank XOR or shared-seed premise can break mask/rotation coherence.

The 51 new obligations comprise one normalized source identity, twelve core register/counter contracts, eleven store contracts, bank preservation, six parameter/bound equalities in one obligation, sixteen rotation obligations, six tail-load contracts, the scratch-store contract, fixed tail fields and dispatch/backing bindings. Rechecking 1070 frozen obligations yields 1121 UNSAT results. Each query has a 30 s limit. The normalized source cut, inductive composition, finite tests, typed backing and native observations retain their separate scopes.

Replay time/space is conservatively `O(C*(B+V*J+P*F+R))` for C profiles, pinned source bytes B, visits V, per-visit state/journal extent J, touched pages P, page/frame payload F and other retained data R. The scalar mixer is fixed-size u32 arithmetic. Component testing takes `O(C*9216*234)` time with bounded private memory maps; 234 is the maximum combined phase/constructor instruction count per case. Solver costs/limits are separate.

No new incoming/outgoing Mach port, right, descriptor, emission site or daemon/kext endpoint pair is established. The interfaces here are process-local scalar words, stack cells, table/backing pointers and one authenticated local branch. No native target/API/IPC, IDA access or IDB mutation occurs. Original reference data suffices. The full investigation remains active.

| Impact | Next investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Prove upstream production of equal mixer seeds and the bank XOR for arbitrary raw preparation. | Join original initializers, both scans and intervening state lifetimes; the six retained profiles alone are insufficient. |
| High | Carry source-produced m/r/Z into canonical input words and all workspace consumers. | Establish every same-epoch load/phase update and reduce the complete first-block mapping. Constructor coherence alone is insufficient. |
| High | Establish native context/selector/holder initialization and record owners. | Require source-created backing, ownership and entry admission rather than private pointer fixtures. |
| Medium | Derive later-block state updates and phase invariants. | Prove source loop-update equations and their consumers for arbitrary block count. |
| Low | Join local scalar/table contracts to daemon/kext transport. | Require an actual serializer/consumer handoff and matched endpoint/right epochs. |

- **QG1**: No normative premise is required.
- **QG2**: PP1-PP6 identify dependencies and falsification probes.
- **QG3**: Both scalar chains, memory/control flow, mask rotations, constructor backing/dispatch and external-interface limits are covered.
- **QG4**: Widths, modular arithmetic, signed indices, extents, exact corpus counts and the 42-bit representation bound are explicit.
- **QG5**: Arbitrary scalar contracts retain paired premises; upstream production, native admission and whole-algorithm identity remain unknown. Raw high-byte folds and shift-discarded mask terms are handled explicitly.
- **QG6**: Original bytes/fixups, pinned parent contracts, fresh independent replay/interpreter/integer arithmetic, unchanged-byte component tests and retained queries provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains upstream invariants, canonical consumers, later blocks, native owners and cross-level transport. The full goal remains active.
