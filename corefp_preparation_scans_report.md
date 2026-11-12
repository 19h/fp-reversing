# CoreFP duplicate preparation scans and bounded split dispatch

Subsequent phase evidence: the [phase-parameter report](corefp_phase_parameters_report.md) derives the shared scalar mixer and a conditional arbitrary-input encoding contract from equal seeds and the bank XOR. Source-produced m/r/Z determine all five workspace parameters. Upstream establishment of those premises and native/cross-level continuity remain unresolved.

The forty preparation reads preceding the late output component implement two copies of one sixteen-step u32 state transform. Each scan uses four preparation-indexed reads to select a split in 1..15, then reads all sixteen preparation bytes in order. Its two loop bodies have the same four-state transfer. Under the retained parameter bindings, both scans therefore apply identical three-word XOR deltas to different incoming accumulator vectors.

The split also leaves one scratch residue: W1 after the first scan, W3 after the second. Forced-split tests retain these full-frame differences. Straight-line source overwrites each residue before reading it. This is a conditional source/control-flow result; the complete raw-preparation-to-workspace phase contract, native input admission and whole transform identity remain unknown.

This extends the [late-preparation report](corefp_late_preparation_report.md), which had kept these forty earlier reads outside its entry quantifier.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_preparation_scans.py), [checks archive](triage_evidence/corefp_preparation_scans_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_preparation_scans.py), [audit archive](triage_evidence/corefp_preparation_scans_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_preparation_scans_publication.py) retain the source, twelve scan entries/ends, full regional visits/reads, PAC records, intermediate recurrence states, residues and queries. Eight parent receipts and eleven frozen source dependencies are SHA-256 pinned. The three originally supplied inputs are unchanged.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. All source PCs/table cells below are preferred-base-zero offsets; B denotes bytes. The two regions contain 184 four-byte instructions/736 B, within the existing 59120 B caller/allocator/retirement source coverage. A further 109-instruction/436 B census covers the two residue-kill paths. These extents remain subsets of that retained source coverage.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PS1 | Pinned original source/fixups, eight parent receipts and frozen dependencies describe this image. All source claims depend on these bindings. | Compare original bodies, both complete regions, proof slices, dependency hashes and authenticated pointer-chain rows; preserve the supplied inputs. |
| PS2 | Existing private caller/context/pool/malloc/PAC/sequential-CASAL fixtures apply. Whole-caller continuity depends on them. | Reconstruct six initial CPU/RAM states and freshly replay 488136 visits. Native object/context admission and concurrency remain unknown. |
| PS3 | The prepared interface is a backed sixteen-byte array p at FP-`0x88`, or SP+`0x498` with FP=SP+`0x520`; counters start at zero. Array and termination contracts depend on these typed inputs. | Prove every selector address lies in the sixteen-byte interface and every split lies in 1..15; check all sixteen sequential reads and all split values in each component domain. Native address validity/nonwrapping is a separate prerequisite. |
| PS4 | The tail shifts normalize to 8/16, and the second head's cached bias d equals a. Common-recurrence claims depend on these explicit premises. | Recheck source shift expressions and all six entry bindings; generic body proofs quantify arbitrary u32 states/parameters with the stated constraints. Other native parameter classes remain unclassified. |
| PS5 | The fixed control fields and seven original relocated dispatch cells apply, with declared PAC target/modifier semantics. Bounded-target claims depend on those bindings. | Check both branch decisions at each dispatcher, original chain membership/target/diversity and every emulated branch. Cryptographic PAC authentication is not executed. Arbitrary native control fields do not inherit these cell bindings. |
| PS6 | The two scans see the same p, multiplier, biases and recurrence seed; the residue-kill paths complete normally. Equal-delta and caller-dead-residue claims depend on them. | Compare all retained paired inputs/parameters, independently compute both deltas, retain every forced-split residue and census both branch-free kill paths. Propagation through the intervening phase code and native exception/lifetime behavior remain outside this theorem. |

## Source regions, interfaces and read epochs [PS1-PS4]

| Scan | Source interval | Static instructions / B | A, B, C, h registers | Dynamic visits |
| --- | --- | --- | --- | --- |
| First | `[0x1b536c,0x1b54d0)` | 89 / 356 | W26, W30, W22, W14 | `583 - 4*n0` |
| Second | `[0x1b6530,0x1b66ac)` | 95 / 380 | W15, W10, W11, W4 | `590 - 5*n1` |

Each region executes once per complete retained caller. Each has twenty prepared-byte read instances: four selector reads plus a sequential scan of sixteen bytes. The first region additionally reads its pointer-table base/cells 34 times; the second has 35 non-preparation reads, including one control load at SP+`0x410`. Thus each first scan has 54 reads, each second scan 55. There are no memory stores in either region. Their architectural outputs are registers; both 1312 B stack snapshots remain unchanged.

The first counter is X8 in the head loop and X11 in the tail loop. The second uses X12 and X13. Each head starts at 0 and exits after counter n; each tail starts at n and exits after counter 16. n is always 1..15, so both bodies execute at least once. Dynamic source counts follow directly from the initial segment plus the two body/dispatch lengths:

```text
first:  23 + 31*n0 + 35*(16-n0) = 583 - 4*n0
second: 30 + 30*n1 + 35*(16-n1) = 590 - 5*n1
```

The retained ramp/flip/clobber profiles use `(n0,n1)=(1,6)`; the zero-preparation profiles use `(11,14)`. Message extents 16 B and 32 B change incoming accumulators but retain those preparation-dependent split values. Across six complete callers, the twelve regions contain 6674 visits, 654 reads, 240 prepared-byte reads and 204 PAC models, with zero writes. Their read extent is `6*(20+34*8 + 20+35*8)=3552 B`.

## Exact selectors and bounded local control [PS3,PS5]

All p elements are u8. Index arithmetic below is reduced modulo 16; max(1,v) clamps only the zero nibble to one.

```text
first selector:
  a = (p[4] + 4)  mod 16
  b = (p[a] + 14) mod 16
  c = (p[b] + 2)  mod 16
  n0 = max(1, p[c] mod 16)

second selector:
  a = (p[2] + 14) mod 16
  b = (p[a] + 14) mod 16
  c = p[b] mod 16
  n1 = max(1, (p[c] + 3) mod 16)
```

The first four load sites are `0x1b536c`, `0x1b5380`, `0x1b5390`, `0x1b53a0`; the second four are `0x1b6530`, `0x1b6544`, `0x1b6554`, `0x1b6560`. TST of bits 1..3 followed by CSINC maps low nibbles 0 and 1 to 1 and preserves 2..15. Eight source obligations normalize the selector addresses, two prove the exact split formulas and two prove the range. The second CSINC at `0x1b657c` is separated from its TST by three flag-preserving typed pointer/control loads; the retained proof slice includes the actual CSINC and the whole-region interpreter covers the intervening loads.

Each iteration ends in an authenticated indirect branch. With the retained control fields, the table base is image+`0x1c81940`; the effective cell is `base + 8*sign_extend_u32(index)`, using u64 modular address arithmetic. The seven original cells below bound both outcomes of every dispatcher.

| Cell index, hex u32 | Cell offset | Target PC | Modifier/diversity | Role |
| --- | --- | --- | --- | --- |
| `4d3a` | `0x1ca8310` | `0x1b53c8` | `831f` | First head entry/continuation |
| `4d25` | `0x1ca8268` | `0x1b5444` | `831f` | First tail entry/continuation |
| `da6e` | `0x1ceecb0` | `0x1b54d0` | `831f` | First scan end |
| `55be` | `0x1cac730` | `0x1b65a8` | `c9c2` | Second head entry/continuation |
| `55f5` | `0x1cac8e8` | `0x1b6620` | `c9c2` | Second head-to-tail transition |
| `4208` | `0x1ca2980` | `0x1b6620` | `9720` | Second tail continuation |
| `4257` | `0x1ca2bf8` | `0x1b66ac` | `9720` | Second scan end |

| Dispatcher PC | Source index formula, under retained control binding |
| --- | --- |
| `0x1b5440` | `0x4d25 XOR (31 if head_counter != n0 else 0)` |
| `0x1b54cc` | `0x4d25 XOR (0x974b if tail_counter == 16 else 0)` |
| `0x1b661c` | `0x55be XOR (0x4b if head_counter == n1 else 0)` |
| `0x1b66a8` | `0x4208 XOR (0x5f if tail_counter == 16 else 0)` |

The initial branches at `0x1b53c4` and `0x1b65a4` enter the corresponding head. Each scan has one initial branch plus sixteen iteration branches. Four source obligations check table-base-slot addresses and four check exact signed-index addressing. Concrete cells are checked against original authenticated fixups and relocated page bytes. The private execution model checks the computed target and modifier, then advances PC; it does not execute cryptographic PAC authentication or infer native acceptance.

## Common sixteen-step state recurrence [PS1,PS3,PS4]

All additions, multiplication and XOR below operate on u32 values; each addition/multiplication wraps modulo 2^32 before its result is used. Right shifts are logical. Byte p[i] is zero-extended to u32; i ranges from 0 to 15.

```text
F(x):
  y = x + (x >> 16)
  return y + (y >> 8)

u = p[i] * k
 t = F((u XOR h) + i)
 v = F(((t + a) XOR u) + i)

A_next = A XOR t XOR v
B_next = B XOR (t+b)   XOR (v+b)
C_next = C XOR (t+a)   XOR (v+a)
h_next = v + a
```

The retained bindings, shared by both scans in all six profiles, are:

| Parameter | u32 value | Source interface |
| --- | --- | --- |
| k | `0x750549fb` | First W2; second W6, loaded by original MOV/MOVK |
| a | `0xdecc2544` | W0 |
| b | `0xef6612a2` | W9 |
| Initial h | `0x6d31a173` | First W14, set by original MOV/MOVK; second incoming W4 |

The generic body proofs do not restrict A/B/C/h/k/a/b to these numbers. They quantify arbitrary u32 inputs and an arbitrary u8 byte, with counter in 0..15. The first tail's source shift must satisfy `(W10-0x4d1d) AND 31 = 8`; the retained W10 is `0x4d25`. The second tail requires `(W8-0x41f8) AND 31 = 16`; retained W8 is `0x4208`. The second head initially caches a in W16: `0x4208 + 0xdecbe33c`, modulo 2^32, equals `0xdecc2544`. Its source proof permits a separate d; equality d=a discharges the common-recurrence binding in the retained entries.

Four source obligations prove byte addresses for the four loop bodies; four prove their state, counter and scratch-residue transfers. These cover original load, multiply, add, XOR and masked variable-shift semantics. In particular, an intermediate W14 in the first head is overwritten before dispatch; treating that intermediate as the ending h produces a wrong recurrence. The independent integer oracle and source interpreter check the final register lifetime.

For counter i, use the invariant that `(A,B,C,h)` equals the first i steps of the common recurrence. The head executes indices 0..n-1, the tail n..15. Source body proofs give unit counter progress and the same four-state transfer under the explicit shift/bias premises. The selectors and target bindings ensure that the next index is processed in the corresponding body. Since 1<=n<=15, the two lengths are positive and sum to sixteen; no counter wrap occurs. This proves four-state independence from the split, rather than inferring it from a few split choices.

## Equal deltas, scratch residues and downstream reads [PS4-PS6]

A/B/C do not feed the h/t/v recurrence. Their per-step changes are XOR masks determined only by p, h, k, a, b and i. A separate universal obligation proves that changing the incoming accumulator triple preserves those three XOR deltas and the next h. Induction over sixteen steps therefore gives identical deltas in two scans with the same p/seed/parameters, even if their initial accumulator triples differ.

| Preparation control | Delta A | Delta B | Delta C | Final h, both scans |
| --- | --- | --- | --- | --- |
| Ramp | `9c85e197` | `c4a46623` | `87b50e7f` | `606baae7` |
| Zero | `e5c5d895` | `404e09e5` | `0cfa0b9d` | `947bcde8` |
| Byte-0 flip | `4be08d0e` | `85e8a3ea` | `70b844a6` | `594f53af` |

The 32 B controls and clobber control repeat the corresponding preparation deltas despite different incoming accumulator values. These concrete vectors corroborate the conditional common-fold theorem; they assign no native key, checksum, cipher or authentication role to the words.

The complete ending CPU frames need not be split-independent. Let `(A_n,B_n,C_n,h_n)` be the state after the head's n steps and t_(n-1) the first folded value of its final iteration.

| Scan | Retained head residue at scan end | First subsequent access | Consequence under normal completed execution |
| --- | --- | --- | --- |
| First | `W1 = C_n XOR h_n` | `0x1b5618: ldr w1,[sp,#0x410]` | Overwritten before any read |
| Second | `W3 = t_(n-1) + b`, modulo 2^32 | `0x1b6710: eor w3,w9,w2` | Overwritten before any read |

Both tails preserve their respective residue. The source body obligations check its creation/preservation as well as the four recurrence states. A register-access census finds no read of either W/X alias before these kills and no control transfer along either kill path. The first path contains 83 instructions/332 B including the overwrite; the second contains 26/104 B. No memory store occurs in either scan. An exception/observation of an intermediate CPU frame is outside the normal-completion dead-register conclusion.

The first statically visible reads of the six accumulator outputs, before an intervening explicit write to the same register, are:

| Scan output | First source read after scan end |
| --- | --- |
| First A, W26 | `0x1b66d8: eor w0,w9,w26` |
| First B, W30 | `0x1b66f0: eor w4,w9,w30` |
| First C, W22 | `0x1b6788: eor w9,w9,w22` |
| Second A, W15 | `0x1b6808: eor w15,w12,w15` |
| Second B, W10 | `0x1b6870: eor w10,w12,w10` |
| Second C, W11 | `0x1b6890: eor w11,w16,w11` |

These are concrete local touch points into the later obfuscated phase code. A complete algebraic reduction from these six words to workspace encodings and canonical consumer inputs remains open.

## Validation and continuation

Capture and independent audit each freshly execute all six complete original private caller profiles. The audit reconstructs six initial CPU frames and 3313664 B of initial RAM, checks 488136 visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM. The scan counts are included in these totals.

An independent scalar interpreter checks 6674 regional visits, 654 reads, 204 declared PAC branches, complete ending CPU frames and 15744 B of unchanged stack snapshots across twelve regions. The independent compact oracle checks all 192 actual state steps, twelve residues and six equal-delta pairs. It does not import the new producer.

Original-byte component tests use sixteen one-byte variation sweeps plus 256 constant-fill vectors per domain: `16*256+256=4352` cases, across twelve domains giving 52224 cases. Each domain covers all fifteen split values. The zero vector repeats seventeen times, so each domain contains 4336 distinct p vectors. The corpus produces 29978304 source visits, 887808 modeled PAC instructions and 29090496 emulated instructions; 835584 recurrence steps, 208896 four-state u32 results and 52224 residues are checked. Each source region remains unchanged and performs no memory write. Twelve actual-entry runs additionally match full CPU/stack snapshots.

A separate initial-dispatch interface cut forces every n=1..15 for each retained p/state pair, yielding 180 diagnostic runs. Their four recurrence states agree, while the ending full frames differ exactly by the declared W1/W3 residue. All fifteen residue values and CPU digests are retained per domain. These are explicit diagnostic component inputs, not executions of the original selector for those forced n values and not native caller-admission claims.

All thirty new source obligations are independently UNSAT: twelve selector equations/bounds, eight body address/state obligations, eight dispatcher equations, accumulator-delta independence and loop-count bounds. Rechecking 1040 frozen obligations yields 1070 total. Each solver has a 30 s query limit. Inductive composition, finite tests, typed read bindings and native observations retain distinct scopes.

No native target/API/IPC or cryptographic PAC authentication executes; no IDB is accessed or mutated. Original reference data suffices. No new Mach port/right, descriptor, emission site or daemon/kext endpoint pairing is established. The new architectural interfaces are private byte reads, scalar register states and bounded authenticated-dispatch cells. The full interface investigation remains active.

For C profiles, N scan regions, V source visits, J retained per-visit state/journal size, P touched pages, F page/frame payload size, B pinned source bytes and R other retained bytes, whole replay is conservatively `O(C*(B+V*J+P*F+R))` time/space. The compact fold takes `O(16)` time and four u32 state words; selectors take four array reads. Component testing is `O(N*4352*600)` time with bounded private maps and at most 600 source visits per case; sixteen-step arithmetic and seventeen PAC models apply to each complete scan. Solver limits are separate. Aggregate counts/histograms/digests retain the corpus without storing every emulated state.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Reduce the six accumulator consumers to phase/workspace parameters and canonical input words. | Carry the equal-delta identities through all intervening source equations and prove or reject coherent general preparation cancellation. |
| High | Join raw preparation preprocessing to both scans and the late identity-XOR interface. | Prove all entry parameter/backing dependencies for arbitrary raw preparation, including register residue lifetimes and source context fields. |
| High | Establish native selector/holder/context initialization and upstream records. | Require source-produced same-epoch backing and ownership before native admission or lifetime claims. |
| Medium | Complete later-block message/state updates. | Derive the four loop-update fields and their consumers; first-block preparation results alone do not identify a chaining mode. |
| Low | Connect local scalar/byte results to daemon/kext transport. | Require an actual serializer/consumer handoff with matched endpoint/right epochs. No local branch cell supplies a Mach emission. |

- **QG1**: No normative premise is required.
- **QG2**: PS1-PS6 identify assumptions, dependent results and falsification probes.
- **QG3**: Both selectors/scans, memory footprints, register states, residues, dispatch cells, downstream source reads and external-interface limits are covered.
- **QG4**: u8/u32/u64 widths, modular sums/products, logical/masked shifts, signed pointer indices, byte extents and corpus cardinalities are explicit.
- **QG5**: Equal recurrence states are separated from differing full frames; residues and their kills are retained; native PAC and arbitrary raw-input admission remain unproven.
- **QG6**: Original source/fixups, fresh complete replay, independent scalar/integer oracles, unchanged-byte component tests and retained solver queries provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains phase-parameter consumers, whole-caller entry coherence, later blocks and cross-level handoffs. The full goal remains active.
