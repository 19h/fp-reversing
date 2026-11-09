# Mode1 encoded nibble-sum and carry tables

The routine at0x100c18e20 constructs a second256-entry table. Paired with the preceding table at0x100c07254,it implements the sum and carry of adding two base16 digits under a shared relabeling. The new table uses a different byte encoding. This establishes local arithmetic structure in the protected core;caller-visible output,whole return and a successful daemon/kext exchange remain unknown. [CT1-CT8]

The previous report called0x100c18e20 the next consumer without assigning its behavior. Its captured source instead reads the inverse and forward16-entry tables and writes another table. It does not read the preceding256-entry sum table. The carry data also identifies a natural digit labeling that refines the earlier cyclic-group labeling. [CT2-CT6]

Evidence: [original source,data and fixups](triage_evidence/daemon_mode_one_carry_table_source.json), [SSA certificates and finite cases](triage_evidence/daemon_mode_one_carry_table_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_carry_table.py), [validator](triage_evidence/validate_daemon_mode_one_carry_table.py), [preservation](triage_evidence/daemon_mode_one_carry_table_delivery.json), [quality gates](triage_evidence/daemon_mode_one_carry_table_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_carry_table_publication.py). Parent: [inverse tables and cyclic operation](daemon_mode_one_inverse_tables_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New routine |125 instructions/500 B;all124 nonbranch sites translated |
| Captured lineage |Four ranges,total245 instructions/980 B |
| Original recapture |Ten parent ranges/4208 B;944 B fixed-data region |
| Metadata |Three pointer records;two branch-slot/IA-diversity matches |
| Solver |19 UNSAT certificates,including six replayed parent certificates;one SAT abstract-domain check |
| Finite checks |256 fixed-data indices,256 decoder bytes,256 input/destination cases;all256 sum/carry pairs |
| Mutation controls |Four altered source/data/branch/native-claim records rejected by fresh source comparison |
| Scope |Source and finite algebra only;target execution,emulation,requests,hardware PAC and IDB mutation all false |

## Arithmetic meaning and byte-table ABI

Let F be the protected-core frame and T=F+0xd00. Let pi be the permutation already established by the two equal seeded shuffles. The existing tables satisfy A[j]=E(pi(j)) and B[pi(j)]=E(j),where E(j)=0xd4 XOR j. Define H(j)=0xd4 XOR(j<<4),with the result truncated to8 bits.

The natural digit-label sequence recovered from the fixed carry operation is:

`M = [9, 4, a, d, 0, 5, 7, c, 1, 3, 8, f, b, e, 2, 6]`

All sixteen labels occur once. Write R(a)=pi(M[a]) for a=0..15. The source-backed table relations are:

```
C[R(a)+16*R(b)] = E(R((a+b) mod16))
D[R(a)+16*R(b)] = H(R(floor((a+b)/16)))
```

Consequently,after inverting their respective byte encoding and the common R labeling,the outputs satisfy a+b=sum+16*carry for every digit pair. Sum lies in0..15;carry lies in0..1. The stored carry byte is H(R(0)) or H(R(1)),rather than a literal Boolean. This composition holds for any bijective pi meeting the parent source contract;neither uniform sampling nor reachability of every permutation is assumed. [CT2-CT6]

The carry operation's fixed labels are9 for zero and4 for one. Counting occurrences of label4 in each logical row gives the unique ranks0..15. Independent decoding of the original sum data then verifies both addition identities over all256 pairs. The previous cyclic label sequence used generator3,whose natural rank is9. That sequence remains a valid cyclic-group isomorphism;the carry table selects the digit labeling needed for integer sum/carry interpretation. No standard cipher identity is inferred.

| Logical table | Physical address at T+offset | Cells / stored representation |
| --- | --- | --- |
| A[j] |(84784+757*j) mod963 |16,E(pi(j)) |
| B[j] |(12869+757*j) mod963 |16,E(pi_inverse(j)) |
| C[t] |(534442+757*t) mod963 |256,E(encoded sum label) |
| D[t] |(137774+757*t) mod963 |256,H(encoded carry label) |

All544 byte positions are pairwise disjoint within the963 B scratch address domain. The new routine writes D exactly once at each of its256 positions. It preserves A,B,C,the second-bank spills,the saved scratch/branch/word-cell roots and the8 B budget cell at F+0x1210 through its branch at0x100c19010. The source contains one byte store per round and no SP write. This invariant does not extend into the next routine. [CT3,CT6]

## Source data flow and control

At entry W4=0,W5=0xa8575b74,W8=0xc25d,X21=T and X23=0x100f715a0. The shuffle's source seed and exit establish W4/W8;the intervening sum writer does not write either register and sets W5 explicitly. Its source-certified image-data root provides X23. This distinguishes new source liveness checks from the six replayed parent certificates. [CT1-CT4]

Each round t reads B[t&15] at0x100c18e98 and B[t>>4] at0x100c18e94. If these bytes encode inverse labels u and v,the obfuscated arithmetic reduces to the packed byte (u+16*v) XOR0x7a. At0x100c18f7c it reads the fixed byte y at:

`0x100f715a0 + ((527*((u+16*v) XOR0x7a)) mod944)`

The following decoder forms vbyte=((0x5a OR(y>>7)) XOR(y>>4)) OR0x20. For every possible byte y,vbyte is in0x70..0x7f. Its scattered address selects A[vbyte-112] at0x100c18fc0. The byte store at0x100c18ff4 computes0x94 XOR(value<<4),which equals H(j) when value=E(j). Source SSA establishes these instruction-level expressions;bounded reciprocal identities and exhaustive finite cases establish their address and algebraic interpretations. [CT4-CT6]

The source updates W4 to t+1 and W5 to0xa8575b75+t. It compares the latter with0xa8575c74,so t=0..255 gives exactly256 rounds. It loads the private branch table from F+0x740 at0x100c19004 and a selected pointer at0x100c19008,then executes BRAA X1,X17 at0x100c19010 with X17=0x4177.

| Condition | Private selector | Pointer slot | Original target |
| --- | --- | --- | --- |
|t<255 |0xc262 |0x10109b200 |0x100c18e20,repeat |
|t=255 |0xc25d |0x10109b1d8 |0x100c9589c,next routine |

These are original IA-authenticated rebase records with matching diversity0x4177. Static resolution does not prove successful hardware authentication or native pointer validity. The routine contains no call,trap or Mach emission. No incoming/outgoing Mach port,name,right or message contract is established here;the two selectors are private branch indices. The links from these arithmetic tables to caller output and cross-layer requests remain unknown. [CT7-CT8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CT1 |Pinned original image,unslid addresses,source and original fixups |Rehash image and recapture all source/data/metadata;reject any discrepancy |
| CT2 |Selected mode1 path and the parent inverse/equal-shuffle contract |Recheck admission,stable source bytes and paired seed equality;other paths do not inherit these tables |
| CT3 |Valid nonwrapping private frame and coherent memory,disjoint from immutable image data |Check actual mappings,owner lifetime and intervening writes;native validity is unknown |
| CT4 |Saved roots and fixed image bytes remain stable across the local writers |Recheck root lineage,original rebase/bias and all944 fixed-data bytes;outside writes invalidate the result |
| CT5 |SSA widths,variable-shift masking,SUBS flags and comparison operand roles match AArch64 |All124 nonbranch sites are translated;source shape,exact bounded division and exhaustive cases check the arithmetic |
| CT6 |Bijective pi and compositional use of proved source relations |Check A/B inversion,region disjointness,both byte encodings and every paired sum/carry identity;no sampled permutation is required |
| CT7 |Static authenticated-pointer metadata identifies selected branch targets |Hardware PAC,exceptions and native authorization are not executed or proved |
| CT8 |Whole operation,caller output and daemon/kext pairing remain unknown |Trace0x100c9589c and later table reads through output publication;the local adder contract alone is insufficient |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence that would resolve it |
| --- | --- | --- |
|High |Trace0x100c9589c and actual C/D readers |Source reads connecting both table encodings to a wider arithmetic transformation or output |
|High |Connect the arithmetic state to caller-visible buffers and daemon/kext messages |A continuous source-backed ownership,extent and serialization chain |
|Medium |Establish synchronization of persistent word cells |Writer/lock/lifetime evidence;the current table family is constant under arbitrary cell values |
|Low |Test standard algorithm hypotheses only after wider semantics are recovered |Operation-level independent invariants;local encoded addition is insufficient for attribution |

The selected loop takes256 rounds and uses a fixed963 B scratch domain,of which544 B are identified table cells. Source extraction/hashing is linear in bytes;finite table checks take O(n^2) time and O(n^2) retained evidence for n=16. SMT runtime is solver-dependent,limited to15000 ms per query;unknown or timeout is rejected. All address sizes are bytes and all source arithmetic has explicit8/32/64-bit widths.

QG1: The report states factual source and algebraic results.

QG2: CT1-CT8 register assumptions,dependent conclusions and falsification probes.

QG3: Routine role,source/data/control flow,local memory ABI,external-control limits and Mach-emission scope are covered for this increment. The full interface objective remains active.

QG4: Bit widths,byte extents,256-round recurrence,reciprocal bounds and finite cases are reproducible in the validator.

QG5: High/low byte encodings,source liveness,disjoint regions and the refinement of the earlier generator labeling are reconciled. Native and downstream unknowns remain explicit.

QG6: Original bytes/data/fixups,124 translated sites,19 UNSAT certificates,one abstract-domain SAT check,256 paired identities and four alteration controls provide provenance for the scoped result.

QG7: Four impact-ranked continuation questions bound the expansion. No native exchange,whole cipher or completed goal is claimed.
