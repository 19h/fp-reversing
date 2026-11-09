# Mode1 compact two-bank combination and hidden addition circuits

Follow-up: [Encoded-word mix and size context](daemon_mode_one_word_mix_report.md) reduces the next209-instruction block to five compact unary maps and15 exit-register formulas. All275 captured nonbranch sites are translated;39 UNSAT,including12 predecessor replays,and one abstract SAT check pass. The frame+0x434 size-derived word is consumed and the actual bank-coordinate mix is proved. There are no stores or saved-view dereferences. Next routine0x100bf3160,caller output and native daemon-kext exchange remain unknown.

The block at0x100bdba34 combines the two retained four-word banks through32-bit XOR/add/subtract operations. A long Boolean carry circuit reduces to one addition and XOR. The following masked circuit is another ordinary addition of encoded operands. With those universal identities,the full source reduces to14 compact register formulas,including the same function applied independently to each bank. This identifies a local arithmetic stage;whole algorithm,caller output and native daemon/kext linkage remain unknown. [BC1-BC8]

Evidence: [source and original pointers](triage_evidence/daemon_mode_one_bank_combine_source.json), [universal proofs,live cuts and register formulas](triage_evidence/daemon_mode_one_bank_combine_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_bank_combine.py), [validator](triage_evidence/validate_daemon_mode_one_bank_combine.py), [preservation](triage_evidence/daemon_mode_one_bank_combine_delivery.json), [quality gates](triage_evidence/daemon_mode_one_bank_combine_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_bank_combine_publication.py). Parent: [source passes and initializer](daemon_mode_one_post_table_passes_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New block |162 instructions/648 B;all161 nonbranch sites translated |
| With initializer lineage |Two ranges,338 instructions/1352 B;all336 distinct nonbranch sites translated |
| Recapture |Twelve parent ranges/2480 B |
| Metadata |Two original authenticated pointer records and branch/modifier matches |
| SMT |Eighteen UNSAT certificates;one SAT abstract eight-word-domain check |
| Reduction |Two universal u32 identities,two source-linked live cuts,14 compact register formulas |
| Memory |One4 B store in the new block;816 identified arithmetic-table cells preserved |
| Controls |Four source/phase/target/native-claim alterations rejected by fresh original-source comparison |
| Execution |No target execution,emulation,API/IPC request,hardware PAC or IDB mutation |

## Bank coordinates and common operation

All following operations wrap modulo2^32;XOR is bitwise. Define the incoming words at the combiner as:

```
first bank:  W10=A, W5=B, W25=C, W30=D+0xad732488
second bank: W13=E, W11=F, W3=G, W26=H
```

The additive representation of D comes from the preceding handoff. The fresh initializer proof preserves those eight words and establishes W0=0,W4=0x528cdb78,W8=1,W20=0x4cdb,W22=0xad732488 and X21=frame+0x8348. It does not require particular bank values. The constant equality0xad732488+0x528cdb78=0 modulo2^32 cancels the D representation in the first XOR. [BC2-BC5]

Define:

```
m = D XOR B
n = F XOR H
T(x) = (x+0x01fe06c9) XOR0x59259907
Q(a,b,c,d) = T(d XOR b)+(d XOR b)+c-a+0x144c3fb2
```

Then W12=Q(A,B,C,D) and W19=Q(E,F,G,H). The same function acts on each bank. This does not establish equality of the banks or their results;the preceding report did not prove equivalence of its two new source recurrences. No standard algorithm identity is assigned.

| Register after this block | Compact value |
| --- | --- |
|W12 |T(m)+m+C-A+0x144c3fb2 |
|W19 |T(n)+n+G-E+0x144c3fb2 |
|W5 |C+m+0xd06c2258 |
|W0 |G+n+0x2dc65bfe |
|W7 |G-H+0xf8afc709 |
|W11 |D+m+0x1368083a |
|W2 |H+n+0x351694f5 |
|W4 |G-E+n+0xf768929f |
|W14 |G-E+n+0x144c3fb2 |
|W1 |(C-A+m+0x144c3fb2) XOR0x08156cbf |
|W6 |G-H |
|W15 |C-D+0x528cdb78 |
|W3 |0x000266d8 |
|W16 |0x000017d8 |

These formulas are proved universally for all eight u32 inputs. A combined14-output query timed out and is excluded;fourteen accepted per-register queries cover the same domain. They are not fitted only to sampled banks. The full source is translated;the two explicit live cuts use separately proved universal source identities before substitution. Original and replacement expressions,input bindings and source spans are retained in the checks artifact. [BC4-BC6]

## Source circuit recovery

The source span0x100bdba84..0x100bdbbf8 repeatedly combines shifted generate/propagate-like masks at distances1,2,4,8 and16. Its observable W1 output for arbitrary entry W16=x is exactly:

`F(x) = (x+0x6891e1c7) XOR0x08156cbf`

The universal certificate includes every captured instruction in that span,including interleaved work on other registers. Its W1 result is independent of the other symbolic entry registers. The identity is used only to replace the newly computed W1 at0x100bdbbf4;all other source register effects remain modeled.

The span0x100bdbc00..0x100bdbc58 receives entry W12=u and W1=v. Its final W12 is exactly:

`Gadd(u,v) = ((u+0x01fe06c9) XOR0x59259907)+(v XOR0x08156cbf)`

It implements the sum through masked XOR terms and a doubled conjunction. The second universal certificate proves that identity independently of the unary carry circuit. Composing Gadd with F cancels the0x08156cbf representation on the second operand and yields the first-bank Q formula. The source's shorter second-bank path yields the same Q directly. [BC4-BC6]

W17 requires distinct epochs. It temporarily holds an arithmetic value used while producing other outputs;the source later overwrites it with the private branch selector and then with the authentication modifier. No transient arithmetic W17 value is exported as an exit-state bank word. Similarly,the incoming G in W3 is copied through X7 before W3 becomes a count-derived constant. Register numbers alone do not identify stable semantic roles.

## Memory,private control and interface limits

The new block has one store:STR W0 at0x100bdba34 writes zero to frame+0x448 before W0 becomes an arithmetic output. This is a local4 B cell;it is not identified as a public status or the private request's result field. The source has no return instruction here. Its continuation is an internal authenticated branch. [BC3,BC7]

The arithmetic tables occupy816 identified bytes in the earlier T+[0,962] scratch domain,where T=frame+0xd00. The new store does not overlap them,the saved source/image-data roots at frame+0x450/+0x458,the size word at+0x750,the scratch/branch roots at+0x738/+0x740,or the8 B budget cell at+0x1210. The earlier literals and computed words are also untouched by this new block.

X21 remains frame+0x8348. This block does not dereference that view. Its native validity,accessible extent and downstream offset decoding therefore remain unknown. The arithmetic-table contents are likewise not read by this block;their later consumers remain to be traced. [BC3,BC8]

The initializer's pointer at private selector0x6284 reaches0x100bdba34 with IA diversity0xcdf0. In the combiner,W8=1 produces temporary phase bits0x22 through the low-bit test,shift and BFI. XOR with W20=0x4cdb yields selector0x4cf9. The source loads the private table from frame+0x740 at0x100bdbcac,loads the selected pointer at0x100bdbcb0,and executes BRAA at0x100bdbcb8 with modifier0x74b2. The original authenticated rebase resolves to0x100dab3d0.

Both pointer records match their source modifiers. This is static selection evidence,not successful hardware PAC or native traversal. The captured blocks contain no call,trap or Mach emission. They establish no new incoming/outgoing Mach port,name,right or message ABI. W0's arithmetic role and the private selectors must not be interpreted as public status/port contracts without further source linkage. [BC7-BC8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| BC1 |Pinned original image,unslid code and original fixups |Rehash image,recapture both blocks and parent ranges,compare pointer records |
| BC2 |Selected mode1 handoff and the stated bank representations |Recheck the preceding bank transfers and initializer's preserved words;other entry states require separate phase contracts |
| BC3 |Valid nonwrapping private frame and coherent memory |Check owner/mapping/lifetime and outside writes;the saved view has no native extent proof |
| BC4 |SSA widths,BFI bit placement and source operations match the original |All336 captured nonbranch sites are translated;universal source/output queries reject differing expressions |
| BC5 |Each generic source identity is substituted with its actual live inputs |Review the two source spans,their original expressions and recorded input bindings;other register effects remain in the full model |
| BC6 |u32 arithmetic and XOR representations are composed without changing epochs |Check the D offset cancellation,the shared Q function and scratch-register overwrites |
| BC7 |Original authenticated pointers supply static targets |Hardware PAC,exceptions,native authorization and actual traversal are not executed or proved |
| BC8 |Whole operation,caller output,view extent and daemon/kext pairing remain unknown |Trace0x100dab3d0 and subsequent bank/table/view consumers through publication |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Trace0x100dab3d0 with the compact register map |Source use of Q outputs and the remaining bank expressions |
|High |Connect the arithmetic stage to actual table/view accesses and caller output |Ownership,offset decoding,extents and publication/serialization chain |
|Medium |Recover equivalent compact expressions in later Boolean circuits |Independent universal identities and source-bound substitutions |
|Low |Evaluate algorithm hypotheses after wider operation semantics are known |Independent structure beyond local addition and XOR |

The new block is straight-line,with fixed162 instructions and one4 B store. Source extraction/hashing is linear in bytes. SSA construction/storage is linear in modeled instruction instances;SMT runtime is solver-dependent,limited to15000 ms per query. Unknown and timeout are rejected. All extents are bytes;arithmetic formulas use u32 wrapping and byte-address calculations use u64.

QG1: Factual source,arithmetic and metadata results are reported.

QG2: BC1-BC8 record assumptions,dependent results and falsification probes.

QG3: Bank roles,compact arithmetic,register epochs,memory footprint,private control and Mach-emission scope are covered for this increment;the full objective remains active.

QG4: All14 formulas,word widths,source constants,two substitutions and exact store extent are reproducible.

QG5: The transient W17 value,the zero-before-arithmetic W0 store,the D representation and saved-view limits are distinguished.

QG6: Original recapture,336 translated sites,eighteen UNSAT certificates,one abstract SAT check and four alteration controls establish scoped provenance.

QG7: Four impact-ranked continuation questions bound the expansion;whole algorithm,caller output and native exchange are not claimed.
