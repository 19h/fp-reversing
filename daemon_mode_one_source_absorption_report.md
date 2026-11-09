# Mode1 source-byte absorption and post-loop state handoff

The selected LEN32 continuation consumes SRC[0..31] and updates the first32 cells of both previously materialized64-byte planes. Plane0 XORs the input bytes;Plane1 XORs a repeating16-byte mask derived from immutable image data. The loop preserves all800 live arithmetic-table cells and the other64 plane bytes. The following handoff installs a private address schedule,reloads three materialized words and transfers to0x100b4ef4c. Whole-operation semantics,caller output and native daemon/kext linkage remain unknown. [SA1-SA8]

Evidence: [original source and pointer records](triage_evidence/daemon_mode_one_source_absorption_source.json), [source certificates and state ledger](triage_evidence/daemon_mode_one_source_absorption_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_source_absorption.py), [validator](triage_evidence/validate_daemon_mode_one_source_absorption.py), [preservation](triage_evidence/daemon_mode_one_source_absorption_delivery.json), [quality gates](triage_evidence/daemon_mode_one_source_absorption_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_source_absorption_publication.py). Parent: [state materialization](daemon_mode_one_state_materialization_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New source |Three ranges,414 instructions/1656 B;all411 nonbranch sites translated |
| Original recapture |Four predecessor ranges/6572 B and944 B immutable image data |
| Pointer metadata |Four original authenticated-rebase records and matching branch modifiers |
| SMT |Twelve new and five replayed UNSAT certificates;one SAT abstract-domain check |
| Finite algebra |Sixteen image lookup/mask cases;256 byte-decoder cases |
| Input |Thirty-two source bytes,read once each in increasing offset order |
| State |Sixty-four distinct plane bytes updated;800 table cells and64 other plane bytes preserved |
| Handoff |Nineteen stores/136 B;three materialized u32 reloads with predecessor producer sites |
| Alteration controls |Five source,data,target or native-claim alterations rejected |
| Execution |No target execution,emulation,API/IPC request,hardware PAC check or IDB mutation |

## Selected entry and the 32-iteration loop

The predecessor selects0x100c21d7c for its LEN32 context W24=0x3874e8e9. The entry copies u32 F+0x730=0x4923 into F+0x750 and reads the earlier constant u32 F+0x504=0x0dc87a81. The resulting register contracts are:

| Register | Entry to0x100bd7648 |
| --- | --- |
|W13 |0xc12face8,encoded counter zero |
|W10 |0x3ed05318,negative of the encoded counter base modulo2^32 |
|W11 |0xaace,repeat selector base |
|W15 |0x6ef65769,image-byte decoder seed |
|X25 |SRC,restored from predecessor F+0x458 |
|X26 |T=F+0xd00 |
|X23 |Immutable image-data root0x100f715a0 |
|W24 |0x3874e8e9 for the selected32-byte context |

All inherited arithmetic/address constants are preserved. Selector0x631f at the entry's final load reaches0x100bd7648 with IA diversity0x89de. [SA1-SA3]

Let i be the logical counter. W13=0xc12face8+i modulo2^32. The source load at0x100bd7994 uses u32 W10+W13,zero-extended to u64,so its address is SRC+i. No source bytes are written here.

The Boolean arithmetic before UDIV at0x100bd79cc computes denominator16 and numerator i for every0<=i<32. The certificate is universal over this selected domain;it does not substitute a sampled denominator. The model cuts the denominator only after proving its exact source expression equals16. UDIV's zero-divisor result is independently modeled as zero,rather than the all-ones value of SMT bvudiv by zero. The accepted loop domain has a nonzero divisor. [SA4]

The terminal comparison implements the following local predicate for0<=i<32,with u32 subtraction:

```
repeat = (i+1 <u (W24-0x3874e8c9))
W13    = 0xc12face8+i+1
```

For W24=0x3874e8e9,this is exactly i<31. Counter zero enters the body,31 iterations select repeat,and iteration31 selects the join. The counter and every next-iteration live constant/root are source-certified,which closes the32-step induction. The generic local comparison does not prove a general source-length decoder or the behavior of other-length invocations. [SA2,SA4,SA7]

| Selection | Original target | IA diversity |
| --- | --- | --- |
|0xaace,repeat |0x100bd7648 |0x9bc3 |
|0xaad2,join |0x100a763d4 |0x9bc3 |

## Compact data-flow contract

Define P(j)=T+((757*j) mod963),and S0[i]=byte at P(40+i),S1[i]=byte at P(112+i). Under the recorded disjoint,stable-memory assumptions,the whole selected loop is:

```
for i in 0..31:
    S0[i] = S0[i] XOR SRC[i]
    S1[i] = S1[i] XOR K[i mod16]
```

K is an image-derived mask,not an identified native secret key:

```
dc 1c 4a eb 19 6a c1 a7 ef e9 9d b7 07 92 c8 82
```

The two byte stores at0x100bd7a4c and0x100bd7ae4 have the exact source-proved addresses P(40+i) and P(112+i). Their earlier reads at0x100bd79d4 and0x100bd7ac4 use those same addresses. All32 iterations touch distinct cells within each plane,and the two sets are disjoint. The load/store ledger records every site,width and value expression. [SA3-SA6]

Thus input bytes enter only Plane0 in this loop. Plane1 receives a source-independent image mask applied to its existing values. This is a local dependency fact;the incoming materialized state already depends on prior input walks. It does not identify a standard primitive or establish global input independence.

The immutable data read at0x100bd7a68 uses a16-periodic address. For r=i mod16,the source's intermediate byte is32+(r XOR4). The validator retains the exact u32 transforms,multiplier527,reciprocal quotient and subtraction by944. The selected numerators span303552..311457;each retained quotient agrees with integer division by944.

| r | Image offset from0x100f715a0 | Original byte | K[r] |
| --- | --- | --- | --- |
|0 |638 |ce |dc |
|1 |221 |8e |1c |
|2 |528 |b8 |4a |
|3 |111 |d9 |eb |
|4 |858 |8b |19 |
|5 |441 |58 |6a |
|6 |748 |c3 |c1 |
|7 |331 |25 |a7 |
|8 |134 |dd |ef |
|9 |661 |db |e9 |
|10 |24 |0f |9d |
|11 |551 |35 |b7 |
|12 |354 |85 |07 |
|13 |881 |10 |92 |
|14 |244 |3a |c8 |
|15 |771 |00 |82 |

The decoder's256-case function is independently certified against the original decoder span for arbitrary image bytes and old state bytes. A second certificate proves both complete original loop store values against the same XOR contract. The table is original image data;no runtime table contents are inferred from an emulator trace. [SA1,SA4-SA5]

## Extents,ownership and interface touch points

The loop performs32 B of source reads,64 B of state reads and32 B of image reads:128 data-byte read operations. Its two8 B control loads per iteration add512 B,for640 B read operations across32 iterations. These are aggregate access counts,not a claim of640 distinct memory bytes. The64 one-byte writes touch64 distinct plane cells. The remaining64 plane cells and all800 live B/U/C/D/Q table cells are disjoint from those writes. [SA3,SA6]

The entry has24 B of reads and one4 B store. The handoff has32 B of reads and136 B of stores. Across entry,loop and handoff,the aggregate read count is696 B and store count204 B. Frame validity,object ownership,native buffer extent and memory coherence remain premises. In particular,SRC must be disjoint from the private state/control frame and immutable image roots for the compact array interpretation;separate symbolic load inputs do not establish that native allocation fact.

The new source has no call,trap,Mach send/receive operation,port allocation,right transfer or external callback. The only indirect transfers are the four recorded private authenticated branches. No new incoming/outgoing Mach-port name,right or emitted message location is established. This input-to-private-state contract advances the daemon's internal ABI;the existing Mach/XPC/IOKit contracts retain their prior evidence boundaries. [SA1,SA7-SA8]

## Post-loop register and frame epochs

The join at0x100a763d4 reads F+0x750=0x4923. It installs nineteen frame stores:four u32 stores and fifteen u64 stores,total136 B. Their offsets,widths,constants and original sites are retained. F+0x6d8 is cleared;F+0x610 receives selector0x803e,F+0x618 receives0xb8d8 and F+0x608 receives963. The remaining stores carry a scattered-coordinate schedule. Its complete downstream meaning is unknown. [SA6-SA8]

The full8 B writes at F+0x730/F+0x728/F+0x720 replace those cells' earlier roles. The source/table roots F+0x450/F+0x458,the saved view F+0x568,the arithmetic-bank roots,the scratch root F+0x738,the branch root F+0x740,the phase F+0x750 and the budget cell F+0x1210 are preserved.

Three materialized u32 words are reloaded without intervening writes to their cells:

| Reload | Frame cell | Original materializer store | Exit register |
| --- | --- | --- | --- |
|0x100a7650c |F+0x6cc |0x100c9e6fc |W26 |
|0x100a76510 |F+0x6d0 |0x100c9e67c |W0 |
|0x100a76514 |F+0x690 |0x100c9e6d4 |W25 |

X25 and X26 therefore cease to hold SRC and T. W23 is set to0x7648,ending X23's image-root register role;W24 becomes0x793d,ending its size-context register role. X28 becomes0x881ba59da4055115. These are register epochs,not loss of the saved roots. The handoff's selector0x803e reaches0x100b4ef4c with IA diversity0x505b. Native hardware authentication/traversal is not proved. [SA7]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SA1 |Pinned original image and unslid code/data/fixups |Rehash image,recapture three blocks,four predecessor ranges,944 data bytes and four pointer records |
| SA2 |Selected mode1 LEN32 context and predecessor epoch |Replay five producer certificates,including F+0x504 constant,and compare fresh predecessor source |
| SA3 |Valid nonwrapping frame/source extents and disjoint coherent memory |Check native allocation,lifetime,mappings and outside writes;SRC/private-frame aliasing would invalidate the compact array interpretation |
| SA4 |SSA widths,UDIV,shifts,comparison flags and proved-domain cut |Translate all411 nonbranch sites;recheck source denominator,numerator,addresses,values,counter and invariants;unknown/timeouts are rejected |
| SA5 |Immutable image bytes feed the certified decoder |Rehash all944 bytes,check16 address cases and universally compare256-case decoder plus complete loop values |
| SA6 |Selected32 iterations preserve table/state/frame epochs |Recompute all64 destinations,disjointness,19 handoff stores and three materialized-word producer joins |
| SA7 |Private static branches and post-loop roles apply only locally |Recheck original slot/modifier matches and subsequent use at0x100b4ef4c;hardware PAC and other-length paths remain unknown |
| SA8 |No external publication or complete algorithm is established |Follow state consumers through return/serialization/IPC;internal XOR updates alone do not establish daemon-kext exchange |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Follow0x100b4ef4c through both updated planes |Actual schedule accesses,first cross-plane combination and preserved table consumers |
|High |Connect final private state to caller output and serialization |Return,owner,lifetime,extents and message/publication producer chain |
|Medium |Establish the input-length contract beyond this32-byte context |Earlier size codec,entry selection and independently source-certified loop domains |
|Medium |Recover compact128-byte materializer semantics |Normalize earlier retained value SSA,then compose these proved XOR updates |

Source capture,SSA construction,hashing and the fixed-size finite checks require O(I+D+256) time and O(I+D+256) storage,where I is the captured instruction count and D the immutable data-byte count. The selected compact loop is O(32) time with O(1) extra state. SMT complexity is solver-dependent;each query has a15000 ms solver limit and20 s process limit. The excluded unrestricted divisor query timed out;only the accepted0<=i<32 certificate supports the denominator claim.

QG1: The report states factual code,data,layout and metadata results.

QG2: SA1-SA8 identify assumptions,dependent results and falsification probes.

QG3: Source ingress,plane updates,loop control,frame/register handoff and absence of new Mach emission are covered for this increment;the full objective remains active.

QG4: Byte counts,u32/u64 widths,32-step induction,16 mask cases,256 decoder cases and all access ledgers are reproducible.

QG5: The selected length domain,source alias assumptions,aggregate versus distinct bytes and pointer/register epochs are distinguished;whole algorithm and native effects remain unknown.

QG6: Original recapture,411 translated sites,17 UNSAT certificates,one abstract SAT check and five alteration controls establish scoped provenance.

QG7: Four impact-ranked continuation questions bound further work without assigning an unsupported standard primitive or native exchange.
