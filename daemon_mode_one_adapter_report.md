# Mode-1 private request, protected adapter and return-frame contract

The mode-1 helper at `0x100729920` builds a 48 B private request, calls adapter `0x100d03348`, and reaches protected core `0x100cf0194`. The core decodes private mode0x4923 and a size operand derived from u32[OBJ+0x58]. Its first predicate selects a processing frontier when the source pointer is NULL or that size is32 B; a nonnull source with any other size takes an immediate raw-result return. The source is OBJ+0x18, distinct from the previously staged first-key payload pointer. Application and cryptographic meanings remain unknown. [MA1-MA8]

The wrapper adjusts architectural SP by an adapter-returned delta. Its raw-result reload uses an original saved register base, but its continuation reload uses the adjusted SP. Equality with the original saved continuation cell therefore requires delta zero. On the immediate-rejection route, that zero delta follows under the stated bounded-fill,owner,guard and ordinary-return premises. Full32 B processing and its budget write history remain a frontier. [MA3-MA10]

Evidence: [original source,banks,fixups and assertions](triage_evidence/daemon_mode_one_adapter_source.json), [selected source/solver certificates](triage_evidence/daemon_mode_one_adapter_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_adapter.py), [validator](triage_evidence/validate_daemon_mode_one_adapter.py), [preservation](triage_evidence/daemon_mode_one_adapter_delivery.json), [quality gates](triage_evidence/daemon_mode_one_adapter_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_adapter_publication.py). Context: [first-key/mode-1 producer](daemon_outer_first_key_report.md), [outer object/local32](daemon_reader_outer_lifecycle_report.md), [original bank origins](daemon_constructor_bank_origins_report.md), [related A70 budget/frame distinction](daemon_xpc_error_outputs_report.md), [previous stack-probe ABI](daemon_descriptor_producers_report.md), [internal bounded fill](daemon_output_publication_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`;SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source |11 ranges,662 instructions,2648 B;includes full retained wrapper/adapter and core entry/rejection spans |
| Bank resolution |11 roles;2816 byte-input cases;27 original pointer records;nine branch/modifier matches;three resolved call sites |
| Structural assertions |20 exact instruction assertions cover frame extents,fill extent,guard branch and epilogues |
| Semantic coverage |281 selected instruction sites/instances,254 SSA definitions;remaining source is retained,not universally translated |
| Certificates |35 UNSAT queries;one SAT alignment-scope counterexample;six altered-ledger integrity controls |
| Prior source |38 ranges,10368 B freshly matched |
| Execution |No target/native execution,new CPU emulation,API/IPC request,IDA access,IDB edit or memory-folder update |

All VAs are unslid. Offsets/selectors/constants are hexadecimal;extents use B. K is wrapper SP before the call; OBJ is the outer object; C0=[OBJ+0]; SRC=OBJ+0x18; LEN=u32[OBJ+0x58]; LOCAL is the earlier reserved32 B record. R=K+0x10cb8 is the private request; DOUT=K+0xbe28 is its separate seed/delta word. Budget/seed arithmetic uses u64;request scalar codecs use u32. Host stores are little-endian. Pointer/offset arithmetic is modular unless native owner and no-wrap premises are stated. These are analytical roles,not public C types or recovered operation names.

## Entry and 48 B request [MA2-MA7]

The prior mode-1 producer derives W24=0x15db,W21=0x2486 and W9=0xd1a433c1. Setup0x10090151c forms SRC=OBJ+0x18 and length-cell address OBJ+0x58,loads LOCAL from K+0x2290,and derives actual incoming W10=0x9d05. Entry0x100729920 then reads C0 and LEN,and saves the original table[0x15db] continuation at K+0x2300. C0 NULL selects the direct saved-return relay with raw0x74c29d88;nonnull selects wrapper0x1009bb3b0. [MA2-MA6]

Let k be the source-derived u32 cookie for R. The exact caller fields are:

| R offset | Width | Stored value / site |
| --- | --- | --- |
|+0 |4 B |Result slot;not initialized by this wrapper;the core later writes it |
|+4 |4 B |Padding/unknown;no source definition assigned |
|+8 |8 B |C0 at0x1009bb3b4 |
|+0x10 |8 B |SRC at0x1009bb3e8 |
|+0x18 |8 B |LOCAL at0x1009bb3b8 |
|+0x20 |4 B |k+0xd1a433c1 at0x1009bb464 |
|+0x24 |4 B |k+0x4923 at0x1009bb460 |
|+0x28 |4 B |k+0x3e060fa6 at0x1009bb44c |
|+0x2c |4 B |k+LEN*0x4fabe741+0x1d89a59c at0x1009bb448 |

All scalar additions/multiplications in this table are modulo2^32. The cookie has the compact source form:

```text
r = low32(R)
k = u32(((2*(r AND482b0568) -r +37d4fa95) XORa1baa287) *592e2f77)
```

The protected core computes a separate address expression and subtracts its low32 cookie from request+0x24/+0x2c. Under 4 B alignment of R,source certificates establish equality with k,decoded mode0x4923,and decoded size operand LEN*0x4fabe741+0x1d89a59c. Ordinary16 B alignment of K makes R eight-byte aligned and supplies this sufficient premise. An abstract SAT counterexample rejects universal cookie equality over arbitrary unaligned addresses;it is not a target input or native observation. No minimum necessary alignment for every possible address is claimed. [MA3,MA4,MA7]

## Original adapter/core bindings [MA1,MA2,MA5,MA6]

| Boundary | Source site | Original selection |
| --- | --- | --- |
| Wrapper ->adapter |0x1009bb540 |Table0xce18 ->0x100d03348,IA0x2220;X0=R,X1=DOUT |
| Wrapper seed source |0x1009bb4d0 |Pool0x56b plus bias0xffffffff9b6579d5 ->global0x1010c4dd0;copy u64 to DOUT |
| Adapter controller A/B |Retained adapter prefix |Globals0x1010b7fb0/0x1010c4670 |
| Adapter LCG destination |0x100d034c4 |Same global0x1010c4dd0;source value V*0x2ea5+1 |
| Adapter ->core |0x100d03580 |Table0xce3c ->0x100cf0194,IA0x6e16;X0=R,X1=budget pointer |
| Core stack probe |0x100cf01c4 |Original `___chkstk_darwin` binding;requested extent0x11b0=4528 B |
| Core bounded fill |0x100cf042c |Original selected target0x10046faf8,IA0xac7d;destination coreSP+0x768,value0,extent0x128=296 B |

Both opaque-controller selectors and bank arrays are pinned to the original image. All256 possible selector bytes per role are checked,not guessed from one controller value. This resolves selected static bindings;it does not identify evolved native global state,prove native PAC acceptance or perform a call. The unauthenticated `___stack_chk_guard` binding is decoded separately from authenticated function pointers. [MA1,MA2,MA5,MA6]

## First core predicate and immediate result [MA3-MA8]

The core's aligned request decoder supplies W19=0x4923 and W20=LEN*0x4fabe741+0x1d89a59c. Its next source normalization is:

```text
N = u32(W20*7aa4a8c1 +0d8e5924)
  = u32(LEN +16f293c0)
because u32(4fabe741*7aa4a8c1) =1.
```

A separate universal source lemma proves that the following mixed Boolean/arithmetic expression equals comparison constant0x16f293e0 exactly when N equals that constant. Thus the compared size condition is exactly LEN=32 B. The wrapper-through-predicate monolithic diagnostic timed out;it is excluded from accepted evidence. The successful component queries prove the same claimed predicate through explicit source-linked cuts. [MA7]

The CCMP fallback matters: with SRC NULL,the fallback NZCV=4 supplies equality. The exact local routing is:

| Condition | Target / consequence |
| --- | --- |
|SRC==NULL OR LEN==32 B |Index0x8ed9 ->0x100d5dfc8,processing frontier |
|SRC!=NULL AND LEN!=32 B |Index0x4923 ->0x100d7cc50,immediate raw0x74c29dee result |

For this outer-object caller,SRC=OBJ+0x18 is nonnull under the valid-object/no-wrap premise. The corresponding normal processing condition reduces to LEN=32 B. The generic NULL case is recorded without assigning its later outcome. This is an internal source-pointer/size contract;it is not the first-key span length P at K+0xf7c. A relation between LEN/SRC and that staged span remains unknown. [MA3,MA4,MA8]

At0x100d7cc54 the immediate path writes raw0x74c29dee to R+0 before checking the saved/live stack guard. Equal guards select the retained epilogue;unequal guards reach BL0x100d7cc94 ->stack-failure stub. Result publication therefore does not itself establish an ordinary return. Raw error names and the processing body's application purpose remain unknown. [MA4,MA6-MA10]

## Budget,stack and distinct return-cell epochs [MA3-MA10]

The wrapper copies arbitrary u64 global seed V to DOUT before calling the adapter. The adapter subsequently reads that local copy,updates the separate global LCG destination,and constructs its budget. It does not use the updated global value as the initial budget V. [MA3,MA5]

```text
adapter fixed frame A = K -64 B
L = u64(V*2ea5 +1)
reserve =16 B*((L >>60)+1)                  #16..256 B
BP = A -reserve
*BP = u64(V -144 B)                        #adapter budget initialization
*BP = u64(*BP +144 B)                      #core entry update
core frame J = BP -4624 B                  #96 B saves +4528 B locals
Q = low32(returned budget)
delta =16 B*low16(Q -low32(V))             #0..1,048,560 B
*DOUT = delta
```

The adapter restores its own fixed frame through FP and returns with wrapper SP K. The wrapper then independently applies delta at0x1009bb56c/570. The source values here are integer cursor/budget encodings measured in byte offsets;they are not elapsed time or observed native stack extents. Explicit adapter/core reservations total4704..4944 B relative to K,excluding nested helper/probe use and their guards. [MA3-MA7]

| Wrapper post-call access | Address / significance |
| --- | --- |
|0x1009bb564 |Load delta through preserved X19=K+0xb000,thus from original DOUT=K+0xbe28 |
|0x1009bb570 |SP := K+delta |
|0x1009bb574 |Load raw u32 result through preserved X24=K+0x10000,thus from original R=K+0x10cb8 |
|0x1009bb578 |Load continuation from adjusted SP+0x2300 =K+delta+0x2300 |
|0x1009bb57c |Original table0x6358 ->relay0x10068b47c |
|0x10068b480 |BRAA through the loaded continuation with IA0x3275 |

Numeric equality of the continuation address with its original saved cell K+0x2300 holds exactly when delta=0. A different address might coincidentally contain an equal pointer,but no such value/owner/PAC claim is established. In contrast,the result read remains anchored to R through X24 for ordinary callee-preserved registers. [MA3,MA4,MA6]

For the immediate rejection route,source entry's -144/+144 budget operations cancel. Its remaining pre-return core stores concern image-controller cells,core locals and R+0. The only retained internal call is the bounded296 B fill. The exact fill range is `[J+0x768,J+0x890)`,below BP;an arbitrary-index certificate proves it does not overlap any of BP's eight budget bytes. Under normal bounded fill,disjoint stack/image/request owners,no concurrent budget writer and equal guard,Q=low32(V),hence delta=0. This is a conditional path composition,not a complete interprocedural memory theorem for all paths. [MA3-MA8]

With delta zero,the saved continuation is original slot0x15db ->0x100911fe0. Its saved-frame constants route exact result0x8b3dc651 to table0xa1da ->0x10084fbc4,and every other result to table0xb9a ->common outer result staging0x100975d34. The immediate raw0x74c29dee therefore takes the latter. The32 B processing route's later budget/result effects are unknown;matching frame offsets alone cannot establish its return join. [MA3,MA6-MA10]

## Coverage and provenance limits

The extractor retains all662 original instructions in the eleven spans,all selected fixup/bank inputs,and twenty exact structural assertions. The validator translates281 selected instruction sites into SSA for field construction/decoding,normalization,predicate,budget,delta,result/continuation addresses and raw-result staging. It does not claim universal translation of all prologue/epilogue,controller side-effect or processing instructions. Fixed frame equations additionally use the asserted original stack instructions;register restore,imported stack-probe normal return and hardware PAC remain explicit premises. [MA1-MA7]

The new selected call chain has no recovered Mach/IOKit emission site. Its external imports in the retained core boundary are stack-probe/guard facilities;the fill target is an internal routine. This does not exclude transport in deeper processing or other callers. Native daemon-kext exchange remains unproved. [MA9,MA10]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| MA1 |Original thin-image identity and captured ranges;all source claims |Rehash original and byte-compare every span;pointer format and original import decoding are independent checks |
| MA2 |Actual selected mode1 phases and original bank/table roots;static bindings |Derive incoming registers from prior setup,check2816 byte cases and all selected pointer/modifier records;native mutable roots/PAC remain unknown |
| MA3 |One correctly identified wrapper frame,valid R/DOUT/OBJ/LOCAL owners and saved-base continuity |Audit escaped aliases and omitted writes;use the explicit K versus K+delta address equations instead of equating offsets |
| MA4 |Live mapped pointers,source nonnull under valid OBJ,no invalid wrap and required alignment |Ordinary SP alignment implies sufficient R alignment;SAT check rejects an arbitrary-address cookie theorem;native mappings/lifetimes remain unknown |
| MA5 |Controller/seed cells are the selected original globals and are separate from live stack/request owners |Match original biased pool selections and bank roots;do not substitute file-initial seed values for arbitrary evolved V |
| MA6 |Ordinary adapter/core/import/fill return,callee-preserved bases,equal guard and successful PAC |Retain source calls and epilogues;guard mismatch publishes result before failure;normal native return is not inferred from a store |
| MA7 |Exact u32/u64 codecs and source-cut composition |35 accepted queries pin fields,aligned cookie,normalization,predicate and frame algebra;exclude the timed-out monolithic query and reject solver errors/unknowns |
| MA8 |Immediate-route bounded fill and no additional relevant budget/owner mutation |Disjoint296 B fill versus budget proof,original immediate return stores and image/stack separation support the conditional zero-delta result;full32 B path remains unproved |
| MA9 |No application,cryptographic,authorization or port semantics inferred from private mode/key/size |Require deeper producer/consumer evidence;request mode4923 and32 B size alone do not identify an algorithm or external operation |
| MA10 |Static paths remain distinct from historical guest trace/native delivery |Preserve original trace and prior reports;no native call,success,port identity or daemon-kext delivery is supplied by these certificates |

## Bounded next investigations

| Impact | Follow-up | Discriminating evidence |
| --- | --- | --- |
|High |Follow processing0x100d5dfc8 and return result/budget writers |Determine the actual32 B operation,its C0/key/LOCAL use and whether delta remains zero on normal processing |
|High |Join object source OBJ+0x18/count OBJ+0x58 to their initializers |Establish actual byte provenance and any relationship to the first-key span staged at K+0x58a0/0xf7c |
|High |Audit request fields+8/+0x18/+0x20/+0x28 through later core consumers |Recover collection/output/key/auxiliary roles rather than assigning a public ABI from record size |
|Medium |Complete the controller side-effect and stack-probe/guard memory composition |Discharge current import/owner/normal-return premises without assuming native image/cache pairing |
|Medium |Follow successful outer continuation0x10084fbc4 |Establish whether mode1 eventually rejoins optional/N19 paths or selects a separate object operation |
|Low |Reuse exact delta/address equations at analogous adapters |Parameterize per-adapter biases/multipliers;similar shape does not imply identical records or callee semantics |

QG1: No normative judgment is required;the deliverable is a source and ABI analysis.

QG2: MA1-MA10 state assumptions,dependent claims and falsification probes.

QG3: The increment covers the mode1 object/local inputs,48 B request,alignment-sensitive cookie,protected call bindings,size predicate,immediate result,stack/budget accounting and conditional caller return. All respective reports and the status index are updated;the broad objective remains active.

QG4: Byte units,modular widths,field extents,alignment,frame inverses and delta bounds are explicit. Fixed source-span validation is O(source bytes+fixups+256*bank roles+recaptures);selected translation is O(translated instructions). SMT complexity and deeper runtime complexity are not assigned linear bounds.

QG5: Actual request padding remains unknown;aligned and arbitrary-address domains differ;SRC/LEN are distinct from staged first-key span fields;result and continuation use different frame bases;immediate and32 B processing budget histories are separated;guard failure differs from ordinary return.

QG6:Original source,27 pointers,nine selected branch matches,three call bindings,2816 bank cases,twenty structural assertions and38 recaptures support the scoped claims.35 queries return UNSAT;one SAT alignment check is separate. Six altered-ledger controls reject changes. The timed-out monolithic diagnostic is excluded;coverage is281 selected sites,not all662 source instructions.

QG7: The impact-ranked follow-ups remain bounded to semantic,owner,frame and return interfaces. No new Mach emission,native execution,transport success or full-goal completion is claimed.
