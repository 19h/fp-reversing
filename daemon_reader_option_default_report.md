# Keyed u32 option, context default and N19 admission

The source reads an optional u32 record from the first child collection and uses its decoded value as the N19 discriminator F. Caller0x1008b35a4 supplies encoded key0xf24be74b, CELL=OBJ and OUT=&K[0x53ac] to the established typed scalar accessor. Exact success preserves the published value. Only the exact missing-key marker computes the fallback `M-0x1d45dafb mod2^32`, where M=u32[OBJ+0x10]. Every other raw accessor result selects error staging. [OD1-OD7]

This expands the selected context-default route in the [nested-input report](daemon_reader_nested_input_report.md). Header equality is not a requirement for every N19 caller covered by these branches. Under the validated accessor, nested-record and stable-frame premises, the complete local selection rule is:

```text
accessor exact success: F = decoded u32 record value V
accessor exact miss:    F = M -1d45dafb mod2^32
other accessor result: error staging; no selected nested admission

N19 admission = (success AND V==0)
            OR (exact miss AND M==1d45dafb)
```

The flag low bit chooses between alternate continuations when the selected F is nonzero; it does not change the zero/nonzero admission rule. A successful explicit zero option permits the selected N19 path with a nondefault M. This is a private record/control interface, not an authorization, vulnerability or native-reachability finding. [OD3-OD8]

Evidence: [original source, pointers, caller locator and recaptures](triage_evidence/daemon_reader_option_default_source.json), [22 new and107 replayed UNSAT certificates, one interpretation counterexample and six controls](triage_evidence/daemon_reader_option_default_checks.json), [extractor](triage_evidence/recover_daemon_reader_option_default.py), [validator](triage_evidence/validate_daemon_reader_option_default.py), [preservation](triage_evidence/daemon_reader_option_default_delivery.json), [scoped gates](triage_evidence/daemon_reader_option_default_quality_gates.json), [independent publication audit](triage_evidence/verify_daemon_reader_option_default_publication.py). Adjacent contracts: [complete typed u32 reader](daemon_existing_scalar_reader_report.md), [accessor entry and raw relays](daemon_scalar_field_population_report.md), [first-match lookup](daemon_constructor_lookup_report.md), [nested span into N19](daemon_reader_nested_input_report.md), [outer object/publication](daemon_reader_outer_lifecycle_report.md).

| Evidence | Verified scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source |18 branch-terminated ranges,326 instructions,1304 B;zero SP writes |
| Translation |All308 nonbranch instruction sites;325 translated instances,297 SSA definitions |
| Metadata |26 original pointer records;28 selected branch slot/modifier matches |
| Prior source recapture |66 ranges,11672 B;accessor,lookup,word/tag reader and return source |
| Certificates |22 new and107 replayed UNSAT queries;one SAT interpretation counterexample;six altered-ledger controls |
| Locator |One exact `ADD X11,X11,#3ac` word in3,712,490 aligned text words;not a complete address/alias search |
| Execution |No native/target execution,new CPU emulation,FairPlay API/IPC,IDA access,IDB or memory writes |

Addresses are unslid VAs. Offsets,selectors and constants are hexadecimal; extents use B. K is shared-frame SP; OBJ is the outer object value saved at K+0x1ae8; COLL=[OBJ+0]; M=u32[OBJ+0x10]; V is a decoded big-endian wire u32 published as a host u32; F is u32[K+0x53ac]. Host memory stores are little-endian. Arithmetic wraps at u32/u64 width unless a bound is stated. These are analytical roles, not public Apple types or original routine names.

## Two captured predecessors produce the actual accessor phase [OD2-OD5]

An antecedent raw-result component0x100781014, under incoming W8=0xb9a, recognizes exact low32 marker0x74c29ded. It derives W9=0x7b40,W22=0x6cf4 and selects0x43ec ->0x100861958. Other markers use a different continuation; the complete producer of that antecedent result is outside this new certificate.

The following two branches identify concrete producers of W10=0x935, previously a candidate private accessor return selector:

| Condition after the antecedent exact miss | Source path | Accessor entry consequence |
| --- | --- | --- |
| u8[OBJ+0x61]!=0x25 |0x100861958 ->index0x7b40,IA0xdcf1 |0x1008b35a4 with W10=0x935 |
| u8[OBJ+0x61]==0x25 and u32[OBJ+0x14]==0 |0x100861958 ->0xbb19 ->0x100864a48 ->0xa656,IA0xd1e2 |Same caller,also W10=0x935 |
| u8[OBJ+0x61]==0x25 and u32[OBJ+0x14]!=0 |0x100864a48 ->0x62f8 |Different frontier with raw0x74c29d72;not this accessor call |

No application-specific meaning is assigned to the byte or word. A third original incoming caller slot0xab4b,IA0x30e7, also points to0x1008b35a4; its predecessor is not joined here. The source equations at this caller are checked for W10=0x935, with two actual predecessor producers, rather than extrapolated to all callers or modes.

## Optional scalar record and the F output cell [OD2-OD7]

| Site | Exact private contract |
| --- | --- |
| 0x1008b35a8 | Load OBJ/u64 from K+0x1ae8 into X8;CELL=OBJ |
| 0x1008b35b0..0x1008b35c8 | Derive W22=0x6cf4,key W9=0xf24be74b;index0x3b01 ->0x100847998,IA0x5722 |
| 0x1008b35cc..0x1008b35d0 | X11=K+0x53ac,the borrowed F output-cell address |
| 0x10084799c | Accessor reads COLL=[CELL]=[OBJ+0] |
| 0x1008479a4 /0x1008479a8 | Resolve return selector0x935 ->0x100736108;save CONT at K+0x7af0 |
| 0x1008479ac | Save F-cell address at K+0x4ca0 |
| 0x1008479b0 | Zero matched-node output cell K+0x59b0 |
| 0x100506a18..0x100506a30 | Successful typed reader converts the staged XOR representation and writes V/u32 through [K+0x4ca0],thus to K+0x53ac |
| 0x1006f76a8..0x1006f76b0 | Load saved CONT;relay the full raw X6 unchanged,IA0x90ec |

The encoded identifier corresponds to decoded wire key0x7976211a under the established XOR0x8b3dc651. Its application meaning remains unknown. The complete prior accessor contract recognizes wire tag0x9777/private reader tag0xd0ee and exactly4 B of payload under its header/extent-fit requirements. It publishes the decoded BE32 value V as a host u32; it does not publish the constructor's internal XOR operand as F.

The null collection and lookup-miss paths do not publish a value through the borrowed output cell. Found-node/record validity, stable key matching and normal return remain premises. The source saves OUT before checking COLL; that store alone is not initialization of F. The exact-miss arm below supplies a default instead of consuming an unproved old F value.

## Complete local raw-result routing [OD3,OD5-OD8]

The actual saved continuation0x100736108 derives W10=0x4ee7 from the shared phase and selects0x84ca ->0x1006c4600. That block uses a signed32 split on RESULT versus0x74c29ded while carrying W8=W9=0x445a. The following exact-marker gates complete the local partition for every u32 RESULT:

| Raw low32 RESULT | Route | Effect on F before nested child lookup |
| --- | --- | --- |
| 0x8b3dc651 |0x4f26 ->0x10093c438 ->0xb17d ->0x1008cf6cc |Preserve the decoded scalar V published by the successful accessor |
| 0x74c29ded |0x4ee7 ->0x1006a9e90 ->0x4979 ->0x1006bf434 |Write `(M-0x1d45dafb) mod2^32` at K+0x53ac |
| Every other u32 |One of the same exact-marker gates ->0x445a ->0x100975d34 |Stage RESULT at K+0x5f60;select outer error/cleanup arm0xc04f |

On success,0x1008cf6cc derives selector0x2122 and loads OBJ into X8. It writes no memory. On exact miss,0x1006bf434 uses the actual W9=0x2122 produced by0x1006a9e90, derives phase0x6cf4 and writes the context default. Both select0x2122 ->0x1006ab91c,IA0xbad2. Thus the prior isolated W9=0x2122 premise is now joined to this real missing-option status route.

The head setup reads COLL=[OBJ+0],zeros K+0x3be0 and stages its cursor at K+0x4890. A separate byte-array certificate composes the exact4 B little-endian F store with these two8 B frame stores and proves the subsequent F read preserves every option bit. It does not establish native mappings,arbitrary intervening aliases or concurrency safety.

Raw0x74c29d8f from an invalid scalar record,raw0x74c29cd6 from a recognized alternate type,and raw0x74c29d88 from the null path all belong to the error class in this local routing. Names describe their established source roles; no public error enum is assigned. Complete cleanup,final status consumption and an external return remain outside this increment.

## Selected record value overrides the context-derived default [OD3,OD6-OD9]

The [nested-input contract](daemon_reader_nested_input_report.md) supplies the following second record from COLL: encoded key0x7615e796/decoded identifier0xfd2821c7,recognized span type,borrowed pointer BUF+10,encoded extent `P XOR0x8b3dc651` and exact bound P+10<=SIZE. Its span branch produces W12=0x4b1d before reading F.

For either continuing accessor result,the selected F is therefore:

```text
Fselected = (RESULT==8b3dc651) ? V : (M-1d45dafb mod2^32)
```

This expression is used only under RESULT==0x8b3dc651 OR RESULT==0x74c29ded. The two N19 gates admit exactly Fselected==0. A nonzero selected value goes to an alternate frontier chosen by the flag low bit. On admission,the caller supplies the same OUT=OBJ+8 and nested buffer/extent cells as previously recovered.

| Collection/context case | Selected F | Selected N19 admission |
| --- | --- | --- |
| Valid successful option record,V=0 |0 |Yes,for arbitrary M and either flag lowbit |
| Valid successful option record,V!=0 |V |No;alternate frontier |
| Exact option-key miss,M=0x1d45dafb |0 |Yes,for either flag lowbit |
| Exact option-key miss,M!=0x1d45dafb |Context subtraction |No;alternate frontier |
| Any other accessor result |Not consumed by this selected path |Error staging |

A SAT interpretation counterexample combines exact accessor success,V=0 and M!=0x1d45dafb with the actual N19 selector. It refutes a universal header-equality requirement across these routes. It is an abstract source model,not a generated target packet,observed request,access-control bypass or native behavior claim.

The resulting conditional data graph has two distinct record roles in COLL: the u32 option selects F,while the span record supplies N19's input bytes. OBJ+8 receives the separately allocated N19 list container under its established successful return contract. Source provenance of COLL's original producer and attribution to an external caller remain unresolved.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OD1 |Pinned original daemon/address map;all source results |Rehash image and recapture1304 B new plus11672 B prior source;any mismatch rejects the increment |
| OD2 |Original dispatch/fixup roots match;selected calls and returns |Independently decode26 pointers and28 slot/modifier matches;actual PAC/table state remains a separate check |
| OD3 |One stable K epoch and saved F/OUT/OBJ/CONT cells;option/default composition |Find an intervening overlapping write,frame change or alias;the byte-array proof covers only its named exact stores |
| OD4 |Live valid disjoint collection,node,record,object/frame owners;accessor memory use |Verify concrete extents/lifetimes and aliases;returned marker alone does not establish native ownership |
| OD5 |Antecedent entry W8=b9a and selected phase6cf4;two caller producers |Trace actual upstream definitions and the unjoined0xab4b edge;another mode invalidates the selected constant targets |
| OD6 |Replayed first-match and complete scalar accessor contracts;success V and exact miss semantics |Recapture code and replay107 scoped queries;unstable list/key/frame state or a different return contract breaks applicability |
| OD7 |Matching scalar record remains stable until its value output;V reaches F |Check typed tag/extent and saved output address;success must mean the proved scalar publication,not transport success |
| OD8 |Nested span input and actual phase4b1d contract applies;F controls the selected N19 call |Verify that key0xfd2821c7's matched buffer/extent and saved F reaching definitions join in the same epoch |
| OD9 |Source format/control roles do not imply actor/authorization meaning;interpretation limits |Trace the collection producer to an actual external interface before attributing control to any process or peer |
| OD10 |Original emulator trace remains unchanged;native pairing boundary |Rehash it and distinguish transport success from failed user-client open;require separate successful native exchange evidence |

## Bounded interface continuation and Mach-port context

No captured component emits a Mach message or produces a numeric Mach-port right. The new interfaces are local borrowed cells,record lookups,value publication and authenticated internal branches. The [Mach-port inventory](mach_ports_report.md) retains the separate send/emission evidence. No port or IOKit connection identity follows from OBJ,COLL,BUF or F.

The supplied annotated trace remains at SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. Its user-client-open result0xe00002c2/NULL connection still does not establish a successful selector26 or RPC502/700 daemon-kext exchange. The new option/default rule adds static data/control lineage rather than runtime observations.

| Impact | Remaining question | Evidence required |
| --- | --- | --- |
| High |Original COLL/option/span producer and external origin |Join both decoded keys to the first-child parser's input and actual outer caller/API arguments |
| High |Third option-caller edge0xab4b |Recover its predecessor and actual W10 mode;do not assume the two captured antecedents exhaust callers |
| High |Nonzero F alternate behavior |Recover both alternate-frontier consumers and their object/buffer/result contracts without assigning a policy meaning from the predicate alone |
| High |External result and daemon-kext exchange |Trace OBJ's final output consumer/serializer and correlate a successful user-client connection,selector/status and reply identity |
| Medium |Context byte0x61/word0x14 producer |Complete context copying and instance identity before calling these public modes or required-field rules |
| Medium |Cleanup and borrowed record lifetime |Join all error markers,partial N19 containers and final result recovery;establish owner stability through return |
| Low |All semantic F-cell address producers |Expand the exact one-word locator to computed/memory-derived aliases and actual frame epochs |

Complexity: main source recovery/translation is O(I),I=326 instructions;308 distinct modeled nonbranch sites and325 translated instances. The exact-word locator is O(N) time and O(H) retained memory for N=3,712,490 aligned text words and H=1 hit. SMT complexity is solver-dependent; each query has a15000 ms timeout and20000 ms subprocess limit,with unknown/timeout rejected. The byte-array certificate models4 B plus two8 B stores. Publication validation is O(total logical artifact bytes+links),with memory bounded by the manifest and largest decoded JSON/report. Artifact SHA-256 and lengths describe decoded contents if canonical JSON resides in `.json.zst` after archival migration.

## Scoped quality gates

QG1: Factual source/interface analysis;no normative judgment is required.

QG2: OD1-OD10 list assumptions,dependent results and falsification probes.

QG3: This increment covers keyed scalar input,actual caller/return phases,exact raw-result routing,default/store preservation and selected N19 admission. The broad cross-layer goal remains active and incomplete.

QG4: u32/u64 widths,wire/host endian,modular subtraction,exact store extents,source coverage and solver/algorithm bounds are reproducible.

QG5: Explicit value versus fallback default,antecedent versus option-key absence,selected versus universal header equality,raw result versus transport status,and source control versus external actor meaning remain distinct.

QG6: Original bytes/fixups,22 new/107 replayed certificates,six altered-ledger controls and unchanged trace are checked. The scope counterexample is labeled abstract.

QG7: High/medium/low continuation questions are bounded and source-linked. Native caller/owner/PAC/peer identity,complete parser/cleanup,external delivery and successful daemon-kext pairing remain unproved.

## First-child producer follow-up

The [outer wire-ingress report](daemon_outer_record_ingress_report.md) now identifies a conditional producer of the OBJ+0 collection consumed by this accessor. The selected caller passes saved INPUT and encoded u32 length to parser0x1006997a4 with OUTcell=OBJ. Its plain header and typed payload operands feed the shared constructor;successful publication stores C0 at OBJ+0. The omitted upstream route and stable frame/owner identity remain assumptions. A zero-ID span may terminate before exhaustion;no native delivery or daemon-kext association follows from this local producer.
