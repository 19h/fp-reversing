# First-child key lookup, missing-key option bridge and found-span mode contract

The first operation after successful C0 publication queries encoded key `0xd719dce3`, corresponding to decoded wire identifier `0x5c241ab2`. Caller `0x10066e5b0` supplies C0 and matched-node output cell K+0x1de8 to the established first-match lookup. Its actual saved return selector is 0x12d9. The recovered result tree connects an exact missing-key result to the previously established optional u32 discriminator. A found record instead enters a typed-record accessor: only a fitted span continues normally, and its next helper requires mode u32[OBJ+0x14] equal to one. [FK1-FK8]

This removes two former source-control premises: the origin of W8=0xb9a at the optional-discriminator antecedent, and the source of the first-key lookup's collection/caller phases. It does not establish native caller/owner identity or all memory effects through omitted callees. The mode-1 helper remains a deeper frontier; no claim is made that its later control cannot rejoin another path. [FK2-FK10]

Evidence: [source, pointers, preparation and recaptures](triage_evidence/daemon_outer_first_key_source.json), [source/solver certificates and integrity controls](triage_evidence/daemon_outer_first_key_checks.json), [extractor](triage_evidence/recover_daemon_outer_first_key.py), [validator](triage_evidence/validate_daemon_outer_first_key.py), [preservation](triage_evidence/daemon_outer_first_key_delivery.json), [scoped quality gates](triage_evidence/daemon_outer_first_key_quality_gates.json), [publication audit](triage_evidence/verify_daemon_outer_first_key_publication.py). Parent and consumer contracts: [outer wire ingress](daemon_outer_record_ingress_report.md), [generic first-match lookup](daemon_constructor_lookup_report.md), [complete scalar/tag reader](daemon_existing_scalar_reader_report.md), [option/default selection](daemon_reader_option_default_report.md), [nested input into N19](daemon_reader_nested_input_report.md), [outer lifecycle and local32 record](daemon_reader_outer_lifecycle_report.md).

| Evidence | Verified scope |
| --- | --- |
| Thin original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| New retained source |35 branch-terminated ranges,671 instructions,2684 B |
| Shared preparation |386 instructions,1544 B; captured separately and freshly matched |
| Translation |1021 distinct non-transfer sites;1432 instances,1282 SSA definitions |
| Pointer metadata |53 original pointer records;53 selected branch-slot/IA-diversity matches |
| Prior original-byte recapture |120 ranges,23184 B |
| Certificates |41 new and58 replayed UNSAT;one SAT scope check;six altered-ledger controls |
| Execution boundary |No target/native execution,new CPU emulation,IPC/API requests,IDA access,IDB edits or memory-folder writes |

Addresses are unslid VAs. Offsets/selectors/constants are hexadecimal; extents use B. K is shared-frame SP; OBJ is the outer object saved at K+0x1ae8; C0=[OBJ+0]; NODE is the matched node; BUF=[NODE+0x18]; SIZE=u32[NODE+0x10]. MODE=u32[OBJ+0x14], FLAG=u8[OBJ+0x61]. P is decoded payload extent. T is the private reader tag, equal to wire BE16 tag XOR0x4799 under the prior tag-reader contract. Host scalar stores are little-endian; wire record fields are big-endian. Arithmetic is modulo the declared u16/u32/u64 width unless bounded otherwise. These are analytical roles, not recovered original names or public Apple types.

## Publication to the first-match lookup [FK2-FK7]

| Site / selected edge | Exact private contract |
| --- | --- |
|0x100758af0 |Store the parser's C0/u64 through OUTcell=OBJ, writing OBJ+0 |
|0x100758b1c ->0x188e |Selected success phase reaches saved parser return0x1008c8b80 |
|Saved selector0x1649 |Original target0x1008b3a7c; exact parser success selects0xc6db ->0x10069a00c and derives W9=0xa80a |
|0x10069a01c/020 |Reload OBJ then C0=[OBJ+0] |
|0x10069a024/038 |Clear matched-node cell K+0x1de8; initialize encoded cursor C=0x7f76f633d66f61c6 at K+0x6468 |
|0x10069a058 |C0!=0 ->0xa80f/lookup caller0x10066e5b0; NULL ->0xa80a/error staging |
|0x10066e5b0..5e8 |Derive phase0x6cf4, encoded key0xd719dce3, OUT=&K[0x1de8], return selector0x12d9; index0x18e2 ->shared lookup0x1006fd1b8 |
|0x1006fd1c4/1cc/1d0 |Save continuation at K+0x7060, key/u32 at K+0xaa5c and OUT address at K+0xaa60 |

The captured parser return and outer-return components contain no intervening store between publication and the head read. An exact byte-array certificate proves that the published eight bytes reload as the same C0. Stable OBJ/frame identity and nonaliasing of the heap publication with the frame remain premises; this is not a whole-process alias or lifetime proof. [FK3,FK4]

The shared lookup contract follows C0's head and node links, decodes candidate identifiers and publishes the first matching NODE or NULL on finite exhaustion. Its complete source and accepted decoder/lookup certificates are recaptured/replayed. Cycles, concurrent mutation, native PAC acceptance and invalid owners remain outside that contract. The key's application-level meaning is unknown. [FK4-FK8]

## Exact missing-key bridge to optional F selection [FK2-FK8]

The saved lookup continuation0x12d9 names `0x1008949cc`, which selects0xc92d ->`0x100939f18`. The latter derives W8=0xb9a and W10=0x445a, then partitions raw low32 RESULT using signed RESULT>0x74c29dec. This is the actual phase producer formerly assumed at `0x100781014`.

| Result class | Selected source path |
| --- | --- |
|Exact missing-key marker0x74c29ded |0x3613 ->0x100781014 ->0x43ec/0x100861958 |
|Other RESULT in that signed upper partition |0x100781014 ->0xb9a/common outer error staging |
|Exact found marker0x8b3dc651 |0x3610 ->0x1006fd600 ->0x7228/matched-record access |
|Other RESULT in the signed lower partition |0x1006fd600 ->0x445a/common outer error staging |

For an exact miss, the next routes are:

| Context condition | Consequence |
| --- | --- |
|FLAG!=0x25 |Directly selects0x7b40 ->option caller0x1008b35a4 |
|FLAG==0x25 and MODE==0 |Via0xbb19/0x100864a48, then0xa656 ->same option caller |
|FLAG==0x25 and MODE!=0 |Different error frontier with raw0x74c29d72 |

Both continuing arms derive the actual W10=0x935. The caller supplies encoded option key0xf24be74b, CELL=OBJ and OUT=&K[0x53ac] to the typed u32 accessor. Its downstream contract is unchanged: exact success selects the decoded u32 value V as F, exact miss selects F=u32[OBJ+0x10]-0x1d45dafb, and other statuses select error. [FK3,FK6-FK8]

On this particular missing-first-key route, the established selected N19 admission condition therefore composes as follows, subject to the separate nested-record lookup/span/owner premises:

```text
FIRST_RESULT == 74c29ded
AND (FLAG != 25 OR MODE == 0)
AND ((OPTION_RESULT == 8b3dc651 AND V == 0)
     OR (OPTION_RESULT == 74c29ded AND M == 1d45dafb))
where M = u32[OBJ+10].
```

This is a conditional composition with the prior option/N19 certificates. It does not assert that all native N19 callers require a first-key miss, or that the newly exposed mode-1 helper cannot later rejoin N19. [FK3,FK6-FK10]

## Found record: encoded-header and span selection [FK3-FK8]

`0x1008b4120` loads NODE from K+0x1de8, BUF from NODE+0x18 and SIZE/u32 from NODE+0x10, and saves BUF at K+0x1b20. NULL BUF selects error. Minimum gate0x100852344 requires SIZE>9 and saves zero-extended SIZE at K+0xae08 and the encoded cursor C at K+0xae10.

| Reader stage | Actual argument / continuation |
| --- | --- |
|Header word setup0x10089811c |BUF, offset key0x661a590b302baf96, dispatch0x8c3f, return selector0xf1 |
|Shared preparation0x1006f6bf0 |Preserves actual BUF/key/selector; sets first-round key0x324a764c67af2e0e; eager frame reads remain storage premises |
|Word return0x100609488 |Tag input uses BUF cell K+0x1b20 and encoded-cursor cell K+0xae10; actual byte offset is4; return selector0x208 |
|Tag return0x100538e08 |Save T/u16 at K+0x9bee; length key from K+0x908; return selector0xf4 |
|Prepared length key |Actual AE10 load N9 at0x1006f6ed0 gives key0x661a590b302baf9c, exactly offset6 |
|Word caller0x100530d34 |Reload BUF; reuse established first-round key; invoke word decoder with selector0xf4 |
|Extent0x1005cf4c8 |Both decoder outputs imply the exact gate u64(P)+10<=u64(SIZE) |
|Fitted return0x100611778 |Encoded end=C+P+10; payload offset10; unsigned u16 T loaded from K+0x9bee |

The complete obfuscated fit comparison, including its conditional-select/overflow-looking arithmetic, is translated. The resulting gate uses zero-extended u32 P and SIZE, so P+10 does not overflow u64. Fit implies P<SIZE and P<=0xfffffff5; BUF's native mapping, pointer wrap, ownership and lifetime are separate premises. [FK4,FK7]

The following signed-tag tree differs from the outer wire parser's constructor admission:

| Private reader T / wire tag | Local behavior |
| --- | --- |
|0xc31c /0x8485 |Recognized scalar64 alternative; stage end and encoded P, then raw0x74c29cd6/error staging |
|0xd0ee /0x9777 |Recognized scalar32 alternative; same raw-status behavior |
|0x1742 /0x50db |Only normal continuation into span staging |
|Every other T |Error staging, without this normal span continuation |

This accessor does not decode a scalar value or require P=4/P=8 on its recognized scalar alternatives. Importing the complete scalar-value reader's size grammar here would misdescribe the source. The distinction matters even though the outer wire parser and constructors accept these same wire tags for their own roles. [FK6,FK7]

## Span outputs, mode gate and next helper [FK3-FK8]

For a fitted span, `0x1005a55d0` stages:

| Site / frame cell | Exact value |
| --- | --- |
|0x1005a55e8 ->K+0x6468 |Encoded end C+P+10 /u64 |
|0x1005a55ec ->K+0xf7c |Encoded payload extent P XOR0x8b3dc651 /u32 |
|0x1005a55f0 ->K+0x58a0 |Borrowed BUF+10 /u64; no payload copy here |
|0x1005a55f4 |OBJ ->X19 |
|0x1005a55f8 |MODE=u32[OBJ+0x14] ->W8 |

The next exact local partition is:

| MODE | Behavior |
| --- | --- |
|1 |Select0x5fe6 ->0x1005b0494, then helper setup0x10090151c and entry0x100729920 |
|0, FLAG==0x25 |Error staging with raw0x74c29d77 |
|0, FLAG!=0x25 |Error staging with raw0x74c29dee |
|Every other u32 pattern, including signed-negative values |Error staging with raw0x74c29dee |

The first signed comparison splits MODE>=1 from the remaining values; exact equality tests then select mode1 or mode0. Mode0's flag component always branches to error. Thus normal continuation through this captured found-span branch is exactly MODE==1. The SAT interpretation check separately exhibits a fitted span/mode0 state selecting error; it constructs no target input or native transaction. [FK6-FK10]

The next helper's exact entry interface is source-grounded, but its application role remains unknown:

| Entry0x100729920 operand | Source |
| --- | --- |
|X8 |OBJ |
|W9 |Private constant0xd1a433c1; no public operation meaning assigned |
|X20 |LOCAL loaded from K+0x2290, the previously reserved32 B outer local record |
|X11 |OBJ+0x18, formed at0x100901524 |
|X12 |OBJ+0x58, formed at0x100901528 |
|W24 |0x15db |
|Selected original pointer |Table index0x2486 ->0x100729920,IA0x844f |

The setup derives additional frame constants and register seeds, retained in the source/translation ledger. The staged span at K+0x58a0/0xf7c is a distinct interface from the object/local arguments above. This increment does not prove which of these fields the deeper helper consumes, how it returns or what it produces. [FK3,FK6-FK9]

Error staging0x100941a74 snapshots raw low32 result at K+0x5f60 and selects shared cleanup0x100a0bf60 with phase0x6cf4 and W9=0x1fbb. Raw markers have no assigned public error names here. The retained ranges contain private BRAA transfers and no direct Mach/SVC emission; no new port name, right or external delivery is established. [FK4,FK6-FK10]

## Semantic flow and complexity [FK2-FK8]

```text
C0 = [OBJ+0]                         # successful parser publication
NODE, FIRST_RESULT = first_match(C0, encoded_key=d719dce3)
if FIRST_RESULT == exact_miss:
    if FLAG == 25 and MODE != 0: error(raw74c29d72)
    invoke option_accessor(OBJ, key=f24be74b, OUT=&F, return=935)
elif FIRST_RESULT == exact_found:
    require BUF != NULL and SIZE >= 10 B
    decode encoded header at offsets0,4,6
    require u64(P)+10 B <= u64(SIZE)
    if T is recognized scalar: error(raw74c29cd6)
    require T == reader_span1742
    stage end, encoded P and borrowed BUF+10 B
    if MODE == 1: enter helper729920 with OBJ/local32 interface
    elif MODE == 0 and FLAG == 25: error(raw74c29d77)
    else: error(raw74c29dee)
else:
    common outer result/error staging
```

This pseudocode abstracts prior lookup/decoder contracts and later helper/cleanup frontiers. For a finite stable list of n candidates, first-match lookup is O(n) time and O(1) traversal space with fixed-size per-candidate decoding. The captured post-lookup header/type/mode work is O(1) time/space; no bound is assigned to the deeper helper, external scheduling or cleanup. Static extraction is O(B+I+R) in retained bytes,instructions and recaptured bytes. SMT solving is not assumed linear.

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| FK1 |Original thin-image identity;all source claims |Hash original and compare captured instruction bytes;any mismatch rejects recovery |
| FK2 |Selected success phase0x6cf4 and original dispatch table;caller/result joins |Prove actual phase producers and match53 selected slots/modifiers;native PAC acceptance remains unknown |
| FK3 |Stable shared-frame/OBJ epoch and named-load reaching definitions;C0,staging and local32 joins |Audit omitted writers,escaped aliases and helper side effects;an incompatible intervening write falsifies composition |
| FK4 |Live sized owners,valid pointers,heap/frame separation and no concurrent mutation;memory effects |Establish native allocation/input/node/OUT owners and mappings;offset-fit/byte-array proofs do not establish them |
| FK5 |Finite stable lookup chain and established candidate codec;first-match/miss meaning |Retain prior complete source and58 accepted lemmas;cycles,invalid links or other encoding epochs invalidate the interpretation |
| FK6 |Ordinary saved-return and opaque-callee behavior;continuation/result/helper interfaces |Match original return selectors and recapture their source;full helper/cleanup effects and native termination remain unknown |
| FK7 |Exact widths,endian conventions,word/tag decoder outputs and frame argument keys |Replay source-pinned decoder lemmas,derive actual offset keys/selectors and reject width/address changes |
| FK8 |Prior option/default,N19 and outer-local contracts apply to the same selected instance |Verify caller-to-owner and complete memory continuity before asserting full native composition;current result is conditional |
| FK9 |No public operation/authorization/cryptographic/transport meaning inferred from private constants |Require explicit semantic producer/consumer evidence;the mode1 helper's application purpose remains unknown |
| FK10 |Static certificates and preserved RAX trace are distinct from native observations |Rehash supplied trace and original image;neither a SAT model nor guest numeric port equality proves delivery |

## Bounded next investigations

| Impact | Follow-up | Discriminating evidence |
| --- | --- | --- |
|High |Analyze entry0x100729920 and its normal/error returns |Whether it consumes the staged span,how it uses OBJ+0x18/+0x58 and LOCAL,and whether it rejoins another parser path |
|High |Complete caller/owner/frame continuity from outer input to C0 and all selected accessors |Discharge remaining named-load/alias/epoch assumptions across the omitted constructor and context-copy paths |
|High |Connect the decoded first key5c241ab2 to original producers and object-mode initialization |Actual field meaning and why present-span/mode1 differs from missing-key option/default behavior |
|Medium |Audit local32 construction and complete cleanup |Byte-level initialization,ownership transitions and raw-result propagation without conflating pointer cells and pointees |
|Medium |Compare the two accessor grammars with the outer wire parser |Preserve recognized-scalar status versus actual scalar-value decoding and size checks |
|Low |Use the recovered address/role map for descriptive names |No IDB mutation is needed to review these bounded classifications |

QG1: No normative judgment is required;the work is source,control and ABI analysis.

QG2: FK1-FK10 state assumptions,dependent results and falsification probes.

QG3: The increment covers C0-to-first-key routing,actual lookup return/phase,missing-key option bridge,found-record grammar,span outputs,mode partition,helper entry and error frontier. The four respective reporting files and investigation index are updated;the broad objective remains active.

QG4: Bit widths,endian conventions,byte extents,offset/fit identities and complexity premises are explicit and reproducible.

QG5: First-key miss differs from found scalar/span;mode0 always errors on the captured found-span branch;unused/deeper helper behavior remains unknown;pointer publication differs from delivery;conditional joins do not become global N19 requirements.

QG6:35 ranges/671 instructions plus386-instruction preparation,53 original pointers/53 selected matches and120 recaptures ground the claims.41 new and58 replayed queries return UNSAT;one SAT interpretation check is separately labeled. Solver errors,unknowns and timeouts are rejected;six altered-ledger controls are rejected by fresh-source comparison.

QG7: Scope expansion is bounded by impact-ranked semantic/owner/continuation questions. Native processing and successful daemon-kext interaction remain unproved.

## Protected-adapter follow-up

The [mode1 adapter report](daemon_mode_one_adapter_report.md) now follows entry729920 into its48 B request,adapterd03348 and corecf0194. The source pointer is OBJ+0x18 and the tested count is u32[OBJ+0x58];neither is identified with the staged first-key span. A nonnull source with count!=32 selects immediate raw74c29dee return. Result and continuation reloads use different frame bases;the immediate route conditionally supplies zero delta,while the32 B processing route remains a frontier.
