# Matched-record span into N19 and context-word admission

The selected N19 input is the in-memory payload of an earlier matched record. The source looks up encoded identifier0x7615e796 in the collection at OBJ+0, reads the matched node's BUF/u64 at+0x18 and SIZE/u32 at+0x10, and saves BUF at K+0x3a18. The recognized span path supplies N19 with BUF+10 and encoded extent `P XOR0x8b3dc651`, under the exact u64 bound `P+10<=SIZE`. The type branch also derives the actual entry phase0x4b1d; the preceding report treated that phase as an upstream premise. No payload copy or allocation occurs between the matched-record span handoff and the N19 input staging in these captured components. [NI1-NI7]

The source producer for the previously opaque F is now identified. At selected mode0x2122, it computes `F = u32[OBJ+0x10] -0x1d45dafb mod2^32` and saves it at K+0x53ac. The two previously recovered N19 gates compose to F==0, hence exactly to context word0x1d45dafb. A separate112 B constructor writes that default word, and the selected field copier transfers CTX+0 to OBJ+0x10. Identity of that particular constructor result with an actual copy input remains unknown. [NI3-NI6]

These are static private interfaces and conditional source compositions. They do not establish that the original outer buffer is the same allocation, that this span is an externally delivered canonical wire packet, or that the source paths ran natively. The borrowed memory representation remains subject to the existing address-dependent codecs. [NI4,NI6-NI10]

Evidence: [original source, fixups, preparation and writer candidates](triage_evidence/daemon_reader_nested_input_source.json), [27 new and58 replayed UNSAT certificates, one interpretation counterexample and six controls](triage_evidence/daemon_reader_nested_input_checks.json), [extractor](triage_evidence/recover_daemon_reader_nested_input.py), [validator](triage_evidence/validate_daemon_reader_nested_input.py), [preservation](triage_evidence/daemon_reader_nested_input_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_nested_input_quality_gates.json), [independent publication audit](triage_evidence/verify_daemon_reader_nested_input_publication.py). Adjacent contracts: [outer allocation/output/cleanup](daemon_reader_outer_lifecycle_report.md), [first-match lookup](daemon_constructor_lookup_report.md), [generic word/tag reader](daemon_existing_scalar_reader_report.md), [preparation footprint](daemon_reader_context_footprint_report.md), [N19 allocated container and u64 codec](daemon_reader_u64_codec_report.md), [separate112 B allocation prefix](daemon_reader_container_origins_report.md).

| Evidence | Verified scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| New interface ranges |25 fragments,452 instructions,1808 B;23 branch-terminated ranges and two explicit prefixes |
| Shared preparation |386 instructions,1544 B; recaptured and translated in both historical and arbitrary-argument projections |
| Original metadata |38 independently decoded pointer records;36 branch slot/modifier matches |
| Prior code recapture |32 ranges,7924 B; shared lookup/word/tag source |
| Translation |814 distinct nonbranch instruction sites;1208 instances,1060 SSA definitions |
| Certificate |27 new and58 replayed UNSAT queries;one SAT interpretation counterexample;six altered-ledger controls |
| Writer census |12 overlapping SP-affine candidates across K+0x3a18,K+0x53ac,K+0x285c;3,712,490 aligned text words |
| Execution boundary |No target/native execution,new CPU emulation,FairPlay API/IPC,IDA access,IDB edits or memory writes |

Addresses are unslid VAs; offsets/constants/selectors are hexadecimal. Extents use B. K denotes shared-frame SP, OBJ the saved outer pointer, COLL=[OBJ+0], NODE a matched record node, BUF=[NODE+0x18], SIZE=u32[NODE+0x10], P the decoded u32 payload extent, T the private16-bit reader tag, and M=u32[OBJ+0x10]. Frame/object integers are little-endian. The existing codec interprets decoded header words/tags in big-endian wire order. All modular arithmetic is stated at u32/u64 width. Role names are analytical, not original symbols or complete public types.

## Context word, child lookup and matched node [NI2-NI6]

| Stage/site | Source interface |
| --- | --- |
| 0x1006bf438 /0x1006bf43c | Load OBJ from K+0x1ae8;load M/u32 from OBJ+0x10 |
| 0x1006bf458 | Save `(M-0x1d45dafb) mod2^32` at K+0x53ac;W22=0x6cf4 |
| 0x1006ab920 | Read COLL/u64 at OBJ+0 |
| 0x1006ab924 /0x1006ab938 | Zero matched-node output K+0x3be0;initialize encoded cursor K+0x4890 to0x4ce73660a8625cd3 |
| 0x1006d6c00 | X8=COLL,W9=0x7615e796,X11=&K[0x3be0],W10=0x130b |
| 0x1006d6c14 | Slot0x18e2 ->shared first-match lookup0x1006fd1b8,IA0xa818 |
| 0x1006fd1c0..0x1006fd1d0 | Resolve continuation0x130b ->0x1006d913c;save CONT at K+0x7060,key at K+0xaa5c,OUT address at K+0xaa60 |
| 0x1006d916c | Exact low32 returned marker0x8b3dc651 selects0x432d ->0x1006d038c;other markers select0x3c37 ->error staging |
| 0x1006d03b0 /0x1006d03b4 | Read BUF/u64 at NODE+0x18 and SIZE/u32 at NODE+0x10 |
| 0x1006d03b8 | Save BUF/u64 at K+0x3a18 |

The established lookup contract supplies the first matching record under stable live list, key-codec and normal-return premises. The encoded key corresponds to decoded identifier0xfd2821c7 under the established word XOR0x8b3dc651; no application-specific identity is assigned. The subsequent offset-zero word return does not re-compare the identifier. The lookup's matched record and saved node must remain stable before its buffer/size reads.

COLL==0 or BUF==0 selects the common error frontier with raw0x74c29d88. A nonnull COLL does not itself prove a valid list, and a returned found marker alone is not an independent native owner proof. The common error block stores its incoming raw result at K+0x5f60 and selects the existing outer cleanup arm; the complete cleanup/native return is outside this increment.

## Header reads and exact payload extent [NI2-NI7]

The cursor representation C0=0x4ce73660a8625cd3 encodes logical offset zero for this component. The minimum gate stores SIZE/u64 at K+0xae18 and C0/u64 at K+0xae20, then requires unsigned SIZE>9. It returns raw0x74c29d8f on the rejected branch. Under valid readable SIZE-byte BUF ownership, the admitted path contains the full10 B header envelope.

| Interface | Exact selected arguments/result |
| --- | --- |
| Identifier read preparation0x1008a9d38 | X1=BUF,X4=0x661a590b302baf96,W8=0x8c3f,W16=0xf3;slot0x2520 ->shared preparation |
| Identifier return0x10059ad28 | Tag return selector0x218;X4=&K[0x3a18],X22=&K[0xae20],X1=0x2cc95ff01b942589;tag byte offset is4 |
| Tag return0x100609f40 | Save low16(W24)=T at K+0x9bfe;length return selector0x100;X1=&K[0x3a18],X4=[K+0x910],X6=X28 |
| Shared preparation key | K+0x910 = AE20+0x193322aa87c952c9 =0x661a590b302baf9c;length word is at offset6 |
| Shared word call0x100530d34 | Load BUF through its saved cell;preserve the actual key/selector and branch via0x8c3f |
| Length results | W1=`P XOR0x8ec35f08`;W4=`P XOR0x8b3dc651` |
| Extent gate0x1006ec8f8 | Accept exactly `zero_extend64(P)+10 <= zero_extend64(SIZE)` |
| Fit bridge0x1007cfed8 | X9=10,X8=`C0+P+10 mod2^64`;load signed16 T from K+0x9bfe |

The complete shared preparation is additionally translated with arbitrary X4 offset key and W16 selector: it preserves X1=BUF,X4 and W16, supplies X6=0x324a764c67af2e0e and carries the selected code pointer. This avoids substituting the older cursor-zero selector0x74 for the actual selector0xf3. Its other eager context reads still require valid stable storage.

The preceding word's full residual-key query is replayed, and the complete tag source is checked not to write X28. This supplies the actual first-round key passed to the length reader. The word/tag mask, merge, address and shared-call queries are replayed against recaptured original bytes. The new proof binds this caller's offset0/4/6 interfaces and actual saved cursor, rather than asserting a new all-input value algorithm from unverified pseudocode.

P is u32, so its u64 sum with10 cannot wrap. The accepted bound implies P<SIZE and P<=0xfffffff5=4,294,967,285 B. Logical payload interval [10,10+P) lies inside [0,SIZE). SIZE=10 and P=0 are accepted by the span branch. These are logical extent facts, not native address/lifetime proofs. BUF+10 may require separate physical-address and owner checks.

## Type forest and the actual span handoff [NI3,NI6,NI7]

The signed16 forest recognizes private tags0xc31c,0xd0ee and0x1742, corresponding through XOR0x4799 to wire tags0x8485,0x9777 and0x50db. Its source branches are independently checked for all16-bit T values.

| T | Source result after extent admission |
| --- | --- |
| 0xc31c | Select0xacbf ->0x10052f47c;stage encoded end and length;raw marker0x74c29cd6 |
| 0xd0ee | Select0x9fe3 ->the same recognized-other-type component |
| 0x1742 | Select0x658c ->0x100609e2c with W12=0x4b1d,W22=0x6cf4 |
| Other |Common error frontier;no selected N19 span handoff |

These scalar routes do not check P==8/P==4 or decode a scalar payload in the captured component. Their marker describes the local recognized-type path. The complete caller handling of those variants is not recovered here. The existing N19 ordinary-record scalar checks belong to another layer and must not be imported into this outer accessor.

For the span tag,0x100609e2c uses the actual preceding register outputs and performs:

```text
K+4890 /u64 := C0+P+10
K+285c /u32 := P XOR8b3dc651
K+82e8 /u64 := [K+3a18]+10 = BUF+10
X19 := [K+1ae8] = OBJ
F   := u32[K+53ac]
RFLAG := u8[OBJ+7c]
```

The following two gates select N19 exactly when F==0. Substituting the newly proved producer gives `M==0x1d45dafb`, independently of RFLAG's low bit. Caller0x1004e1f94 then supplies OUT=OBJ+8,X9=&K[0x82e8],X10=&K[0x285c],return selector0xb9a and mode0xc4dd. The existing N19 contract decodes that extent to P and publishes its16 B record container through OBJ+8 on its successful path.

The input is therefore a borrowed subspan of the matched record, rather than the entire SIZE-byte record. The new source does not equate P with the outer routine's original encoded input extent at K+0x5d4c. It also does not establish cleartext byte equality, serializer output identity, external-buffer ownership or a complete native nested-parser execution.

When M differs from the default, the flag low bit selects between the previously documented alternate frontiers0x1007eff34 and0x1005f3a78. Neither path is assigned a cryptographic, authorization or public-mode meaning here. One SAT interpretation counterexample shows default M with RFLAG=0x7e still selects N19; flag lowbit1 is not a requirement. The certificate creates no target packet, request or execution.

## Default-context correspondence and evidence limits [NI4-NI6,NI8]

The fresh12-instruction prefix0x100939f64..0x100939f94 writes0x1d45dafb/u32 at the separate context object's offset0. The fresh field-transfer prefix0x1006c8a10..0x1006c8a6c copies CTX+0/u32 unchanged to OBJ+0x10. If the copy input is that constructor result and the word has remained unchanged, the copied M is the exact N19-admitted default.

This conditional correspondence does not prove that a particular112 B allocation is the actual CTX used by the outer object. Full initialization, context publication, owner identity and intervening stores remain open. Equal constants and matching offsets establish a source-compatible role, not complete object-type equivalence or native instance identity.

The new full-text candidate census finds one locally SP-affine full-width store candidate for BUF cell K+0x3a18 and one for F cell K+0x53ac. Other candidates overlap K+0x285c through u32 and u64 writes. These12 candidates span different routines/frame epochs and exclude non-affine/memory-derived aliases, unknown stores and opaque callees. They are locators, not a global reaching-definition proof.

## Mach/IOKit boundary and bounded continuation

The recovered components use local cells, borrowed record storage, a shared lookup and authenticated internal branches. They contain no Mach-message emission or Mach-port production. The [port inventory](mach_ports_report.md) retains the independently identified transport sites. No numeric port or IOKit connection identity is inferred from OBJ,COLL,NODE or BUF.

The supplied annotated trace remains unchanged at SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. Its reported failed user-client open0xe00002c2/NULL connection still prevents that trace from establishing a successful selector26 or RPC502/700 daemon-kext exchange. This increment adds static nested-input lineage, not new runtime observations.

| Impact | Next bounded interface question | Required evidence |
| --- | --- | --- |
| High |Upstream entry into context-word producer |Recover actual W9=0x2122 reaching definition and the caller/record that selects0x1006bf434;do not replace it with the frame phase |
| High |First-child allocation/content lineage |Join COLL and the selected encoded key's record producer to the outer input parser and its successful return |
| High |External publication/serialization |Follow OBJ's final borrowed OUT consumer and K+0xd5c discriminator to actual serializer/API/IPC arguments |
| High |Daemon/kext runtime pairing |Require an available successful user-client open,exact selector/argument/status trace and correlated callback/reply evidence;the supplied failed-open trace cannot supply it |
| Medium |Default112 B context identity |Join complete initialization/publication to the CTX argument used by the outer copier;verify owners and intervening stores |
| Medium |Nondefault M and scalar variants |Recover alternate-frontier consumers and recognized-type marker handling without borrowing another accessor's4/8 B grammar |
| Medium |Lifetime and error cleanup |Join matched-node stability,borrowed BUF lifetime,partial N19 results and the complete shared cleanup/result recovery |
| Low |Census completeness |Extend alias/store recognition and partition actual frame epochs around the12 candidate writes |

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| NI1 |Pinned thin daemon and address mapping;all source results |Rehash image and recapture new ranges,preparation and7924 B prior ranges;any mismatch rejects the increment |
| NI2 |Original table/fixups and preparation roots remain valid;selected branches and codecs |Independently decode the38 original pointers;check actual table/cache roots before native application |
| NI3 |Stable K epoch and saved BUF/F/tag/extent cells;cross-component lineage |Find an intervening overlapping write,frame change or opaque-callee clobber;the bounded census alone cannot exclude these |
| NI4 |Live valid disjoint OBJ/CTX/frame/list/node/BUF owners;memory effects |Verify concrete allocations,extents,aliases and lifetimes;record fit alone does not establish physical memory ownership |
| NI5 |Mode producer entry W9=0x2122;its constant targets and normalized F |Trace the real reaching register definition;another phase invalidates these selected targets |
| NI6 |Established first-match/decoder/N19 contracts and stable normal returns;matched-record-to-child composition |Revalidate source certificates and saved OUT/continuation uses;an unstable list or changed return breaks the join |
| NI7 |Dual word outputs and private tag representation apply to the current buffer/key state;header/length meaning |Check actual selector,offset,key producers and preserved X28;58 relevant source-pinned certificates are replayed |
| NI8 |If invoking default-context correspondence,the copied CTX is that constructor result with unchanged word |Establish actual instance identity and reaching writes;matching constants alone does not prove this premise |
| NI9 |Logical extent arithmetic is distinct from native pointer/readability;borrowed span use |Check physical BUF+10 mapping and lifetime separately;all u32 P/SIZE edge cases remain in the algebraic proof |
| NI10 |Existing trace is emulator evidence with unchanged bytes;runtime boundary |Rehash it and distinguish transport status from user-client result;require independent native evidence for successful pairing |

Complexity: source recovery/translation is O(I), with838 captured interface/preparation instructions and814 distinct modeled nonbranch sites; overlapping projections yield1208 translated instances. The candidate census is O(N+E+H) time and O(E+H+A) retained memory for N text words,E known entries,H candidates and bounded live aliases A. SMT complexity is solver-dependent:15000 ms per-query timeout,20000 ms subprocess limit; unknown/timeout is rejected. Publication validation is O(total logical artifact bytes+links), with memory bounded by the manifest and largest decoded JSON/report. SHA-256 and lengths describe decoded logical artifacts if stored as `.json.zst` after archival migration.

## Scoped quality gates

QG1: Technical source analysis;no normative judgment is required.

QG2: NI1-NI10 name assumptions,dependent results and falsification probes.

QG3: This increment covers selected context/lookup/header/extent/type/N19 input interfaces and the associated control/data/owner frontiers. The broad cross-layer goal remains active and incomplete.

QG4: u32/u64 widths,host/wire endian,modular cursor encoding,nonwrapping extent sums,B extents,coverage and complexity are explicit and reproducible.

QG5: The actual span-derived mode,outer versus nested extent,borrowed versus copied bytes,default constant versus instance identity,scalar versus span accessor grammar and local versus external publication are distinguished.

QG6: Original bytes/fixups,source-pinned new/replayed certificates,altered-ledger checks and unchanged trace are checked. No inherited IDA knowledge is substituted for source proof.

QG7: Impact-labeled continuation questions are bounded by named evidence. Native ownership/PAC/caller/context identity,complete parser/cleanup,external delivery and daemon-kext pairing remain unproved.


[Keyed option and context default](daemon_reader_option_default_report.md): encoded keyf24be74b/decoded7976211a in OBJ+0 publishes a typed u32 value to F at K53ac. Exact success preserves V; exact miss writes M-1d45dafb; every other accessor result selects error. Selected N19 admission is (success AND V=0) OR (miss AND M=1d45dafb), rather than universal header equality. Two context-dependent predecessors derive caller selector935, and the actual status tree derives default phase2122. Eighteen ranges/326 instructions,26 fixups/28 slot matches,308 modeled PCs,22 new and107 replayed UNSAT certificates,one SAT scope counterexample,six controls and an exact byte-memory join pass. Native caller/owner/PAC/context identity,complete parser/cleanup,external delivery and daemon-kext pairing remain unproved.
