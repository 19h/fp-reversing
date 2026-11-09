# Outer wire ingress, first-child collection and constructor operands

The selected outer caller0x1006c82e4 supplies the saved INPUT and encoded u32 extent to shared parser0x1006997a4, with its borrowed output cell equal to OBJ. Successful local publication therefore writes the resulting16 B collection-container pointer to OBJ+0. This supplies a conditional producer for the first child later queried by the [option/default accessor](daemon_reader_option_default_report.md) and [nested-input lookup](daemon_reader_nested_input_report.md). The omitted upstream route, stable frame, ordinary constructor returns and valid owners remain explicit premises; this is not a continuous native ingress observation. [OI1-OI8]

The parser reads plain bytes from a10 B header: BE32 identifier, BE16 type and BE32 payload extent. It converts those fields and scalar payloads to the common constructor's private XOR operands. This is a separate representation boundary from the address-dependent encoding of allocated internal record buffers. Both wire9777/u32 and wire8485/u64 require exact scalar extents; wire50db is a span. A span whose identifier is zero returns local success without constructing that record, including when its fitted end precedes total exhaustion. [OI2-OI8]

Evidence: [source, original pointers, allocation bank and recaptures](triage_evidence/daemon_outer_record_ingress_source.json), [37 new and three replayed UNSAT certificates, one SAT scope counterexample and six integrity controls](triage_evidence/daemon_outer_record_ingress_checks.json), [extractor](triage_evidence/recover_daemon_outer_record_ingress.py), [validator](triage_evidence/validate_daemon_outer_record_ingress.py), [preservation](triage_evidence/daemon_outer_record_ingress_delivery.json), [quality gates](triage_evidence/daemon_outer_record_ingress_quality_gates.json), [publication audit](triage_evidence/verify_daemon_outer_record_ingress_publication.py). Related contracts: [generic constructor root](daemon_constructor_callers_report.md), [constructor field sources](daemon_constructor_inputs_report.md), [typed writers](daemon_typed_scalar_report.md), [internal byte encoding](daemon_payload_codec_report.md), [outer object lifecycle](daemon_reader_outer_lifecycle_report.md), [other caller of the same parser](daemon_client_object_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source |27 branch-terminated ranges;675 instructions,2700 B;zero architectural SP writes |
| Translation |All647 non-transfer instruction sites;690 translated instances,651 SSA definitions |
| Pointer metadata |35 original pointer records;41 selected branch-slot/IA-diversity matches |
| Allocation bank |256 possible byte inputs independently give index0xcc0d, original `libSystem/_malloc` binding |
| Prior source |88 ranges,13064 B freshly matched against original bytes |
| Certificates |37 new and three replayed UNSAT;one SAT interpretation counterexample;six altered-ledger controls |
| Target effects |No target/native execution,new CPU emulation,IPC/API request,IDA access,IDB mutation or memory-store update |

All addresses are unslid VAs; offsets,selectors and constants are hexadecimal. Extents use B. K is the shared frame SP; BUF is INPUT; OBJ is the outer object at K+0x1ae8; C is this parser's container at K+0x2ff8; O is its u64 cursor. ENCLEN is the u32 XOR extent; N=ENCLEN XOR0x8b3dc651, zero-extended to u64. ID and P denote decoded wire identifier and payload extent; T denotes the wire tag. Frame/heap scalar stores use little-endian host layout; wire fields use big-endian layout. u32/u64 arithmetic wraps at the stated width unless a no-wrap bound is given. Analytical role names are not recovered original names or public Apple types.

## Selected caller and container setup [OI1-OI6]

| Site | Source effect |
| --- | --- |
|0x1006c82f0/0x1006c82f4/0x1006c82fc |Read OBJ/u64 from K+0x1ae8, BUF/u64 from K+0x56f8 and ENCLEN/u32 from K+0x5d4c |
|0x1006c82e4..0x1006c8318 |Derive return selector0x1649 and phase0x6cf4;index0x18bd ->parser0x1006997a4,IA0x141e |
|0x1006997bc..0x1006997d4 |Save return at K+0x5ff0, OUTcell=OBJ at0x7068, ENCLEN at0x7550, BUF at0x3818 and zero cursor at0x4d50 |
|0x1006997e0/0x1006997f4/0x10069983c |Initialize staged u32=0x8b3dc651,u64=0x2c220a381b62f9ab,span pointer=0 |
|0x100699850..0x100699858 |Request malloc(16 B),index0xcc0d,IA0x6aa4;opaque ordinary callee model,not an executed allocation |
|0x10069985c..0x100699888 |Save C at K+0x2ff8;NULL ->index0x70bc/direct saved return with raw0x74c29d85;nonnull ->0x7081/initialization |
|0x1008c3890 |Zero both8 B container cells at C+0 and C+8 |
|0x1008c3898 |Index0x1892 ->loop0x1006d54e8;W10=0xa62b |

The selected outer lifecycle had already saved INPUT and ENCLEN at the cells above. This increment recaptures that source but does not prove every intervening flattened transition or all writes through aliases. The caller-to-entry register transfer is proved; caller-entry phase and frame-reaching definitions are OI2/OI3 premises. The full parser entry contains one imported BLRAA followed by a BRAA, and the model preserves SP/X19-X29 across an ordinary imported return while making volatile GPRs fresh. Hardware PAC acceptance remains unknown. [OI2-OI6]

The output of this parser is the first child C0 at OBJ+0. The N19 result published through OBJ+8 uses another container/frame slot. These are different roles; no heap-address inequality or native allocation identity is inferred merely from different slots. [OI3-OI8]

## Plain header and bounds [OI2-OI7]

| Relative byte offset | Width | Plain input interpretation | Constructor representation |
| --- | --- | --- | --- |
|0 |4 B |ID=BE32(BUF+O) |HE=ID XOR0x8b3dc651 in W19 |
|4 |2 B |T=BE16(BUF+O+4) |low16(W9)=T XOR0x11c3 |
|6 |4 B |P=BE32(BUF+O+6) |E=P XOR0x8b3dc651 in W21 |
|10 |P B |Payload |Type-dependent operand or borrowed span |

Loop0x1006d54e8 loads O and N and compares them as unsigned u64. O<N selects the nonempty path; otherwise it selects successful exhaustion. Nonempty processing requires BUF!=0, then N-O>9 at0x10076b274. The raw byte loads for P are0x100670470/484/490/4a8. Their arithmetic universally reduces to end=O+10+zero_extend(P);0x1006704e0 rejects end>N. Header0x100705408 reads ID at0x10070545c/478/494/4bc and T at0x1007054f0/4f8. All ten source read addresses and their field identities are certified. None of these ingress byte loads invokes the internal address-dependent mask. [OI3-OI7]

Under O<N and u32 N, O<2^32. Since P is u32, end cannot wrap u64. With end<=N, end>=O+10, end<=0xffffffff and P<=0xfffffff5. The ten header offsets are within N under the minimum-header gate. These are offset bounds; they do not establish mapped/live BUF+offset addresses or absence of native pointer wrap. [OI4,OI7]

## Full local type forest and typed operand staging [OI2-OI7]

The header also computes signed16((T XOR0x11c3)+3) for the flattened comparison tree. Its lower/middle/upper partitions at0x100842bd0,0x100893a90,0x100750e08,0x1007c7954 and0x100768270 are proved to accept exactly the following three wire tags; every other tag selects the captured error frontier. Signed16 wrap is included in the universal bit-vector proof.

| Wire T | Internal kind | Payload gate | Stage and exact constructor operand |
| --- | --- | --- | --- |
|0x9777 |0x86b4 |P=4,gate0x1009b66b4 |0x1007079b4..0x100707a6c reads payload+0..3;K+0x1a74 receives BE32(payload) XOR0x8b3dc651 |
|0x8485 |0x9546 |P=8,gate0x100778bc0 |0x100838b54..0x100838cfc reads payload+0..7;K+0x7768 receives BE64(payload) XOR0x2c220a381b62f9ab |
|0x50db |0x4118 |Any fitted P |0x1008c0384/38c stages borrowed BUF+O+10 at K+0x31f0;no payload copy here |

Both scalar readers resolve index0x8868 ->0x1008f0cb0 with phase0x6cf4. It stores end at K+0x4d50 before selecting0x3eff ->generic root0x10097b9b0. Thus cursor advancement precedes the constructor's result, rather than following only a successful append. The span arm likewise advances the cursor before its zero-ID test. [OI3,OI6-OI8]

Generic root0x10097b9b0 reads C/u64, staged u32/u64 and span pointer from K+0x2ff8/1a74/7768/31f0. It preserves HE,T,E and supplies return selector0x228 to common constructor0x100700d80 through index0x5eb2,IA0x2c67. Selected u32/u64/span caller compositions are checked independently. Other typed staging fields are arbitrary unused values; initialization does not imply they reset between loop iterations. [OI3,OI6,OI7]

The established typed writers later apply their scalar XORs while constructing the internal records. Composing those prior writer contracts with this newly proved input staging cancels the scalar XOR and preserves the plain BE32/BE64 payload representation. The generic span producer encodes plain source bytes at destination addresses. This is distinct from the N19 span recoding loop that consumes an already encoded source. The new certificate establishes the inputs to the common constructor; full byte-memory identity through every allocator/list mutation is not re-proved here. [OI3-OI8]

## Zero-ID span, iteration and local outputs [OI3-OI8]

At0x1008c039c the span arm compares the intermediate identifier expression with0xabffbeef. Under the proved header conversion this is exactly ID==0. It is independent of P==0.

| Local outcome | Selected continuation |
| --- | --- |
|Span ID!=0 |Index0x3eff ->generic constructor root |
|Span ID==0 |Index0x3f49 ->0x1007481bc;raw success0x8b3dc651 ->0x3b30/publication,without constructing that record |
|Constructor exact success0x8b3dc651 |Return0x10084d5d0 ->index0x8784/loop0x1006d54e8;restores W10=0xa62b |
|Other constructor low32 result |Index0x1a25 ->0x1008f045c,error/drain frontier |
|Cursor O>=N |0x1006c47bc ->success0x8b3dc651 ->0x3b30/publication |

Both success routes reach0x100758ae8. It reloads C and OUTcell and stores C through OUTcell at0x100758af0;the selected caller makes that address OBJ+0. Phase0x6cf4 selects0x188e ->0x1008c8b80,which reloads the saved continuation and branches with IA0xfc72. Original saved slot0x1649 names outer return0x1008b3a7c;its exact-success gate selects0xc6db ->0x10069a00c,other parser results select0x445a ->0x100975d34. The next outer operation is now covered by the [first-key control report](daemon_outer_first_key_report.md); native owner/frame continuity remains a premise. [OI2-OI8]

The abstract SAT scope counterexample permits T=0x50db,ID=0 and fitted end<N. Consequently success here does not require complete input exhaustion. It does not prove that any native external caller supplies such a state or assigns a particular application meaning to trailing bytes. The solver result is an interpretation check,not a target test or constructed packet. [OI4,OI7-OI10]

The parse-error frontier snapshots low32 status at K+0x850c,copies C into pointer cell K+0x1548,and passes X19=&K[0x1548],W24=0x6cf4 to helper0x1006e3d4c. The pointee and pointer-cell address are distinct. This increment does not establish all cleanup/free effects,public error names or externally emitted replies. No SVC,Mach import call or Mach emission is present in these retained ranges. [OI4,OI6-OI10]

## Compact semantic contract and complexity [OI2-OI8]

```text
parser(BUF, ENCLEN, OUTcell):                 # selected phase/frame premises
    N = u32(ENCLEN XOR 8b3dc651)
    C = malloc(16 B); if C == NULL: return raw74c29d85
    C.head = C.tail = NULL; O = 0
    while O < N:
        require BUF != NULL and N - O >= 10 B
        ID = BE32(BUF+O); T = BE16(BUF+O+4)
        P = BE32(BUF+O+6); end = O + 10 B + P
        require end <= N
        select T:
            9777: require P == 4 B; V = BE32(payload) XOR8b3dc651
            8485: require P == 8 B; B = BE64(payload) XOR2c220a381b62f9ab
            50db: S = BUF+O+10 B
            otherwise: enter captured error/drain frontier
        O = end
        if T == 50db and ID == 0: break
        RESULT = constructor(C, ID XOR8b3dc651,
                             T XOR11c3, P XOR8b3dc651, V, B, S)
        if RESULT != raw8b3dc651: enter error/drain frontier
    *OUTcell = C; return raw8b3dc651
```

Unused V/B/S may retain earlier values. The pseudocode abstracts the existing constructor and drain contracts; it is not a complete executable replacement. Each continuing record advances O by at least10 B,so the selected loop admits at most floor(N/10 B) successful construction iterations before exhaustion or earlier termination. Header/control work is O(m) for m iterations; full time is O(m+sum constructor costs),not an established O(N) bound for all list searches. Additional parser staging space is O(1); constructed collection space depends on constructor ownership/replacement behavior. Static extraction is O(B+I+256+R) in retained source bytes,instructions,bank inputs and recaptured bytes; solver complexity is not assumed linear. [OI3-OI8]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| OI1 |Original thin daemon identity;all source claims |Extractor hashes original and compares retained bytes;any source mismatch rejects the result |
| OI2 |Selected phase0x6cf4 and authentic original table;caller/entry and branch equations |Captured phase calculations and all selected pointer/modifier checks;native phase/PAC acceptance is unknown |
| OI3 |One stable frame epoch and named-load reaching definitions;input,C,staged values,OUTcell joins |Check omitted frame writers/aliases and call side effects;an intervening incompatible write falsifies the composition |
| OI4 |Live correctly sized disjoint owners and valid mapped pointers;memory reads/writes |Establish actual allocation/input/output owner bounds and alias relations;offset-fit proofs alone cannot discharge this premise |
| OI5 |Ordinary imported malloc ABI and bank roots;container setup |All256 bank inputs checked,original import/modifier matched;nonnull result/liveness and native implementation remain unknown |
| OI6 |Ordinary shared constructor/saved-return behavior and stable control table;iteration/return composition |Replay three accepted generic certificates and recapture prior source;full callee frame footprint and native returns remain a frontier |
| OI7 |Exact u16/u32/u64 and BE wire/LE host conventions;field identities and bounds |Universal bit-vector identities,address checks,type partition and no-wrap lemmas;change byte order/width to falsify |
| OI8 |Prior writer/lookup contracts apply to the same selected owner epoch;representation and C0 consumer connection |Prior source recaptured;verify owner/epoch and complete memory join before asserting whole-parser byte identity |
| OI9 |No inference from this parser to a particular Mach name,external operation or kext selector |Require an independent producer-to-transport/control chain with matching build,arguments and identity;currently unknown |
| OI10 |Historical RAX trace is an emulated observation;no new native delivery claim |Preservation seal rehashes the supplied trace;native success still requires independent evidence,not a solver model |

## Bounded next investigations

| Impact | Follow-up | Discriminating evidence |
| --- | --- | --- |
|High |Follow outer caller0x1009638c0 and success0x10069a00c into the first option/accessor path |Complete source/frame reaching definitions connecting external borrowed inputs,C0 construction and selected option/N19 consumers |
|High |Audit constructor/drain frame footprints and owner epochs |Discharge named-load stability for cursor,typed staging,C and OUTcell;distinguish normal append/replacement from failure retirement |
|High |Join the same parser's other known client-state caller to its exact borrowed-record producer |Compare original operation-specific layouts;do not assume all borrowed B records have one public ABI |
|Medium |Classify the zero-ID span terminator in later consumers |Whether callers intentionally permit trailing fields or bound the selected substream independently |
|Medium |Correlate decoded keys7976211a and fd2821c7 with semantic producers across daemon/kext |Exact field construction/consumption evidence;literal spelling absence would not establish cross-binary absence |
|Low |Assign descriptive analytical role names to these retained entries |Read-only address/role mapping is now available;no IDB changes were made |

QG1: No normative judgment is required;the deliverable is a source and ABI analysis.

QG2: OI1-OI10 state assumptions,dependent claims and falsification probes.

QG3: This increment covers the selected first-child producer,plain header,complete local type forest,payload staging,shared constructor ABI,cursor/sentinel/output and cleanup frontiers. Respective routine,port,data/control and ABI reports are updated. The broader cross-layer objective remains active.

QG4: Byte extents,endian conventions,bit widths,offset bounds and complexity premises are explicit and reproducible from stored source/queries.

QG5: Initial defaults are distinguished from arbitrary unused later fields;cursor update precedes constructor result;zero-ID span differs from P-zero/exhaustion;pointer publication differs from delivery;unknown native/alias/cleanup cases are bounded explicitly.

QG6: Claims are pinned to original bytes,35 pointer records,41 branch matches,256 bank cases and88 recaptures. All37 new and three replayed proof queries return UNSAT;one SAT interpretation check is separately labeled. Solver errors,unknowns and timeouts are rejected. Six altered-ledger controls are rejected by fresh-source comparison.

QG7: The impact-ranked follow-ups are bounded to semantic interfaces and provenance. No target invocation,IPC reproduction,IDA mutation or broad-goal completion is claimed.
