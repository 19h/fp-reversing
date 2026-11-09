# RPC502 body interface: certificate schema, TLV records, digests and atomic state

The original `.v5.supf` body path is a table-driven certificate parser. A closed26-row schema follows the X.509 certificate structure; the generic item helper exposes a cursor-based64-byte argument ABI and produces a32-byte parsed-item ABI. Original callbacks compute encoded digests of the whole certificate, its RSA public-key encoding and its TBS certificate. Forty-four complete worker fixtures establish these paths without entering the parser directly or overriding target instructions,registers,frames or branch gates. **Successful certificate authentication and a subsequent daemon/kext transaction remain unknown.** The full interface goal remains active.

[Original source contracts](triage_evidence/rpc502_certificate_contracts.json),[whole-worker profiles](triage_evidence/rpc502_certificate_profiles.json),and [independent checks](triage_evidence/rpc502_certificate_checks.json) are the primary artifacts. Earlier [supplemental-file evidence](rpc502_supplemental_report.md) remains frozen. [Preservation](triage_evidence/rpc502_certificate_preservation.json) checks the preceding977-artifact snapshot,with only six permitted reporting/aggregator changes.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| C1 | The current selected thin arm64e image is the supplied daemon slice; it is not an attestation of a native process or current IDB. | Every target address and source claim. | Rehash thin/universal images,compare the complete slice,redecode source opcodes,chained pointers and compiler metadata. |
| C2 | Entry is original worker `0x100422d48` with inherited RPC502 environment,stack,first.sinf,serial synchronization and external API declarations. | Path reachability and every finite outcome. | Vary actual upstream inputs;preserve parser-populated state;do not skip predecessor blocks. |
| C3 | Candidate certificate bytes have synthetic moduli and zero signatures. Names,serials,algorithms and trailing bytes are deliberate fixtures. | Structural parser and digest findings. | Supply independently authenticated records and resolve actual issuer/trust/key/policy requirements before claiming protected acceptance. |
| C4 | RFC field names are an inference from the original closed schema and observed field bytes; this does not prove full RFC5280 or strict DER conformance. | Certificate field labels. | Exercise GeneralizedTime,unique identifiers,extensions,nonminimal lengths and every callback policy. Source A1/A2 expectations and UTC-only rows remain explicit. |
| C5 | Private Unicorn CPUs A72 and MAX have different instruction capabilities; PAC remains explicitly bypassed. MAX is configured before memory mapping,not at a target branch. | CASAL continuation and private CPU comparison. | Compare the complete original instruction prefix and pre-CASAL register/memory state;verify hardware authentication,ordering and contention separately. |
| C6 | Item mode is the source-observed `0x80d1`. Finite header oracles cover the retained inputs; no general memory-safety or complete ASN.1 implementation proof is claimed. | TLV grammar,bounds and output fields. | Vary modes,cursors,available32/size64 axes,overflow,all length forms and tag classes. |
| C7 | The caller-side simplified item key requires an8-byte-aligned argument pointer. The callee key identity itself covers all32-bit pointers. | Compact caller/callee ABI equivalence. | The retained unaligned SMT counterexample falsifies unrestricted equivalence;verify actual alignment at every source call. |
| C8 | Digest identification uses standard IVs,source writers and independent digest outputs for exact source spans. It is not a formal proof of every compression input or certificate verification. | SHA-1/MD5 names and hash coverage. | Vary bytes and block boundaries,compare another implementation,and trace accepted signature/trust decisions. |
| C9 | A digest context is a temporary stack epoch. Retired bytes can be overwritten by cleanup or later frames. | Context layouts and source byte journals. | Track allocation/initialization/callback return separately;use final digest sinks before return rather than interpreting a later stack snapshot. |
| C10 | No native target,IOKit,Mach,loader,target-file or synchronization API runs. Live IDA bytes remain unverified because the bridge was unavailable in the preceding source investigation. | Native scope and port claims. | Compare current IDB spans and obtain a native endpoint/credential/driver transaction;original file evidence remains reproducible. |

The selected thin file `/Users/___/Downloads/zut/fairplayd.arm64e` has SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,17668912 bytes and UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. It equals the entire arm64e slice at universal offset3407872. Universal `/Users/___/Downloads/fpx/fairplayd` has SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`. Every original guest opcode is checked against file bytes at each visit;the verifier independently decodes and hashes the retained sequences. Physical compiler ranges are metadata ownership,not declarations that a large flattened carrier has one semantic purpose. [C1,C2,C5]

```text
RPC502 worker -> source-built .sinf -> .v5.supf
  -> variable file cursor -> mapped body pointer/length
  -> protected carrier -> generic TLV cursor helper
       -> 26-row certificate schema -> typed callback item32
            +-> certificate fingerprint: SHA-1
            +-> RSA public-key encoding fingerprint: SHA-1
            +-> inner/outer signature OIDs -> TBS digest: SHA-1 or MD5
            `-> signature callback -> CASAL state gate -> error return
  -> inherited file/copy/FD cleanup -> QoS restoration -> worker return

No new Mach/IOKit emission is established on these paths.
```

## Closed original schema and source callbacks

The schema begins at `0x1010389a0`. Source at `0x1008c2d64..0x1008c2da0` uses an index and a48-byte stride. Each row's tag reduces by subtracting `0x5cbf4ba3`; child/sibling indices reduce by subtracting `0x3fcc2052`,where `0xffffffff` is the terminal value. Flags reduce by subtracting `0x2f9615c4`. These are modulo32 representations. The graph rooted at row0 reaches exactly rows0..25,and all its edges remain within that set or terminate. The following adjacent rows use another representation;they are not silently included in this schema. Fifteen nonzero callback cells are independently decoded authenticated chained rebases. [C1,C4]

The field-name interpretation follows [RFC5280 section4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1); tags,edges,flags and addresses below come from the original daemon. The table is not itself evidence of successful validation.

| Row | Tag | Field interpretation | Callback | Child / sibling | Flags |
| --- | --- | --- | --- | --- | --- |
| 0 | 30 | Certificate | 10040f7a4 | 1 / - | 2 |
| 1 | 30 | TBSCertificate | 10044f7a4 | 2 / 22 | 2 |
| 2 | A0 | Version wrapper | - | 3 / 4 | 8 |
| 3 | 02 | Version INTEGER | 10041f768 | - / - | 2 |
| 4 | 02 | Serial number | 10040f1d4 | - / 5 | 2 |
| 5 | 30 | Inner signature algorithm | - | 6 / 8 | 0 |
| 6 | 06 | Inner algorithm OID | 1004150f0 | - / 7 | 2 |
| 7 | 05 | Inner NULL parameters | - | - / - | 1 |
| 8 | 30 | Issuer | 100413254 | - / 9 | 2 |
| 9 | 30 | Validity | - | 10 / 12 | 0 |
| 10 | 17 | notBefore | 10043cf70 | - / 11 | 2 |
| 11 | 17 | notAfter | 10043fdb0 | - / - | 2 |
| 12 | 30 | Subject | 10000cd38 | - / 13 | 2 |
| 13 | 30 | Subject public-key information | 10000aecc | - / 14 | 2 |
| 14 | A1 | Unique-ID position1 | - | - / 15 | 8 |
| 15 | A2 | Unique-ID position2 | - | - / 16 | 8 |
| 16 | A3 | Extensions wrapper | - | 17 / - | 8 |
| 17 | 30 | Extensions sequence | - | 18 / - | 0 |
| 18 | 30 | Repeated extension | - | 19 / 18 | 0 |
| 19 | 06 | Extension OID | 100411e10 | - / 20 | 2 |
| 20 | 01 | Critical Boolean | 10043ed6c | - / 21 | A |
| 21 | 04 | Extension value | 10044c204 | - / - | 2 |
| 22 | 30 | Outer signature algorithm | - | 23 / 25 | 0 |
| 23 | 06 | Outer algorithm OID | 10043e878 | - / 24 | 2 |
| 24 | 05 | Outer NULL parameters | - | - / - | 1 |
| 25 | 03 | Signature BIT STRING | 100421ec4 | - / - | 2 |

Addresses in the callback column are hexadecimal. Child/sibling roles are supported by cursor progression,observed table reads and callback item records. Full flag semantics remain partial:the numeric values above are decoded source values,not complete authorization rules. In particular,the table uses A1/A2 and tag17;it must not be generalized into support for every standards-defined unique-ID or time encoding. [C4,C6]

## Generic item-helper ABI and cursor semantics

The source helper entry is `0x10044dd40`. For argument address `P`,its callee key simplifies to:

```text
Ki = ((low32(P) XOR 0xe732d262) * 0xba209ef7) mod 2^32
```

The distinct caller expression at `0x100a656dc..0x100a65714` equals Ki under `P mod8=0`. Both identities are proved separately. The [contract counterexample](triage_evidence/rpc502_certificate_contracts.json) records an unaligned pointer for which the two expressions differ. All368 observed helper calls use aligned pointers and mode `0x80d1`; native frame assumptions remain separate. [C6,C7]

| Argument offset / width,bytes | Source representation / direction |
| --- | --- |
| +0 / 4 | Mode: `(stored+Ki) mod2^32 =0x80d1` in this corpus |
| +8 / 8 | Input span base pointer |
| +16 / 4 | Output status; XOR `0x8b3dc651` decodes zero or the tested error `0xffff5bde` |
| +24 / 8 | Pointer to output content length,encoded XOR `0x8b3dc651` |
| +32 / 8 | Pointer to output content pointer |
| +40 / 4 | Available span bytes: `(stored+Ki-0x67ac8198) mod2^32` |
| +48 / 8 | Pointer to output tag,encoded XOR `0x21e8ae22` |
| +56 / 8 | Pointer to input/output cursor,encoded additively with `0x50af9a6f` |

The cursor is cumulative within the supplied span; it is not always zero. On successful parsing,content points at `input+old_cursor+header_size`,length is the value length,and the new cursor is `old_cursor+header_size+length`. Every observed mapped input read made by the item helper is independently compared with its declared span. All834 retained item reads lie within those spans. This finite result is not a universal memory-safety proof. [C6]

Output stores at `0x1002fe928..0x1002fe938` update the cursor,tag,length and content pointer;`0x1002f04d4` stores status at argument+16. The partial callback record built from those outputs is independently checked against original file bytes142 times:

| Parsed-item offset / width,bytes | Field |
| --- | --- |
| +0 / 4 | Encoded tag: byte XOR `0x21e8ae22` |
| +4 / 4 | Encoded content length: XOR `0x8b3dc651` |
| +8 / 8 | Raw content pointer |
| +16 / 4 | Encoded complete TLV length: XOR `0x8b3dc651` |
| +24 / 8 | Raw TLV start pointer |

The SDK analytical views have sizes64,32 and48 bytes for helper arguments,parsed items and schema rows,respectively. Padding and total native allocation semantics are not inferred solely from those views. At `0x10044f7a4..0x10044f7b8`,the TBS callback directly copies item+16 to user-record+0 and item+24 to user-record+8,then returns zero. Later digest input covers that exact stored TBS encoding. [C1,C6,C8]

## Header behavior and canonicality boundary

The independent finite oracle matches358 successful item headers and10 rejections. Short lengths and tested definite long lengths work. The helper accepts nonminimal encodings such as `30 81 00` and `30 82 00 00` as zero-length items. `30 80 00 00` rejects; so do a one-byte header,truncated declared content,a tested four-byte extreme length,and a five-byte length-of-length. The tested high-tag-number prefixes1F andFF reject. A complete tag/length grammar for every mode and32-bit overflow case remains unknown. [C6]

Certificate fixture lengths span named/empty-name cases,version omission,64-/128-/256-byte synthetic moduli,algorithm OIDs,serial zero,and trailing bytes. Their signatures are zero,so reaching callbacks must not be described as authenticating them. The whole-certificate fingerprint excludes bytes after the root TLV even when the declared body contains those trailing bytes. The trailing-byte control reaches the same worker error; it does not establish successful file acceptance. [C3,C4,C8]

## Digest identification and exact source spans

At `0x1004904bc` and `0x10031cf48..0x10031cf60`,initialization stores five words. XOR with `0xf4f92df7` gives the SHA-1 IV from [FIPS180-4 section5.3.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). The new digest-writer proof covers a complete32-bit state word and its four big-endian output bytes,each encoded XOR0x98. Independent standard-digest oracles match42 SHA-1 outputs and one MD5 output at actual source-store epochs. This supports algorithm identification;it is not a complete formal proof of the implementation. [C8,C9]

| Encoded state word | Decoded SHA-1 IV |
| --- | --- |
| 93bc0ef6 | 67452301 |
| 1b34867e | efcdab89 |
| 6c43f109 | 98badcfe |
| e4cb7981 | 10325476 |
| 372bcc07 | c3d2e1f0 |

The synthetic empty-name certificate yields these independent end-to-end examples. Offsets are relative to the certificate body,not the whole supplemental file;the file adds12 bytes for this layout. The source sink addresses are private fixture addresses,not native pointers.

| Input span | Algorithm / decoded digest | Encoded output sink |
| --- | --- | --- |
| Complete certificate `[0,375)` | SHA-1 `ca12d534fc1027ad352c2ae57664daf315efeef4` | 70066724 |
| RSA public-key encoding `[88,228)` | SHA-1 `e861214f8ddb3176af535778566cf63e0c8aee73` | 700665a0 |
| TBS certificate `[4,228)` | SHA-1 `e716cd2475869f6ddc3db302c257d231eed41d22` | 700666d0 |

The public-key span is the encoded `RSAPublicKey` sequence inside the subject-public-key BIT STRING. Its schema and signature OID names are cross-checked against [RFC8017 appendixA](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A). Standard SHA-1 and [MD5](https://www.rfc-editor.org/rfc/rfc1321.html) computations are independent of the target instruction interpreter.

| Source callback / writer | Established data flow |
| --- | --- |
| 10040f7a4 / 1000c69b8,1000c69e8,1000c6a00,1000c6a04 | Entire root certificate TLV -> encoded SHA-1 fingerprint |
| 10000aecc / 100265474,1002654a8,1002654c0,1002654c8 | Encoded RSA public key -> encoded SHA-1 fingerprint |
| 10043e878 / 1002c38d0,1002c3904,1002c391c,1002c3924 | Stored TBS TLV with OID suffix5 -> encoded SHA-1 digest |
| 10043e878 / 100287c3c,100287c64,100287c8c,100287cb4 | TBS TLV with OID suffix4 -> encoded MD5 digest in its fixture |

The complete relevant OIDs are `1.2.840.113549.1.1.5`,`.4`,and`.11`. The first two drive observed digest modes2 and1. OID suffix11 reaches mode3 with output-size field zero; no standard TBS digest output is established for that fixture. It is unknown whether this denotes an intentionally empty mode,unsupported handling,or another protocol requirement. The initializer writes result marker `0x8519bd23` even in that case;the marker is not treated as a successful digest operation. A fixture changing only the inner OID causes an earlier error with no TBS digest context. [C3,C8]

The generic initializer at `0x10045c4f0` uses address key `((low32(P)^0xf9d49974)*0xda51a827) mod2^32`,proved from its original expression. In the observed input field+8,`((stored XOR key)&0x1ff) XOR0x1e` becomes the context algorithm selector. Its pointed context has a64-byte buffer,two32-bit counters,five encoded state words at+72,output size at+92,and selector at+96. This100-byte view describes the observed modes; it is not a complete type for every algorithm. Context initialization and retirement are separate from final digest outputs:post-retirement stack bytes are not interpreted as retained hash state. [C8,C9]

## Atomic state and environmental capability

The A72 case reaches `0x100a04c58`,original `casal w11,w0,[x19]`,and stops with an unsupported private CPU exception. The MAX counterpart executes the same330166 original instruction addresses through that instruction,with identical recorded pre-instruction registers and word. It then returns `0xffff5bd4`. No native synchronization operation executes. [C5,C10]

| Stage | Source / private state |
| --- | --- |
| Address | X19=`0x1010b5de0` |
| Before CASAL | Memory=`0x00005d96`,expected W11=`0x5d96`,desired W0=`0xa94ef` |
| After CASAL | W11 contains old value `0x5d96`;memory=`0x000a94ef` |
| Restoration | Original STR at `0x1009757d0` writes `0x5d96` back |

Nine retained MAX cases execute this transition; the verifier checks the actual single-thread compare-and-swap effect. These observations establish an encoded shared control-word interface,not its complete contention,ordering,initialization or reentrancy contract. The restoration is an ordinary STR in the inspected bytes; no release semantics are invented for it. Source image-write journals retain both transitions. [C5]

Across all retained paths,the outer protected record still reads only offsets0/4/16/24/36. Field+28 remains unconsumed. The results therefore do not identify it as a driver selector,algorithm parameter,signature width or operation. The corpus adds no Mach name,destination,right transfer or IOKit emission. Existing [port evidence](mach_ports_report.md) and [cross-layer ABI evidence](interface_abi_report.md) retain their native/synthetic boundaries. [C10]

## Verification and preservation

All **5931245 assertions** pass across44 fresh whole-worker sequences,5800739 retained original-source visits plus the same number freshly replayed,and30887 distinct instruction records. The source contracts include23 bounded spans in13 physical compiler ranges,896 consumed pointer/import records,26 schema rows,and six unsatisfiable local obligations. One satisfiable unaligned-key counterexample is retained separately. The SDK views compile for arm64e without executing compiled code.

| Independent check | Count |
| --- | --- |
| Original item-helper calls / successful headers / rejected headers | 368 / 358 / 10 |
| Actual item-span reads / source schema reads | 834 / 1195 |
| Source callbacks / parsed-item ABI records | 142 / 142 |
| Source stack-store epochs / live digest stores | 75173 / 16745 |
| Independent digest outputs:SHA-1 / MD5 | 42 / 1 |
| Zero-output-size algorithm contexts | 1 |
| Whole-worker returns / unsupported A72 boundaries | 43 / 1 |
| Original CASAL effects | 9 |

[Scoped quality gates](triage_evidence/rpc502_certificate_quality_gates.json) and [preservation](triage_evidence/rpc502_certificate_preservation.json) include current source identity and final link/artifact checks. Of977 previous artifacts,971 remain byte-identical;only the four reporting indexes,the active-status file and the delivery aggregator change. The three original supplied inputs remain unchanged. No original binary or IDB is written.

Reproduction from `/Users/___/dev/dylex/extracted`:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_certificate_cases.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_certificate.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_certificate.py
```

External API results remain declarations. Fresh replays use four isolated Python processes with ordered,bounded results;this is verification scheduling,not target concurrency. Complete replay compares canonical JSON byte journals,including source-generated records,pointer reads,digest lifetimes and source stores. Time/space are O(C*(B+V+E+S)) for bounded cases,bytes,visits,events and snapshots;compiler partitioning additionally uses O(R log F) lookups. Local solver obligations have60000 ms limits. No SI quantity is inferred from a software step count;integer widths,byte extents and modulo arithmetic are explicit.

| Gate | Scoped result |
| --- | --- |
| QG1 | Pass: descriptive source analysis;no normative premise. |
| QG2 | Pass:C1-C10 state dependencies and falsification probes. |
| QG3 | Pass for this increment:body grammar,callback ABI,schema,digests,CPU state;full goal remains active. |
| QG4 | Pass:byte spans,u32/u64 widths,aligned-key constraint,SDK views,standard digest oracles and bounded complexity. |
| QG5 | Pass:parser success versus authentication,nonminimal lengths,table interpretation,context retirement,zero-size mode and CPU boundaries remain distinct. |
| QG6 | Pass:current original bytes/fixups/metadata,six local proofs,all44 fresh source sequences,independent record/digest checks and linked primary standards. |
| QG7 | Pass:bounded continuation table below. |

## Bounded continuation opportunities

| Impact | Next evidence | Consequence resolved |
| --- | --- | --- |
| High | Trace the post-CASAL original control path to the producer of `0xffff5bd4`,including actual global initialization and every exit. | Distinguish initialization,resource,policy and certificate errors without naming a reused numeric status by analogy. |
| High | Recover signature callback100421ec4,issuer/key selection,trust predicates and a valid authenticated record. | Actual certificate authentication and the first feasible downstream driver/Mach interface. |
| High | Follow the first real consumer of outer record+28 after its predecessor gates. | Its semantic role and complete protected-operation ABI. |
| Medium | Recover the public-key sub-schema,integer normalization,key-size/capacity rules and associated scratch lifetimes. | Complete RSA key representation beyond structural fixtures and fingerprints. |
| Medium | Resolve algorithm selector3 and full inner/outer OID policy. | Whether zero-size digest state is intentional,unsupported or constrained elsewhere. |
| Medium | Exercise A1/A2,GeneralizedTime,extension loops,nonminimal complete certificates and alternate item modes. | Actual accepted grammar and policy versus the RFC-derived field-name interpretation. |
| Medium | Follow digest sinks and TBS/key records into daemon output and kext consumer records. | Cross-layer record linkage and successful reply/output semantics. |
| Low | Compare source ranges with the live IDB when its bridge is reachable. | Current database correspondence;file-backed findings are already reproducible. |
