# RPC502 signed-prefix, signature-span and public-operation interfaces

Original worker execution now links three previously opaque carrier fields to a signed-data path. Field+8 supplies a prefix extent;the source-produced32-byte digest equals SHA-256 of that exact prefix. Field+40 contributes the pointer to a signature after the embedded certificate and its following length word. Field+28 supplies the signature extent C,checked against four times the decoded modulus limb count. A source-built public-operation record carries exponent,modulus,signature,input/output buffers and an exported byte count.

Matched inputs distinguish width rejection from a later rejection after local public-operation success,although both return `0xffff5bd9`. Zero and a within-range nonzero signature representative are checked against independent public modular exponentiation. No accepted signed operation,new native Mach/IOKit emission or complete trust/padding implementation is established. The broad interface goal remains active and incomplete.

This extends the frozen [AAA continuation](rpc502_policy_report.md),[RSA integer/arithmetic interfaces](rpc502_rsa_report.md) and [supplemental file layouts](rpc502_supplemental_report.md). Historical statements that C,+8 or+40 have no observed consumer remain scoped to their earlier corpora.

## Assumption register and provenance

| ID | Assumption | Dependent results | Stress test / falsification probe | Boundary |
| --- | --- | --- | --- | --- |
| L1 | The exact original daemon slice is the intended source | Addresses,codecs,source calls and source-built records | Recheck thin/universal SHA,UUID,opcodes,fixups and compiler ranges;attest native provider/slice pairing separately | Original file provenance checked;native pairing unknown |
| L2 | The original registered startup callback supplies the retained predecessor | Worker data/control flow and observed calls | Require actual callback return;preserve source state into worker;recover alternate startup writers | Complete process startup not executed |
| L3 | Explicit inherited API/PAC/MAX/heap/serial-lock declarations apply to these private cases | Finite paths,allocations,returns and cleanup | Reject unknown bytes/owners/imports;vary declared inputs;compare native PAC/scheduling independently | No native target,filesystem,Mach,IOKit,loader,credential or synchronization API execution |
| L4 | Both external files are fixed before all guest instructions | Attribution of differences to C,A,selector or signature bytes | Check exact file strings and source reads;fresh whole-worker replay;reject internal PC/frame/record/gate overrides | Matched C cases isolate C;A/selector/signature controls are separately declared |
| L5 | Selected source-built views identify active fields only | Carrier/public-operation/key layouts and output byte counts | Check original stores/readers,actual call/return state,source byte epochs and SDK offsets | Complete source types,padding and remaining controls unknown |
| L6 | The local width expression retains recorded dispatch seed1daa | Full32-bit width identity | Recheck source shifts/flags,all-u32 proof,actual raw count and branch operands;vary seed separately | Modular scalar equivalence;not valid header capacity or native extent proof |
| L7 | Original source stores and guarded heap masks establish the selected bytes | Prefix/digest/key/packet/export provenance | Reconstruct source byte epochs,require heap masks,compare independent raw-file/hash/math oracles | Before-instruction points may share a counter with their preceding executed store;inactive snapshot bytes excluded |
| L8 | Matching independent outputs establishes only the retained computations | SHA-256 prefix and zero/nonzero public output | Vary actual nonempty prefix/signature bytes;compare full outputs;recover algorithm control and all callers | Finite observations and local scalar proofs;not unrestricted implementation equivalence |
| L9 | Local success and standard mathematical encoding are separate from complete target acceptance | Distinct rejection stages and public-operation interpretation | Trace every caller/padding/status/trust gate and actual operation/transport consequence | Workers still fail;complete padding language,authorization and native transaction unknown |

[Four matched controls](triage_evidence/rpc502_late_profiles.json),[two nonempty spans](triage_evidence/rpc502_late_span_profiles.json) and a [nonzero signature](triage_evidence/rpc502_late_signature_profiles.json) retain complete original callback/worker journals. [Contracts](triage_evidence/rpc502_late_contracts.json) retain12 selected source spans in9 physical compiler intervals,1547 consumed pointer/import records,two scalar proofs,a modular counterexample and an SDK partial view. The [main verifier](triage_evidence/rpc502_late_checks.json) and [nonzero verifier](triage_evidence/rpc502_late_signature_checks.json) independently check source bytes,selected epochs,raw input reads,full outputs and fresh canonical executions. Physical compiler intervals are not assumed to be complete semantic routines. [L1-L9]

The read-only [IDA availability query](triage_evidence/rpc502_late_ida_context.json) returned `IDA Assist is not reachable` and no database facts. No live IDB bytes or knowledge-store facts are claimed for this increment. Original source files and the preserved evidence suffice for the contracts below. Prior memory supplied procedural guidance about exact source provenance and preserving parser-created predecessor state,not new target semantics. [L1,L2]

## Exact version5 wire and data-flow boundaries

All offsets and extents below are bytes. The byte-span controls use A=0,1,4;the certificate has B=719 bytes. Earlier reports establish the separate version1/4 layouts;the new matched span/hash cases use version5 only. [L4,L8]

| Wire location | Observed field / role |
| --- | --- |
|0..3 |First byte5;three retained zero bytes |
|4..7 |BE32 A |
|8..8+A-1 |A explicit payload bytes;empty,a5 hex,or01234567 hex |
|8+A..11+A |BE32 certificate length B |
|12+A..11+A+B |Raw DER certificate:embedded fairplayd leaf under AAA |
|12+A+B..15+A+B |BE32 signature extent C |
|16+A+B..15+A+B+C |Raw signature bytes;actual reads additionally depend on the local width gate |

```text
version5 mapping
+----------------------+-------+----------------+-------+-----------------+
| byte5 + BE32 A + data | BE32 B| DER certificate| BE32 C| signature bytes |
+----------------------+-------+----------------+-------+-----------------+
[0,8+A) ---- SHA-256 ----> source-produced32-byte digest
                              |
certificate chain ->two prior local successes
                              |
C == 4*decoded modulus limb count
         false ->width rejection ->ffff5bd9
         true  ->signature input ->public operation ->encoded output
                                                   ->later reduction fails
                                                   ->ffff5bd9
```

The observed SHA-256 prefix excludes the B word,DER certificate,C word and signature bytes. Certificate authentication and signature-width validation are separate source paths. This byte partition alone does not establish an unbound metadata field or a vulnerability;all transitive checks and complete accepted operations remain unknown. [L8,L9]

## Carrier fields, signed-prefix hash and physical representations

For carrier pointer P,the preserved address key is `Kp=((low32(P) XORc6d66014)*6b86592f) mod2^32`;K below is8b3dc651 hex. [L5]

| Field / source site | New established use | Exact retained representation |
| --- | --- | --- |
|+8 /100747f84 |Prefix allocation/processing extent |`((stored8 XOR Kp)+d51c85f8) mod2^32`;equals8+A in the retained span cases |
|+28 /100747f70 |Signature extent C |`((stored28+Kp) mod2^32) XOR K` |
|+40 /100747f7c |Contributes signature offset after certificate/C |Intermediate `aux=stored40-Kp mod2^32`;later status-sensitive equation below |
|100919330 |Prefix `_malloc` call |8,9 or12 bytes for A=0,1 or4 |
|100a0a5e8 |Digest `_malloc` call |32 bytes |
|100647ad8 /100647ba4 |Raw prefix byte load /encoded private-prefix store |Exactly8+A raw bytes read in descending order;complete internal prefix codec unknown |
|100882f08 |Source-produced digest byte store |All32 output bytes;decoded by byte XOR98 |
|10008eaf4 |Raw signature byte load |128 descending bytes only after the width gate passes |

The encoded private prefix and the encoded digest are different physical representations. The prefix bytes are reconstructed from original stores without assigning a complete inverse codec. The digest's32 bytes XOR98 match an independent SHA-256 of the exact raw prefix. Source-knownness masks and full selected owner ledgers agree. [L5,L7,L8]

| A / payload | Hashed extent | Independent SHA-256 of raw prefix |
| --- | ---: | --- |
|0 /empty |8 |f13ee6ed54ea2aae9fc49a9faeb5da6e8ddef0e12ed5d30d35a624ae813e0485 |
|1 /a5 |9 |9c9bc65398a1e8d4c330669d28df769816a39e0de56942b591b812a58d661d4f |
|4 /01234567 |12 |d55a386d82bf1149cf663f6afff182f831fdc27d7cd2c173d75a856ea6787f63 |

C=0,128 and129 produce the same prefix hash with A=0. Changing first-file inner selector1 to2 with the retained zero scalar fields also preserves this hash. Neither observation proves independence from every possible C,first-file field or environmental state. [L4,L8]

SHA-256's standard digest length is256 bits,or32 bytes. The NIST standard supplies the algorithm reference;identification here comes from independently matching the original worker outputs and exact input extents,not from a routine label. [FIPS180-4,2015,DOI10.6028/NIST.FIPS.180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

## Signature pointer and width predicates

At `100a8b838..100a8b878`,let s be W11 on entry,t be the saved u32 at SP+110,and aux the decoded+40 intermediate. All scalar operations below are modulo2^32:

```text
expected = (((s+0x83b4) XOR0x8b3d25e5)+s)
offset   = aux+s+0xd59ecc1e - (t==expected ?1:0)
input    = mapping_base + zero_extend_u32(offset)   [u64 addition]
```

The scalar offset equivalence is proved for all triples of32-bit aux,t,s. The actual pointer ADD at100a8b880 is checked separately. In the retained version5 cases,the offset is `16+A+B`:735,736 or739 bytes for A=0,1 or4. The source mapping reader at10008eaf4 consumes the exact128 bytes beginning there when C passes. This proves a concrete signature span under the retained state;other statuses/builders and full size/overflow guards remain unknown. [L5-L8]

The source width gate at `100a21958..100a21ac4` uses a raw biased modulus count and saved `C XOR K`. Under the recorded W12=1daa,its complete32-bit expression is equivalent to:

```text
C == (4 * (stored_modulus_count -0x693be708)) mod2^32
```

The actual count word693be728 decodes to32 limbs,so the observed byte width is128. C=128 passes,C=0 and129 fail. The two matched failures perform the same prefix hash and pointer derivation but do not read the signature bytes or enter the later public operation. [L6,L8]

A separate local scalar counterexample uses decoded count40000000 hex and C=0:the product wraps to zero and the local equality holds. This is not a valid header,allocated extent,worker input or native-reachability claim. The source's preceding count/capacity/extent gates must be recovered independently before promoting a local modular alias to a program-level result. [L6,L9]

## Reused certificate and file verification machinery

The [independent reuse check](triage_evidence/rpc502_late_reuse_checks.json) audits21 visits to the same local width gate across all seven profiles. The original source carries three distinct verification contexts through that gate:

| Retained use | Modulus active limbs | Signature extent,bytes | Digest-size carrier,bytes |
| --- | ---: | ---: | ---: |
| Embedded AAA certificate under Root public key |64 |256 |20 |
| Supplied embedded leaf under AAA public key |32 |128 |20 |
| Supplied file signature under leaf public key |32 |C |32 |

The first two local width checks pass in every retained case. The third follows the supplied C value. The original dispatch seed is1daa in all21 observations. This establishes reuse of the same local width/verification machinery across certificate-chain and file-signature contexts,with the recorded SHA-1 certificate tails and the newly matched SHA-256 file prefix kept separate. It is not a complete call graph or proof of every hash/padding flavor. [L5,L6,L8,L9]

## Source-built public-operation record and export

The actual call at `100657488` targets100abebe4 and proceeds through original wrappers. Its selected80-byte built prefix exposes the following fields. Unknown words and control codecs remain unnamed. The [SDK view](triage_evidence/rpc502_late_layouts.c) verifies offsets and selected C layout size;it is an analyst type. [L5]

| Record offset / width | Established selected role |
| --- | --- |
|+8,pointer64 |Public exponent integer header:leaf record+320 hex |
|+16,u32 |Local result output;source writes8b3dc651 hex on retained public-operation success |
|+32,pointer64 |Modulus integer header:leaf record+210 hex |
|+40,pointer64 |Caller-owned exported extent u32;source publishes raw128 |
|+56,pointer64 |Output byte buffer;retained128-byte output uses byte XOR98 |
|+64,pointer64 |Raw mapped signature span after certificate and C word |
|Other selected bytes |Unknown controls/state;no complete source prototype claimed |

Active source-built key fields match the embedded leaf's1024-bit modulus and exponent65537. The signature input is big endian. For all four zero-signature controls that reach the operation,the source exports128 XOR98 zero bytes,returns its local success word,and publishes exported extent128. The nonzero control uses an existing public certificate signature reduced modulo the leaf modulus;it is not a newly authenticated signature. Its full decoded128-byte output matches independent `pow(S,65537,N)`. [L5,L7-L9]

The captured calls reach the same original square/product entries established in the [arithmetic report](rpc502_rsa_report.md). That report provides separate nonzero2048-bit full-product/row evidence. This increment checks complete1024-bit public outputs and their byte ABI;it does not claim new full-domain equivalence of every integer helper or every key size. [L8]

For zero inputs,the output cannot equal a standard PKCS#1 v1.5 encoded message. The original later reduction at100950fd8/10095103c nevertheless remains a separately observed local failure:under the observed W9=W10=1 seeds,the raw low byte differs from a2 and the result is74c29d8a hex. The complete target padding parser and acceptance language remain unknown. The mathematical encoding reference is [RFC8017,section9.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.2). [L9]

The two prefix/digest allocations each receive one source-requested `_free` in every retained case. Actual call/return pairs and source-defined data epochs are retained. These local modeled ownership observations do not establish complete native allocation,FD,mapping or IPC lifetime. [L3,L7,L9]

## Verification, preservation and continuation

The [main checks](triage_evidence/rpc502_late_checks.json) pass86776514 assertions;the [nonzero checks](triage_evidence/rpc502_late_signature_checks.json) pass15453242. Together they verify101899360 retained original-source visits and the same number freshly replayed across seven complete workers. The reuse audit adds42 checks across21 shared-gate observations. The main corpus covers53 prefix bytes,512 conditional signature bytes,six independent SHA-256 outputs,four admitted widths,two rejected widths and four locally successful public operations. The additional nonzero case checks another128 signature bytes and the full nonzero1024-bit output. Every retained opcode,selected original fixup,byte epoch and complete canonical replay is checked;the two local proofs and SDK compilation are freshly rerun.

Reproduction from the extracted directory with the existing analysis interpreter/runtime:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_late_cases.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_late_spans.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_late_signature.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_late.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_late.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_late_signature.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_late_reuse.py
```

Time/space are O(C*(B+V+E+S)) for cases,source bytes,visits,events and retained state,plus bounded integer arithmetic. Prefix hashing is O(A+8) input work for the stated spans. Each local SMT solver is bounded to60000 ms. Scalar counts,widths,bit/byte conversions and source extents are explicitly distinguished.

A [bounded filename inventory](triage_evidence/rpc502_late_sidecar_inventory.json) finds no `.sinf`,`.supf` or`.supp` candidate in the supplied zut/fpx roots. Other paths,formats and installed metadata were not searched. This does not establish absence of an accepted signed input.

[Preservation](triage_evidence/rpc502_late_preservation.json) checks1081 prior artifacts,1075 byte-identical plus six permitted reporting/index/aggregator updates. Original supplied inputs,source binaries and IDBs remain unchanged. [Scoped quality gates](triage_evidence/rpc502_late_quality_gates.json) include final source identity,hashes,links,replay and preservation readback;full_goal_complete remains false.

| Impact | Bounded next question | Evidence required |
| --- | --- | --- |
| High | Complete signed-data verification and later failure | Recover every output-byte/padding/hash comparison and precise failure producer;use original external inputs without gate changes |
| High | Successful protected output and daemon/kext/deeper coupling | Establish genuine accepted input/state,then match actual request/reply bytes,ports,rights,provider and selected slice |
| High | Full certificate-family and signer/key policy | Recover exact AAA/Key-Services selection and all name/OID/identity/trust controls |
| Medium | Hash coverage and canonicalization for other formats | Recover version1/2/3/4 prefix builders and bounds;compare nonzero variable records and native producers |
| Medium | Complete public-operation ABI and arithmetic lifecycle | Recover remaining80-byte controls,stack-seed conventions,capacity/range checks,alternate algorithms and nonstandard extents |
| Medium | Internal prefix representation | Recover complete position/state-dependent byte encoder/decoder and its consumers;digest equality alone does not identify that codec |

QG1:factual analysis. QG2:L1-L9 assumptions and falsification probes. QG3:late signed-data increment covered;full interface goal active. QG4:widths,byte extents,wrap counterexample,two local proofs,SDK and complexity. QG5:width versus later rejection,zero versus nonzero data,local success versus native acceptance. QG6:original source/fixup/metadata,exact raw reads,source epochs,independent SHA-256/public arithmetic and fresh replay. QG7:bounded impact table above.
