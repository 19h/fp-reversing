# RPC502 exported-block byte checks and digest comparison

Original execution now identifies the readers of the public-operation output:two header bytes,a fixed FF padding region,a zero separator,a selected DigestInfo prefix,and the digest tail. The two workers expose four successful certificate-stage comparisons and two failing file-stage comparisons. Both workers still return `0xffff5bd9`;accepted signed processing and new native Mach/IOKit transport remain unknown.

The [late interface report](rpc502_late_report.md) established the preceding key/signature/output ABI. This increment adds exact read regions,original prefix literals,local mismatch folds and source byte epochs. It does not prove the complete acceptance language,all caller-state combinations,all algorithms or native trust behavior. The broad interface goal remains active and incomplete.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe | Boundary |
| --- | --- | --- | --- | --- |
| B1 | The exact supplied daemon slice is the intended implementation | Addresses,source literals,opcodes and fixups | Rehash thin/universal bytes,UUID,compiler ranges and consumed pointer records;attest native pairing separately | Original file identity verified;live IDB/native pairing not refreshed |
| B2 | The actual original startup callback supplies the retained worker predecessor | All six observation windows | Require callback return;carry source state into worker;inspect alternate startup writers | Complete process startup not executed |
| B3 | Explicit inherited API/PAC/MAX/heap/serial-lock models apply to these cases | Finite paths,returns and ownership | Reject unknown imports/owners/bytes;compare native scheduling/PAC and provider behavior separately | No native target,filesystem,loader,Mach,IOKit or synchronization API execution |
| B4 | Observation starts only after actual export return and ends at the recorded local result boundary | Byte-role and read-coverage findings | Recheck actual call/return PCs,buffer pointer/extent and window ends;inspect other callers/windows separately | Four certificate windows end at8969a8;two file windows end at95103c |
| B5 | The selected active bytes were defined by original source before observation | Block,digest and literal provenance | Reconstruct last stack-store epochs;require heap masks;compare original ROM bytes and independent public/hash outputs | Private buffers are reused between stages;inactive snapshot bytes are excluded |
| B6 | Recorded dispatch seeds and byte/word widths apply to each local lift | Seven scalar identities | Check every relevant live seed,LDRB width,shift and operation;rerun bounded SMT proofs | Local proof domains are explicit;not arbitrary caller states or complete acceptance |
| B7 | Public exponentiation and independently hashed messages provide separate byte oracles | Positive/negative block and digest interpretation | Recompute original DER signatures/TBS SHA-1 and file-prefix SHA-256;compare entire exported blocks | Mathematical relations do not establish native trust or accepted operation |
| B8 | Two complete retained/fresh cases support finite behavior only | Loop coverage,early exit and status observations | Compare full canonical replays;review other sizes,algorithms,malformed encodings and caller conditions independently | Complete malformed-input acceptance and generalized timing behavior remain unknown |

[Retained profiles](triage_evidence/rpc502_padding_profiles.json) and [distinct fresh replays](triage_evidence/rpc502_padding_replays.json) preserve original input files and complete source journals. [Contracts](triage_evidence/rpc502_padding_contracts.json) retain12 source spans in7 physical compiler intervals,1541 consumed pointer/import records,seven local proofs and two original ROM prefixes. [Independent checks](triage_evidence/rpc502_padding_checks.json) verify source bytes,selected data epochs,public outputs,region readers,fold states,digest comparisons and whole-worker equality. Compiler intervals are not assumed to be complete semantic functions. [B1-B8]

## Byte-region and source-site mapping

All offsets/extents are bytes. Exported blocks and expected digest/prefix bytes use byte XOR98. Let N be the exported block width,h the digest extent,and p the selected DigestInfo-prefix extent. The observed padding count is `N-h-p-3`. [B4-B7]

| Reader PC | Selected role | Observed block-relative extent |
| --- | --- | --- |
|1009d8fd0 /1009d8fd4 |Header bytes |0 and1 |
|100a75bf8 |FF padding bytes |2 through`1+N-h-p-3` |
|1009329b4 |Separator byte |`N-h-p-1` |
|100656dbc /100656dc4 |Candidate prefix /original ROM prefix |p forward byte pairs,starting at`N-h-p` |
|100882dd0 /100882dd4 |Candidate digest /expected digest |Forward byte pairs,starting at`N-h`;stop at first mismatch or completion |
|100a46c04..100a46cc0 |Mismatch difference |Decoded candidate byte minus decoded expected byte |
|100a61564 /100a6156c |Additional post-comparison byte reads |Recorded separately from the primary digest loop |
|100950fd8..100951038 |Raw local-status reduction |Observed W9=W10=1;not a complete verifier-result specification |

| Verification context | N | h | p | FF bytes | Separator offset | Digest start |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AAA certificate under Root public key |256 |20 |15 |218 |220 |236 |
| Supplied embedded leaf under AAA public key |128 |20 |15 |90 |92 |108 |
| File signature under leaf public key |128 |32 |19 |74 |76 |96 |

```text
actual public-operation export returns
  -> header[2] -> FF region -> separator -> fixed prefix -> digest tail
                                                      |
                                  all digest bytes equal /first mismatch
                                                      |
                                  local result reduction and caller use
```

These fixed-region readers execute even for the two failing file blocks. The digest loop compares20 bytes in each successful certificate stage and one byte in each failing file stage. This is software read/control-flow evidence,not a native timing or constant-time implementation claim. [B4,B8]

## Local mismatch folds and fixed literals

For encoded header bytes a,b,the source's selected word equals `d036cea0 XOR((a XOR98) OR(b XOR99))`. Each padding byte contributes `byte XOR67`;a correct encoded FF byte is67. The separator contributes `byte XOR98`. Prefix byte pairs contribute their raw XOR because both arrays use the same98 encoding. Within the proved byte-state domains,the mismatch mask accumulates by OR. Original source seeds and each actual successor state are independently checked. [B5,B6]

| Selected boundary | Observed zero-error word | Local proof domain |
| --- | --- | --- |
|Header/padding |d036cea0 |Header:all65536 byte pairs,W25=7249;pad:all prior-error8/current-byte8 pairs,W10=67d0 |
|Separator output |40df01a2 |All prior-error8/separator-byte8 pairs,W10=67d0 |
|Fixed-prefix loop |62b16bcc |All prior-error8/candidate8/reference8 triples |
|Mismatch difference |Decoded candidate minus decoded reference |All pairs of32-bit words,W15=4a29;actual operands are byte loads |
|Auxiliary failure fold |40df015d |All256 selected bytes with that fixed incoming failure word only |
|First result reduction |8b3dc651 iff raw word's low byte is a2;74c29d8a otherwise |All32-bit raw words,observed W9=W10=1 |

The final two rows remain local statements. They do not establish the result for arbitrary combinations of caller flags,comparison outcomes or auxiliary state. The finite complete-block oracle agrees with the six observed stage results;complete malformed-input acceptance remains unknown. [B6,B8]

The original readonly prefix literals decode by byte XOR98 to:

| Digest context | Original address | Decoded DigestInfo prefix |
| --- | --- | --- |
|SHA-1,20-byte digest |100ee5a50 |3021300906052b0e03021a05000414 |
|SHA-256,32-byte digest |100f1fc42 |3031300d060960864801650304020105000420 |

These are15 and19 bytes respectively. The byte sequences and region arrangement correspond to the deterministic encoding described in [RFC8017,section9.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.2). That reference supplies format context,not proof of the target's complete conformance or accepted-input language. [B6-B8]

## Digest pointers, mismatch values and caller boundaries

The primary digest loop loads the candidate from the exported block's last h bytes and the expected value from a separate source-created digest buffer. The first two expected digests equal independent SHA-1 computations over the original certificate TBS bytes;the third equals SHA-256 of the retained version5 file prefix. The original `LDRB` results,forward pointer increments and byte equality branches are retained. [B4,B5,B7]

| File signature input | Candidate first digest byte | Expected first digest byte | Signed first difference | Observed first reduction |
| --- | ---: | ---: | ---: | --- |
|Zero representative |00 |f1 |-241 |74c29d8a |
|Within-range nonzero representative |4f |f1 |-162 |74c29d8a |

The source mismatch word is exactly `(candidate XOR98)-(expected XOR98) mod2^32`. For actual bytes,the signed difference lies in[-255,255]. The compared raw bytes are encoded;the table above shows their decoded values. Both inputs remain mathematically unauthenticated file signatures. [B6,B7]

The four valid certificate-stage blocks match the independent full encoding,compare all20 digest bytes,produce first reduction8b3dc651 and reach the later local conjunction at8969a8 with the same success word. The two file-stage windows close at the failing first reduction95103c. Both file blocks also have header,padding,separator or prefix mismatches;the repeated outer result does not isolate a single failing predicate. [B4,B8]

The two auxiliary read sites100a61564/100a6156c and the following state-mixing path are recorded separately from the main digest loop. The fixed-failure-word proof is deliberately limited to the observed incoming word. No generalized acceptance result is inferred from those extra reads. [B6,B8]

## Verification, preservation and bounded continuation

All **30042711 counted assertions** pass. The corpus includes two complete fresh worker replays,29969824 retained original-source visits and the same number freshly replayed,64548 distinct instructions,six full public-output blocks totaling1024 bytes,and2474 post-export data-read events. The verifier checks968 encoded-block reads,764 padding bytes,6 separators,98 fixed-prefix byte pairs,82 digest pairs,2032 stack-byte epochs and42 source-known expected heap bytes. All seven local proofs are freshly rerun. These counts describe this increment,not a completion metric for the broad goal.

Reproduction from the extracted directory:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_padding_cases.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_padding_replay.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_padding.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_padding.py
```

The byte loops perform O(N) work for the observed block widths,with early exit in the primary digest comparison. Retained source/profile work is O(C*(B+V+E+S)) for cases,source bytes,visits,events and state,plus bounded public-key arithmetic. Each local solver has a60000 ms timeout. Extents are bytes;20/32-byte digests correspond to160/256 bits,and128/256-byte blocks to1024/2048 bits. No new original C type or complete function prototype is inferred from these byte views.

[Preservation](triage_evidence/rpc502_padding_preservation.json) checks1110 prior artifacts,1104 byte-identical plus the six permitted reporting/index/aggregator updates. Original supplied files,source binaries and IDBs remain unchanged. [Scoped quality gates](triage_evidence/rpc502_padding_quality_gates.json) include final identity,source,proof,replay,link and preservation readback. No new native Mach/IOKit emission or accepted signed operation is established.

| Impact | Bounded continuation question | Evidence required |
| --- | --- | --- |
|High |Complete verification result and caller-state mapping |Review all result carriers,auxiliary state and caller conditions;local folds and six stage observations do not prove the whole acceptance language |
|High |Accepted protected output and transport coupling |Establish accepted input/state,then match request/reply bytes,port objects,rights and provider/slice identity |
|Medium |Other sizes,algorithms and malformed encodings |Recover complete minimum-size,overflow,algorithm-selection and buffer-bound predicates independently |
|Medium |Ownership and auxiliary state |Trace complete buffer reuse,cleanup,global state updates and alternate exits across callers |

QG1:factual analysis. QG2:B1-B8 assumptions and probes. QG3:byte-contract increment covered;full goal active. QG4:explicit widths,regions,proof domains and complexity. QG5:local versus complete results,positive versus negative stages and multiple failing regions distinguished. QG6:original opcodes/fixups/ROM,source epochs,independent hash/public outputs and fresh replay. QG7:bounded impact table above.
