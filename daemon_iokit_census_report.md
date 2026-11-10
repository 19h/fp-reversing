# Daemon IOKit caller census and version/capability query contract

The daemon has a source-backed selector22/23 query sequence compatible with the supplied FairPlayIOKit `ucGetVersion` and `ucGetProtocolCapabilities` endpoints. Both calls use zero input bytes and a four-byte output capacity. Each daemon guard requires status32=0 and returned size64=4; otherwise source clears that query's output. The second query still executes after the first query is rejected.256 fresh private cases independently vary the two responses;13 source proof pairs cover all status32/size64 values under the stated entry premises. Native open, actual version/capability values, port identity and a selector18 caller remain unknown. [DC1-DC12]

A separate whole-text syntactic census finds24 exact immediate-modifier call sites. Twelve windows prepare selectors21,22,23 or26, but discriminator0x7A6C also occurs on three daemon-local rebase slots. Target identity requires pointer/table provenance. No selector18 caller is established; absence from this narrow pattern does not establish absence from fairplayd or its linked modules.

[Source contracts and candidate windows](triage_evidence/daemon_iokit_census_contracts.json), [retained cases](triage_evidence/daemon_iokit_census_profiles.json), [fresh replays](triage_evidence/daemon_iokit_census_replays.json), [independent checks](triage_evidence/daemon_iokit_census_checks.json), [source proofs](triage_evidence/daemon_iokit_census_proofs.json), [live IDB snapshot](triage_evidence/daemon_iokit_census_live_ida.json), [source identity](triage_evidence/daemon_iokit_census_source_identity.json), [preservation](triage_evidence/daemon_iokit_census_preservation.json) and [scoped gates](triage_evidence/daemon_iokit_census_quality_gates.json) retain the evidence. The full objective remains active.

```text
native open / predecessor state [unknown]
  -> declared source entry at0x100364398
  -> query22(connection,NULL,0,SP+0x64,&size64=4) [API response model]
  -> status32==0 AND size64==4 ? keep returned word : clear word
  -> query23(connection,NULL,0,SP+0x6C,&size64=4) [API response model]
  -> status32==0 AND size64==4 ? keep returned word : clear word
  ->0x1003C39B0 [stop before joint consumer]

compatible kext endpoints [source association; live object unknown]
  selector22 -> ucGetVersion -> provider vtable+0x8C0 -> uOxAg
  selector23 -> ucGetProtocolCapabilities -> vtable+0x8C8 -> Q5TC6
```

All addresses are preferred file VAs. B denotes bytes. Connection0x5804, response words and API outcomes are explicit private fixtures; they are not native port names or observations.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
|DC1 |Pinned daemon thin image, universal IDB and KC identify the inspected builds |Source/annotation/counterpart correspondence |Rehash originals; compare105 live instruction rows and512 byte-table bytes with original source |
|DC2 |Exact aligned `MOVZ X17,#0x7A6C; BLRAA X8,X17` defines the census |24 candidates |Independent four-byte scan; computed modifiers, other registers/forms and linked modules remain outside this census |
|DC3 |Query entry W21=0x9376,X24=0x101039EF0 |Local query phases and targets |Source-lift phases and verify original slots; recover native predecessor separately |
|DC4 |Saved frame pointers/connection cell have the declared aliases and extents |Query arguments and common consumer |Reconstruct every byte epoch across two frame placements; source frame/port origins remain conditional |
|DC5 |Private A64 execution and abstract PAC match the declared model |Finite source paths |Verify every instruction byte, original binding and branch slot; native authentication remains unknown |
|DC6 |Two API summaries return normally and preserve callee-saved state |Composed query sequence |Clobber X1-X17/NZCV, independently vary both responses; no native IOKit/port or synchronization effect is modeled |
|DC7 |Status0,size4 summaries supply one explicit u32 value; other outputs stay unknown until source clears |Output/provenance claims |Verify API/source provenance and all448 failure clears; no partial response contents are invented |
|DC8 |Returned size is the complete64-bit size_t cell |Status/extent acceptance |Prove all u64 sizes;128 responses with size0x100000004 are rejected |
|DC9 |Live IDB import bytes are loader representations |IDB/file comparison |Check import bind metadata separately; source chained word and IDB external address must not be compared as identical bytes |
|DC10 |Static provider vtables describe the declared base-class route |Kext query counterparts and obfuscated roles |Verify exact symbols/slots/diversities and UserClient source; actual runtime vptr/overrides remain unknown |
|DC11 |Provider calls return and output pointers are valid |Kext low32 publication/outer zero return |Source-lift all provider-result64 values; core getter values and complete native query execution remain unknown |
|DC12 |Matching selector/layout establishes compatibility, not active routing |Daemon/kext association |Capture actual connection ownership, framework binding and transaction; none is supplied here |

DC1-DC12 qualify dependent claims. The entry fixture begins after a conditional open-success path. Earlier analysis required additional selector/global-byte/helper premises; those native prerequisites are not promoted to facts by these local cases.

## Whole-text call census and discriminator collisions

The original `__text` scan covers14849960 B, or3712490 four-byte units. Independent raw-byte and aligned-word scans agree on24 instances. Candidate windows are bounded to at most148 B; compiler metadata ownership is recorded separately. A shared LC_FUNCTION_STARTS envelope is not a complete semantic routine and is not dumped as one.

| Local W1 preparation | Candidate source call PCs |
| --- | --- |
|21, input extent552 B |0x10020b568;0x10040dc18;0x100478a04;0x10048f4f0;0x100580640;0x100757518;0x100b128a8;0x100be6a64 |
|22 |0x100364420 |
|23 |0x1004ba9c4 |
|26 |0x1002069c4;0x100293074 |

The remaining candidate windows retain unresolved target/argument provenance. A last literal seen in a bounded window is only a hint unless its reaching definition is established. In particular, the additional0x7E1 hint is not assigned an IOKit selector. No computed selector is classified by this literal census.

| Original slot with diversity0x7A6C | Original decoded target |
| --- | --- |
|0x1010a04c8 |Daemon rebase0x100440d6c |
|0x1010a0560 |Daemon rebase0x100454640 |
|0x1010a05b8 |Daemon rebase0x10041e8d0 |
|0x1010a0640 |IOKit `_IOConnectCallStructMethod`,import ordinal104 |

The API bind belongs to `/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit`; its original format12 word is0xC0087A6C00000068, IA diversity0x7A6C, address diversity0, total addend0. The live IDB rewrites that pointer cell to external address0x1010CA388. That is an IDB loader representation, not an observed loaded-framework address.

The source/API targets at the two query sites are established with two exhaustive byte-bank rules under table-base premise DC3:

| Query | Left / right byte table | Key / constant / additive | Index / original slot |
| --- | --- | --- | --- |
|22 |0x100e99a00 /0x100f4e390 |0x6D /0xD0 /+0xCC1A |0xCCEA /0x1010a0640 |
|23 |0x101031da0 /0x100e99900 |0x86 /0x58 /+0xCC92 |0xCCEA /0x1010a0640 |

Query23's explicit source roots are pool0x1010a44b0 containing decoded0x110D63522 plus0xFFFFFFFFF02CE87E, and pool0x1010a4a58 containing0x101BDEF67 minus0xD45667. They resolve to the listed tables. Query22's two tables are declared saved-frame inputs, with earlier conditional source provenance retained in the prior analysis. No target is inferred from discriminator equality alone.

## Daemon request and response ABI

| Boundary | Query22 | Query23 |
| --- | --- | --- |
|Source API submission PC |0x100364420 |0x1004ba9c4 |
|X0 |u32 through saved pointer at SP+8 |Same saved connection pointer |
|X1 |22 |23 |
|X2 / X3 |0 /0 |0 /0 |
|X4 |SP+0x64 |SP+0x6C |
|X5 |SP+0x70 |SP+0x70 |
|Source initial size64 |4 at0x1003643b4 |4 at0x1004ba938 |

These are source-level IOKit submission sites. No raw Mach send instruction, actual right transfer or native message emission is established by the private models.

Both predicates reduce exactly to `status32==0 && returned_size64==4`. They are not low-word-only extent tests. The source reinitializes the reused size cell to4 before query23, regardless of query22's returned size. Each API model clobbers caller-saved registers and flags; original source recovers its remaining arguments and phases.

| Source outcome | Target / action |
| --- | --- |
|Query22 accepted |Slot0x101083af0 ->0x1004ba914; preserve first returned word |
|Query22 rejected |Slot0x101083aa0 ->0x100628754; source clears SP+0x64, then slot0x101063000 joins query23 |
|Query23 accepted |Slot0x10104f728 ->0x100332734; load second word into W8 |
|Query23 rejected |Slot0x10104f638 ->0x1004d6be4; source clears SP+0x6C and W8 |
|Both query23 continuations |Slot0x10106d450 ->0x1003c39b0, W20=0x4EF4 |

The first word remains in SP+0x64 and the second reaches W8 at the joint-consumer boundary. The four bytes SP+0x68..0x6B remain unknown and unread. A zero query word can be either an explicitly returned zero or source fallback after rejection; its value alone does not distinguish those cases.

The independent fixture matrix has eight response pairs per query: statuses0/0xE00002C7 crossed with sizes4,3,0,0x100000004. Two placements and two output-word patterns yield8*8*2*2=256 cases. Only status0,size4 initializes the modeled output word; source clears it in every other case.

| Query22 predicate | Query23 predicate | Fresh case count |
| --- | --- | ---: |
|True |True |4 |
|True |False |28 |
|False |True |28 |
|False |False |196 |

These counts describe the fixture grid, not native probabilities.224 cases reject the first query and still reach the second. Successful response words, including0x13180000 and0xAABBCCDD, are test values; no native version or capability bits are assigned.

## Kext counterparts and obfuscated provider roles

The original selector records independently declare flags3,input0 B,output4 B. Their member-function targets and provider slots are original chained pointers, with exact symbols checked in the KC.

| Selector | UserClient source | Provider slot / raw target | Further source target |
| --- | --- | --- | --- |
|22 |`ucGetVersion`,0xfffffe000a5050c8 |0xfffffe000846c190 ->0xfffffe000a504ed4;offset0x8C0,diversity0xC54A |`uOxAg` stub ->0xfffffe000a5a299c |
|23 |`ucGetProtocolCapabilities`,0xfffffe000a505120 |0xfffffe000846c198 ->0xfffffe000a504edc;offset0x8C8,diversity0xB3EE |`Q5TC6` stub ->0xfffffe000a5a49d8 |

This gives `uOxAg` and `Q5TC6` source-established version/capability-query forwarding roles under the base-class vtable premise. Their deeper getter implementations remain opaque; bounded entry prefixes are retained without assigning return constants.

Both UserClient methods load the provider from this+0xD8. They save the output pointer in X19, call the provider, store low32(X0) to that pointer and return outer W0=0. Exact publication stores are0xfffffe000a505110 and0xfffffe000a505168. Source proofs range over every64-bit provider result. The kext getter result is output data, distinct from the outer UserClient return code.

## Provenance and verification

| Item | Verified value |
| --- | --- |
|Daemon thin SHA-256 |`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
|Live IDB input universal SHA-256 |`4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7` |
|KC SHA-256 |`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
|Normalized kext SHA-256 |`2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
|Fresh cases / API response summaries |256 /512 |
|Original instruction visits / byte checks |34464 /137856 B |
|Source read / write epochs |6144 /960 |
|API write epochs |576 |
|Source capacity resets / failure-word clears |512 /448 |
|High-word size mismatches rejected |128 |
|Source proof pairs / lifted instruction instances |13 /83 |
|Exhaustive banks / byte inputs |2 /512 |
|Live IDB instruction rows matched to file |105 |

Live IDA node `6b117c693e3b` supplied annotations and bounded source snapshots. Automatic model diagnostics were excluded. The exposed tool set lacked knowledge-store search; existing live annotations and retained files under `/Users/___/Downloads/fpx/analysis` supplied prior context. Those notes guided the entry premises, while original bytes/fixups and fresh source proofs support the new local results. No IDB was changed.

An exploratory compiler-envelope dump produced excessive diagnostic output and several command/filesystem calls delayed termination. Their original handles were retained; all subsequently reported terminal exit0 or completed successfully. The accepted checks were run after that recovery, without treating an observation timeout as completion.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_iokit_census.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_iokit_census.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_iokit_census.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_census.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_census_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_census_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Run commands sequentially and wait for terminal completion. Time is O(B+C*(V+E+J*F)+I+256R), plus solver cost (30 s/query); retained space is O(B+C*(V+E)+I+F+4096*J). B is pinned bytes,C cases,V visits,E byte-event extents,I decoded/lifted instructions,R bank rules,F fixup records and J demand pages. Each mapped page is4096 B; mapping scans F fixups per page. No native service query, provider getter, hardware PAC or Mach transport executes.

The baseline contains2254 artifacts,2248 unchanged with six declared report/index edits. Original analysis.md, C and calls inputs remain unchanged.

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
|High |Find actual selector18 clients |Per-site target/selector provenance, computed call forms and linked modules; no caller absence inferred from this census |
|High |Connect the eight selector21 candidate windows to ucRunVersioned |Resolved targets,552-byte packet construction and original kext consumer |
|High |Recover the joint version/capability consumer |Source0x1003c39b0, field uses and downstream feature decisions |
|Medium |Recover provider getter values/lifetime |Original deeper targets and actual provider/vptr/context evidence |
|Medium |Establish real open/port ownership and emissions |Native predecessor, framework binding, send/reply and right lifetime evidence |

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
|QG1 |Pass |Factual source/interface analysis |
|QG2 |Pass |DC1-DC12 list dependencies and falsification probes |
|QG3 |Pass for increment |Bounded caller census and query ABI/data/status covered; selector18 and broad objective incomplete |
|QG4 |Pass |Exact widths, fixture cardinality, counts and reproduction |
|QG5 |Pass |Discriminator/target, IDB/file pointers, conditional/native routing and output/return layers separated |
|QG6 |Pass |256 fresh byte audits,13 source proof pairs, independent text census, original fixups and105 live source-row comparisons |
|QG7 |Pass |Impact-labeled continuation table |


## Provider getter values and daemon specialization

The deeper getter opacity recorded above is refined by the current source proof:the pinned version route returns0x4c0b0000 and capability route returns0x1f8 under stable original bank/pointer and ordinary-return conditions. The new report proves both internal record/result paths and specializes the retained daemon guards,cache and fallback. These are pinned-code values,not observations of a native connection or hardware capability. [Evidence and exact boundaries](kext_query_getter_values_report.md).
