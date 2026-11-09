# RPC502 alternate certificate family and late carrier consumers

Three original initialized-worker cases containing the embedded `fairplayd.3333AF100127AF0003AF000001` certificate pass two local certificate-verification stages and reach previously unobserved consumers of carrier fields+28,+40 and+8. The observed chain is Root ->Apple FairPlay AAA Certification Authority ->the supplied embedded fairplayd leaf. Versions2,4 and5 all reach those reads and return `0xffff5bd9`. Successful protected processing,subsequent native IPC and complete field semantics remain unknown.

This extends the frozen [issuer/verification report](rpc502_auth_report.md):its Key Services literal and prefix comparison describe that observed branch,not every possible certificate-family path. The AAA cases reach a different original continuation with valid public signature relationships. The [arithmetic report](rpc502_rsa_report.md) separately establishes actual integer/key/Montgomery interfaces for its Root/Key-Services corpus. The full interface investigation remains active and incomplete.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe | Boundary |
| --- | --- | --- | --- | --- |
| P1 | The exact supplied daemon slice is the intended implementation | Addresses,embedded DER and source consumers | Rehash source/universal slice,UUID,opcodes,fixups and compiler starts;attest native pairing separately | Original file provenance checked;native provider/slice identity unknown |
| P2 | Actual original startup callback execution provides the stated worker predecessor | Three private sequences and record carriers | Require callback return;carry state unchanged into worker;recover alternate startup writers | Complete process startup not executed |
| P3 | Explicit inherited API/PAC/MAX/heap/lock models apply only to these cases | Finite path,allocator and cleanup observations | Reject unknown operations/bytes;vary external file/API inputs;compare native execution independently | No native target,filesystem,Mach,IOKit,loader,credential or synchronization API execution |
| P4 | Both file inputs are fixed before all guest instructions | Attribution of new paths to external inputs | Retain both byte strings;check original source reads and fresh replay;reject internal PC/frame/gate/record interventions | Original files/binaries and guest instruction bytes unchanged |
| P5 | Partial integer/carrier views cover selected active fields only | Public-key identity,late scalar decoders and SDK view | Check original builders/readers,active extents and source byte epochs;recover remaining fields separately | Complete record types and most field semantics unknown |
| P6 | Public signature equality and local success words are distinct evidence | Two successful verification stages | Recompute exact DER signature/TBS/hash/key relations;verify original status outputs and later failure | No complete trust,date,revocation,authorization or operation acceptance claim |
| P7 | Observed decoded kinds explain the retained local branch only | Version2 versus4/5 continuation | Verify raw record/address key,actual compare and branch target;test other kinds/predecessor states | Full tag grammar and certificate-family selection predicates unknown |
| P8 | Source-store epochs,heap masks and recorded API effects distinguish byte provenance | Selected field/key/tail and allocator observations | Check original stores before reads;separate API-defined bytes from source-defined bytes | Snapshots of unknown padding are excluded from definedness claims |

[Profiles](triage_evidence/rpc502_policy_profiles.json) retain all three complete original callback/worker sequences and both file inputs. [Contracts](triage_evidence/rpc502_policy_contracts.json) retain8 source spans in6 physical compiler intervals,1605 consumed pointer/import records,two original DER extracts and SDK compilation. [Independent checks](triage_evidence/rpc502_policy_checks.json) cover every retained source visit,actual key/signature/digest fields,late consumer registers/stack fields,status publication and three fresh canonical replays. Physical compiler intervals and large flattened regions remain distinct from semantic routine boundaries. [P1-P8]

## Valid embedded family and distinct later error

| Original DER | File offset | Representation | Selected mathematical role |
| --- | --- | --- | --- |
| `fairplayd.3333AF100127AF0003AF000001` |ee87f4 hex |719 bytes,XOR98 | Supplied leaf;issuer Apple FairPlay AAA Certification Authority |
| Apple FairPlay AAA Certification Authority |ff63a4 hex |889 bytes,XOR98 | Public parent of the supplied leaf;child of Root |
| Embedded Root | Preserved startup DER/source record | Earlier source-pinned constructor output | Parent of the AAA certificate |

Both signature relationships are recomputed from original DER using independent modular exponentiation and SHA-1 DigestInfo equality. Actual X9 child and X11 parent modulus/exponent fields at `0x10097531c` match the corresponding original DER public keys. Active raw signatures and encoded digest bytes match each child. The first relationship uses a256-byte signature under Root;the second uses a128-byte signature under AAA. [P1,P5,P6]

| Source observation | Result in each case |
| --- | --- |
| First local conjunction at1008969a8 |8b3dc651 hex |
| Second local conjunction at1008969a8 |8b3dc651 hex |
| Later first-status reduction at10095103c |74c29d8a hex,after the earlier two successes |
| Carrier status write10065f11c,+32 |Raw74c29d88 hex;XOR8b3dc651 ->ffff5bd9 |
| Whole worker return |ffff5bd9 hex |

The same worker result need not identify the same producer as an earlier case. Here the source exposes two successful local stages,then a distinct later failure and encoded outer publication. The retained unsigned Key-Services corpus returnsffff5bdb;these AAA inputs returnffff5bd9. Neither value receives a semantic error name from its number alone. [P6]

```text
original callback returns -> source parses both explicit file inputs
  -> embedded AAA certificate + Root public key
  -> local signature/status success
  -> supplied embedded fairplayd leaf + AAA public key
  -> local signature/status success
  -> late carrier reads+28,+40,+8
  -> kind-selected continuation,additional source processing
  -> later local failure ->carrier+32 ->workerffff5bd9
```

The input change establishes a feasible private predecessor to the late reads. It does not by itself identify the complete predicate selecting AAA versus Key Services,or prove that a version byte alone selects a certificate family. Version2 reaches the same late reads with decoded kind38411d06;versions4/5 use38411d07. [P4,P6,P7]

## Late field consumers and local decoding

Let `Kp=((low32(P) XORc6d66014)*6b86592f) mod2^32`,for carrier pointer P. This address key and the builders were established in the frozen [supplemental report](rpc502_supplemental_report.md). The new evidence is actual later consumption,register state and downstream control. [P5]

| Carrier field / width | Actual consumer | Exact selected decoding / publication | Established scope |
| --- | --- | --- | --- |
|+28,u32 |100747f70 |`stored28+Kp mod2^32`;save at SP+68 via100747f78 | Intermediate is `C XOR8b3dc651`;C=128 in all three cases |
|+40,u32 |100747f7c |`stored40-Kp mod2^32`;save at SP+ec via100747fc4 | Encoded auxiliary intermediate;full role unknown |
|+8,u32 |100747f84 |`stored8 XOR Kp`;save at SP+178 via100747f8c | Later selected call argument derives by addingd51c85f8 mod2^32 |
| Kind,earlier decoded |100747fa8 |Signed32 comparison with38411d07 hex | Actual local partition below |

The decoded field+28 parameter is128. No operation number,signature-width,IOKit selector or complete payload role is assigned merely from that value. The loaded intermediate subsequently participates in source arithmetic at `100a21aac` and `10065731c`;those byte ranges are retained,but their complete semantic predicates remain unknown. The +40 intermediate likewise feeds later address arithmetic through `100a8b860..880`;a complete pointer/extent contract remains to be recovered. [P5,P7]

| Case | Kind | Actual target at100747fcc | Further observed common call |
| --- | --- | --- | --- |
| Version2 |38411d06 |10098e144 | This specific100919330 site absent |
| Version4 |38411d07 |100a7b00c |100919330 ->declared `_malloc`,X0=8 |
| Version5 |38411d07 |100a7b00c |100919330 ->declared `_malloc`,X0=8 |

At the common call, `X0=((stored8 XOR Kp)+d51c85f8) mod2^32 =8` bytes. The imported pointer comes from original `_malloc` slot10109ff58 at100919328;the inherited API model supplies the private allocation result. The argument's derivation and source call site are verified separately from the allocator's modeled output. Version2 takes another original continuation;absence of this specific call is not absence of all allocation. [P3,P5,P7,P8]

The before-instruction observer point at100747f90 shares its numeric step count with the immediately preceding executed store100747f8c. Epoch reconstruction includes that store;the final delivery check independently verifies adjacent original visits and matching bytes in all three cases. This counter convention does not introduce a new source of guest bytes. [P8]

The selected accessed carrier extent remains44 bytes. The [SDK analyst view](triage_evidence/rpc502_policy_layouts.c) has size48 bytes including ABI trailing padding;it asserts offsets8,16,28 and40. Neither padding nor unknown fields are treated as established source types. [P5,P8]

## Input and verification coverage

All three cases use the same64-byte first input,beginning with six BE32 words `(1,0,1,0,0,0)` and forty trailing zero bytes. The second input is4096 bytes,contains the original719-byte leaf at its source-built format offset,and supplies/derives C=128. Inputs are set before any guest instruction. No internal readiness,status,record,branch,PC,frame or arithmetic result is overridden. [P2-P4]

| Case | Whole worker instruction steps | Local successful conjunctions | Late+28/+40/+8 reads | Result |
| --- | ---: | ---: | --- | --- |
| AAA_v2 |14573165 |2 |All three |ffff5bd9 |
| AAA_v4 |14589490 |2 |All three |ffff5bd9 |
| AAA_v5 |14583253 |2 |All three |ffff5bd9 |

All43816075 counted assertions pass across43745711 retained original-source visits and the same number freshly replayed. The [check record](triage_evidence/rpc502_policy_checks.json) contains exact assertion and source-visit counts,source-store epochs and guarded heap-byte masks,six valid public signature relations,six parent and six child key observations,three reads of each late field,six successful local conjunctions,three later failures and three fresh complete executions. A fresh SDK compile reproduces the selected ABI assembly. Source/PAC guards and every retained opcode/fixup remain enforced. No new native Mach/IOKit message or port publication is established. [P1-P8]

Reproduction from the extracted directory:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_policy_cases.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_policy.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_policy.py
```

Time/space are O(C*(B+V+E+S)) for cases,source bytes,visits,events and retained state,plus bounded public-key arithmetic. Offsets/extents are bytes;scalar operations specify32-bit modular width;instruction counts are observations,not durations. [Preservation](triage_evidence/rpc502_rsa_preservation.json) checks the1047-artifact baseline with only six permitted index/aggregator updates. [Scoped quality gates](triage_evidence/rpc502_rsa_quality_gates.json) cover both new reports. Published predecessors,original inputs,binaries and IDBs remain preserved.

| Impact | Bounded continuation | Evidence required |
| --- | --- | --- |
| High | Complete C/+40 input-to-pointer/predicate contract | Recover every downstream load,decoder,extent guard and original variable predecessor;vary external first/second-file values |
| High | Later failure after valid certificates | Trace last status producer and its actual original inputs;recover byte export,padding,signature/control and first-file checks without internal gate changes |
| High | Certificate-family/identity selection | Recover precise name/OID/kind/caller predicates selecting AAA versus Key Services and alternate embedded families |
| High | Subsequent daemon/kext/deeper transaction | Establish original successful protected output before matching transport bytes,port objects,rights and provider/slice identity |
| Medium | Ownership after the later continuation | Trace new allocations,mapping/FD transfer,zero/failure/retry and complete source cleanup epochs |

QG1:factual analysis. QG2:P1-P8 register/probes. QG3:late-consumer increment covered,full goal active. QG4:widths,byte extents,SDK and complexity explicit. QG5:versions,local statuses,source/API bytes and native gaps distinguished. QG6:original bytes/fixups/DER,independent math and fresh canonical replay. QG7:bounded impact table above.
