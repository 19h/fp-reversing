# CoreFP: FPSD certificate request and ADID XPC/Mach client

Current extension: the [optional-input and signed-record report](fpsd1201_key_routes_report.md) separates the exact selector byte at image+0x1d44409 from the saved global at image+0x1d47fb0. It traces selector=1 to a preparation-object boundary and the retained fallback to a later optional-input read, checking one mixed-state update and two complete predicates. Native initialization and full output/IPC pairing remain unknown.

Prior extension: the [token, entropy and seed report](fpsd1201_seed_report.md) continues the receipt-pinned CASAL frontier through source token restoration, three entropy callsites, a complete 624-word MT-compatible seed expansion and a four-word time/random tuple. Twelve cases and 4992 oracle words pass. The request1200 gap, subsequent key mixing, remaining context bytes and native transport pairing remain unresolved.

Prior extension: the [initialized parent and predicate report](fpsd1201_predicates_report.md) refreshes 19717 original prefix visits plus six modeled steps, supplies the actual private cursor/owner/key cells and independently replays four conditional continuations. Two complete predicate contracts explain selected table indices and expose atomic/global initialization frontiers. The request1200 call/status checks and the later pre-helper connection remain separate gaps; native parent continuity, full context and transport pairing remain unknown.

Prior extension: the [workspace and pre-helper gate report](fpsd1201_workspace_report.md) supplies original context/candidate/XOR pointer producers, a selected 1872 B cursor increment and nine-byte fdpc prefix. Five successful gate cases derive the later constructor registers and complete records under an explicit unexecuted-gap premise. Two sealed daemon representatives share the prefix; full input/key semantics, native parent continuity and message/right pairing remain unknown.

Two distinct request1200 paths are now resolved locally. The64-byte client uses the name returned by the recovered `com.apple.fpsd` lookup and sends a756-byte embedded FPPineBoard certificate. The56-byte client belongs to a separate constructor that targets `com.apple.adid`,prefers synchronous XPC with a28-byte `data` field,and uses Mach fallback with bootstrap/retry on MACH_SEND_INVALID_DEST. Identical numerical request IDs do not identify the same endpoint or payload ABI.

The main path reaches its larger request even after modeled failure of the metadata query described in the [lookup/protocol report](corefp_lookup_report.md). These are original-byte/static and bounded private-execution findings. Effective native image/port pairing,receiver admission,successful processing and rights lifetime remain unknown. The broad daemon/kext/deeper-interface objective remains active and incomplete.

## Identity,assumptions and provenance

CoreFP offsets use preferred base0 in arm64e slice SHA-256`8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`,UUID`9061ddc3-93b4-3824-914f-9cc97d708d58`. The [preceding export report](corefp_exports_report.md) pins its universal-file identity. Synthetic names such as0x5017/0x6ad1 and private addresses are fixture values;they are not runtime endpoints. Analyst tools read files,parse metadata and compile layouts;no native target,loader,framework,IPC or synchronization API was executed.

| Assumption | Dependent claims | Stress test / current boundary |
| --- | --- | --- |
| P1: original images and declarations define the reference objects | Every offset,byte,string and provider identity | Fresh hashes,source-function/instruction readbacks,selected chain members,plist/provider metadata and independent static-tool output agree. Native selection remains unknown. |
| P2: the stated private caller inputs are the intended local experiment | FPSD acquisition-to-request path | Decoded parent operation0xc1f7,two non-NULL private referents and controlled32-bit record fields are explicit. Fifteen cases retain source visits. Upstream public-export reachability and native application context remain open. |
| P3: warm-once,lock,allocator,cleanup and PAC fixtures supply their declared behavior | Continued paths and failure outcomes | Initial opaque boundaries are retained;NULL/success/cleanup cases are separate. Native initialization,OOM,authentication,reference retirement and concurrency remain untested. |
| P4: local argument widths and observed byte roles are sufficient descriptions | Secondary selector and28-byte packet | Full64-bit selector proof,three selector values and two X1 values reach packet construction. X1's semantic type is unknown;address-shaped fixture values do not establish that real callers pass pointers. Full response schema remains open. |
| P5: opaque XPC objects and API-result fixtures model the selected branches | XPC errors,retries,Mach fallback and event handler | Error-object identity,non-error,interrupted and NULL variants are explicit. The original+4 import addend is compensated before comparison. Native object/type behavior and exceptional APIs remain unknown. |
| P6: decoded embedded certificate bytes establish an argument,not trust | Certificate extraction/staging | Original760-byte XOR source,all copy indices,offline DER extent/parser,and two transmitted payloads agree. Authentication,trust/time policy,private-key possession and protocol acceptance were not tested. |
| P7: launchd metadata declares a provider independently of a live job | ADID architectural touch point | Exact plist/executable hashes,slices and UUID are retained. Running job,actual bootstrap/XPC port identity,peer policy and receiver implementation remain unknown. |

Evidence: [contracts](triage_evidence/corefp_client_paths_contracts.json),[15 FPSD cases](triage_evidence/corefp_client_flow_profiles.json),[36 secondary/callback cases](triage_evidence/corefp_secondary_client_profiles.json),[certificate DER](triage_evidence/corefp_fppineboard_certificate.der),[certificate source/parser metadata](triage_evidence/corefp_fppineboard_certificate.json),[CoreADI provider declaration](triage_evidence/corefp_adid_environment.json),[checks](triage_evidence/corefp_client_paths_checks.json) and [quality gates](triage_evidence/corefp_client_paths_quality_gates.json).

## FPSD: lookup result to certificate request [P1-P3,P6]

```text
protected caller0x8e81c8, decoded operation0xc1f7
  -> original lookup0x1cdb24 -> com.apple.fpsd -> cached name
  -> [metadata error can return while lookup still completes]
  ->760-byte allocation -> XOR copy ->756-byte DER staging
  -> free temporary allocation
  -> parent call0x8ea14c -> builder0x8ae0
  -> mach_msg0x8ba8, request1200,send64,receive capacity220
```

Seven metadata-flag values and four controlled values of the parent record's32-bit field at+24 reach the same first760-byte allocation at`0x249368`. These finite prefix observations do not establish equivalence of later behavior for every flag/value. A NULL allocation follows original code back to the fixture and stores internal record marker`0x45e2a20f`;it is not promoted to a native OOM result.

With bounded successful allocation and explicit owned cleanup,two cases reach the larger request:one starts from the cached name;the other executes primary bootstrap lookup,receives modeled name0x5017,observes metadata transport error`0x10000003`,and then reaches request1200. The original parent call selects target`0x8ae0` using modifier`0x563e`,matching original pointer slot`0x1d04218`.

| Request field / interface | Observed original value or origin |
| --- | --- |
| Destination | Header+8 equals the u32 lookup result,0x5017 in these fixtures |
| Header ID / byte extent |1200 /64 bytes;receive capacity220 bytes |
| Body+24 | Descriptor count1 |
| OOL descriptor+28/+40 | Private stack address /756-byte extent |
| Descriptor flags at+36 |`0x01000100`:deallocate0,virtual-copy1,type1 |
| NDR+44 | Explicit8-byte data-import fixture |
| Words+52/+56/+60 |2,2,756;the complete application semantics of the first two words remain unknown |

The temporary760-byte object is freed at`0x8e9fa8`. At emission,the OOL source is a separate private stack address containing exactly the756 DER bytes. This establishes local staging and address separation in the two cases. Actual kernel copyin,post-return stack lifetime and successful response ownership remain open. The caller's pre-library header-size word is not treated as the final native message size;the API receives the explicit send length64.

## Embedded FPPineBoard certificate [P1,P2,P6]

| Source / extent | Established bytes |
| --- | --- |
| Original encoded source |`0x185c226`,760 bytes |
| Original copy loop | Load`0x249434`,byte XOR`0xba`,store`0x24943c`;760 visits cover indices0..759 |
| Decoded prefix | Raw bytes`01 00 00 07`;semantic role unknown |
| Remaining object |756-byte DER;ASN.1 outer length752 plus4 header bytes |
| Transmitted payload | Exactly decoded object bytes4..759 |

Later inspection of the allocated object shows DER at offset0 and its last four bytes duplicated in the remaining allocation tail. The transmitted extent is756 bytes. The evidence retains the initial container,temporary snapshot and stack payload;it does not assign the prefix a length or version meaning.

Offline parsing establishes subject`FPPineBoard.4CAF170210AF0001AF000001`,issuer`Apple FairPlay AAA Certification Authority`,serial`4CAF170210AF0001AF000001`,RSA public-key size1024 bits and signature identifier`sha1WithRSAEncryption`. Literal validity times are2017-02-10T21:38:24Z through2022-02-11T21:38:24Z. These are metadata,not a native acceptance/rejection decision. DER SHA-256 is`a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de`.

This certificate is distinct from the891-byte StoreAgentStub argument recovered at the AMS/CoreFP boundary. Their relationship and complete native use are not inferred from a shared issuer string.

## ADID constructor,selector and mutable state [P1,P3-P5]

Constructor entry`0x15cc6f4..0x15d1580` uses a separate table at`0x1d16370` and different state constants. Its first argument is tested over64 bits:the accepted values are exactly-8,-6,-5,-4,-3,-2. The zero-extended32-bit pattern`0x00000000fffffff8` is rejected despite sharing low32 bits with-8. Rejection returns W0=`0xffff5037` in the private cases. X1's semantic type and the successful constructor's complete result/ownership contract remain unknown.

Before validating that selector,the routine rewrites two64-bit protected cells. Let`G1=[0x1d441a8]`,`G2=[0x1d44158]`,`C=0xa90ac839`,`K=0x5f0913a0d6d70483`;all arithmetic modulo2^64:

```text
r  = oldG1 XOR (entrySP-0x88) XOR oldG2
G1 = (r+K)*C
G2 = (r XOR K)*C
```

Every constructor fixture checks the first post-store state,including rejected selectors and changed64-bit states/stack offsets. Thus rejection does not imply absence of protected-state side effects. The fields' semantic purpose and synchronization remain unknown.

| Source boundary | Recovered construction stage |
| --- | --- |
|`0x15cc8e4` | First malloc,24 bytes |
|`0x15cc9dc` | Second malloc,4096 bytes |
|`0x15ce9d8` | `xpc_dictionary_create_empty` |
|`0x15cea8c` | `xpc_dictionary_set_data`,key`data`,28 bytes |
|`0x15ceae8` | Queue creation,label`com.apple.adid`,NULL attributes |
|`0x15ceb94` | XPC Mach-service connection request,name`com.apple.adid`,that queue,flags0 |
|`0x15cec70` | Event-handler installation,then modeled activation |
|`0x15ced04` | First synchronous XPC send with the populated dictionary |

First-allocation NULL,second-allocation NULL and connection NULL cases return`0xffff5035`;the second-allocation failure releases the first24-byte allocation in the cleanup model. These remain conditional private results. The dictionary-NULL fixture reaches `xpc_dictionary_set_data` with NULL;no native API consequence is inferred.

## ADID28-byte outgoing payload [P1,P4,P5]

Observed integer fields are in big-endian byte order:

| Offset | Width | Observed value / origin |
| --- | --- | --- |
|0 |32 bits |1 |
|4 |32 bits |`0x632b8d6e` |
|8 |32 bits |1 |
|12 |64 bits | Original signed selector |
|20 |64 bits | Original X1 value;semantic role unknown |

The source cases vary selectors-8/-6/-2 and two X1 values. Names such as protocol version,operation identifier,count,account identifier or address are not assigned to the unexplained fields. The32-bit constants and64-bit origins describe the observed wire construction;the full encoder and successful response grammar remain open.

## ADID error retries and Mach fallback [P1,P3-P5]

```text
XPC com.apple.adid, dictionary data[28]
  -> non-error type: xpc_dictionary_get_data("data") boundary
  -> modeled error type: legacy cached-name Mach attempt
       -> MACH_SEND_INVALID_DEST
          -> bootstrap_look_up(com.apple.adid)
          -> replace cached name -> retry Mach request
```

The exact connection-interrupted object selects five synchronous attempts at`0x15ced04`,`0x15ceecc`,`0x15cf02c`,`0x15cf14c`,`0x15cf28c` before the observed fallback. The original import at`0x1d1c028` has addend+4;source`0x15cee24` subtracts4 before object-identity comparison. The fixture supplies the opaque symbol object's address. A generic error object reaches fallback after one attempt. Mixed replies and native retry timing remain unverified.

The NULL-reply fixture reaches `xpc_get_type(NULL)`;its subsequent non-error classification is an explicit model and does not establish native NULL-object behavior. Successful/non-error object cases stop at data extraction`0x15cf394` with key`data`;response parsing and successful object publication remain open.

| Legacy interface | Established source/private contract |
| --- | --- |
| Parent first call |`0x15d008c` -> builder`0x1590824` |
| Emission |`0x15908c8`,ID1200,send56,receive capacity64 bytes |
| Payload | One OOL descriptor containing the same28 bytes previously stored in XPC |
| Cached name |`0x1d49068`,in the original zero-fill DATA tail;native value unknown |
| Recovery condition | Full32-bit predicate simplifies exactly to`MACH_SEND_INVALID_DEST=0x10000003` |
| Lookup |`0x15d0174`,namespace from `_bootstrap_port`,name`com.apple.adid`,output at the cache cell |
| Retry parent call |`0x15d022c` -> same builder/emission with the newly supplied name |

Cold private mapping uses name0 for the first attempt. Warm fixtures use0x6a90;after modeled invalid destination and successful lookup,the retry uses0x6ad1. No deallocation appears in the observed replacement prefix;complete reference accounting remains unknown. Bootstrap error5 yields`0xffff5027`;a different modeled transport error`0x10000004` yields`0xffff5028` without lookup. Those finite results do not assign native error contracts to every failure.

## Installed XPC event handler and provider context [P1,P3,P5,P7]

The installed block at`0x1d16350` has invoke target`0x15a4c14`. Its original body passes the event argument to `xpc_copy_description` at`0x15a4d8c`,then tail-calls exact `_free` at`0x15a4df4` with that returned pointer. Two callback-entry cases retain the first opaque boundary and normal modeled cleanup. The tail edge is recorded directly rather than inferred from LR,which retains the callback's caller return address. Additional protected-state mutations occur;native callback scheduling,lifetime and concurrency remain open.

The original `/System/Library/LaunchDaemons/com.apple.adid.plist` declares Mach service`com.apple.adid`,program`/System/Library/PrivateFrameworks/CoreADI.framework/adid`,user/group`_fpsd`,adaptive spawning and pressured-exit support. It does not establish a running job. Provider universal SHA-256 is`58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929`;selected arm64e SHA-256 is`ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`,UUID`4d24325f-3529-39b1-bbf8-64bbcf406049`. Three original slices and static fixup output are retained for receiver-side continuation. This increment does not recover that executable's receiver implementation.

## Validation and continuation

The increment passes6220 assertions across51 private cases,5866 distinct retained instruction records,three exhaustive256-input banks,20 selected pointers and two full-domain SMT obligations. The760-byte encoded source,756-byte DER/parser output,provider metadata/static-tool output and arm64e28-byte layout compile are independently reread. Original supplied inputs and IDBs remain preserved. QG1-QG7 pass for these stated claims;the full objective remains incomplete.

```text
$PYTHON triage_evidence/recover_corefp_client_paths.py
$PYTHON triage_evidence/probe_corefp_client_flow.py
$PYTHON triage_evidence/probe_corefp_secondary_client.py
$PYTHON triage_evidence/validate_corefp_client_paths_delivery.py
```

Static extraction/readback is O(B+F+R+V+256K),with image bytes B,fixups F,retained ranges R,source visits V and bank identities K;space O(B+F+R+V). Private cases retain the30000-hook bound. Solver cost is separate,with30 s per-query caps. Byte counts and32/64-bit modular arithmetic are explicit;no native performance result is inferred.

| Impact | Further discriminating evidence |
| --- | --- |
| High | Recover CoreADI adid's actual XPC handler,peer admission,`data` decoder,response grammar and legacy receiver compatibility. Match effective native selection before combining snapshots. |
| High | Follow the FPSD1200 server application handler,certificate policy,returned OOL/port objects and full acquisition-to-close ownership. The local send boundary does not establish successful processing. |
| High | Recover actual callers of the signed-selector constructor and assign X1/packet-field semantics from their provenance. |
| Medium | Complete cached-name replacement/dead-name reference accounting,bootstrap failures,all transport statuses and retry cancellation. |
| Medium | Follow metadata flag consumers and both certificate sources into their exact protocol roles and effective authentication policy. |
| Medium | Establish once/lock lifecycle and synchronization of protected cells shared with event-handler paths;private ordering is not a concurrency proof. |

No source-analysis blocker is asserted. The broader daemon,kext and deeper-facility investigation remains active.

## Provider-side continuation

The [ADID receiver report](adid_receiver_report.md) recovers the provider's peer setup, event callback, audit/data adapter, 48-byte private record and initialized-context dependency. Its local `adi-client` classifier lists 50 values; original cases reach the 28-byte client request after that gate. Six unlisted-client response pairs connect provider `data = ff ff 4f f2` to CoreFP return `0xffff4ff2`. This is source/private ABI correspondence. Native pairing, successful operation semantics, X1's meaning and legacy Mach compatibility remain unknown.

The [request1201 client/server contract](fpsd1201_client_report.md) recovers builder0x8d40, send0x8e04, exact164-byte inline request, ID1301/simple36 reply grammar and reply-port cleanup calls. Twenty-seven client profiles and a fresh original daemon failure replay establish local byte/status continuity under declared receive conversion. The protected caller and actual destination-right origin remain unknown.

The [CoreFP1201 caller report](fpsd1201_caller_report.md) now resolves the later local target, unsigned scalar guard and nominal request1200-output/request1201-destination cell. Three adjacent128-byte ranges and five dynamic SP assignments prevent an unconditional whole-parent handoff claim; native endpoint/right identity remains unknown.

The [CoreFP1201 nested-record report](fpsd1201_record_report.md) recovers source staging, helper/child cursor cancellation, internal rejection status and a selected65537 initializer. It does not establish production of the candidate128-byte source or a continuous request1200-to1201 port handoff.

The [CoreFP1201 byte-import report](fpsd1201_import_report.md) identifies0x17bbb8 as a big-endian byte-to-encoded-limb importer,with selected unsigned length0..256 B and normalized limb counts. Eight nested prefixes import128 bytes from diagnostic context C,leave candidate P+0x880 untouched and stop before0x98189c ->0x14fac64. Sixty-eight independently audited cases and matching reference-file corroboration establish this local ABI; complete protected processing,native port lineage and daemon/kext pairing remain unknown.

The [CoreFP1201 operand-preparation report](fpsd1201_operand_report.md) resolves the selected negative-inverse coefficient, separates three descriptor identities and follows the original scalar-one initializer. Eight unchanged-context cases stop before an unbacked payload read; 28 explicitly backed prefixes stop before 0x14f9408 -> 0x5a600c. Forty source obligations, independent replay and odd/even controls support this local contract. Native context production, complete arithmetic, port lineage and daemon/kext pairing remain unknown.

## CoreFP1201 signed-shift continuation

The [signed-shift increment](fpsd1201_shift_report.md) follows the scalar-one temporary through complete original 0x5a600c dispatch and both leaf/query dependencies. Eight continued caller cases produce 2^32 for one context limb or retain 1 for count zero, then stop before 0x14f94c4 -> 0x649430. Another 136 isolated cases and independent integer oracles establish the bounded signed-magnitude shift contract. Native request1200-to1201 endpoint/data lineage and complete protected processing remain unknown.

## CoreFP1201 working-copy and comparison continuation

The [working-copy/comparison increment](fpsd1201_comparison_report.md) follows the context copy and two complete original comparisons after radix preparation. Eight caller cases compare original and copied context against the same radix descriptor, then stop before 0x14f9d74 -> 0x5e8158. Independent byte/integer oracles and source checks distinguish canonical comparison from four noncanonical-zero controls and resolve seed-dependent frame padding. Native endpoint/data lineage and complete protected processing remain unknown.

## CoreFP1201 subtraction continuation

The [subtraction increment](fpsd1201_subtraction_report.md) continues eight original caller profiles through 0x5e8158, recovers B := B - A and both magnitude leaves, and stops after return at 0x14f9d78. Complete request1201 payload/endpoint production and native daemon/kext lineage remain unknown.

## CoreFP1201 complete precomputation continuation

The [reduction/precomputation increment](fpsd1201_reduction_report.md) completes the arithmetic child and cursor wrapper in twelve positive one-word controls. Nine odd inputs establish R mod n, R^2 mod n and the negative inverse; even and bounded-zero controls retain separate classifications. The next original dependency is 0x9819c4 -> 0x1142c08.

## CoreFP1201 post-precomputation consumer handoff

The [post-precomputation consumer handoff](fpsd1201_consumer_report.md) advances twelve audited checkpoints through 0x1142c08 and 0x1142154 to the unexecuted call 0x114245c -> 0x74fd0c. Its incoming and outgoing 48 B records connect the prepared pair, modulus and imported input; complete arithmetic and native request1201 delivery remain unknown.

## CoreFP1201 complete product continuation

The [complete product continuation](fpsd1201_product_report.md) identifies 0x74eb08 and wrapper 0x74fd0c as Montgomery multiplication on tested canonical inputs. Eighty-one complete arithmetic oracles pass through 2048 bits; six retained width-mismatched odd cases remain explicit counterexamples. Twenty-four nested continuations reach the unexecuted auxiliary call 0x11425bc -> 0x59f4e8. Complete request1201 processing and native delivery remain open.

The [auxiliary continuation](fpsd1201_auxiliary_report.md) resolves 0x59f4e8 as magnitude bit length and 0x57af24 as magnitude bit selection. Sixteen complete private returns through consumer 0x1142154 and wrapper 0x1142c08 establish tested Montgomery exponentiation, with 14 odd-modulus integer-oracle matches and two separate even controls. Eight unbacked descriptors retain pre-read boundaries. The complete cases now stop before 0x981bc8 -> 0x32f628; candidate inline export and native request completion remain unknown.

The [integer-export and complete helper continuation](fpsd1201_export_report.md) resolves 0x32f628 as fixed-length big-endian magnitude export. Sixteen retained cases fill candidate P+0x880..P+0x8ff and return through the local child/wrapper. Two explicit short-length controls show exporter rejection followed by the selected caller's root success marker. The original saved width is 8 B before the diagnostic modulus patch, while actual retained export length is 128 B. Native parent/transport continuity remains conditional.

The [explicit parent handoff](fpsd1201_handoff_report.md) follows those terminal states through root-marker selection, the separate XOR destination and unsigned scalar gate into original serializer preparation. Twenty-one cases copy all 128 candidate bytes and stop before `_mig_get_reply_port` at 0x8db0. The report distinguishes restored state from every declared missing-parent binding; whole native parent, request1200 name/right continuity and daemon/kext pairing remain unestablished.

## Network-registry environment input

The [network-identity increment](corefp_network_identity_report.md) recovers getter 0x86c0 and its lazy Block 0x8754. The block matches IONetworkController, reads IOMACAddress from each node's IOService-plane parent and caches six bytes. Capacity admission is unsigned low32 >= 6 with status zero; final status describes the last iteration, while bytes describe the last successful read. Twenty-seven profiles and three same-instance repeats are independently checked. Incoming callers, downstream use and native daemon/kext continuity remain unknown.

## Cold lookup initialization and lock fallback

The [cold initialization report](corefp_lookup_initialization_report.md) executes both original once callbacks omitted by warm fixtures. Callback 0x4a21e0 attempts two 200 B lock constructions, clears both cached names and metadata, and continues across tested allocation/init failures. Helper 0x20f37c chooses the first heap lock or static fallback image+0x1d27bf0. Three profiles reach com.apple.fpsd bootstrap preparation at 0x1ce1bc; all stop before lookup execution. Native lock/right behavior and subsequent source-produced metadata remain unknown.

## Cold metadata and sequential cache continuation

The [cold metadata and re-entry report](corefp_cold_metadata_report.md) now joins original initialization to the unchanged-ID daemon rejection. Three primary-service cases return metadata status -304 yet copy selected name 0x5017 and flags 0x0a; a same-instance second call reuses those values without another metadata RPC. All six cases still reach write-lock acquisition twice. Native re-entry requires the surrounding unlock/owner contract.

## Caller-managed lookup lock release

The [caller lock-release increment](corefp_lookup_release_report.md) completes seven cold parent failure paths. Original caller 0x8e81c8 produces the lookup record and invokes cleanup wrapper 0x457838 at 0x8fc3f0; wrapper 0x457aa0 reaches unlock helper 0x1be978 and pthread_rwlock_unlock at 0x1becc8 with the acquired heap/static pointer. Parent marker, final X0 and the early X1-referenced u64 update are separate outputs. Successful-request cleanup and native ownership remain open.
