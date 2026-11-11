# CoreFP: recovered exports, initialization prefix and Mach request ABI

`lxpgvVMLd0S7uRl` is a version-output routine in the inspected CoreFP image: its original backend writes three32-bit words,`6,8,3`,matching the original bundle version`6.8.3`. `WIn9UJ86JKdV4dM` constructs a larger address-encoded argument record; its full payload schema and protected algorithm remain unknown. Five additional direct CoreFP `mach_msg` callsites construct requests1200-1203,with two distinct request1200 layouts. Their effective endpoints and reachability from the inspected AMS caller remain unknown.

This is progress within the active daemon/kext/deeper-interface investigation. It does not establish a completed native interaction. The preceding [AMS/CoreFP report](ams_core_report.md) supplies the caller,loader,five symbol lookups and certificate provenance. The [Mach report](mach_ports_report.md) retains the separate kext502/700 and daemon service interfaces.

## Evidence identity and scope

All CoreFP addresses below are preferred-image offsets,base0. They are not runtime addresses or Mach names. Original file reading,format12 fixup decoding,byte-bank enumeration,SMT and compile-only SDK checks are static evidence. Private Unicorn cases use original instructions and explicitly modeled external boundaries. No native target,loader,framework,IPC,filesystem or synchronization API was executed; analyst file reads,static tools and compiler invocations are distinct.

| Primary object | Identity |
| --- | --- |
| CoreFP original file | `/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP`,resolved `Versions/A/CoreFP` |
| Universal SHA-256 |`68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f` |
| Selected arm64e slice | Fat offset33849344,length30797904 bytes; SHA-256`8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c` |
| Selected UUID |`9061ddc3-93b4-3824-914f-9cc97d708d58` |
| Reference AMS/cache | AMS UUID`1b464993-f0e2-3804-b412-a6cc8091798c`;cache UUID`2bd06591-e751-3e84-963f-b08dab6af23a` |
| Bundle metadata | Identifier`com.apple.CoreFP`;both version keys`6.8.3`;original plist path/hash in contracts |
| Pointer provenance |79512 original format12 chain members,196 import entries;independent chain traversal agrees with analyst `dyld_info` output on membership,targets,authentication and imports |

Primary artifacts: [contracts](triage_evidence/corefp_exports_contracts.json),[complete fixup inventory](triage_evidence/corefp_fixups_inventory.json),[independent static-tool output](triage_evidence/corefp_library_fixups.txt),[15 export/prefix cases](triage_evidence/corefp_exports_profiles.json),[two AMS source-output transfers](triage_evidence/corefp_version_bridge_profiles.json),[static import edges](triage_evidence/corefp_import_calls.json),[seven request-building cases](triage_evidence/corefp_mach_request_profiles.json),[independent checks](triage_evidence/corefp_exports_profile_checks.json) and [quality gates](triage_evidence/corefp_exports_quality_gates.json).

## Assumption register

| ID / assumption | Dependent results | Stress test and current status |
| --- | --- | --- |
| CF1: the pinned original files define the reference objects | Every offset,tuple and cross-image relationship | Rehash universal/slice/plist/cache and read original ranges/chains. Passed for these snapshots. Actual native selection remains unknown. |
| CF2: W/X arithmetic has32/64-bit modular semantics and decoded bank entries are the selected targets | Version operation,branch partition,state updates and packet codec | Exhaust all256 inputs for nine bank uses/seven distinct identities;four SMT obligations;compare original instructions,slots and finite source runs. Passed within these local contracts;this does not establish an arbitrary protected path. |
| CF3: decoded targets can be materialized in private pages with PAC bypassed | All private control-flow outcomes | Original format12 authentication fields,modifiers and chain membership are retained. Hardware authentication,signatures,address diversity and native mappings are not tested. A native authentication failure falsifies transfer to that environment. |
| CF4: explicit stack/once/atomic/page/mapping fixtures supply the stated external behavior | Initialization prefix and failure propagation | Preserve the first unmodeled boundaries;compare fixture variants and exact source visits. Native stack-symbol resolution,concurrency,once lifetime,page-size handling beyond the prefix and allocator behavior remain unknown. |
| CF5: copying the exact source-produced12 bytes/status models this selected AMS call boundary | AMS continuation to mode7/certificate call | Two fresh isolated caller/child spaces reach the same original next call. Shared-image state,native dyld pairing and other CoreFP effects across calls remain unverified. |
| CF6: direct request-builder entry and explicit reply-name/NDR/voucher fixtures are valid local experiments | Seven constructed requests and field origins | Original branch/stub/fixup/byte readbacks;poisoned stack;zero reply-name and absent/no-op voucher variants. Complete protected callers,real port objects,NDR binding,voucher mutations and actual requests/replies remain unknown. |

## Version-output contract [CF1-CF4]

Original wrapper`0xcd20..0xcf2c` calls helper`0x20f6fc..0x20f82c` at`0xcefc`. Selected authenticated slot`0x1d044b8` contains target`0x20f6fc`,IA diversity`0x70c8`,address diversity0;the call modifier is`0x70c8`.

| Offset from wrapper post-prologue SP+8 | Width | Role |
| --- | --- | --- |
|0 |32 bits | Returned status |
|4 |32 bits | Address-encoded operation |
|8 |64 bits | Original X0,version-output pointer |

Let`p=low32(record_address)`;all following arithmetic is modulo2^32:

```text
mix = p XOR 0x302a1e77
stored_operation = (mix * 0xcae5b081) XOR 0x3231
decoded_operation = stored_operation XOR (mix * 0xcae5b081) = 0x3231
branch_index = 0x3231 XOR (output_pointer != 0 ? 9 : 0)
```

The first SMT obligation proves that the distinct original encoder/decoder OR/AND/SUB/XOR expressions both equal`mix`. The second proves operation cancellation under that established equality. The third proves the full64-bit NULL/non-NULL partition. The fourth concerns the packet codec below. These are local full-width algebra proofs;they do not prove native PAC or a complete program path.

Bank outputs resolve version-cell selectors`0xc0,0x1f`,helper target/table selectors`0x2e,0x2e` and branch-table selector`0xd6`. Branch slots`0x1c9aac8` and`0x1c9ab00` select`0x20f820` and`0x20f7fc` for indices`0x3231` and`0x3238` respectively.

| Output pointer condition | Original effect / result |
| --- | --- |
| NULL | No version-output store;returns W0=`0xffff5bd9` |
| Non-NULL,writable for at least12 bytes,with valid stack/image and preserved canary | Stores u32`6,8,3` at+0/+4/+8;returns W0=0 |

The routine also performs four64-bit writes across three mutable image cells. It is not a side-effect-free query. With`C=0x68001f0b`,`K=0x2a3c56842e5d49ec`,`S=entrySP-0x30`,all modulo2^64:

```text
G1 = [0x1d355c0]; G2 = [0x1d37f68]; G3 = [0x1d358b8]
r  = (oldG1 XOR oldG2) + S
G1 = r*C - K
G2 = (r XOR K)*C
r2 = oldG3 - (S-0x10+8) + G2
G3 = (r2*C) XOR K
G2 = (r2 XOR K)*C
```

Six private cases vary NULL/non-NULL,three initial64-bit state tuples and stack offsets. All return normally within198/207 private hook steps;the non-NULL cases write exactly the expected12 output bytes and preserve the following four poisoned bytes. The cells' synchronization and high-level purpose remain unknown.

## AMS continuation with source-produced version bytes [CF1,CF3,CF5]

```text
original private AMS create/import caller
  -> existing explicit once/allocation/lock/loader models
  -> lxpgvVMLd0S7uRl(output=0x1ebbfd6ec)
  -> separate original CoreFP private run: status0, u32[6,8,3]
  -> explicit12-byte ABI transfer to the caller's output cell
  -> original AMS continuation
  -> WIn9UJ86JKdV4dM at AMS0x19c20e690
       W0=7; certificate=0x19cb1a483; W4=891 bytes
```

Both create/import cases reach the latter boundary. This replaces the preceding report's opaque first-export return0 assumption for this local version-output effect. CoreFP child-state writes remain in the child evidence;the adapter does not represent a shared native image. The891-byte DER certificate has the original provenance retained in the AMS report;certificate authentication and protocol acceptance remain unknown.

## WIn9UJ86JKdV4dM argument record [CF1-CF4]

Wrapper`0xe160..0xe450` resolves helper`0x27afd4..0x27b3c4` through slot`0x1d04730`,IA diversity`0x17c6`,address diversity0. Call`0xe40c` uses modifier`0x17c6`. Four bank uses resolve cell/target/table constants`0xec,0x09,0xd6,0xaa`. Two bank identities duplicate version-bank identities;the total is nine uses/seven identities.

Let`P=postprologue_SP+0x20`,`R=postprologue_SP+8` and`k=((low32(P) XOR 0x309487ae)*0x87cfdb29) mod2^32`.

| Offset from P | Width | Original field origin |
| --- | --- | --- |
|0x00 |32 bits |`k+0x2472c1e1` modulo2^32 |
|0x08 |64 bits | X1 |
|0x10 |32 bits | Returned status;wrapper loads this field into W0 at`0xe410` |
|0x18 |64 bits | X7 |
|0x20 |32 bits |`W4-k` modulo2^32;W4=891 in the inspected AMS caller |
|0x28 |64 bits | X3;certificate pointer in that caller |
|0x30 |64 bits | X6 |
|0x38 |64 bits | X5 |
|0x40 |32 bits |`W0+k` modulo2^32;W0=7 in that caller |
|0x48 |64 bits | X2 |
|0x50 |64 bits |`R XOR 0xc43af69d4c49fa99` |

The highest wrapper store establishes an88-byte written extent,not a complete record size or complete definedness. Unlisted bytes,padding,the preceding encoded self-record and the semantic operation represented by field0 remain unknown. The fourth SMT obligation proves the source ORN-based simplification and arithmetic invertibility of the mode/length encodings. It does not prove that the backend uses those proposed inverses. Private record snapshots verify the original stores with controlled pointer/certificate inputs.

## Initialization and allocation prefix [CF3,CF4]

| Original site | Established source/private interface |
| --- | --- |
|`0x9e8aec` | Calls import`___chkstk_darwin`,requested X9 extent`0x1c030`=114736 bytes |
|`0x2f7200` |`pthread_once(control=0x1d36080,initializer=0x28994)` |
|`0x28e4c` |`swpal w8,w8,[x19]`;private cell at offset`0x1d49008`;source1,old0,new1 |
|`0x28f40` |`sysconf(29)`;SDK selector`_SC_PAGESIZE`/`_SC_PAGE_SIZE` |
|`0x29028` |`mmap(0,65536,3,0x1002,-1,0)`;SDK PROT_READ\|PROT_WRITE,MAP_ANON\|MAP_PRIVATE |

The sequential SWPAL model captures the source value before writing the aliased destination register. It models exchange only. Arm defines acquire/release behavior for SWPAL;no concurrent memory-order claim follows from this single-thread fixture. [Arm A64 instruction specification,D3.133](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab).

The exact CoreFP import name has three leading underscores. Effective native resolution is unknown;the inspected cache's similarly named four-underscore export is not promoted to an exact match. The explicit private stack model preserves registers and bounds the requested stack extent. The once model invokes original initializer instructions with private once state. Atomics,once and locks are not native synchronization tests.

Modeled sysconf results4096,16384 and-1 all reach the same first65536-byte mmap request. This establishes only the first request for these fixtures. A modeled MAP_FAILED return follows original instructions back to the public wrapper with status`0xffffffff`. One modeled successful zero-initialized mapping reaches another request at the same mmap callsite;execution stops before a second mapping. Neither case proves native allocation behavior,errno semantics,cleanup completeness or successful certificate processing.

## CoreFP Mach request construction [CF1,CF3,CF6]

The static scan decodes all B/BL encodings in original `__text` targeting73 authenticated import stubs:875 candidate edges across720 compiler-start ranges. Full path reachability is not inferred from these encodings;684 edges target stack-canary failure. Protected indirect API calls are outside this direct-edge inventory. Seven fresh entry fixtures establish local construction for the five Mach builders below.

| Builder | `mach_msg` callsite | Request ID | Send bytes | Receive capacity bytes | Expected reply-ID comparison |
| --- | --- | --- | --- | --- | --- |
|`0x8ae0` |`0x8ba8` |1200 |64 |220 |1300 |
|`0x8d40` |`0x8e04` |1201 |164 |44 |1301 |
|`0x8ed4` |`0x8f90` |1202 |84 |80 |1302 |
|`0x90c8` |`0x914c` |1203 |24 |60 |1303 |
|`0x1590824` |`0x15908c8` |1200 |56 |64 |1300 |

All five calls use import stub`0x15d18e4` and authenticated import cell`0x1d1c3f0` for`_mach_msg`;options3 mean MACH_SEND_MSG|MACH_RCV_MSG. Timeout and notify arguments are0. Header+8 is initialized from original W0 as destination. Header+12 is initialized from `_mig_get_reply_port`'s return. With the weak voucher hook absent,that return also supplies the receive-name argument. With the hook present,the caller passes the message pointer to it and subsequently reloads header+12 into W4;the no-op fixture preserves the same value,but native hook effects remain unknown. Header bits are initially`0x1513` for COPY_SEND remote and MAKE_SEND_ONCE local;requests with an OOL descriptor add`0x80000000`. Header+16 is initially0;header+20 contains the request ID. These field origins precede any effective voucher mutation.

Header+4 remains poisoned in the seven fixtures at this caller boundary. The send-size argument supplies the actual request extent. This is a pre-library-call observation,not a malformed native message finding. The reply-ID comparisons above are original local checks;full reply validation,ownership and outcomes have not been recovered. ID71 has separate source branches and prevents interpreting the table as the complete accepted-reply set.

| Builder | Body after the24-byte header |
| --- | --- |
|`0x8ae0` |+24 count1;+28 address X3;+36 descriptor flags`0x01000100`;+40 W4;+44 NDR8;+52 W1;+56 u32[X2];+60 W4 |
|`0x8d40` |+24 NDR8;+32 W1;+36 inline128 bytes from X2 |
|`0x8ed4` |+24 count1;+28 address X5;+36 flags`0x01000100`;+40 W6;+44 NDR8;+52 W1;+56 W2;+60 W3;+64 inline16 bytes from X4;+80 W6 |
|`0x90c8` | No request body |
|`0x1590824` |+24 count1;+28 address X1;+36 flags`0x01000100`;+40 W2;+44 NDR8;+52 W2 |

The OOL descriptor encodes deallocate0,virtual-copy1,type1 and a32-bit byte length. The fixture NDR bytes are an explicit noncanonical marker to establish byte transfer,not the effective native NDR value. Absent-voucher and no-op-voucher fixtures are separately labeled. A zero reply-name fixture still reaches the local callsite with receive name0;actual send/receive behavior is not inferred.

| Authenticated function-pointer cell | Builder target | IA diversity |
| --- | --- | --- |
|`0x1d04218` |`0x8ae0` |`0x563e` |
|`0x1d03f08` |`0x8d40` |`0x8390` |
|`0x1d05960` |`0x8ed4` |`0xf094` |
|`0x1d059a0` |`0x90c8` |`0x48c5` |
|`0x1d1bba8` |`0x1590824` |`0x57e4` |

These are original table references,not complete caller or destination proofs. Import inventory additionally includes bootstrap lookup,XPC Mach-service creation/synchronous reply and IOKit matching/registry APIs. Their runtime consumers and endpoint names remain unknown in this increment. Numerical request IDs alone do not link these builders to kext502/700,daemon61471 or one another.

## Verification and bounded continuation

Reproduction from the extraction directory,using the existing analysis environment:

```text
$PYTHON triage_evidence/recover_corefp_import_calls.py
$PYTHON triage_evidence/recover_corefp_exports.py
$PYTHON triage_evidence/probe_corefp_exports.py
$PYTHON triage_evidence/probe_corefp_version_bridge.py
$PYTHON triage_evidence/probe_corefp_mach_requests.py
$PYTHON triage_evidence/validate_corefp_exports_delivery.py
```

The existing [format12 reader](triage_evidence/corefp_fixups_reader.py) independently checks all original chain members against the static-tool text. The verifier reads all original fixup words,selected targets,banks,source-function hashes,ordered private instruction hashes,bridge pages/stubs,request fields and dependencies. It reruns all four SMT obligations and compiles the [arm64e layouts/SDK constants](triage_evidence/corefp_exports_layouts.c) without linking or executing. Exact counts and QG1-QG7 status are in the linked check/gate records. The original three supplied inputs remain hash-checked and preserved;no IDB changes were made.

The completed delivery readback passes90956 assertions. Coverage includes79512 original fixups,196 imports,14 selected chain targets,nine bank uses,four SMT obligations,15 export/prefix cases,two AMS transfers,seven request cases,73 import stubs and875 direct branch candidates. The arm64e compile exits0. QG3 and QG5 are explicitly scoped to this increment and its stated claims;the full objective remains incomplete.

Algorithms: static recovery is O(B+F+256K+R),where B is image bytes,F fixups,K bank uses and R retained source bytes;space O(B+F+R). Direct branch enumeration is O(B+S+X+R),with S stubs and X retained edges. Private probes are bounded at30000 instructions per case;time O(C(B+F+Kp)),space O(B+F+C*Kp),with C cases and Kp the bound. Solver time is capped at30 s per query and is not included in those linear bounds. All arithmetic widths and byte extents are explicit;there are no statistical confidence or native performance claims.

| Impact | Further interface question / discriminating evidence |
| --- | --- |
| High | Follow the five builder-pointer cells through their original bank/table callers;recover destination acquisition,bootstrap/XPC service names,port ownership and the two request1200 schemas before endpoint unification. |
| High | Continue WIn mode7 beyond initialization into certificate/record consumers and actual IOKit/bootstrap/XPC calls;separate argument codecs from payload protocol and successful output. |
| High | Recover each reply parser,ID71 handling,transport-error cleanup,OOL extent/ownership and reply-name retirement;then correlate with the daemon/kext message families. |
| Medium | Recover the allocation loop bound and every MAP_FAILED/partial-initialization exit,once-state lifetime and synchronization of mutable cells;the current first-map failure is a conditional result. |
| Medium | Resolve the exact native stack import and CoreFP/AMS image pairing before applying these private continuation results to a running process. |
| Low | Compare the other arm64 slice's export/record layouts using its own identity;the selected-slice proof cannot be transferred by symbol name alone. |

The full investigation remains active and incomplete. No source-analysis blocker is asserted.

## Subsequent lookup and reference-protocol recovery

The [lookup/cache and paired-image report](corefp_lookup_report.md) resolves the destination acquisition for header-only request1203:original lookup0x1cdb24 requests `com.apple.fpsd`,falls back to `com.apple.fairplayd` only on1102,and passes the primary cached name to builder0x90c8. It recovers the32-byte lookup record,one original protected caller,cache reuse/two-name reset and ignored metadata status. The supplied daemon's metadata method is1204;its1203 rejects this24-byte simple query with-304. Three explicit private comparisons establish original-ID rejection,request-only reply-ID mismatch,and payload parsing under counterfactual adaptation of both IDs. Actual native pairing and the other builders' acquisition paths remain unknown.

The [subsequent client-path report](corefp_client_paths_report.md) resolves two request1200 destinations:the64-byte FPSD client receives the lookup name and stages a756-byte certificate;the56-byte client targets `com.apple.adid` through XPC and a legacy Mach fallback. Its signed64-bit selector,28-byte network-order payload,five interrupted-object XPC attempts,invalid-destination recovery and event-description/free handler have original-byte/private evidence. Current CoreADI provider declarations are retained separately from live endpoint identity.

## FPSD1200 application and reply contract increment

The reference64-byte FPSD1200 builder now has a recovered212-byte reply parser: eight caller output regions, descriptor/count guards, simple-error propagation and transport-dependent reply-port cleanup. The separate56-byte request1200 interface remains outside this pairing. See [FPSD1200 contract](fpsd1200_contract_report.md) and [source/private evidence](triage_evidence/fpsd1200_contract_checks.json.zst).
