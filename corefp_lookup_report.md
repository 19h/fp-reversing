# CoreFP service lookup,cache lifetime and reference-image metadata protocol

Original CoreFP routine`0x1cdb24` acquires `com.apple.fpsd`,falling back to `com.apple.fairplayd` only on bootstrap status1102. Successful primary lookup supplies the destination for the header-only request1203. Successful fallback returns the cached name without this metadata query. A protected caller at`0x8e81c8` now reaches this lookup through original instructions under the recorded input preconditions.

The inspected CoreFP and supplied daemon differ at the metadata method ID. CoreFP sends simple request1203,size24,and expects reply1303. The daemon's1203 requires a complex100-byte request and rejects the simple form with-304;its four-word metadata method is1204. A private source-to-source adapter reproduces the rejection and the CoreFP caller's subsequent success-marker publication. This establishes a reference-image protocol difference,not native deployment incompatibility or a successful native transaction.

## Evidence and assumptions

CoreFP offsets use preferred base0. Daemon addresses are preferred arm64e image VAs. Neither denotes runtime addresses or port-object identities. CoreFP slice SHA-256 is`8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`,UUID`9061ddc3-93b4-3824-914f-9cc97d708d58`;the [preceding report](corefp_exports_report.md) retains its universal-file identity and version6.8.3. Daemon SHA-256 is`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,UUID`204741e9-b89f-32b4-9321-51f3975c7cac`.

| ID / assumption | Dependent claims | Stress test / current status |
| --- | --- | --- |
| L1: pinned originals define the reference images | Every offset,string,record and protocol comparison | Fresh file hashes,original instruction bytes,selected chains/imports and source-range readbacks pass. Actual native library/slice/cache pairing remains unknown. |
| L2: local W/X arithmetic and tag preconditions describe these records | Codecs,flag/cache partitions and caller prefix | Eleven distinct bank identities exhaust256 inputs;three SMT obligations prove local32/64-bit identities. Lookup tag0xba27 and parent decoded operation0xc1f7 are explicit preconditions;other operations remain open. |
| L3: private fixup materialization and PAC bypass select the decoded targets | All private source paths | Original pointers,authentication fields,bytes and ordered visits retained. Hardware PAC,ASLR,signatures and runtime targets are unverified. |
| L4: warm-once and abstract-lock models provide the stated initialized environment | Lookup/cache/reset continuation | Separate first-once and lock-boundary cases precede the models. Once initializers are not executed in warm cases. Native synchronization,complete initialization and lock lifetime remain unknown. |
| L5: bootstrap/transport/cleanup fixtures supply the stated results and output effects | Port-name outputs,metadata failures and reset cases | Fallback,error,cache and cleanup variants are explicit. Failure models preserve bootstrap output;alternate failure-output contracts remain open. No real right is acquired or retired. |
| L6: ordinary callee ABI and explicit receive envelopes are adequate for the local comparison | Ignored metadata result and paired-image outcomes | Exact body bytes cross isolated engines;normal source returns and post-call instructions are checked. Names,bits,transport return and ID adaptations are labeled fixtures. Native message delivery,exceptional control flow and endpoint identity remain unknown. |

Artifacts: [static contracts](triage_evidence/corefp_lookup_contracts.json),[16 lookup/cache cases](triage_evidence/corefp_lookup_profiles.json),[protected caller prefix](triage_evidence/corefp_lookup_caller_profile.json),[three paired-image cases](triage_evidence/corefp_protocol_pair_profiles.json),[independent checks](triage_evidence/corefp_lookup_profile_checks.json) and [quality gates](triage_evidence/corefp_lookup_quality_gates.json). The existing79512-member fixup inventory remains a pinned dependency;this increment independently reads20 selected resolutions.

## Lookup record and protected caller [L1-L4]

Routine`0x1cdb24..0x1ce4f0` consumes the following observed32-byte record:

| Offset | Width | Local role |
| --- | --- | --- |
|0 |32 bits | Encoded completion marker |
|4 |32 bits | No application role established |
|8 |64 bits | Pointer to caller's u32 port-name output |
|16 |64 bits | Pointer to caller's u32 metadata-flags output |
|24 |8 bits | Address-encoded flag |
|25..27 |24 bits | No application role established |
|28 |32 bits | Address-encoded operation tag |

With`p=low32(record_pointer)`,all word arithmetic modulo2^32:

```text
k = (p XOR 0x8b4ea7c9) * 0x0bcb7857
decoded_tag  = stored_tag - k
decoded_flag = (stored_byte - k) mod256
```

The recovered caller constructs tag`0xba27` and flag9. Conditional bank/table resolution at caller`0x8e851c` selects authenticated slot`0x1d04e40`,target`0x1cdb24`,IA diversity`0x1eb7`;the call modifier matches. Original caller entry`0x8e81c8` reaches it with decoded input operation`0xc1f7`,two non-NULL private pointer inputs and an explicit bounded stack-probe model. Its incoming cursor cell increases by256. The cursor's broader semantics and complete parent-record schema remain unknown;the48-byte fixture buffer is not asserted to be the full ABI size.

The parent32-bit operation is derived from a64-bit address mix. Its proof uses`mixed64=record_pointer XOR 0x84b771aed97ffe38`;the source then multiplies by`0xfcf33521` modulo2^64. The source guard selects table index`0xc20a` under the stated operation/pointer preconditions,and the child tag simplifies to`0xba27`. One fresh parent run reaches the original bootstrap boundary without jumping directly into the lookup helper.

For tag0xba27,flag9 skips reset and tests the cache. Every other byte flag selects the reset helper before the cache test. The third-party/native reachability of these flags is not established merely by enumerating their local branch semantics.

## Service acquisition and metadata destination [L1-L6]

```text
protected caller0x8e81c8
  -> lookup0x1cdb24, tag0xba27
  -> once / write-lock interfaces
  -> [flag != 9: reset two cached names]
  -> cached name != 0 -------------------------------> copy name/flags
  -> bootstrap_look_up(com.apple.fpsd)
       status0 -> cache name -> request1203 -> copy name/flags
       status1102 -> bootstrap_look_up(com.apple.fairplayd)
                       status0 -> copy name/flags
                       error   -> failure marker
       other error ----------------------------------> failure marker
```

| Original CoreFP interface | Address / source origin |
| --- | --- |
| First once call |`0x1cdd74`;control`0x1d34f90`,initializer`0x4a21e0` |
| Lock-helper once |`0x20f5a8`;control`0x1d37f50`,initializer`0x59e868` |
| Write-lock call |`0x20f6cc`,exact import`pthread_rwlock_wrlock`;selected private object`0x1d27bf0` |
| Bootstrap namespace input | Import`_bootstrap_port` through slot`0x1d08c10` |
| Primary lookup |`0x1ce1bc`,exact import`bootstrap_look_up` through slot`0x1d05318` |
| Fallback lookup |`0x1ce448`,same exact import/slot |
| Cached returned-name cell |`0x1d44448`;both lookups pass its address as output |
| Metadata call |`0x1ce274` -> slot`0x1d059a0` -> builder`0x90c8` |
| Metadata destination | W0 loaded from cached-name cell at`0x1ce210` |
| Metadata emission | Builder calls `mach_msg` at`0x914c`,ID1203,send24,receive capacity60 bytes |

The lock helper's optional input cell`0x1d444a8` is originally zero. Its source fallback reads pointer cell`0x1d383d8`,which resolves to`0x1d27bf0`. This distinguishes a nullable input cell from the selected lock object. Warm cases model already-initialized once controls and an abstract successful lock;they do not validate the object's native initialization. No unlock is established within this local lookup path;the surrounding lock-owner/lifetime contract remains open.

The primary service string is decoded from15 bytes at`0x1746bf0` with byte XOR`0x19`. Fallback decodes20 bytes at`0x1915ec0` with XOR`0xf7`;the one state-derived XOR byte simplifies to the same key for tag0xba27. Both include their terminating NUL. This is original string/argument evidence,not inference from nearby plaintext.

Primary status1102 alone selects fallback. Installed SDK headers identify it as BOOTSTRAP_UNKNOWN_SERVICE. Other modeled primary errors return encoded failure marker`0x45e2a2e3` and preserve both poisoned caller outputs. Successful primary/fallback/cache paths store marker`0xba1df9db` and copy a u32 cached name plus u32 flags into caller-owned outputs. These are internal record markers;they are not assigned public error-enumeration names.

## Cache reset,metadata state and ignored status [L2-L6]

| Cell / range | Recovered role |
| --- | --- |
|`0x1d44448` | Primary cached name |
|`0x1d37838` | Separate cached name used by reset |
|`0x1d37990`,`0x1d37994`,`0x1d37998`,`0x1d3799c` | Four metadata output words;the fourth is copied to the caller's flags output |
| Structure+`0x38`,base`0x1d37838` | Reset/primary paths store marker`0x59fece35`;broader semantics unknown |

Reset helper`0x57a67c..0x57aa78` conditionally calls `mach_port_deallocate` for nonzero names at`0x57a988` and`0x57aa2c`,then clears both name cells and the metadata words. Populated private cases request retirement of secondary0x5066 followed by primary0x5055 in synthetic task0x1717. Modeled deallocation status0 and status5 both lead to cleared names and renewed primary lookup. Requested deallocation,local cache clearing and actual right retirement are separate facts;native ownership/refcounts remain unknown.

Reset also clears the u32 field at structure+`0x168`;its consumers remain unknown. Additional64-bit protected-state writes are retained in the profiles. Their complete state formulas,lifetimes and concurrency contract remain open.

A nonzero cached name under flag9 bypasses both bootstrap lookup and metadata RPC. The function copies the stored name and flags without an additional right-acquisition operation in this inspected local path. This does not establish whether the caller receives a borrowed right,an owned reference or a name backed by multiple user references.

After successful primary lookup,the code ORs`0x0a` into the metadata flags and calls request1203. A successful52-byte reply replaces the four metadata words. With zero-initialized metadata fixtures,transport status`0x10000003` and application reply status`0x42` preserve flags`0x0a`;both still lead to the success marker and acquired-name output. These are conditional finite outcomes,not native transport failures.

At`0x1ce278..0x1ce28c` and`0x1ce47c..0x1ce4a8`,the normal post-call continuation has no X0/W0 operand. Its tag-selected branch targets copy cached outputs and write the fixed success marker. Thus the returned metadata status is not consumed on this local continuation under the ordinary callee ABI. Metadata success,bootstrap success and lookup completion are distinct postconditions.

## Reference protocol difference [L1,L3,L5,L6]

The daemon's [original MIG catalog](interface_abi_report.md) and [receive routing](daemon_receive_interface_report.md) place IDs1200-1204 in one subsystem. The first three request shapes agree with the corresponding CoreFP builders;the metadata method differs:

| Operation / request ID | CoreFP request | Supplied daemon request / reply |
| --- | --- | --- |
|1200,main CoreFP builder | Complex64 bytes,one OOL | Complex64 bytes;reply212 bytes |
|1201 | Simple164 bytes | Simple164 bytes;status reply36 bytes |
|1202 | Complex84 bytes,one OOL | Complex84 bytes;reply72 bytes |
|1203 | Simple24-byte metadata query;expects1303 | Complex100-byte request at`0x100004918`;simple form rejected with-304 |
|1204 | No corresponding builder established here | Simple24-byte metadata query at`0x100004ae4`;reply1304,size52 |

The distinct CoreFP builder at`0x1590824` also uses ID1200 with56 bytes;its endpoint remains unresolved and it is excluded from this main-interface comparison.

Daemon1203 first tests the complex bit at`0x10000491c`;the simple CoreFP form goes directly to`0x1000049b4`,which stores-304 at reply+32. The source demultiplexer recognizes the ID and builds reply1303,size36. Installed SDK names this structural rejection MIG_BAD_ARGUMENTS.

Daemon1204 requires simple size24,then invokes`0x100006424`,which stores four u32 words`76,9,0,42` and returns0. The stub constructs a52-byte reply. The words' semantic labels are unknown;they are not declared to be a version tuple from their numerical appearance.

| Private paired-image case | Original daemon result | Original CoreFP metadata result | Lookup output |
| --- | --- | --- | --- |
| Original request/reply IDs |36-byte reply1303,status-304 | Returns-304 | Success marker;cached name;flags0x0a |
| Counterfactual request changed to1204 only |52-byte reply1304,status0 | Returns-301,MIG_REPLY_MISMATCH | Success marker;cached name;flags0x0a |
| Counterfactual request1204 and reply-ID adaptation to1303 |52-byte source body containing76/9/0/42 | Returns0;parses all four words | Success marker;cached name;flags42 |

Both engines execute original instruction bytes in isolated private spaces. The adapter supplies request size,received-header bits and synthetic task-local names;it copies reply body bytes exactly. Transport return0 and cleanup are explicit models. Counterfactual ID changes occur only in adapter buffers. No original binary,IDB or native process is patched. This comparison proves local guard/parser behavior and payload-layout compatibility under the stated adaptations. It does not prove a shared native namespace or overall library compatibility.

## Validation and continuation

The increment passes3100 assertions:11 exhaustive bank identities,20 selected resolutions,two decoded service strings,three SMT obligations,16 lookup/cache cases,one protected caller case,three paired-image cases,six static CoreFP functions and four daemon ranges. Original instruction hashes and dependency hashes are reread;the arm64e32-byte layout and bootstrap/MIG constants compile with exit0. QG1-QG7 pass for the stated increment;the full objective remains active and incomplete. The three supplied original inputs and IDBs are preserved.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_corefp_lookup.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_corefp_lookup.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_corefp_protocol_pair.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_corefp_lookup_delivery.py
```

Static recovery/readback is O(B+F+R+V+256K),with image bytes B,fixups F,retained ranges R,source visits V and bank identities K;space O(B+F+R+V). Private source probes retain the30000-hook bound;daemon children have a2000-hook bound and explicit source-range allowlist. Solver complexity is separate,with30 s per-query limits. Sizes are bytes and fixed-width modular arithmetic is explicit. No timing or native scheduling claim is made.

| Impact | Further discriminating evidence |
| --- | --- |
| High | Establish actual CoreFP/daemon selection and effective registered receive endpoint before transferring this method-ID difference to a native environment. |
| High | Follow the protected caller's returned name/flags into the larger1200/1202 clients and every other lookup/reset caller;complete acquisition-to-use-to-retirement ownership. |
| High | Recover metadata-word consumers and behavior when the query fails. The observed success marker proves lookup completion,not metadata validity or later processing success. |
| Medium | Matching first-three request shapes plus differing metadata IDs are consistent with independently versioned MIG definitions or method insertion;historical chronology and intent remain unknown. Recover definitions/build provenance. |
| Medium | Complete both once initializers,write-lock owner/unlock paths,reconnect/reset races and failure-output behavior;cache-name equality requires user-reference accounting before interpreting repeated deallocation. |
| Medium | Resolve the separate56-byte request1200 client's service and schema. Equal numerical IDs do not establish a shared interface. |

No source-analysis blocker is asserted. Native ports,rights,PAC,concurrency,complete protected algorithms and the full daemon/kext/deeper-interface topology remain unresolved.

## Subsequent acquisition-to-request and secondary endpoint recovery

The [client-path report](corefp_client_paths_report.md) continues the original protected caller beyond lookup:the returned name reaches the64-byte request1200 destination,including after modeled metadata failure. Its OOL payload is a756-byte FPPineBoard certificate decoded from an embedded760-byte container and staged on the stack before emission. The separate56-byte request1200 belongs to `com.apple.adid`,with a28-byte XPC payload,Mach fallback,invalid-destination bootstrap/retry and a recovered event handler. This resolves the former endpoint ambiguity within the recorded source/private boundaries. Native pairing,receiver processing and rights lifetime remain open.
