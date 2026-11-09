# Launchd incoming audit context and check-in caller identity

The global audit-shaped record consumed by the check-in core now has two identified original producers in each launchd slice. The XPC dispatcher copies the request dictionary's32 B audit token to `0x10008b408` before invoking its registered callback. The raw-Mach dispatcher copies32 B from the aligned message trailer to the same address before calling raw demultiplexers. The ordinary libxpc dictionary path supplies its metadata from that trailer. Original libbsm accessors independently name all eight token words. This extends the [bootstrap handoff report](bootstrap_checkin_handoff_report.md); the previous global-writer gap is resolved for these selected paths, conditional on no intervening writer. Native sender authenticity, admission, cross-path serialization and a complete writer/lifetime census remain unknown. [Source](triage_evidence/launchd_audit_context_source.json), [checks](triage_evidence/launchd_audit_context_checks.json).

## Identity and scope

Launchd universal SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The capture reads original cache implementations in `/usr/lib/system/libxpc.dylib` and `/usr/lib/libbsm.0.dylib`, with exact exports/nlist records, library UUIDs, used-cache-file hashes and installed SDK/tool identities. [Capture](triage_evidence/launchd_audit_context_source.json).

The selected35 complete compiler-bounded bodies contain2,973 instructions/11,892 B:20 launchd and15 cache bodies, including eight two-instruction libbsm field accessors. Twenty-two x1 words require LLVM decoding. The x1 raw dispatcher uses `addpt` where the normal slice uses `add`; no architectural equivalence or hardware pointer/authentication behavior is inferred. No recovered dispatcher, target IPC, policy API, token override or native sender experiment was executed. Only static inspection and SDK compilation ran. [Validation scope](triage_evidence/launchd_audit_context_checks.json).

## Incoming-message and producer correspondence

| Analytical role | arm64e start | arm64e.x1 start |
|---|---|---|
| Dispatch Mach event callback | `0x100046804` | `0x100045aec` |
| Dispatch Mach message entry | `0x10004695c` | `0x100045c38` |
| Dictionary/carrier entry | `0x100046188` | `0x100045470` |
| Raw-Mach dispatcher/token writer | `0x1000462f8` | `0x1000455e0` |
| XPC dispatcher/token writer | `0x1000464a8` | `0x100045790` |
| Current-dictionary setter/clearer | `0x10003a3a4` | `0x100039864` |
| Group/callback array writer | `0x100045930` | `0x100044c60` |
| Group5 check-in dispatcher | `0x10002e16c` | `0x10002d830` |
| Routine206 handler | `0x100038158` | `0x100037690` |
| Endpoint/check-in core | `0x100059640` | `0x1000586a0` |

The new capture retains89 exact-address token locators per slice (178 total), two direct callers of each XPC dispatcher, two raw-dispatcher callback literals, and one direct caller of each Mach-message entry. The locators cover ADRP+ADD and ADR exact-address patterns in `__text`; the caller scan covers aligned B/BL instructions. They do not establish an exhaustive census of scalar/partial stores, pointer aliases, indirect writers, other images or runtime-generated code [AC1,AC6]. [Reference records](triage_evidence/launchd_audit_context_source.json).

```text
dispatch Mach event reason2
       |
dispatch_mach_msg_get_msg -> saved original ID
       +-- XPC classes -> normalize class ID, preserve low24 routine
       |       |
       |   xpc_receive_mach_msg
       |       -> aligned trailer audit bytes
       |       -> ordinary dictionary metadata
       |       -> xpc_dictionary_get_audit_token
       |       -> global32 B at 0x10008b408
       |       -> registered group5 -> routine206 -> check-in core
       |
       +-- raw-Mach path -> raw dispatcher -> trailer audit -> same global

dictionary entry
       +-- ordinary XPC dictionary -> XPC dispatcher
       +-- "mig-request" data carrier -> raw dispatcher
```

This is a static producer/consumer diagram. Raw carrier/trailer validity, metadata category selection, asynchronous callbacks, nested dispatch and effective native caller identity remain distinct obligations [AC2-AC5].

## Class normalization and audit-trailer ingress

The event callback's reason2 path loads its endpoint context, invokes the Mach-message entry, and clears the separate current-endpoint context slot on return. Other event reasons have different cleanup/control paths; numeric reasons are not assigned unverified SDK enum names here. The message entry obtains a pointer and extent from `_dispatch_mach_msg_get_msg` and checks extent>23 before reading a24 B header.

For IDs whose high byte is `0x40` or `0x10`, it saves the original ID, rewrites the message header's ID to the high-byte class alone, and calls `_xpc_receive_mach_msg`. On success it sets the current-dictionary pointer, invokes the XPC dispatcher with the saved low24 routine, releases the decoded dictionary and clears the current-dictionary pointer. This accounts for historical request `0x400000ce` becoming class `0x40000000` plus routine206 before dispatch. It is not a new runtime observation. [Entry and context-helper bodies](triage_evidence/launchd_audit_context_source.json).

The original cached `_xpc_receive_mach_msg` validates the normalized header and computes the trailer position as:

```text
aligned_message_bytes = (u64(u32(msgh_size)) + 3) & 0x00000001fffffffc
audit_address         = message_address + aligned_message_bytes + 20
```

It copies two16 B blocks from trailer offsets20 and36 to its local metadata record. The installed SDK defines `mach_msg_audit_trailer_t` as52 B with `msgh_audit` at+20. The raw dispatcher performs the same alignment and two loads, then stores directly into the global token. The numeric alignment formula is proved for the full u32 size domain; that proof excludes buffer extent/ownership, actual trailer validity and x1 `ADDPT` semantics. [Original copy instructions and SDK checks](triage_evidence/launchd_audit_context_checks.json).

The standalone cached `_xpc_receive_mach_msg_validate_hdr` at `0x184b89370` has these precise selected predicates. They describe the validator's input phase, which can follow header normalization; they are not blanket classifications of every wire packet.

| Canonical input ID | Accepted remote-port condition in this validator |
|---|---|
| `0x10000000`, `0x20000000`, `0x40000000` | Remote name is0, or low5 header bits equal18 (`MOVE_SEND_ONCE`) |
| `0x30000000` | Remote name is0 |
| Any other u32 ID | Rejected |

The zero-name case follows the conditional comparison's fallback Z flag. It must not be simplified to a requirement for a nonzero remote port. A full32-bit ID/header/name proof verifies the predicate. This selected header check does not establish a complete validation of all payload/trailer bytes or native sender provenance [AC2,AC6].

## Dictionary metadata and getter categories

In the captured ordinary graph-unpack path, libxpc sets the dictionary's low-two-bit metadata category to1 and copies the metadata token to dictionary offsets+`0x78` and+`0x88`. `_xpc_dictionary_get_audit_token` at `0x184b72b64` validates the dictionary class and selects its copy by that category. [Receive, graph-unpack and getter bodies](triage_evidence/launchd_audit_context_source.json).

| Metadata category, low2 bits | Getter source / result |
|---|---|
| 1 | Copy32 B from dictionary+`0x78` |
| 3 | Copy32 B from dictionary+`0x58`; producer lineage not completed here |
| 0 or2 | Write seven `0xffffffff` words and PID word0 |
| Wrong object class | Separate diagnostic path |

The fallback pattern is not the installed SDK's all-ones `INVALID_AUDIT_TOKEN_VALUE`. It is reported as an exact library output pattern, without inferring kernel origin, a native sender, or a policy outcome from PID0. The ordinary category1 lineage is established statically; category3 and other producer/lifetime paths remain open [AC2,AC5].

## Global producer, consumer and field interpretation

The XPC dispatcher clears its local32 B output buffer, calls `_xpc_dictionary_get_audit_token`, loads both16 B blocks and stores them to `0x10008b408`. This store precedes group lookup and the authenticated registered callback. The group5 dispatcher passes that exact address in X1 to routine206; the handler preserves it and passes it in X1 to the endpoint core. The core preserves the record pointer and reads its32-bit word+20 for caller/job lookup. This establishes the selected static data flow; it assumes no intervening nested/aliased writer before the consumer read [AC3].

| Operation | arm64e site | arm64e.x1 site |
|---|---|---|
| Raw dispatcher stores32 B token | `0x100046348` | `0x100045630` |
| XPC dispatcher gets token | `0x100046528` | `0x100045810` |
| XPC dispatcher stores32 B token | `0x100046538` | `0x100045820` |
| XPC dispatcher calls registered callback | `0x100046718` | `0x100045a00` |
| Group5 passes token address for routine206 | `0x10002e2e0` | `0x10002d9a4` |
| Check-in core reads word+20 | `0x100059680` | `0x1000586e0` |

All eight original libbsm exports consist of a32-bit load from the token argument plus return. Their exact exports, UUID, bytes and offsets independently establish this target-version field interpretation. This is not an assumption that an opaque token has the same representation on every platform or release. [Accessors](triage_evidence/launchd_audit_context_source.json).

| Word index | Offset, B | Original accessor | Selected global address | Interpretation |
|---|---|---|---|---|
| 0 | 0 | `audit_token_to_auid` | `0x10008b408` | Audit UID |
| 1 | 4 | `audit_token_to_euid` | `0x10008b40c` | Effective UID |
| 2 | 8 | `audit_token_to_egid` | `0x10008b410` | Effective GID |
| 3 | 12 | `audit_token_to_ruid` | `0x10008b414` | Real UID |
| 4 | 16 | `audit_token_to_rgid` | `0x10008b418` | Real GID |
| 5 | 20 | `audit_token_to_pid` | `0x10008b41c` | PID |
| 6 | 24 | `audit_token_to_asid` | `0x10008b420` | Audit session ID |
| 7 | 28 | `audit_token_to_pidversion` | `0x10008b424` | PID version |

Storage words are32 bit; interpretation/return types follow the respective accessors. The XPC dispatcher's optional reply augmentation reads the PID and PID-version words and inserts keys `"req_pid"` and `"rec_execcnt"`. The second key's literal label does not change the independently verified PID-version accessor mapping. The global byte enabling that augmentation is cleared at dispatcher entry; its complete setter/callback lineage and client-side checks remain separate work.

## Routing and callback array linkage

The numeric dispatch path accepts routine values up to1399 for classification. Its shift/multiply/shift sequence computes `floor(routine/100)` over that complete bounded domain. A bit mask `0x861` excludes table indices0,5,6 and11. The captured14-entry table is identical across slices, at `0x10005ff08` and `0x10005eec8`. [Table bytes, proof and finite bank](triage_evidence/launchd_audit_context_checks.json).

| Routine hundred band | Table group | Numeric path selects table entry? |
|---|---|---|
| 0..99 | 0 | No; routine0 takes the explicit-dictionary branch |
| 100..199 | 7 | Yes |
| 200..299 | 5 | Yes |
| 300..399 | 6 | Yes |
| 400..499 | 4 | Yes |
| 500..599 | 0 | No |
| 600..699 | 0 | No |
| 700..799 | 2 | Yes |
| 800..899 | 3 | Yes |
| 900..999 | 8 | Yes |
| 1000..1099 | 10 | Yes |
| 1100..1199 | 0 | No |
| 1200..1299 | 11 | Yes |
| 1300..1399 | 12 | Yes |

The finite bank checks all1400 classifier inputs and records1000 selected numeric values. It does not claim those requests pass context, registry or application-policy gates. Zero selects an alternate branch reading `"subsystem"` and `"routine"` from the dictionary; its low-word checks and signed upper comparison are retained as such, rather than recast as a general u64 range guarantee.

Group IDs and callbacks are stored in the parallel arrays written by the previously captured registration helper. The XPC dispatcher matches a32-bit group ID, indexes the callback array and invokes it with X0=context, X1=routine, X2=request, X3=&reply. For routine206 the classifier yields index2/group5; the [prior group5 routine table](bootstrap_checkin_handoff_report.md) then selects entry6/check-in. Callback pointer authentication is present in the original instructions but was not executed or hardware-validated.

## Request lifetime, reentry and carrier boundaries

| Selected state cell | Static producer/consumer behavior | Remaining boundary |
|---|---|---|
| Audit token `0x10008b408`,32 B | XPC/raw dispatchers overwrite; check-in core reads | No restoration/zeroing is visible in the selected ordinary dispatcher suffixes; other writers and nested/raw paths remain open |
| XPC busy byte `0x10008a9e0` | Entry checks equality with1; sets1 before work; ordinary suffix clears0 | Ordinary byte operations are not a cross-thread lock or complete serialization proof |
| Current dictionary `0x10008b3d8` | Setter stores dictionary/NULL under its lock-related helpers and clears a separate cached-reply cell | This is a pointer lifetime aid, not the audit-token record or a demonstrated thread-local slot |
| Current endpoint context `0x10008b428` | Event/carrier entry supplies context; ordinary return clears it | Callback/error/nested lifetimes and wider context structure remain open |
| Reply augmentation byte `0x10008b430` | Cleared at XPC entry; later conditional branch adds identity fields | Complete setter and native/client validation behavior not established here |

The current-dictionary helper's critical section does not encompass every audit-token store and every application callback. The XPC busy byte detects its selected reentry condition, but the raw dispatcher has its own path; neither fact proves serialization across all producers. At ordinary return, the previous audit token is not restored by the captured suffix, so a later consumer must be interpreted in its actual request/dispatch epoch [AC3,AC4].

The dictionary/carrier entry checks for `"mig-request"`. Its data branch obtains the bytes and length, requires length>23, and hands the raw request to `__xpc_pipe_handle_mig` with the raw dispatcher as callback. The raw dispatcher then sources its global token from the supplied raw message's aligned trailer. Its outer dictionary and inner raw-message identity carriers therefore must be tracked separately. This increment does not establish their equivalence, complete upstream carrier validation or native authenticity, and does not reproduce a failure or vulnerability [AC2,AC5].

The raw dispatcher also retains a current raw-message pointer and tries registered raw demultiplexers. `__xpc_pipe_handle_mig` supplies the request/reply to its callback, processes the callback result and performs its own selected destruction/reply-send paths. It is distinct from `_xpc_pipe_routine_reply`, which packs an XPC reply through the earlier serializer. Numeric request/reply IDs, carrier objects, local metadata and kernel-produced trailer context remain different interfaces.

## Assumptions, falsification and continuation

| ID | Assumption / dependent result | Stress test or falsification probe | Status |
|---|---|---|---|
| AC1 | Pinned files identify the selected implementation | Rehash all spans/cache files/tools, match4894 fixups and both producer/caller relationships; separately attest loaded images | Static identities verified; native pairing unknown |
| AC2 | Ordinary XPC receive metadata derives from the indicated trailer | Check header normalization, receive/unpack token copies and category1 getter; complete carrier validation/category3 producer and native trailer provenance independently | Selected ordinary static lineage verified; authenticity/other paths unknown |
| AC3 | The global consumer reads the token written for its request | Match write-before-callback and pointer forwarding through group5/206/core; trace every nested/aliased writer and one native dispatch epoch to test persistence assumptions | Selected direct data flow verified; complete writer/epoch proof unknown |
| AC4 | Busy/context operations delimit the analyzed lifetime | Check entry/exit stores, current-dictionary helper and raw path; prove actual queue/thread serialization and exceptional/nested completion separately | Local stores/order verified; cross-path concurrency unknown |
| AC5 | Field and fallback interpretation follows this target's primary interfaces | Check all eight libbsm bodies, SDK sizes/initializer, metadata categories and reply labels; do not infer origin or admission from a token pattern alone | Field ABI/pattern verified; effective native identity/policy unknown |
| AC6 | Manual routing/alignment/header formulas match selected instructions | Check188 instruction anchors, three complete-domain proofs,1400 classifier values and seven altered evidence records; independently evaluate ISA/pointer behavior | Scalar scope verified; no ADDPT/hardware or whole-path proof |

| Impact | Remaining interface question | Discriminating evidence |
|---|---|---|
| High | Are outer dictionary and raw carrier identities always tied to the same incoming transport? | Trace upstream `mig-request` producers/validation and preserve separate carrier/trailer objects; no fabricated request or native policy change is needed |
| High | Can another producer overwrite the global before a later consumer? | Broader alias/store census, actual callback/queue topology and native request epoch; the178 locators are not exhaustive |
| High | How does notification69 return a destroyed receive right to launchd? | Continue notification receiver and source callbacks from the prior handoff report |
| Medium | Where does metadata category3 obtain its audit token? | Trace its original builder and lifetime; the getter alone cannot establish origin |
| Medium | Who enables identity-field reply augmentation, and how do clients consume it? | Trace byte430 writers and both `req_pid`/`rec_execcnt` reader contracts |
| Medium | Which live endpoint receives RPC700/host slot34? | Correlate publication, handoff and read-only port identity evidence; audit data flow alone does not identify the peer |

## Reproduction and quality gates

Run `/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_launchd_audit_context.py` from the extracted directory. It recaptures original files, checks188 instruction assertions, compiles22 SDK assertions, runs three scalar queries, checks1400 routing inputs and rejects seven evidence alterations. It emits no target IPC and creates no caller records for target execution. Time/space are O(B+F+I) for bytes B, fixups/references F and selected instructions I; the numeric bank is a separate fixed1400-input calculation. [Recovery](triage_evidence/recover_launchd_audit_context.py), [validator](triage_evidence/validate_launchd_audit_context.py).

QG1: Factual interface and provenance analysis; no normative judgment required.

QG2: AC1-AC6 state assumptions, dependent results and falsification probes.

QG3: This increment covers selected producers, ordinary trailer/metadata lineage, check-in consumer, field ABI and routing/lifetime boundaries. Complete carrier authenticity, writer/queue/epoch proof, native admission, notification return and RPC700 remain open; the full goal is active.

QG4: Token32 B/eight32-bit storage words, trailer52 B/audit offset20 B, header24 B, address widths and signed/low-word routing checks are explicit. Numerical alignment and bounded quotient proofs do not claim address validity or ADDPT equivalence.

QG5: Outer/inner carriers, token/current-pointer/busy cells, ordinary/alternate metadata categories, fallback/invalid initializer, scalar/ISA behavior and static/native provenance remain distinct.

QG6: Original bytes, exact exports/nlist entries, authenticated bindings, SDK/tool/file hashes, reference scans and proof queries support the stated scope. No native identity or policy result is inferred from field labels alone.

QG7: The impact-labeled continuation table retains carrier, writer, notification, alternate metadata and peer-identity gaps.

Publication: [prior manifest](triage_evidence/launchd_audit_context_prior_manifest.json), [preservation seal](triage_evidence/launchd_audit_context_delivery.json), [scoped gates](triage_evidence/launchd_audit_context_quality_gates.json), [seal script](triage_evidence/seal_launchd_audit_context.py), [independent audit](triage_evidence/verify_launchd_audit_context_publication.py), [current corpus manifest](triage_evidence/interface_manifest.json). `full_goal_complete=false`.
