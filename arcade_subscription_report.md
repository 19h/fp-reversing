# Arcade subscription path, record serialization and CoreFP XPC boundary

The kernel's4096-byte RPC61471 input is produced by a process-path routine corroborated by its `proc_pidpathinfo_internal` diagnostic name and exact vnode exports. The daemon copies that path, checks the anonymous service name, builds an80-byte private record and serializes a nested tagged message into an XPC dictionary under key `data`. The outgoing connection is `com.apple.fpsd.arcadeservice`, with bundle path `/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/XPCServices/com.apple.fpsd.arcadeservice.xpc`.

This extends the [41471/51471 registration report](created_port_report.md). The outgoing synchronous XPC call is established at`0x10077e614`. A subsequent [service report](arcade_service_report.md) recovers the installed peer requirement and packet-to-audit/guest boundary; the [reply report](arcade_reply_report.md) recovers daemon envelope/status-width checks. Actual XPC delivery,successful response schema,final subscription policy and native task outcome remain unknown. All execution evidence below is private Unicorn execution with explicit API models and PAC bypass; no target host IPC,files,frameworks or loader calls execute. The broad goal remains active and incomplete.

```text
kernel thread/task context
  +-- process-like pointer: [thread read-only view+0x18]
  +-- proc_pidpathinfo_internal-like producer ->4096-byte buffer
  +-- opaque u64 from process-like object+0x5a0
        |
        +-- registered anonymous daemon endpoint / MIG61471
              |
              +-- output word :=1
              +-- strcpy_chk(local1024,path) BEFORE service-name gate
              +-- compare incoming name with anonymous CFMachPort name
              +-- strnlen(path,1024)
              +--80-byte private path record / allocated parser objects
              +-- typed nested serialization
              +-- CoreFP arcade XPC connection / main queue
              +-- dictionary["data"] := serialized bytes
              +-- send_message_with_reply_sync  <--- private fixture stops here
                    |
                    +-- actual reply/policy/decision processing: unknown
              |
        MIG61571 status + decision word
              |
kernel: selected retry statuses,normal return,or task-teardown helper
```

## Provenance and measurement

| Evidence | Verified identity and scope |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; UUID `204741e9-b89f-32b4-9321-51f3975c7cac` |
| Original collection | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84` |
| Original-code extraction |27 daemon spans,four complete compiler-bounded kernel functions,nine exhaustive256-input bank selections,three arithmetic proofs,nine fresh IDA byte-window matches |
| Fresh private initialization |5668177 original/model instruction steps; returns from initializer`0x10045053c`; one90000-byte arena,four200-byte rwlock objects,one960-byte allocation,two58/101-byte mutable buffers; fixed explicit random/time inputs |
| Subscription cases |16 cases from isolated copies of that freshly produced state;12 reach and fully decode outgoing XPC messages; mismatch,copy-model boundary and two allocation-failure boundaries remain distinct |
| Installed-cache copy comparison | Cache UUID `2bd06591-e751-3e84-963f-b08dab6af23a`;libsystem_c UUID `4bf47ebb-4cd0-3f4a-995a-717b8550cb12`; seven private cases; actual daemon/library pairing unverified |

Primary artifacts: [original contracts](triage_evidence/arcade_subscription_contracts.json),[fresh IDA bytes](triage_evidence/arcade_subscription_live_ida_bytes.json),[fresh initializer profile](triage_evidence/arcade_subscription_initialization_profile.json),[subscription profiles](triage_evidence/arcade_subscription_profiles.json),[independent checks and decoded messages](triage_evidence/arcade_subscription_profile_checks.json),[copy-wrapper evidence](triage_evidence/checked_path_copy_profiles.json) and [partial layout assertions](triage_evidence/arcade_subscription_layouts.c). IDA knowledge-store facts and existing annotations were locators; automatically appended model analysis was excluded from evidentiary readbacks. Original inputs and IDBs remain unchanged.

## Kernel producer and result consumer

The consumer`0xfffffe000bce1a64` calls helper`0xfffffe000bd7e084`,which obtains the current thread's validated read-only view. It reads a pointer at that view+`0x18`; the path producer receives that pointer. Calling it a process-like object is corroborated by the producer's diagnostic name and vnode operations; an exact target source structure definition has not been matched.

| Kernel site | Original data/control behavior |
| --- | --- |
| `0xfffffe000bce1d44..1d58` | Allocate4096 bytes through the selected kernel allocator,flags4 |
| `0xfffffe000bce1d60..1d6c` | Call path producer`0xfffffe000c36e108` with process-like pointer,buffer and4096-byte capacity |
| `0xfffffe000c36e124..1e0` | Load/authenticate object+`0x598` vnode pointer; obtain vnode ID; exact `_vnode_getwithvid`; construct path through an internal helper; vnode/access checks |
| `0xfffffe000c36e1f4` and retry route | Exact `_vnode_lookupat`; exact `_vnode_isrecycled` and `_vnode_put` also corroborate pathname/vnode semantics |
| `0xfffffe000bce1d70..1d9c` | Continue into VM-copy preparation without testing path-producer status; release the temporary4096-byte allocation afterward |
| `0xfffffe000bce1da0` | Load opaque64-bit value from process-like object+`0x5a0` |
| `0xfffffe000bce1db0..1dbc` | Send full4096-byte count and opaque value through client`0xfffffe000bd923a4` /61471 |

The producer has diagnostic strings for `EACCES` from vnode lookup and a privileged retry. This establishes environmental/filesystem dependencies beyond a raw fixed-size record. Exact initialization of the entire allocation,all path/error cases,the meaning of the+`0x5a0` field and VM-copy ownership remain open. The producer's ignored return is a local instruction fact; it does not establish uninitialized-data disclosure or a native memory defect.

After the subscription call,the kernel releases its temporary endpoint send reference. Status-308 selects registration/retry. Status`0x10000003` discards the retained VM-copy object and retries. Other nonzero statuses reach a task-related failure action. With status0,returned word1 selects that same action; another word returns through the normal epilogue. Thus "all nonzero statuses terminate" would overstate the inspected control flow.

The action at`0xfffffe000bd3ee28` has task-teardown behavior:it checks task state,clears task+`0x14`,iterates a thread list,invokes IPC/VM-related cleanup and moves task list membership. This is a semantic interpretation from original code,not a recovered exact symbol. Complete teardown prerequisites,effects and execution are unverified. Decision word1 is initialized provisionally by the daemon; its value after an actual CoreFP response is not established.

## Daemon argument and path contracts

Stub`0x1000054d8` validates complex request64 bytes,one OOL descriptor,type1 and equality between descriptor length and repeated count. It calls application`0x1000057c0` at`0x100005540`. The wrapper constructs this40-byte primary record:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` |u32 | Received local/service name |
| `0x08` |u64 | OOL path-buffer pointer |
| `0x10` |u32 | Transported count |
| `0x18` |u64 | Opaque kernel-supplied scalar |
| `0x20` |u64 | Pointer to decision-output word |

The wrapper's protected control fields contain literals`0x6cf4` and`0xd5525452` after the address-dependent encoding. It enters shared adapter`0x10065ffd8`. These differ from registration41471's secondary control word; a shared primary literal alone does not establish equivalent operations.

Protected code at`0x10059848c` reads service,path and decision pointer. It reserves local storage and initializes two local flags. At`0x10051e4f4`,it writes decision1 through the supplied pointer. The checked path copy follows at`0x10051e560`,using a1024-byte destination size. Only afterward does`0x10051e5a8` call `CFMachPortGetPort` on header+`0x38`,the anonymous CF object established in the registration report. Full-domain arithmetic proves that the obfuscated comparison is equality between the incoming service name and this returned name.

The source path count is not supplied to `__strcpy_chk`. It is also not the bound passed to `strnlen`:the latter receives constant1024 at`0x1007cd098`. The selected pre-send traces read only primary-record offsets0,8 and32. Count values0,1,57,4096 and`0xffffffff`,and three opaque64-bit values,produce identical outgoing messages for the same path in the retained fixtures. These are injected post-delivery pointer/count combinations; successful native delivery of every combination is unverified. They do not prove that the count/opaque slots are unused after an actual XPC reply or on other paths.

Mismatch returns status5 through the prepared36-byte61571 form. Matching-name cases proceed to an80-byte path record. The record is not the copied1024-byte local buffer:its pointer remains the original OOL address.

| Private record offset | Established content |
| --- | --- |
| `0x08` | Observed u64 value`0x00000000a7c636e9`; later serialized as a scalar in the outgoing nested message |
| `0x38` | Original path pointer;64-bit obfuscated arithmetic is an exact identity |
| `0x48` | `(u32(strnlen(path,1024))+1) XOR 0x8b3dc651`; full-domain instruction lift proves the inclusive-length codec |
| `0x4c` | u32 value2 |
| Other fields | Original constants/encoded state retained in profiles; full semantic types unknown |

## Startup state and allocation boundaries

The handler reaches complete compiler-bounded helper`0x100444dfc..0x10044a3e0`:5497 straight-line instructions,no calls or conditional branches. It reads/mutates byte-state buffers through cells`0x1010c6808` and`0x1010c8260`. Both cells are null in the file image. A fixture that skipped initialization stopped on the first null-buffer access; that was not evidence of a native startup failure.

Original initializer continuation`0x1003b41fc` allocates58 bytes at`0x1003b427c`,publishes the pointer through the first destination cell at`0x1003b42d4`,fills the allocation,then allocates101 bytes at`0x1003b4370` and publishes at`0x1003b43c4`. Exact slot/bias recovery identifies the58-byte pointer cell as`0x1010c8260` and the101-byte cell as`0x1010c6808`. Subsequent native stores establish byte-state contents. This is mutable shared state; assigning it a cryptographic algorithm name from its instruction shape would be unsupported.

The fresh fixture executes the real initializer entry through return,including its arena allocation,gates,time/random calls and byte-buffer initialization. `UC_CPU_ARM64_MAX` permits original SHA3-family vector operations such as `EOR3` and atomic instructions to execute privately. PAC remains explicitly bypassed. `arc4random` returns fixed word`0x12345678`; `gettimeofday` supplies1700000000 seconds and123456 microseconds. Four rwlock objects use abstract serial lock states. Their representation is marked unknown after initialization. In this route,only eight allocation bytes were known before each rwlock initialization; an earlier exploratory assertion incorrectly required all200 bytes to be zero and was corrected. No earlier,independent typed-allocation result is generalized to this route.

| Injected condition | Verified finite boundary |
| --- | --- |
| Normal fitting path | Allocates128-byte and112-byte parser objects,constructs records and reaches synchronous XPC send |
| First application allocation returns null | Continues to a separate Objective-C `objc_msgSend` boundary with copied path; complete fallback semantics unknown |
| Second application allocation returns null | Reaches an8-byte read at`0x1005b6120`,from parent allocation+8,without observed initialization of those bytes; private unknown-data guard stops |
| Path length1024 excluding NUL | Requires1025 copy bytes; stops outside the fitting-copy API model before CF name lookup |

These boundaries do not establish native OOM feasibility,full object construction,undefined behavior across every path or an exploitable defect. Allocation lifetime tracking distinguishes live,freed and never-initialized bytes; it does not replace framework ownership analysis.

## Outgoing CoreFP interface

| Site | Original boundary / argument |
| --- | --- |
| `0x10040fcf8` | `_xpc_add_bundle(bundle_path,2)`; no host bundle registration occurs in fixtures |
| `0x10040fdb0` | `_xpc_connection_create("com.apple.fpsd.arcadeservice",&_dispatch_main_q)` |
| `0x10040fe60` | Set event-handler global block`0x101039d50`,invoke pointer`0x100460008` |
| `0x10040fea8` | Resume connection |
| `0x10040feb0` | Publish connection through a caller-supplied destination; complete owner/cache lifetime unresolved |
| `0x10077e508` | Create empty XPC dictionary |
| `0x10077e5c4` | Set `data` from serialized buffer and explicit byte length |
| `0x10077e614` | `_xpc_connection_send_message_with_reply_sync(connection,dictionary)` |

The global block has32-byte prefix,flags`0x50000000`,invoke at+16 and descriptor at+24. The callback moves incoming X1 to X0 and tail-dispatches through protected code. Its event/error policy is not yet recovered. The queue is the normalized address of original imported symbol `__dispatch_main_q`,not a fabricated queue-name string. Bundle path/name presence does not attest installed service existence,loaded module UUID,entitlements,launch policy or successful connection.

The dictionaries in12 retained send-boundary profiles contain exactly one key,`data`. The entire value decodes into the following structure. Semantic field names are unknown unless explicitly described:

```text
outer key7976211a,tag9777,len4: raw BE32=00000000
outer keyfd2821c7,tag50db: nested sequence
  +-- key7e852555,tag9777,len4: raw2cfbf0b8,decoded a7c636e9
  +-- key1fe19f28,tag50db: path bytes INCLUDING terminal NUL
  +-- keyf6964e3e,tag9777,len4: raw04f2abb5,decoded8fcf6de4
  +-- key00000000,tag50db: zero-filled inner padding
outer key00000000,tag50db: fourteen zero padding bytes
```

Framing is a10-byte big-endian header:`key:u32,tag:u16,payload_length:u32`. Scalar tag`0x9777` carries four bytes and uses the previously recovered BE32/XOR`0x8b3dc651` convention;`0x50db` carries spans. The fixed first nested scalar matches the private record+8 value after decoding. No semantic operation/field names are inferred from these numeric keys.

| Path bytes excluding NUL | Nested path extent | Outgoing XPC data bytes | Inner padding bytes |
| --- | --- | --- | --- |
|0 |1 |112 |15 |
|1 |2 |112 |14 |
|15 |16 |128 |16 |
|16 |17 |128 |15 |
|56 |57 |160 |7 |
|1023 |1024 |1136 |16 |

These cases show a full extra16-byte inner padding span when inclusive path length is aligned. They match `total=112+16*floor((strlen+1)/16)` for the tested lengths. That is a bounded observed sizing pattern,not a full-domain proof of the serializer's padding algorithm. Actual XPC response type,reply data keys/records,decision construction,release/cancellation and endpoint lifetime remain open.

## Installed checked-copy implementation

The separately identified installed-cache export `___strcpy_chk` at`0x1805b3148` calls exact `_stpcpy` at`0x1805b31b4`. That wrapper resolves original authenticated cache bindings to platform `strlen` and `memmove`. It obtains/copies `strlen(source)+1` bytes,then the outer wrapper compares the resulting extent with the claimed size. Overflow branches to exact `___chk_fail_overflow` at`0x180620c30` after the copy. The optional monitor branch is seeded disabled in the private cases.

Seven private cases execute the original wrappers/stubs with bounded strlen/memmove models. Lengths0,1,56 and1023 return. Lengths1024,1025 and4095 copy1025,1026 and4096 bytes respectively into a larger private backing region,then reach the original overflow-failure entry. Its termination routine is not executed. Thus a checked-copy import name alone does not establish pre-copy enforcement in this cache. The analyzed daemon's actual loaded implementation,monitor state and native path-length reachability remain unverified; no native overwrite claim is made.

## Assumption register

| ID | Assumption / dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| S1 | Addresses and static interpretations depend on recorded daemon/collection identity | Rehash inputs,compare nine IDA windows and original import/fixup words | Verified for original files; actual loaded pairing unknown |
| S2 | Kernel process/path interpretation depends on diagnostic/callee corroboration | Match target source structures,producer helper,pathname status and vnode identity | Path semantics corroborated; exact structure/opaque field name unknown |
| S3 | Private handler state derives from fresh initializer under explicit environmental inputs | Re-run source-pinned initializer; vary random/time/initialization failures and concurrency | One fresh state reaches return; native time/random/locking unverified |
| S4 | CF name and XPC handles are opaque modeled API results | Mismatched service,actual CF cache/right identity,bundle/service policy and null/error outcomes | Local comparisons and call arguments established; native objects unknown |
| S5 | Fitting-copy model covers only C strings that fit1024 bytes | Test boundary lengths against original installed wrappers;attest actual loaded library | Seven cache cases pass; actual daemon/library pairing unknown |
| S6 | Count/opaque invariance is limited to selected paths reaching send | Count0/1/57/max and opaque0/max;trace after real/modeled replies and alternate routes | Twelve messages decoded; no whole-function unused-argument claim |
| S7 | Packet structure follows retained big-endian record convention | Parse every byte,check nested extents,path bytes,constants and padding across lengths | Verified for12 packets; semantic key names/full padding proof unknown |
| S8 | Allocation failure/definedness claims concern observed native writes under private failure injection | Null first/second allocation,initialized-byte masks,destructor/lifetime/alias proof and native allocation behavior | Distinct Objective-C and unknown-read boundaries retained; native defect unproved |
| S9 | Explicit PAC bypass/private CPU/API models do not attest native execution or full policy | Compare original code pages/tags and full-domain arithmetic; native protocol/lifecycle attestation separately | Original bytes/proofs verified; native authentication,delivery,reply/policy unknown |

## Bounded continuation and quality gates

| Impact | Next investigation | Information resolved |
| --- | --- | --- |
| High | Continue past synchronous XPC reply through exact type/data/status checks and output publication | Actual61571 decision construction and kernel task-outcome predicate |
| High | Inspect the version-matched CoreFP arcade service and its receiving record decoder | Deeper implementation,authorization,filesystem/receipt/crypto/provider interfaces |
| High | Recover event callback`0x100460008`,connection owner and cancellation/restart paths | External asynchronous control and endpoint lifetime |
| High | Complete first/second allocation-failure paths,field initialization and cleanup | Object definedness,Foundation fallback and conditional failure handling |
| High | Trace kernel pending-event writers,path producer errors/initialization and actual host-slot31 access | Trigger reachability,sender provenance and input/path guarantees |
| Medium | Vary startup random/time and native initialization failure paths | Environmental invariants of shared byte-state and codec behavior |
| Medium | Recover exact serializer padding/constructor invariants and all record meanings | Universal sizing proof and complete schema |
| Medium | Attest the loaded checked-copy library,monitor state and upstream pathname bounds | Native relevance of copy-before-size-check behavior |

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/run_arcade_subscription_profiles.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_checked_path_copy.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_arcade_subscription_delivery.py
```

The fresh runner consumes no disk checkpoint. It executes initialization once,then clones the resulting private state for each case. Every visited target instruction matches original bytes; ordered original code-page hashes are independently checked. The initializer is bounded by10000000 instructions and each case by5000000. Extraction is O(B+F+I) for bytes/fixups/instructions;cloning N cases costs O(N*B); bounded nested decoding is O(packet_bytes*depth),depth<=8. Solver cost is separate. Exact byte extents and unsigned32/64-bit arithmetic are explicit; partial40/80/32-byte layout assertions compile for ARM64e.

QG1 factual scope passes. QG2 S1-S9 include dependent results/probes. QG3 passes for this producer/path/serialization/outgoing-XPC increment,not the full interface objective. QG4 widths,extents,layout and complexity are explicit. QG5 native/model/cache boundaries,provisional decision,unread slots and conditional failures remain separate. QG6 original bytes/fixups/IDA,arithmetic,fresh initialization and finite profiles retain provenance. QG7 impact-labeled continuation is included. See [machine-readable gates](triage_evidence/arcade_subscription_quality_gates.json) and [current manifest](triage_evidence/interface_manifest.json).
