# Daemon IOKit discovery, object roles and cleanup boundary

The source connects `IOServiceGetMatchingServices`'s output at caller SP+0x68 to `IOIteratorNext` and later iterator release. A nonzero next-object result supplies `IOServiceOpen`'s service argument and the separate service-release call. Successful open writes a connection at state+4 for selectors22/23. This closes the earlier unknown-iterator frontier under explicit API/frame premises; no native object or Mach right is supplied. [OI1-OI14]

The ordinary `_mach_task_self_` data bind has import-table addend0x7BF13863. Source adds0xFFFFFFFF840EC79D, canceling that addend modulo2^64, then loads a u32 owning-task name from the resolved symbol storage. This differs from both the matching main-port argument and the returned iterator/service/connection roles.

The increment contains632 fresh private cases,443392 original instruction visits,19 source proof pairs over94 lifted instructions,seven exhaustive bank identities,44 original fixup checks,five binding decodes and179 current IDB source-row comparisons. All564 preceding query/fallback instruction/read/write/edge sequences remain embedded unchanged, after visit-index translation. The first query's unused X6/X7 reflect the newly preceding caller-saved clobbers; its six arguments match exactly. All typed SDK checks pass. Full native entry, matching criteria, object lifetime, transport and capability-bit semantics remain unknown.

[Source contracts](triage_evidence/daemon_iokit_objects_contracts.json), [retained cases](triage_evidence/daemon_iokit_objects_profiles.json), [fresh replays](triage_evidence/daemon_iokit_objects_replays.json), [independent checks](triage_evidence/daemon_iokit_objects_checks.json), [source proofs](triage_evidence/daemon_iokit_objects_proofs.json), [live IDB and xref leads](triage_evidence/daemon_iokit_objects_live_ida.json), [typed SDK source](triage_evidence/daemon_iokit_objects_sdk.c), [source identity](triage_evidence/daemon_iokit_objects_source_identity.json), [preservation](triage_evidence/daemon_iokit_objects_preservation.json) and [scoped gates](triage_evidence/daemon_iokit_objects_quality_gates.json) retain the evidence. The [version-fallback report](daemon_query_fallback_report.md) remains the predecessor contract. The full interface objective remains active.

```text
entry0x1003F94EC [matching dictionary/main port already supplied]
  -> IOServiceGetMatchingServices(main, dictionary, &F68)
       nonzero status -> STOP0x100318CC0 [error continuation]
       status0 -> F68 = modeled iterator32
         -> IOIteratorNext(F68)
              result0 -> source status word -> release iterator -> common cleanup
              nonzero -> modeled service32
                -> IOServiceOpen(service, task_self_value, type0, &state[4])
                -> IOObjectRelease(service) [also follows nonzero open status]
                     nonzero saved open status -> STOP0x1004BDB24
                     saved status0 -> selectors22/23(connection=state[4])
                       -> original query/cache/version-fallback path
                       -> IOObjectRelease(iterator=F68)
                       -> STOP0x100383B00 before unknown F50 pointer read
```

F denotes the discovery caller's SP. B denotes bytes. Addresses are preferred file virtual addresses. u32/u64 arithmetic is modular; comparisons against zero or the saved encoded open-status value cover all32-bit result patterns. API return/output values are explicit private summaries, not native observations.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| OI1 | Pinned thin image,selected IDB and original fixups identify the inspected build | Source/address correspondence | Rehash source and universal image; compare179 current IDB rows |
| OI2 | Entry at0x1003F94EC has W28=0xB606 and a supplied matching dictionary/main-port cell | Discovery phase | Recover upstream IOMainPort,matching-dictionary construction and full entry separately |
| OI3 | Canonical table/controller pointers,FP=F+0x120,saved state pointer and incoming state byte09 have declared values | Composed object/query path | Check seven256-input bank identities; all entry fixtures remain explicit |
| OI4 | Runtime import/PAC handling is represented by declared private pointer normalizations | Function/data targets | Independently decode original bindings,including nonzero task import addend; native resolution/authentication unknown |
| OI5 | API summaries return normally,preserve callee-saved state and write only declared outputs | Finite call/return chain | Clobber X1-X17/NZCV; vary statuses and high-bit names; native side effects remain unmodeled |
| OI6 | Matching dictionary is opaque and nonnull at this entry | Matching-services argument | Source proves pointer forwarding; dictionary validity,criteria and actual reference consumption remain unknown |
| OI7 | Source u32 loads/stores and user SDK type declarations describe accessed widths | Handle/argument/output cells | Eight compile-time width assertions and four signature assignments; no native object validity inferred |
| OI8 | Shared frame/output bytes retain source/API epochs without interference | Iterator and connection lineage | Independently reconstruct all reads,writes,models and provenance; queries must preserve F68 |
| OI9 | QS1-QS12 and QF1-QF12 apply to the embedded query/fallback component | Metadata behavior | Preserve564 embedded instruction/read/write/edge sequences and source-produced records |
| OI10 | Release calls are register-only summaries | Post-release selection | Independently vary returned release statuses; native reference counts,rights and liveness remain unknown |
| OI11 | Installed SDK corroborates declarations rather than target OS-build identity | Typed ABI/documented ownership context | Hash four headers and recompile arm64e syntax-only checks; SDK/target build equivalence unproved |
| OI12 | Error destinations and F50-dependent cleanup remain unexecuted | Final evidence boundary | Stop at0x100318CC0,0x1004BDB24 or0x100383B00; F50 retains unknown provenance |
| OI13 | Two state-pointer candidate phases have their stated index/base/bank premises | Conditional saved pointers | Prove their exact stores under those premises; complete predecessors and downstream field reads remain unproved |
| OI14 | IDB xrefs are annotation-driven,partial pointer-resolution hints | Reader census | Inspect original opcodes and aliases; absence of a direct field xref is not absence of readers/writers |

OI1-OI14 qualify dependent claims. This entry starts after matching-dictionary creation and does not establish the service class or that a live connection belongs to FairPlayIOKit. Selector/layout compatibility remains as established in the preceding query/census report.

## Typed object roles and source call locations

| Role | Source production / storage | Consumer / call PC | Width |
| --- | --- | --- | --- |
| Matching main-port argument | Supplied F+0x7C cell;upstream origin unexecuted | GetMatchingServices W0 at0x1003F9594 |4 B |
| Matching dictionary | Supplied X0,forwarded to X1 at0x1003F94EC | GetMatchingServices X1 at0x1003F9594 |8 B pointer |
| Iterator | GetMatchingServices X2=&F+0x68;explicit API output | Next W0 at0x10036C4A4;release W0 at0x100483CC0 |4 B |
| Service object | Next's modeled u32 return,saved in X20 before open | Open W0 at0x100478BB0;release X0 at0x100478C2C |4 B ABI value;full-register copy |
| Owning task | u32 load from resolved `_mach_task_self_` storage at0x100478B60 | Open W1 at0x100478BB0 |4 B |
| Connection type | Source W2=0 | Open at0x100478BB0 |4 B |
| Connection | Open X3=state+4;explicit API output | Selectors22/23 at0x100364420/0x1004BA9C4 |4 B |

The source saves/copies the service return through full X0/X20 registers. Its typed handle is low32;private summaries return a zero-extended u32. Native upper-register bits are not established. Iterator,main-port,task and connection cell loads use W registers and source-zero-extend their32-bit values.

The local user SDK aliases io_iterator_t,io_service_t and io_connect_t through io_object_t to mach_port_t. The arm64e compile verifies all of these and task_port_t/kern_return_t occupy4 B,while CFDictionaryRef occupies8 B. This identifies source-level roles and widths; it does not establish native names,right dispositions,reference counts or successful kernel routing.

The SDK declaration for matching services documents consumption of one matching-dictionary reference and a returned iterator or null on success. It documents caller release of returned next objects and an IOServiceOpen connection's separate IOServiceClose lifetime. These are documented API contracts; the private summaries model no actual retain/release/close effect. No connection-close conclusion is drawn beyond the current cleanup frontier.

The source makes one IteratorNext call on the selected path. It releases a nonzero returned service immediately after the Open call returns,including a nonzero saved open status. Iterator release occurs later on both the zero-service path and the returning metadata path. Source sites and typed roles distinguish those two release calls even though they share an import binding.

## Iterator and connection byte provenance

| Frame/state region | Role | Source/API producer epoch |
| --- | --- | --- |
| F+0x08,8 B | Saved pointer to connection output | Source0x100478BA8 writes state+4 |
| F+0x64,4 B | Guarded version query output | Query22 summary or source-clear fallback |
| F+0x68,4 B | Saved iterator | Matching-services summary;retained across both queries |
| F+0x6C,4 B | Guarded capability query output | Query23 summary or source-clear fallback |
| F+0x70,8 B | Reused query size_t | Source capacity reset4 before each query;summary returned size |
| F+0x7C,4 B | Matching main-port argument | Incoming fixture |
| State0x1010B6380+4,4 B | Connection output | Successful Open summary,then source query loads |

The earlier query-only profiles correctly left the middle four bytes unknown under their narrower entry premises. Here the API output identifies those bytes as the saved iterator. No source query/cache/fallback store overwrites them. In568 complete metadata cases,connection bytes have API provenance2 rather than an incoming connection fixture. In600 successful matching cases,the iterator cell retains API provenance2 through its later consumers or error frontier.

The first query's formal inputs X0-X5 exactly match the preceding profile. Its captured X6/X7 change from unused incoming values to the new prelude's caller-saved clobbers. All embedded original instruction bytes,read/write epochs and table edges agree after subtracting the184-visit discovery prelude. The12-byte frame snapshot's middle four bytes and their provenance intentionally differ because they now contain the iterator. This is composition under declared premises,not raw equality of every old/new fixture or register.

## Ordinary task-data bind and original function bindings

| Source slot | Imported symbol | Original format12 word / addend | Call/data use |
| --- | --- | --- | --- |
|0x1010A0D88 |`_IOServiceGetMatchingServices` |0xC008A02700000041;IA diversity0xA027 |0x1003F9594 |
|0x1010A0E38 |`_IOIteratorNext` |0xC008D62A0000003B;IA diversity0xD62A |0x10036C4A4 |
|0x1010A0B48 |`_IOServiceOpen` |0xC008E82B00000046;IA diversity0xE82B |0x100478BB0 |
|0x1010A0240 |`_IOObjectRelease` |0xC008BE7E0000007D;IA diversity0xBE7E |0x100478C2C and0x100483CC0 |
|0x1010A39C8 |`_mach_task_self_` |0x4008000000000012;ordinary bind,addend0x7BF13863 |Data load at0x100478B60 |

The task-data import is ordinal18,library ordinal12,`/usr/lib/libSystem.B.dylib`;its pointer-local addend is0 and import-table addend is0x7BF13863. Unlike the four function bindings,it is unauthenticated. Let T64 be the resolved address of the symbol's storage:

```text
slot64 = u64(T64 + 0x7BF13863)
source_bias64 = 0xFFFFFFFF840EC79D = -0x7BF13863 modulo2^64
load_address64 = u64(slot64 + source_bias64) = T64
Open owningTask = zero_extend64(MEM32[T64])
```

Three source instructions at0x100478B54..0x100478B5C construct/add that bias. The next instruction loads W1. The installed SDK declares `mach_task_self_` as mach_port_t storage and defines mach_task_self() as its macro access. The source site is a data-symbol read,not a call to a task-self function. Private loader normalization preserves the addend before source cancellation;flattening that bind to a bare placeholder would give the wrong address here. Actual symbol storage and native task-port value remain unknown.

## Status and cleanup control contracts

| Result / condition | Source-selected continuation | Established effect before frontier |
| --- | --- | --- |
| Matching status32!=0 |slot0x101094F20 ->0x100318CC0 | Stop before error continuation;iterator output remains unmodeled |
| Matching status32=0 |slot0x101094F58 ->0x10036C42C | Call Next with modeled iterator |
| Next result32=0 |slot0x1010711F8 ->0x1004A89F4 | Store0x74C29C07 at F+0x60;select iterator release |
| Next result32!=0 |slot0x101070F80 ->0x100478AF8 | Open the returned service with type0 |
| Saved open status32!=0 |slot0x10108F9C8 ->0x1004BDB24 | Service-release call has returned;stop before error continuation |
| Saved open status32=0 |slot0x10108FA48 ->0x100364398 | Consume connection output in queries |
| Iterator-release call returns |slot0x101066AC0 ->0x100383B00 | Stop before unknown F+0x50 pointer load |

The open status is encoded and saved before service release. Its post-release source predicate depends on that saved encoding,not on the release call's W0. The source proof covers every open-status32 pattern and arbitrary release-status32. Likewise the iterator-release return value does not determine the final table target. These are control/data-flow facts;the private summaries do not establish successful release or object liveness.

Four SDK-documented successful-null-iterator controls model matching status0 with iterator0 and a Next result0. The source passes zero to Next and later iterator release. Release status0/nonzero controls both select common cleanup after a normal return. No native invalid-handle call or fault was reproduced. Next result0 alone does not distinguish iteration exhaustion from an invalid iterator;the local SDK documents both possibilities.

The common-cleanup source begins with `LDR X8,[SP,#0x50]; LDR X8,[X8]`. No producer of F+0x50 executes in this selected entry. All588 common-cleanup cases retain an unknown8 B cell there and stop before the first load. The post-release helper,callback/locking effects,outer result store and connection's later lifetime remain outside this increment. The two selected error continuations likewise remain unexecuted.

## Capability-reader census and conditional pointer publications

A bounded IDB classification returns five annotated references to state base0x1010B6380. They are computed pool-pointer resolutions. Its partial `read_write`/`write` labels occur on LDR register destinations and do not establish writes to the state object. Source opcodes and subsequent aliases control the interpretation. This census covers the registered xrefs,not every encoded or indirect reference in the binary.

Three reference sites belong to the already inspected query-state helper,fallback classifier and discovery initializer. Two additional source fragments publish candidate pointers:

| Source site / IDB owner | Conditional source result | Evidence boundary |
| --- | --- | --- |
|0x100290400 /owner0x10028FC34 | With pool base and low8(W7)=0x43,slot0x1010A2D78 plus bias0xFFFFFFFFFEFF1ACD yields state;store at its local SP+0x668 | Complete upstream bank/index provenance and subsequent field reads unproved |
|0x100634B60 /owner0x1006349B0 | With canonical bank roots,byte identity0xA1 and pool base,same slot/bias yields state;store at its local SP+0x80 | Complete entry and subsequent field reads unproved |

These local SP frames are separate from the discovery caller's F. Two original-source proof phases establish the pointer stores under their explicit index/base premises. The second bank identity is independently exhaustive over256 inputs;that does not prove the canonical roots reach this source from every predecessor. Neither candidate is yet classified as a consumer of capability bit0x08. The bit's meaning remains unknown.

## Validation, reproduction and preservation

The base564 cases retain the preceding query/fallback response/version grid.64 additional controls vary matching status{0,0xE00002C7},Next result{0,0xE1234567},open status{0,1,0xE00002C7,0xFFFFFFFF},two release-status pairs and two frame placements. Their main/task/iterator names have the high bit set. Four further controls use a successful null iterator,zero Next result,two release statuses and two placements. No native target is invoked.

| Check | Result |
| --- | --- |
| Fresh private cases / original instruction visits |632 /443392 |
| Embedded preceding query/fallback sequences preserved |564 |
| Matching error frontiers |32 |
| Open error frontiers after service release |12 |
| Common-cleanup unknown-pointer frontiers |588 |
| Successful connection outputs consumed by both queries |568 |
| API-produced iterator cells preserved |600 |
| Successful null-iterator controls |4 |
| High-bit name controls |64 |
| Matching /Next /Open models |632 /600 /580 |
| Service-release /iterator-release models |580 /588 |
| Metadata query models |1136 |
| Source proof pairs / lifted instructions |19 /94 |
| Exhaustive bank identities / byte inputs |7 /1792 |
| Original fixups / direct dispatch slots / bindings |44 /8 /5 |
| Current IDB rows matching original source |179 |
| SDK compile-time widths / function signatures / compile exit |8 /4 /0 |
| Prior artifacts checked / unchanged |2390 /2384 |
| Original analysis/C/calls inputs preserved |3 |

Independent checks rebuild byte epochs,API/source/incoming provenance,task-data fixup representation,model arguments,output pointers,object-role ordering and embedded source sequences. API output provenance2 is distinct from source stores1 and incoming fixtures3. Original image bytes carry provenance0 and are not promoted to native values. The fresh replay uses the same A64 engine as retained cases;it is not independent native validation.

Nineteen original-source counterexample query pairs cover argument/phase/gate formulas,all32-bit status results,64-bit addend cancellation,cleanup selection and the two conditional pointer publications. Original and simplified SMT files are hashed and rechecked against rebuilt obligations. The installed SDK syntax-only compile checks types without linking or running the target. Four primary headers and four retained analysis notes are hashed/snapshotted in the contracts. The prior notes supplied leads;earlier synthetic/native/PAC interpretations are not imported as facts.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_iokit_objects.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_iokit_objects.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_iokit_objects.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_objects.py
```

Regeneration requires a new preservation/delivery seal. Each case permits at most5000 source visits. With B image bytes,C cases,V visits/case,E memory/API events/case,J demand pages,F fixups,I lifted instructions and R bank identities:time O(B+C*(V+E+J*F)+I+256R+SDK bytes),retained space O(B+C*(V+E)+I+F+4096J),plus30 s/query solver bound. Preservation permits changes only in the four consolidated reports,investigation status and aggregate manifest validator.

## Bounded continuation and scoped quality gates

| Impact | Remaining question / pattern | Evidence that would resolve it |
| --- | --- | --- |
| High | What constructs the matching dictionary and selects the service class? | Source string/dictionary constructor,its arguments and complete native predecessor |
| High | What produces F+0x50 and what are common cleanup's synchronization/callback contracts? | Exact source producer,aliases,helper inputs and selected returning paths |
| High | Which candidate state pointers reach actual capability reads/bit tests? | Subsequent pointer loads,field offsets,decoder and downstream API/IPC choices |
| High | Does this connection bind the supplied FairPlayIOKit UserClient at runtime? | Actual service identity,connection ownership,provider dispatch and transaction evidence |
| Medium | Matching/Open failures select unexecuted internal continuations | Source error-record consumer,status publication and object cleanup order |
| Medium | Xref labels mix register writes with global-access interpretations | Opcode/operand/alias evidence for each actual global load/store;annotation counts alone remain insufficient |
| Low | Does the installed SDK exactly match the target release? | Target build/SDK provenance;current checks establish declarations and widths only |

No new emitted Mach message ID,right disposition or native port name is established. This increment identifies source-level handle roles,their output/argument cells and exact API call PCs. The existing kernel query counterparts remain static compatibility evidence. Full native reachability,matching criteria,object lifetime,actual rights,transport,concurrency and capability-bit semantics remain unknown.

| Gate | Result / evidence |
| --- | --- |
| QG1 | Pass:factual source/interface analysis |
| QG2 | Pass:OI1-OI14 include dependencies and falsification probes |
| QG3 | Pass for this increment:discovery/open/query/release linkage,data-symbol ABI and bounded reader leads covered;full_goal_complete=false |
| QG4 | Pass:explicit B/u32/u64 widths,modular/unsigned formulas,cardinalities and reproduction |
| QG5 | Pass:object roles,native/SDK/private boundaries,unused-register changes and conditional pointer candidates distinguished |
| QG6 | Pass:original source/fixups,179 IDB rows,632 fresh byte audits,19 source proof pairs and typed SDK compile |
| QG7 | Pass:impact-labeled bounded continuation table |
