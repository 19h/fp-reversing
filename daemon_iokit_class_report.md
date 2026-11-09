# Daemon class matching and FairPlayIOKit metaclass association

The daemon's selected source path decodes `com_apple_driver_FairPlayIOKit\0` and passes it to `IOServiceMatching` at0x10040B814. The supplied kext's two metaclass constructors use the identical class-name bytes and kernel `IOService::gMetaClass`. This establishes a static class-family association beyond selector/layout compatibility. The installed SDK specifies class-or-subclass matching;native registry publication,selected instance and connection identity remain unknown. [IC1-IC14]

The decoder's source pointer is independently established from the daemon's original format12 rebase at0x1010B8CC0,not solely from an IDB pointer observation. The prefix obtains the matching main-port value through an explicit IOMainPort summary and constructs the matching dictionary through an explicit IOServiceMatching summary before entering the preceding object/query/release path. No native API,kernel constructor or registry operation executes.

[Source contracts](triage_evidence/daemon_iokit_class_contracts.json), [retained cases](triage_evidence/daemon_iokit_class_profiles.json), [fresh replays](triage_evidence/daemon_iokit_class_replays.json), [independent checks](triage_evidence/daemon_iokit_class_checks.json), [source proofs](triage_evidence/daemon_iokit_class_proofs.json), [live IDB source](triage_evidence/daemon_iokit_class_live_ida.json), [typed SDK source](triage_evidence/daemon_iokit_class_sdk.c), [source identity](triage_evidence/daemon_iokit_class_source_identity.json), [preservation](triage_evidence/daemon_iokit_class_preservation.json) and [scoped gates](triage_evidence/daemon_iokit_class_quality_gates.json) retain the evidence. The [object-flow report](daemon_iokit_objects_report.md) is the predecessor contract. The full interface objective remains active.

```text
entry0x100461C30 [after unexecuted upstream lock/state path]
  -> source saves input/table cells
  -> IOMainPort(bootstrapPort=0,&F7C)
       nonzero status -> STOP before0x10062FB74
       status0:
         original rebase -> encoded31 B -> source stack class C-string
         -> IOServiceMatching("com_apple_driver_FairPlayIOKit")
              NULL -> source result word -> common cleanup [F50 unknown]
              nonNULL dictionary64
                -> IOServiceGetMatchingServices(main,dictionary,&iterator)
                -> preceding iterator/service/Open(type0)/query/release chain

kext static class metadata:
  MetaClass C1/C2(this,name="com_apple_driver_FairPlayIOKit",
                super=IOService::gMetaClass,instance_size=136 B)
  -> kernel OSMetaClass constructor [unexecuted]
```

Addresses are preferred file virtual addresses. F denotes the daemon caller's SP;B denotes bytes. u32/u64 arithmetic is modular. API outputs,opaque dictionary pointers and object values are private summaries,not native observations.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| IC1 | Pinned daemon thin/universal images,KC and kext identify the inspected builds | Cross-image address/name correspondence | Rehash originals;compare208 current IDB instruction rows and original KC symbols/fixups |
| IC2 | Entry0x100461C30 has W28=0x597A,declared table/controller/input registers,FP=F+0x120 and state byte09 | Composed prefix | Recover the earlier record selector,lock helper and state checks separately;full native entry remains unproved |
| IC3 | Original canonical byte banks/pools retain their values | MainPort,class-data and Matching targets | Exhaust all256 inputs for three bank rules and verify original branch slots |
| IC4 | File-initial pointer cell0x1010B8CC0 retains decoded target0x100FD40C0 across both decoder reads | Specific class-name bytes | Verify original rebase and both byte epochs;native mutation or a different loaded pointer invalidates applicability |
| IC5 | Selected source's low8(W28)=0x7A at decoder entry | Exact class-name string | Prove the source formulas for all W28_32;512 isolated controls test every low byte in two frame placements |
| IC6 | Private A64 execution and explicit PAC/return normalization match the declared model | Finite traces | Check original bytes/edges;hardware authentication and ASLR/runtime addresses remain unknown |
| IC7 | External summaries return normally,preserve callee-saved registers and declared cells | Prefix/object/query composition | Clobber X1-X17/NZCV;vary status/null results;native effects remain unmodeled |
| IC8 | API output/model provenance and source stores retain their epochs without interference | Main-port,context/table and dictionary forwarding | Reconstruct every byte and preserve632 embedded object-flow sequences |
| IC9 | SDK describes class-or-subclass matching and typed parameters | Semantic class-family association | Hash the installed header and compile two signatures/three widths;SDK/target build equivalence unproved |
| IC10 | Original kext constructor setup and import stubs retain their source values | Class name,superclass and size arguments | Verify two native-source functions,import stub,two KC pointers and exact symbols;constructor execution unproved |
| IC11 | Class metadata does not establish native service registration or selected instance | Endpoint identity limit | Establish actual publication,registry match result,service identity and runtime provider vptr separately |
| IC12 | Earlier OI/QS/QF premises qualify the embedded component | Later Open/query/cache/release roles | Preserve original instructions/reads/writes/edges and formal arguments;unused-register differences explicit |
| IC13 | MainPort errors and F50-dependent cleanup remain unexecuted | Final boundaries | Stop before main-port error continuation or unknown cleanup pointer;no native failure/lifetime inference |
| IC14 | Isolated wrong-phase decodes stop before followup/API | Decoder characterization | Verify no external models/calls execute in512 controls;altered bytes are not treated as real registry queries |

IC1-IC14 qualify dependent claims. The current prefix derives the main-port output and constructor argument that were incoming fixtures in the preceding report. It does not derive every earlier table/input/state premise or execute the upstream lock path.

## Original class-data pointer and byte ABI

| Evidence element | Original source value / use |
| --- | --- |
| Byte banks |0x100FC4130 /0x101031EA0;key0xA3 gives constant0x72 for all256 inputs |
| Pool selection |index0x94A,slot0x1010A63B0,decoded word0x115AB7AE2 |
| Source bias |+0xFFFFFFFFEB6011DE -> pointer cell0x1010B8CC0 |
| Pointer cell's original format12 word |0x0958000000FD40C0;unauthenticated rebase ->0x100FD40C0 |
| Encoded source extent |31 B at0x100FD40C0 |
| Decoder output |31 source byte stores at F+0x89..F+0xA7 inclusive |
| Consumer |IOServiceMatching X0=F+0x89 at0x10040B814 |

The original31 source bytes are:

```text
9f9391a39d8c8c9099a3988e958a998ea3ba9d958eac909d85b5b3b79588fc
```

Let W be incoming decoder W28,and E[j] the original encoded byte. Source first computes:

```text
A32 = u32(W - 0x31AC)        -> saved at F+0x28
B32 = u32(W - 0x01F6)        -> W26
C32 = A32 XOR 0x91C8         -> replacement W28
```

| Output byte | Source formula |
| --- | --- |
|j=3 |`E[3] XOR low8(B32 XOR 0x78)` |
|j=5 |`E[5] XOR low8(C32 XOR 0xFA)` |
|all other j in0..30 |`E[j] XOR 0xFC` |

All32-bit incoming W values are covered by the source proof. The exact31-byte class string is produced iff low8(W)=0x7A;upper24 bits do not affect these byte outputs. The last byte is always NUL for the original source data. On the selected prefix W=0x597A,the full phase becomes W26=0x5784 and replacement W28=0xB606,the established object-flow entry phase.

The source loads the data pointer twice:0x10040B64C and0x10040B74C. The first20 bytes use the first loaded pointer;the remaining11 use the reloaded pointer. Both private reads resolve to the original file-initial target. This is an explicit stability premise for the native case,not a claim that this mutable global cannot change.

The31 B stack string ends immediately before F+0xA8,the later metadata record start. Current byte epochs verify that those later record stores preserve the string. No UTF-8/ASCII interpretation is assigned to wrong-phase results beyond their exact bytes;the512 decoder controls stop before the following API.

## Main-port and dictionary call contracts

| Source call | Original import slot / binding | Formal arguments / result |
| --- | --- | --- |
|0x100461CC4 |0x1010A0988;`_IOMainPort`;IA diversity0x6240 |W0=0 default bootstrap port;X1=&F+0x7C;status32 result |
|0x10040B814 |0x1010A0C28;`_IOServiceMatching`;IA diversity0x083B |X0=F+0x89 class C-string;64-bit dictionary result |

The installed SDK documents bootstrapPort0 as the default and IOServiceMatching as constructing a dictionary for an IOService class or any subclass. It returns a retained mutable dictionary pointer or null. The source's nonnull result reaches the following GetMatchingServices input directly;the SDK documents consumption of a dictionary reference there. Private summaries do not implement actual CF ownership,registry lookup or Mach-right allocation.

The MainPort status predicate is status32==0. Under entry W28=0x597A,normal status selects index0x9A9B /slot0x1010873C8 ->0x10040B5E0;nonzero status selects0x9AE1 /0x1010875F8 ->0x10062FB74. The latter continuation remains unexecuted. On success,the F+0x7C cell has API provenance2 and survives to GetMatchingServices'32-bit main-port argument.

After class construction,the source tests full X0 for null. It selects index0x27D5 /slot0x10104DD98 ->0x1003F94EC for nonnull,or0x27CE /0x10104DD60 ->0x1004616A8 for null. The proof covers all64-bit pointer patterns. The null path writes0x74C29FC9 to F+0x60 and selects common cleanup without entering the object-flow component;its F+0x50 pointer remains unknown in this entry model.

Entry stores at0x100461C30/0x100461C34 also establish the saved input/table cells F+0x38/+0x40/+0x48 from declared incoming registers. These now have source provenance1 rather than incoming-fixture provenance3. Earlier table-register origins and actual locking remain conditional.

## Kext metaclass correspondence and deeper interface

| Layer | Original source evidence |
| --- | --- |
| Daemon class argument |`com_apple_driver_FairPlayIOKit\0`,31 B decoded at F+0x89 |
| Kext literal |Identical31 B at0xFFFFFE000790CC00 |
| Kext constructor C1 |`__ZN30com_apple_driver_FairPlayIOKit9MetaClassC1Ev` at0xFFFFFE000A50A834 |
| Kext constructor C2 |`__ZN30com_apple_driver_FairPlayIOKit9MetaClassC2Ev` at0xFFFFFE000A50A978 |
| Superclass metadata |slot0xFFFFFE000847C5D8 ->0xFFFFFE000CB5C060;exact kernel symbol `__ZN9IOService10gMetaClassE` |
| Base constructor import |stub0xFFFFFE000A69F174;slot0xFFFFFE000847C3E8 ->0xFFFFFE000C441EC0;exact kernel symbol `__ZN11OSMetaClassC2EPKcPKS_j` |
| Base-constructor argument setup |X0=receiver,X1=name literal,X2=IOService metadata,W3=0x88=136 B |

Both constructor setup spans are source-lifted,including their ADRP page-address instructions and superclass-pointer loads. Exact KC symbols and original format8 pointer records corroborate the names/targets. The kext's normalized extracted bytes also match these code/name spans. No kernel constructor,registration effect,object allocation or PAC operation executes.

The136 B value is the instance-size argument to the base metaclass constructor. It is not a measured native allocation or proof that any instance currently exists. The static metadata links this name to an IOService-derived provider class in the supplied `com.apple.driver.FairPlayIOKit` fileset. The matching criterion is the C++ service class name with underscores,not the dotted fileset/bundle identifier.

Together with the preceding source contracts,the conditional client path requests this class family,enumerates a returned service,opens type0 and issues selectors22/23 through the resulting connection. The kext's compatible UserClient endpoints and provider forwards are already established. Runtime subclass overrides,publication,registry contents,actual port rights and the selected provider vptr remain unknown. This association does not prove that a particular private/native name designates that provider.

## Validation and retained-analysis reconciliation

The composed group has664 cases:the preceding632 object-flow cases plus32 controls varying MainPort status{0,1,0xE00002C7,0xFFFFFFFF},dictionary-nullness,two frame placements and main-port values{0,0xF0000027}. The isolated group has512 decoder cases:all256 entry low bytes with upper bits0x5900,in two frame placements. The source theorem additionally covers arbitrary upper24 bits.

| Check | Verified result |
| --- | --- |
| Composed /isolated decoder cases |664 /512 |
| Composed /decoder instruction visits |573640 /64000 |
| Earlier object-flow sequences preserved |632 |
| MainPort summaries /successful output cells retained |664 /640 |
| Exact-class IOServiceMatching calls |640 |
| Nonnull dictionary results forwarded to GetMatchingServices |636 |
| Null-dictionary cleanup paths |4 |
| MainPort error frontiers |24 |
| Matching-services /Open error frontiers |32 /12 |
| Common-cleanup unknown-F50 frontiers |596 |
| Exact-name isolated controls |2,one low0x7A result per placement |
| Existing IOKit object models /metadata query models retained |3000 /1144 |
| Source proof pairs /lifted instructions |15 /141 |
| Exhaustive bank identities /byte inputs |3 /768 |
| Original daemon fixups /direct branch slots /new import bindings |52 /5 /2 |
| Current IDB instruction rows matching original source |208 |
| Kext metaclass functions /import-stub spans /pointer records |2 /1 /2 |
| SDK widths /signature assignments /compile exit |3 /2 /0 |
| Prior artifacts checked /unchanged |2447 /2441 |
| Original analysis/C/calls inputs preserved |3 |

All632 embedded instruction/read/write/edge sequences agree after subtracting the198-visit prefix. The first GetMatchingServices call's unused X3-X7 now contain the constructor-call clobbers;its three arguments match exactly. Other captured IOKit/query argument records and source epochs match after visit-index translation. The main-port cell changes provenance from incoming3 to API2,and saved input/table cells change from incoming3 to source1. Their values remain equal under the declared entry inputs.

Fresh replays use the same A64 engine as retained cases. Independent byte reconstruction checks original reads,source/API provenance,31-byte stores,the two data-pointer epochs,formal arguments,embedded components and final frontiers. This is not an independent native engine. Original and simplified SMT files are hashed and rechecked against newly rebuilt source-derived obligations.

The retained class-decoder/predecessor analyses supplied leads and already described a conditional string result. Their earlier pointer-value premise is strengthened here by independently decoding the original global rebase. Their full text,related proof scripts and hashes are snapshotted in the contracts. No old exploratory script or IDB target execution was invoked;prior native/PAC interpretations are not adopted as facts.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_iokit_class.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_iokit_class.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_iokit_class.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_iokit_class.py
```

Regeneration requires a new preservation/delivery seal. Each private case permits at most5000 visits. With B daemon bytes,C cases,V visits/case,E memory/API events/case,J demand pages,F fixups,I lifted instructions and R bank identities:time O(B+C*(V+E+J*F)+I+256R+KC+SDK bytes),retained space O(B+C*(V+E)+I+F+4096J+KC),plus a30 s/query solver bound. Original inputs,binaries,IDB and retained notes remain preserved. Six historical edits are limited to the four consolidated reports,investigation status and aggregate manifest validator.

## Bounded continuation and scoped quality gates

| Impact | Remaining question /pattern | Evidence that would resolve it |
| --- | --- | --- |
| High | Which upstream source establishes the lock/context pointer at F+0x50? | Exact producer,aliases,synchronization helper and returning cleanup contract |
| High | Does this class family publish a native service and receive the selected connection? | Registration/registry/service identity and runtime provider/UserClient evidence |
| High | What do state+0x14 consumers do with synthesized capability bit0x08? | Actual field reads/decoder and downstream call/IPC selection |
| Medium | Can the class-data pointer change across the two decoder reads? | Native writer/callback/concurrency provenance;current file-initial stability is conditional |
| Medium | MainPort and dictionary-null cases select error/cleanup paths | Internal record/status consumer and outer publication/lifetime evidence |
| Low | Which class/subclass instance appears first in the matching iterator? | Concrete registry enumeration and selected object identity;class-name equality alone cannot establish it |

No new emitted Mach message ID,right disposition or native port name is established. The source MainPort call location,output cell,class criterion,dictionary forwarding and kext metaclass association are established under the stated premises. Full native entry,registration,instance selection,actual object lifetime,concurrency,hardware authentication and later cleanup remain unknown.

| Gate | Result /evidence |
| --- | --- |
| QG1 | Pass:factual source/interface analysis |
| QG2 | Pass:IC1-IC14 include dependent results and falsification probes |
| QG3 | Pass for this increment:MainPort/class-constructor/object-flow composition and static metaclass association covered;full_goal_complete=false |
| QG4 | Pass:explicit B/u32/u64 widths,modular formulas,case cardinalities and reproduction |
| QG5 | Pass:class-or-subclass criterion,native/publication limits,file-initial pointer and unused-register changes distinguished |
| QG6 | Pass:original daemon/KC bytes/fixups/symbols,208 IDB rows,1176 fresh cases,15 source proof pairs and typed SDK compile |
| QG7 | Pass:impact-labeled bounded continuation table |
