# RPC502 sidecar parser, record ABI and supplemental-file transition

The original RPC502 worker now reaches a concrete `.sinf` parser path and then attempts a second source-built filename ending in `.v5.supf`. The retained path selects header discriminators 1, 3 or 5, inner selector 1 or 2, and a 57-byte minimum extent before constructing its 56-byte record. Scalar fields are big-endian on input and XOR-encoded in the internal record; a four-byte field is copied unchanged; two 16-byte fields use a byte transform equivalent to XOR `0x98`.

These are local source contracts under the earlier explicit PID-zero, environment, filesystem, synchronization and PAC models. They establish a new predecessor of supplemental-file processing, not native `.sinf` acceptance, a complete protected algorithm, a successful daemon/kext exchange or the semantics of every field. The wider objective remains active and incomplete. R1-R12 enumerate assumptions and falsification probes.

```text
original RPC502 worker ABI fixture,entry0x100422d48
       |
original policy/path/open/fstat/mmap/malloc/copy prefix
       |                      declared bytes only
       +-------------------------------+
                                       |
                         original BE32 reader,twice at0
                                       |
                          header_word <= length32
                                       |
                   byte4 probe and header-dispatch branches
                   /                              \
      alternate branch,unresolved         selected header1/3/5
                                                   |
                                          length32 >=57
                                                   |
                                            malloc56 model
                                                   |
                                  scalar/opaque/default initialization
                                                   |
                                       inner selector1/2
                                 /                     \
                           selector1                selector2
                          skip12..23               read12..23
                                 \                     /
                                  two16-byte transformed fields
                                                   |
                                    original local success continuation
                                                   |
                                       free56-byte record request
                                                   |
                          original .v5.supf pathname construction
                                                   |
                        stop before supplying another open result

rejection paths -> free copy -> munmap request -> close request
                -> selected QoS restoration -> worker return
```

## Provenance, source identity and evidence boundaries

The [source identity](triage_evidence/rpc502_parser_source_identity.json) freshly verifies the 17,668,912-byte arm64e slice at universal offset 3,407,872. Thin SHA256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. The current universal copy `/Users/___/Downloads/fpx/fairplayd` has SHA256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; its selected slice exactly equals `/Users/___/Downloads/zut/fairplayd.arm64e`.

A read-only IDA query failed because the Assist bridge had no initialized endpoint. The [transcribed error/context](triage_evidence/rpc502_parser_ida_context.json) explicitly records that no live IDB bytes were verified and no IDB was mutated. Source-file identity does not attest the running daemon's selected slice, slides, runtime bytes or credentials. Prior analysis memory guided source pinning and preservation of parser-populated state; the contracts below derive from current original bytes and current private runs.

The [69 sequences](triage_evidence/rpc502_parser_profiles.json), [source contracts](triage_evidence/rpc502_parser_contracts.json), [compiler ownership](triage_evidence/rpc502_parser_compiler_ownership.json), [independent checks](triage_evidence/rpc502_parser_checks.json) and [quality gates](triage_evidence/rpc502_parser_quality_gates.json) preserve inputs, instruction streams, source pointer members, record writes, initialization, retirement, pathname writes and boundary results. The new [engine](triage_evidence/probe_rpc502_parser.py), [producer](triage_evidence/probe_rpc502_parser_cases.py), [recoverer](triage_evidence/recover_rpc502_parser.py), [local ALU lifter](triage_evidence/rpc502_parser_lift.py), [ownership reader](triage_evidence/recover_rpc502_parser_ownership.py) and [validator](triage_evidence/validate_rpc502_parser.py) extend frozen earlier artifacts.

The original worker runs from its earlier public ABI fixture. There is no new parser-PC jump, frame patch, gate override or hand-built parser record. The [mapping report](rpc502_mapping_report.md) and [runtime report](rpc502_runtime_report.md) remain frozen and delimit inherited PID-zero, VMM-positive/skip-CoreKE, BootPolicy/CSR, private allocator, serial once/lock and PAC assumptions. File bytes and additional malloc/free/unmap/close outcomes are declared inputs. No native target, loader, Mach, file, credential, scheduling or synchronization API executes.

## Routine context and exact source locations

All addresses are unslid daemon addresses. The original `LC_FUNCTION_STARTS` contains 1,005 starts. The 33 bounded source ranges intersect 18 metadata-delimited compiler ranges; whole-range hashes and complete ownership partitions are retained. Those boundaries are source metadata, not proof of conventional calls, complete semantic routines or arbitrary reachability. Many transfers are authenticated table-driven branches between physical ranges.

| Source location | Established local role |
| --- | --- |
| Carrier `0x10099ab1c..0x1009d53cc` |Contains the inspected frame preparation, shared BE32 reader and unrolled byte-field transform;239,792 bytes,not a claim that every byte has been semantically recovered |
| `0x1009b7728..0x1009b787c` |Produce parser size words from the encoded incoming length |
| `0x1009b6eac..0x1009b7014` |BE32 reader and encoded result;reused at multiple field offsets |
| `0x100a49ca4` |Save first encoded header word at current parser frame+`0x4f8` |
| `0x100a50508..0x100a505bc` |32-bit header-versus-length guard and table selection |
| `0x100930198` |Read input byte4 before the later 57-byte guard |
| `0x100a65870`, `0x1008910f0`, `0x100976f98` |Initial signed encoded-header partition |
| `0x100a68734`, `0x10099ffd4`, `0x100ac0480`, `0x100ac8324`, `0x100ab6c24` |Local constructor selection for header values1/3/5 |
| `0x100972888..0x1009728c8` |Minimum-size predicate |
| `0x100913590` |Additional `malloc(56)` emission;in compiler range `0x100912ad8..0x100914120` |
| `0x1009d8804..0x1009d88f4` |Record initialization and unchanged-byte-field copy;in compiler range `0x1009d57f0..0x1009d9908` |
| `0x100644b8c` |Store decoded/encoded inner selector into record+8 |
| `0x10064aa10`, `0x100a604f0`, `0x1009e9afc` |Inner-selector1/2 partition and rejection |
| `0x10094e1e4`, `0x100c717ac`, `0x100656ff0` |Selector2 stores additional scalar fields at+12/+16/+20 |
| `0x1009bb5c4..0x1009bb8dc` |Two unrolled 16-byte input-to-record transforms |
| `0x100926bc0` |Epilogue writes current W24 through current X26+16,then returns through the existing frame |

The epilogue has W24=`0x8b3dc651` in the retained supplemental-open continuations. Its relationship to a zero under that XOR encoding is explicit. Complete caller-record aliasing to the earlier public 120-byte record and all alternate status encodings remain outside this new local layout claim.

## Length view, reader and guards

Let K32=`0x8b3dc651`, L be the observed u32 parser length and H=`BE32(file[0..3])`. The preparation prefix has W23=`0x928` and incoming stack word+`0x234`=`L XOR K32`. Under those exact source inputs:

| Source word /predicate | Compact local semantics |
| --- | --- |
| Store `0x1009b7794`,frame+`0x1d0` |`u32(L-57)` |
| Store `0x1009b7878`,frame+`0x1d8` |`u32(L+0xa30e544d)` |
| Reader output W20 |`BE32(input_at_cursor) XOR K32` |
| Reader intermediate W9 |`BE32(input_at_cursor) XOR 0x6703cce9` |
| Guard ending `0x100a505ac` |Index `0xafe2` when `H<=L`,otherwise `0xbe39`;unsigned32 relation |
| Target cells |`0xafe2 ->0x100aaea34`;`0xbe39 ->0x100b6b01c`;original words/fixups retained |
| `CMN W9,#0x39` /`CSET LO` at`0x10097288c..0x100972890` |With W9=`u32(L-57)`,equivalent to unsigned `L>=57` |

The seven local formulas independently establish the two size-word identities,the header-length predicate,the minimum-size predicate,the header set,the inner-selector set and the low8 byte identity. The new source-derived ALU expressions fail on unsupported scalar operations in the interpreted subset;pointer setup remains source context;the original bytes and declared loads/register preconditions remain attached. The reader's full u32 XOR identity also retains the earlier source proof in the mapping report.

The local constructor tree uses signed comparisons on the encoded header,then equality tests. Its compact accepted set is H in `{1,3,5}`. This does not classify every alternate path as an invalid public version: other header values can take an earlier alternate parser branch whose full semantics remain unresolved. Header2 has a distinct retained rejection. The same distinction applies to inner selector:the inspected record path accepts selector1/2;other future parser families are not covered by that claim.

The inner-selector signed threshold is encoded `0x8b3dc653`;the equality basis for the lower branch is `0x8b3dc650`. They are derived from original ALU prefixes,not substituted from the simplified set. All exact table cells,auth metadata and import/library addends are source evidence;hardware PAC success remains unverified.

L is a 32-bit parser view. The earlier mmap/malloc interface transfers a full64-bit file size. Files larger than the new private allocation bounds are not executed here;the complete writer/alias relation between all 64-bit sizes and this parser view remains unresolved.

## 56-byte record and consumed wire fields

The record is initialized by original instructions after the declared allocation succeeds. The original stores initialize every byte;unwritten allocation bytes are poison and cannot be read by the private model. The [compile-only layout](triage_evidence/rpc502_parser_layouts.c) and [assembly](triage_evidence/rpc502_parser_layouts.s) verify size56 and the field offsets below. These are source shapes,not SDK-defined types or assigned public metadata names.

| Record offset | Width | Source input /stored representation |
| --- | --- | --- |
| +0 |u32 |`BE32(file+0) XOR K32`,stored little-endian |
| +4 |4 bytes |`file[4..7]` copied unchanged;no BE-to-LE scalar conversion is claimed |
| +8 |u32 |`BE32(file+8) XOR K32`,stored little-endian |
| +12 |u32 |Selector2:`BE32(file+12) XOR K32`;selector1:K32,representing decoded zero |
| +16 |u32 |Selector2:`BE32(file+16) XOR K32`;selector1:K32 |
| +20 |u32 |Selector2:`BE32(file+20) XOR K32`;selector1:K32 |
| +24..+39 |16 bytes |`file[i] XOR0x98` at corresponding offsets |
| +40..+55 |16 bytes |Same byte relation at corresponding offsets |

The unchanged four-byte field is not semantically unused:source control flow probes its first byte before the later minimum-size guard. Its public interpretation remains unknown. Controls with leading bytes`0x54`,`0x55`,`0x75`,`0x76` preserve the raw field and reach the recorded supplemental boundary under the selected remaining fields;no universal marker semantics is assigned.

The byte expression is `u8(x-((x<<1)&0x30)-0x68)`. The complete u8-domain check and local SMT identity reduce it to `x XOR0x98`. The register-shift variant has shift1 under the retained source entry state. The two field copies preserve their final byte order;their source reads/stores are unrolled in descending order within each 16-byte span.

A compact local encoder is:

```text
record = 56 source-owned bytes
record.u32[0] = BE32(file+0) XOR K32
record.bytes[4:8] = file[4:8]
record.u32[8] = BE32(file+8) XOR K32
record.u32[12,16,20] = K32
if selector == 2:
    for offset in [12,16,20]:
        record.u32[offset] = BE32(file+offset) XOR K32
for offset in [24..55]:
    record.byte[offset] = file.byte[offset] XOR0x98
```

This fixed record operation is O(1) time/storage;parameterized byte copying is O(N) time and O(1) auxiliary storage for N bytes. The inverse is defined for consumed scalar/span fields by the same XOR masks. Selector1 ignores input bytes12..23 in this retained path,so this is not an invertible codec for every byte of the original file. The tested 57th byte is not consumed and may be0 or`0xff`;it is not established as a NUL terminator.

Eight 32-byte span controls collectively supply all 256 byte values. Every retained field offset is checked against an independent record oracle. This is distinct from testing every u8 value at every physical store instruction. The mathematical byte identity is complete;whole-parser/native behavior is finite and conditional.

## Extents, status axes and failure controls

| Finite control | Original source result /boundary |
| --- | --- |
| Logical extents1/2/3 |First BE32 read reaches the first unavailable byte at offsets1/2/3,respectively |
| Logical extent4 |Header reads complete;byte4 probe reaches the first unavailable byte at offset4 |
| Header1,selector1,extents5..56 in retained samples |Minimum-size rejection;raw worker result`0xffff5bd9` |
| Header1,selector1,extents57/58/63/64 |Record path reaches the supplemental-open boundary |
| H=65 with L=64,plus large H controls |Header-versus-length rejection;raw worker result`0xffff5bdf` |
| Header2,otherwise selected fields |Distinct raw worker result`0xffff5bef` |
| Header0/4/6/7/8 and selected larger values |Alternate parser continuation;retained result`0xffff5b1e`;full family semantics unresolved |
| Inner selector0/3/4/5/6/7/8/large values |Record initialized,then rejected/freed;raw worker result`0xffff5bde` |
| Additional malloc NULL |No56-byte owner;original cleanup/return result`0xffff5bd4` |
| Additional malloc deliberately unmodeled |Explicit constructor-allocation boundary,without supplying a result |

The first four rows concern the requested logical allocation extent. They do not establish a native memory fault,malloc usable size,VM accessibility or real malformed-file reachability. The original first reads precede the later size predicate in these complete worker fixtures. No page-padding bytes are supplied as valid file bytes.

These statuses are raw u32 worker-return values,not assigned public error names. For example,`0xffff5bde -2^32 =-42018` under signed32 interpretation. Internal record/status encodings,worker return values and any later MIG application reply remain distinct axes. No new outgoing reply is emitted by this worker-only fixture.

## Supplemental transition and ownership

The independent pathname ledger reconstructs every observed open string,including its NUL,from original source stores and chronological snapshots. Both attempts use the same original emission `0x100d94494` with flags0. For the synthetic `/synthetic/fixture.bin` input,the original path-building/splitting behavior produces:

```text
/synt/SC_Info/etic/fixture.bin.sinf
                    |
       selected source parse and continuation
                    |
/synt/SC_Info/etic/fixture.bin.v5.supf
```

These are source-built synthetic path examples,not files present on the host. The unusual directory split is retained from the earlier path fixture;it is not asserted to be a valid installed application layout. Across 29 cases,the second string equals the first string with `.sinf` replaced by `.v5.supf`. The second open is stopped before any new FD/result/file contents are supplied;there is no invented supplemental-file response.

| Original API emission | Local transfer /ownership observation |
| --- | --- |
| malloc`0x100913590` |Allocate56-byte record under an explicit result model |
| free`0x100c1172c` |Record rejection frees its exact owner |
| free`0x10097d444` |Selected continuation frees its exact record owner before supplemental open |
| free`0x1008ec710` |Rejected worker paths release the copied sidecar allocation |
| munmap`0x1003aaef4` |Selected rejection requests release of the original mapping and full length |
| close`0x1001f19c4` |Selected rejection requests close of declared FD7 |
| open`0x100d94494` |First `.sinf` fixture result7;later `.v5.supf` attempt remains a boundary |

At the second-open boundary,the 56-byte record is retired in the model;the copied file owner is still live and no unmap request has preceded that boundary. This does not imply that every final path has the same ownership obligation. Complete supplemental processing and enclosing cleanup remain unresolved.

On retained rejection paths,the original sequence reaches copy free,munmap,close and selected QoS restoration. Declared munmap failure leaves the mapping unretired in the model;declared close failure and munmap failure preserve the tested raw parser rejection result. These are separate request/result axes. Native release success,descriptor reuse,mapping identity,other aliases and final resource disposition remain unverified.

The new paths add no direct Mach-send site. They extend daemon processing after the earlier RPC502 ABI boundary;they do not establish new incoming port names or an additional kext RPC. FD7,heap/mapping pointers,record pointers and header values are not Mach port identities. The [cross-layer ABI](interface_abi_report.md), [daemon receive](daemon_receive_interface_report.md) and [kext port/VM report](kext_port_vm_report.md) retain the transport/authorization/ownership boundaries still requiring reconciliation.

## Independent verification and preservation

All 3285116 assertions pass across 69 complete private sequences and 2341837 retained original-instruction visits. All 69 worker invocations are freshly replayed, reproducing another 2341837 visits. The corpus has 29 supplemental-open boundaries, 35 complete worker returns, 4 logical-extent boundaries and 1 deliberate allocation boundary. Independent checks cover 34048 source owner stores, 248 owner snapshots/33617 bytes, 41 record-codec oracles, 270 completed readers, 411 frame-field stores, 98 pathname snapshots/5040 pathname-ledger byte applications, 41260 pointer-read observations, 460 independently decoded members, 13527 unique original instructions and 33 bounded source ranges in 18 compiler ranges.

The validator re-reads original instructions/ranges and pointer members,checks import/addend/library decoding,hashes complete metadata-delimited compiler ranges,reconstructs allocation bytes/initialization/retirement in event order,checks all parser reads against declared file bytes,recomputes BE32 outputs and intermediates,checks size-word producers,and independently reconstructs source-built pathname bytes through each observation epoch. It checks the compact record oracle,all 256 byte values,source shift contexts,all seven formulas and compile-only shapes. Every whole fixture is freshly replayed against exact event/state evidence. Fresh replay uses the same declared Unicorn/models;it is not independent native execution.

Validation costs O(B+I+V+E+S) time/space for bounded original bytes B,unique instructions I,visits V,events E and snapshot bytes S;compiler lookup adds O(R log F) for R ranges and F starts. The record codec is fixed-size. Each original worker run is capped at200000 steps. Initial file-copy/mapping models have a `0x40000`-byte cap;new ordinary allocations have 65536-byte/16-owner guards,in addition to inherited limits. Each solver timeout is30000 ms. These are harness bounds,not native implementation limits.

The current Homebrew Z3 command is available independently of its Python bindings. Contract generation uses the existing package at `/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages` and a private `/tmp/rpc502-parser-z3-runtime/libz3.dylib` link to its existing versioned library,with `Z3_LIBRARY_PATH` set for that command only. No package was installed and no global library/configuration was changed. The retained `.smt2` files and normal validator use the `z3` command directly. Other Python commands use `/Users/___/Downloads/zut/.venv/bin/python -P` with `PYTHONPATH=triage_evidence`.

The [preservation record](triage_evidence/rpc502_parser_preservation.json) checks all 927 prior artifacts against the [prior manifest](triage_evidence/rpc502_parser_prior_manifest.json): 921 remain byte-identical;only the five reporting indexes/status and manifest aggregator change. All three supplied inputs remain unchanged. Published producers/readers/proofs/profiles/reports,original binaries,external dump.md and IDBs remain preserved. The [current manifest](triage_evidence/interface_manifest.json) is refreshed separately and retains goal status active.

## Assumption register

| ID | Assumption /dependent results | Stress test /falsification probe |
| --- | --- | --- |
| R1 | Pinned current source files supply these contracts | Fresh thin/universal equality,UUID,source ranges and fixups;match actual loaded slice/slides/bytes independently |
| R2 | Earlier worker ABI/environment models select this prefix | PID-zero/VMM/BootPolicy/CSR/once/lock/loader assumptions remain inherited;recover native admitted request and environment before promotion |
| R3 | New file bytes and open/stat/mapping/copy results are declared | Exact byte/read/copy ledgers,small extents,header/selector/mask/tail controls;actual sidecar writers,identity and access remain unknown |
| R4 | Local W23/W3 and encoded input words describe the proved guards | Original source-derived frame snapshots and full u32 formulas;other entry states/64-bit parser views remain outside those corollaries |
| R5 | Compiler boundaries provide physical context only | Original1005-start metadata and18 complete range hashes;do not infer conventional calls or complete semantic ownership from range proximity |
| R6 | Private allocation/initialized/retired tracking represents local owners | Poison/unwritten-read guards,independent lifetime/byte oracle,NULL result and deliberate allocation stop;native allocation policy/aliases remain unproved |
| R7 | Header1/3/5 and inner1/2 identify this local record path | Signed encoded-tree proofs and finite positive/negative controls;alternate/legacy families and public metadata names remain unresolved |
| R8 | Codec interpretation applies to consumed fields | Independent BE/LE/raw-byte checks,optional-field controls,all 256 byte values and full u8 identity;selector1 ignored fields and tail bytes are not invertible full-file data |
| R9 | Byte transform/source register prefixes are adequate for retained copies | Original unrolled source ranges and shift1 entry contexts;hardware PAC,other contexts and native execution remain unverified |
| R10 | Free/unmap/close and supplemental open are modeled request boundaries | Exact owner bytes at free,unmap/close failure controls,29 source-path pairs;native effects and complete enclosing cleanup remain unknown |
| R11 | Live IDB knowledge/bytes were unavailable this increment | Retained bridge error;all new claims use current original bytes;reconcile IDB state when the bridge becomes available |
| R12 | Local parse continuation does not complete the protected operation | Resolve `.v5.supf`,alternate parser branches,actual file producer/validation,final replies and kext/deeper RPC coupling separately |

## Bounded continuation

| Impact | Interface to investigate | Unresolved evidence |
| --- | --- | --- |
| High | `.v5.supf` processing | Authentic framing,metadata/crypto/record consumers,second mapping/count ABI,errors and final file/copy ownership |
| High | Native protected request-to-file-to-kext route | Actual admitted sender/audit/port identity,real sidecar producer/content/permissions,loaded environment and selected kext operation/RPC |
| Medium | Alternate parser family and header2 rejection | Complete control tree,three helper roles,record constructors and later consumers without naming unproved formats |
| Medium | Full64-bit size versus32-bit parser view | Every producer/alias of the encoded parser length,large-size guards and all capacities;finite logical-extent witnesses are not native defects |
| Medium | Remaining metadata/record meanings | Interpretation of unchanged four-byte field,inner selectors,optional scalars,two16-byte fields and public response/status consumers |
| Medium | Lifetime and status completion | Supplemental failure/retry,other owner aliases,all unmap/close/QoS outcomes and final MIG/OOL reply ownership |
| Low | Broader byte/header/control domains | All marker predicates,noncanonical fields,other preparation states and allocation failure variants |

QG1-QG7 pass for the stated increment:descriptive findings;R1-R12 assumptions and probes;bounded routine/data/control/ABI progress;consistent byte/width/layout arithmetic;separate source/model/native/error/ownership axes;fresh primary provenance,independent ledgers/oracles,replays,SDK compile and seven local formulas;impact-labeled continuation. The full objective remains active and incomplete.
