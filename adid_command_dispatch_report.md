# CoreADI adid: command dispatch and request-to-Avp interfaces

The BE32 word at request offset 4 selects fourteen commands. It is not a single magic constant. The original signed comparison tree at `0x10016cd58` contains 107 decision instructions and selects exactly fourteen raw words over the complete 32-bit domain. The remaining 4,294,967,282 values take the shared error path. Selection alone does not establish valid command-body syntax, authorization, successful execution or native reachability.

A complete original callback, supplied with a 12-byte command request and explicit environment/API models, now reaches `AvpFairPlayDriver` method 100 at `0x100058a1c`. Original code constructs the outer caller record and the shared 144-byte method buffer. This closes the previous fragment-entry gap for this particular request-to-API path. It does not establish native driver execution, a successful protected operation, or equivalence between Avp and the separately recovered primary FairPlayIOKit method 26.

Other requests naturally reach the 96-/176-byte constructor, per-EUID record unlink, and a request-controlled allocation size. These paths begin at the original XPC callback; no internal instruction, frame, state-codec, caller-record or program-counter override selects them. The initialized peer/context, credentials, filesystem and external APIs remain declared private fixtures. The full investigation remains active.

## Source identity and assumption register

Source: `/System/Library/PrivateFrameworks/CoreADI.framework/adid`, selected arm64e slice, base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. Addresses are unslid addresses in this image. No source binary, original report/input, IDB or native target state is changed.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| D1: pinned original bytes, compiler ranges and fixups identify this image | Every address and source-derived contract | Fresh byte/disassembly/range readback and independent `dyld_info` fixups; another image requires a new address mapping. Native loaded-image integrity remains unknown. |
| D2: frozen private PAC/API/vector/atomic models represent the declared local experiment | All callback and downstream witnesses | Twelve complete fresh replays compare ordered original instructions, events and final watched bytes. Native PAC, APIs and concurrency are not established. |
| D3: restored peer/context, modeled credential/entitlement and filesystem prerequisites delimit admission | Request-to-constructor, file, allocation and Avp paths | Every fixture retains its complete inputs. Original callback entry is used without internal control/frame overrides. Native caller identity, effective entitlement and startup feasibility remain unknown. |
| D4: original comparison conditions and modular word encoding define command selection | Fourteen-command set and rejection complement | Independent concrete source interpreter, exact signed interval coverage, neighboring-word controls and a full-domain SMT equivalence proof. Selection is separated from later body rejection at the same error entry. |
| D5: original request pointer/length stores define the constructor's tail input | Key/length/blob schema, size guard and source-created objects | Capture producer `0x10016ac30`, constructor snapshots, 0/1/26/27/28/64-byte cases and two truncated requests. The first four inner bytes are observed; complete accepted inner grammar remains unknown. |
| D6: source object snapshots describe the captured construction epoch | 96-/176-byte fields and allocation requests | Snapshots are taken at `0x10019cb24`, before later cleanup/reuse. Final memory at the same address is not automatically a live object. Publication, free/ownership and native initialization guarantees remain unknown. |
| D7: modeled unlink results describe only private filesystem effects | Header-only command, EUID path and reply/result separation | EUID 0/265/501 crossed with unlink return 0/-1. Native deletion, path resolution, persistence and race behavior remain unknown. |
| D8: observed W-register arithmetic and original unexecuted boundaries delimit allocation behavior | Wrapped scalar-times-32 request, BRK and mmap arguments | Full-domain arithmetic proof, six scalar cases, byte verification of post-call `BRK #1`; no native trap or large mapping is executed. Complete capacity and allocator state contracts remain unknown. |
| D9: explicit time/random/small-allocation and IOKit responses permit the retained continuation | Request-driven Avp acquisition, method buffer and retry/reply outcomes | Opaque API controls, VMM 0/1/2/query-failure controls, open failure, method transport failure and identity-buffer response. Actual hardware response, packet semantics, rights and native endpoints remain unknown. |
| D10: captured source-built records and API argument widths define the inspected local ABI | Outer 40-byte record, shared 144-byte buffer and output size | Decode record independently using its address; compare all method calls, source sites and reply emissions. No complete native C type or accepted driver protocol is assigned. |

Artifacts: [source contracts and windows](triage_evidence/adid_command_dispatch_contracts.json), [79 complete callback profiles](triage_evidence/adid_command_dispatch_profiles.json), [recoverer](triage_evidence/recover_adid_command_dispatch.py), [producer](triage_evidence/probe_adid_command_dispatch.py), [validator](triage_evidence/validate_adid_command_dispatch_delivery.py), [checks](triage_evidence/adid_command_dispatch_checks.json), [quality gates](triage_evidence/adid_command_dispatch_quality_gates.json), and [prior-artifact preservation](triage_evidence/adid_command_dispatch_preservation.json). Earlier [constructor/allocation](adid_record_lifecycle_report.md), [caller-record](adid_iokit_caller_report.md), [IOKit acquisition](adid_iokit_report.md) and [protected-dispatch](adid_driver_dispatch_report.md) reports retain their original experiment scopes.

## Request and control-flow map [D1-D5,D9]

```text
original XPC callback 0x100029fc8
  -> common peer/audit/context/persistence/header gates
  -> BE32(request+4) + 0x0046d726, modulo 2^32
  -> signed command tree 0x10016cd58
       +-- 0x632b8d6e -> key/EUID lookup -> nested value+0x98 update
       +-- 0x716bd86c -> key64/length32/blob -> constructor 96/176
       |                                      -> inner-blob validation
       +-- 0x72096fe6 -> per-EUID unlink -> payload 0
       +-- 0x9679d4b5 -> scalar32*32, modulo 2^32 -> allocator
       |                                      +-- unexecuted BRK
       |                                      +-- unexecuted mmap boundary
       +-- 0x76e89210 -> VMM query success and exact value 1
       |               -> time/random -> malloc 12/1 bytes
       |               -> original 40-byte caller construction
       |               -> AvpFairPlayDriver / type 0 / method 100
       |               -> original reply/error continuations
       +-- nine other selected parsers: complete schemas unknown
       +-- all other words -> shared error entry 0x10016ec20
```

The first and third request words are both 1 in the retained selected-command fixtures. The first-word 0/2/`0xffffffff` controls bypass the command tree and emit `ffff5026` (-45018). The global semantic name of the third word is unknown. The shared error entry is also reached by later parsing failures of recognized commands; observing that entry alone cannot classify a word as unknown.

## Complete command-selection domain [D1,D4]

Let `c = BE32(request+4)` and `e = (c + 0x0046d726) mod 2^32`. Original W-register comparisons use signed GT/LE splits and EQ/NE leaves. The recovered path predicates are equivalent to these exact raw command values. A separate concrete interpreter reads original instructions rather than trusting the recovered branch list.

The baseline request is 28 bytes: `BE32(1,c,1) || BE64(0xfffffffffffffff8,0)`. Its result is a finite body/context observation, not an operation's universal result.

| Raw command c | Encoded e | Parser entry | Baseline result / established role |
| --- | --- | --- | --- |
| `0x0b2b3196` | `0x0b7208bc` | `0x10016d46c` | `ffff5031`; complete operation unknown |
| `0x385b2ce8` | `0x38a2040e` | `0x10016dee8` | `ffff4ffb`; complete operation unknown |
| `0x55a637c0` | `0x55ed0ee6` | `0x10016e1a0` | `ffff501f`; complete operation unknown |
| `0x632b8d6e` | `0x63726494` | `0x10016d238` | `ffff501f`; earlier key/EUID value update path |
| `0x716bd86c` | `0x71b2af92` | `0x10016d92c` | `ffff5018`; request-driven constructor/blob path |
| `0x72096fe6` | `0x7250470c` | `0x10016cf28` | `00000000`; per-EUID unlink path |
| `0x76e89210` | `0x772f6936` | `0x10016db8c` | `ffff5024`; exact-VMM1 environment/Avp path |
| `0x7715488c` | `0x775c1fb2` | `0x10016d67c` | `ffff4ffa`; complete operation unknown |
| `0x85fe63b0` | `0x86453ad6` | `0x10016dd14` | `ffff4ffb`; complete operation unknown |
| `0x9679d4b5` | `0x96c0abdb` | `0x10016dfb4` | Stops before mapping; scalar allocation path |
| `0xa54951ec` | `0xa5902912` | `0x10016d0fc` | `ffff4ffb`; complete operation unknown |
| `0xa8471cad` | `0xa88df3d3` | `0x10016d850` | `ffff5031`; complete operation unknown |
| `0xb0eda7af` | `0xb1347ed5` | `0x10016cdec` | `ffff4ffb`; complete operation unknown |
| `0xcfe0b46a` | `0xd0278b90` | `0x10016dab8` | `ffff4ffb`; complete operation unknown |

Thirty concrete unselected words (the immediate neighbors of all fourteen commands plus 0 and `0xffffffff`) emit `ffff5025` (-45019). The SMT proof and exact interval partition, rather than these finite probes alone, establish the full rejection complement.

## Wire-driven construction and inner-size guard [D2,D3,D5,D6]

| Offset / width (bytes) | Observed request field | Original staging / use |
| --- | --- | --- |
| 0 / 4 | BE32 1 | Common first-word gate |
| 4 / 4 | BE32 `0x716bd86c` | Constructor command |
| 8 / 4 | BE32 1 | Retained control word; full meaning unknown |
| 12 / 8 | BE64 key | Staged at frame+`0x2be0` |
| 20 / 4 | BE32 length L | Encoded as L+`0x46d726` at frame+`0x1d0c` |
| 24 / L | Raw request tail | Pointer at frame+`0x1740` |

At `0x10016ac30`, original X12 equals input base X11 plus offset X9=24. The fixture input base is `0x7b002000`, so the stored pointer is `0x7b002018`. This corrects the tentative parent-pointer interpretation of frame+`0x1740`: in this request it is the raw blob pointer.

The original path reaches constructor `0x10019c578`, requests 96 and 176 bytes and supplies the source key and audit EUID. At snapshot `0x10019cb24`, the nested key at +8 is XOR-encoded with `0xda8ca8cae5dfbd2d`; EUID at +`0xa0` is encoded by adding `0x46d726`; +`0x98` holds encoded zero. Holder+0 encodes the nested pointer by adding `0x6fac17cb61e34e69`. These corroborate the earlier constructor fragment using a complete callback predecessor.

At `0x10019cb80`, the original operand is `(L-27) mod 2^32`; the following CMN/unsigned-LO predicate selects L >= 27 under the captured control constants. The full-domain [minimum-size proof](triage_evidence/adid_command_blob_minimum32.smt2) establishes this local reduction.

| Tail control | Result | Evidence boundary |
| --- | --- | --- |
| L = 0, 1, 26 | `ffff5018` (-45032) | Original constructor reached; minimum-size rejection |
| L = 27, 28, 64; zero bytes | `ffff5019` (-45031) | Original first inner-word reads reached |
| L = 32; first BE32 = 1 or `0x5747032f` | `ffff5019` | Two additional rejected inner-word controls |
| Declared 32 / supplied 0; declared 27 / supplied 26 | `ffff5016` (-45034) | Rejected before construction/object allocation |
| EUID 501 / L = 27 / zero bytes | `ffff5019` | Source-created EUID field independently checked |

The first four tail bytes are read at `0x1001a1540`, `0x1001a1570`, `0x1001a15a8` and `0x1001a15d8`. A valid inner header, successful collection publication and complete persistence grammar remain unknown. Calls to `0x100062468` are retained with arguments but are not promoted to a complete free/ownership contract. Some rejected constructor continuations also request per-user unlink; native file effects are not established.

## Header-only per-user unlink [D3,D7]

The 12-byte request `BE32(1,0x72096fe6,1)` reaches `_unlink` at `0x100123c74` without a command tail read. The source-selected path uses audit EUID:

| EUID | Requested path |
| --- | --- |
| 0 | `/Users/Shared/adi/adi-00000000.pb` |
| 265 | `/Users/Shared/adi/adi-00000109.pb` |
| 501 | `/Users/Shared/adi/adi-000001F5.pb` |

Each path is tested with modeled unlink return 0 and -1. All six callbacks emit payload `00000000`. Only return 0 marks `path_unlinked=true` in the private filesystem model. Thus this payload alone does not attest deletion. Actual filesystem state, errno, unlink admission, symlink resolution and concurrent consumers remain unknown.

## Request-controlled allocation and original stop boundaries [D3,D8]

The 16-byte request `BE32(1,0x9679d4b5,1,n)` reaches the allocation facade `0x1000621d4` from original call `0x100266b78`. The original W0 expression reduces exactly:

```text
encoded = (n + 0x0046d726) mod 2^32
W0      = (0xf7251b40 + (encoded << 5)) mod 2^32
        = (32*n) mod 2^32                 [requested bytes]
X0      = zero_extend_64(W0)
```

The [allocation proof](triage_evidence/adid_command_allocation32.smt2) covers all 2^32 scalar values. Multiplication wraps in 32 bits before zero extension. Native allocation capacity, object use and operation semantics are not implied.

| Scalar n | Requested bytes | Retained next boundary |
| --- | --- | --- |
| 0 | 0 | Original post-call `BRK #1` at `0x100266b7c` |
| 1 | 32 | Same unexecuted BRK |
| 16 | 512 | Same unexecuted BRK |
| 255 | 8,160 | Same unexecuted BRK |
| 65,535 | 2,097,120 (`0x1fffe0`) | `_mmap` at `0x100267b1c`, length 2,113,536 (`0x204000`) bytes |
| `0xffffffff` | 4,294,967,264 (`0xffffffe0`) | Same mmap site, length 4,294,983,680 (`0x100004000`) bytes |

The source bytes at `0x100266b7c` are `200020d4`: an explicit instruction after the allocation call, rather than an inferred allocator-internal invariant failure. It is intercepted before execution. Its intended higher-level role is unknown. Both larger probes stop before mapping; no host allocation or native fault is asserted. The 28-byte baseline for this command begins its scalar with `0xffffffff` and reaches the same large mapping boundary.

## Complete callback to Avp method 100 [D2,D3,D9,D10]

Request: `00000001 76e89210 00000001` (12 bytes). Successful modeled VMM query with exact value 1 reaches `_time` at `0x100146434`. Values 0 and 2, and query status 5 with output 1, return `ffff5024` (-45020) earlier. Thus the observed gate is exact value 1 plus successful query, not merely nonzero.

The retained continuation explicitly supplies time 1,700,000,000 s and `_arc4random_uniform` result `0x12345678` (305,419,896), less than the original upper bound `0x7fffffff`. Time X0 is NULL. These are declared values, not observed clock/random outputs. Two original imported-malloc calls request 12 and 1 bytes; the bounded private allocator allows at most three requests of at most 4,096 bytes and initializes them with `0xa5`. It calls no host allocator.

| Original API/caller site | Observed interface |
| --- | --- |
| `0x100146434` | `_time(NULL)` |
| `0x100146574` | `_arc4random_uniform(0x7fffffff)` |
| `0x1001466ac`, `0x1001468a4` | `_malloc(12)`, `_malloc(1)` |
| `0x10002c130` | Original authenticated call to caller `0x100058654`; first return `0x10002c134` |
| `0x10002af70` | Original helper-record builder; caller return `0x10005895c` |
| `0x10002b474` | `_IOMainPort`, modeled name `0x5801` |
| `0x10002b63c` | `_IOServiceMatching("AvpFairPlayDriver")` |
| `0x10002b6d8` | `_IOServiceGetMatchingServices`, modeled iterator `0x5802` |
| `0x10002b768` | `_IOIteratorNext`, modeled service `0x5803` |
| `0x10002b854` | `_IOServiceOpen(service, task=0x5810, type=0, out=0x1002dd290)` |
| `0x10002b8ac`, `0x10002b940` | Service and iterator release on retained successful-open path |
| `0x100058a1c` | `_IOConnectCallStructMethod(connection=0x5804, selector=100, shared buffer, 144, shared buffer, size64*)` |

All names `0x58xx` above are private fixtures. The connection output/cache cell `0x1002dd290` is source-derived. Native Mach names, rights, underlying sends, actual task identity, endpoint pairing and reference accounting remain unknown.

Original code supplies this 40-byte record at fixture address `R=0x7a02db50`:

```text
329360edb51da968b55db563010000002004017e000000003005007e00000000901e2c00eee96b20
```

Its independently decoded size is 144 bytes and basis is `0x5f8`:

```text
K     = (((low32(R) XOR 0x4e89bd66) * 0x0b08355f) mod 2^32)
size  = (LE32(record+8)  + K - 0x4349792f) mod 2^32
basis = (LE32(record+36) + K) mod 2^32
```

The raw record+16 pointer is `0x7e010420`; record+24 points to method input `0x7e000530`. The encoded output-count pointer at +0 uses the previously recovered bias `0x68a91db5735d89de`. Full bytes and original register values are retained. No analyst-created caller record is injected.

At method 100, X2 equals X4 (`0x7e000530`), X3 is 144 bytes, and X5 points to an eight-byte output-size cell at `0x7a02d9b8` initially containing 144. The exact input bytes are preserved in every boundary event. Their complete accepted framing, field meanings and hardware transformation remain unknown; recognizable tag-like words alone do not establish a full TLV grammar.

| Continuation model | Open attempts | Method-100 attempts | Stop / emitted payload |
| --- | --- | --- | --- |
| Time/random/small allocations only | 0 | 0 | Opaque `_IOMainPort` boundary; no reply |
| Acquisition modeled; method opaque | 1 | 1 | Original method-100 boundary; no reply |
| Method returns transport error `0xe00002c7` | 1 | 4 | Completed `ffff4fe5` (-45083) |
| Method returns 0 and leaves buffer unchanged | 1 | 1 | Completed `ffff5805` (-43003) |
| Open returns `0xe00002c7` | 4 | 0 | Completed `ffff4fe5` (-45083) |

The transport-error case retries through one cached connection; the open-failure case repeats matching/open acquisition. Additional original caller returns include `0x10002c254`, `0x10002c368` and `0x10002c464`. Successful transport with unchanged bytes is an identity-response control, not a valid driver response or successful protected operation. Both completed error paths reach original XPC data emission `0x1000aa9fc` and reply request `0x1000aaa70`.

## Incoming and outgoing boundaries [D1-D3,D9,D10]

Incoming private requests use the existing `com.apple.adid` callback and audit/data adapter; no new listener or incoming Mach port is inferred. Outgoing driver acquisition and method emission sites are tabulated above. Outgoing reply-data/reply-request API sites remain `0x1000aa9fc`/`0x1000aaa70`. The distinction between callback/XPC APIs and underlying libxpc Mach messages is preserved. No raw incoming or outgoing native Mach destination is established by this increment.

The primary FairPlayIOKit method-26 descriptor route and this Avp method-100 direct-buffer route remain distinct architectural interfaces. The earlier bounded search of 362 kernel-collection filesets did not establish an Avp implementation; it is not proof that Avp is absent from all runtime environments. A native Avp-to-primary-kext or Avp-to-daemon RPC contract remains unknown.

## Reproduction, coverage and quality gates

Run from the extracted directory using the local interpreter:

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_command_dispatch.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_command_dispatch.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_command_dispatch_delivery.py
```

The producer retains 79 complete callback experiments: fourteen selected commands, thirty unknown neighbors/extremes, eleven constructor/blob/truncation/EUID cases, six unlink cases, six allocation-scalar cases, three first-word controls, four VMM controls, one opaque main-port prefix and four IOKit modes. Their retained source paths contain 2,756,710 original instruction visits, 49,284 distinct original instructions and 21 complete compiler ranges. All 51,507 assertions pass. There are 69 completed callbacks, ten captured request-driven constructor snapshots, six method-100 calls, four unexecuted BRK boundaries and three mmap boundaries (including the selected-command baseline). Twelve fresh replay cases additionally reproduce complete ordered instruction hashes, event streams, stop reasons and final watched bytes over 992,345 replay hooks. Replay uses the same declared private API/PAC models; the concrete tree interpreter, byte/range checks, record decoding and SMT obligations provide separate checks of their stated local claims.

Three new full-domain SMT obligations cover selection, minimum length and allocation arithmetic; the earlier header proof is freshly solved again. Source recovery costs O(B+F+T+R) time/space for bytes, fixups, tree nodes and retained path predicates. Callback production costs O(C*(B+F+K)) time/space with C cases and bounded hooks K (800,000 per case). Verification costs O(B+F+C*K+T) under these explicit caps, excluding solver internals; each SMT query has a 30 s timeout. Byte counts and arithmetic widths are explicit. These bounds describe the local workflow, not target-runtime complexity.

| Gate | Delivery scope |
| --- | --- |
| QG1 | Descriptive source/interface analysis; no normative claim required |
| QG2 | D1-D10 list assumptions, dependent results and falsification probes |
| QG3 | Complete local command-selection domain and retained request interfaces; broad native goal remains incomplete |
| QG4 | Full-width arithmetic proofs, bytes, seconds, fixed record extents and bounded algorithms |
| QG5 | Shared error-entry reuse, selection/body admission, constructor epoch, BRK/mmap stops, identity/transport/open results and native gaps separated |
| QG6 | Fresh original bytes/fixups, source identities, independent tree interpretation, local proofs, twelve replays and preserved inputs |
| QG7 | Impact-labeled continuation below; no open continuation is represented as completed |

## Bounded continuation

| Impact | Further evidence / opportunity | Exact closure criterion |
| --- | --- | --- |
| High | Valid inner blob for command `0x716bd86c` | Recover first-word transform and subsequent grammar; reach normal publication and prove record lifetime without collection injection |
| High | Complete fourteen command-body contracts | Recover each parser's field widths, sizes, state prerequisites, authorization, outputs and producer callers; retain selection/body distinction |
| High | Source-built 144-byte Avp request/response | Trace all byte producers and response readers; establish accepted output grammar and protected-operation semantics |
| High | Actual Avp implementation and primary FairPlayIOKit coupling | Identify matching executable/driver and type-0 method table; correlate genuine endpoint/selector/record and deeper daemon/kernel transfers |
| High | Native credential, library, Mach and endpoint pairing | Establish effective peer/task entitlements, real libxpc/IOKit send sites, incoming/outgoing rights and runtime object identities |
| Medium | Retry/cache/resource ownership | Complete open/error/reset/close and iterator/service lifetime paths, concurrent cache access and all response-size/count checks |
| Medium | Scalar allocation and post-call BRK interpretation | Recover actual command producer and all control successors, allocator invariants and native admission before interpreting consequence |
| Medium | Unlink payload/result mismatch and rejected-constructor cleanup | Trace callers' reliance on payload 0, errno/result use, all file consumers and lifecycle; establish native effect separately |
| Medium | Actual CoreADI client exports and persistence feedback | Connect original library command producers to each daemon schema and source-created serialized records |
| Low | Semantic naming of remaining parser leaves | Assign only roles supported by complete field/dataflow and external touch-point evidence |
