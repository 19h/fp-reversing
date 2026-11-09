# CoreADI adid: caller-built records, two-stage IOKit initialization and Avp selector 100

The subsequent [protected-dispatch report](adid_driver_dispatch_report.md) corroborates three upstream source constructors/call sites for0x1000590ac and the original request-frame output-pointer producers. Immediate consumers use equality with0x1f at two sites and inequality at the third. The local continuations explicitly override entry/state and skip intervening gates; complete public-request reachability remains unproved. It also adds conditional byte-table bindings beyond the retained private candidate observations below.

Two original caller routines now construct the recovered helper inputs: `0x1000590ac` calls the initialization helper at `0x1000208fc`, and `0x100058654` calls the separate Avp connection helper at `0x10002af70` before emitting selector 100. Their complete upstream paths from XPC or another native request remain unknown.

Extending the earlier stopped transport prefix changes an architectural interpretation: a nonzero VMM query can cause **Avp selector 26 followed by primary FairPlayIOKit selector 26**. They are separate acquisition/cache stages with different framing, rather than an exclusive choice for the whole helper. Four explicit transport controls preserve the Avp-stage outcome in the helper result even when the later primary-stage outcome differs. This is a finite source/private observation; native error propagation and successful operations remain unknown.

## Identity, assumptions and provenance

Addresses are preferred virtual addresses in the selected `/System/Library/PrivateFrameworks/CoreADI.framework/adid` arm64e slice: base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The [preceding IOKit report](adid_iokit_report.md) pins the full source identity and earlier API boundaries; its 31 cases stop at the first transport boundary for the nonzero-query alternatives. The [CoreFP client](corefp_client_paths_report.md), [ADID receiver](adid_receiver_report.md), [context](adid_context_report.md) and [trace](zut_trace_report.md) reports establish different boundaries. Addresses in those images must not be interchanged.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| J1: pinned original provider/fixups and SDK describe the inspected references | Addresses, call targets, record widths and ABI sites | Fresh bytes, complete compiler ranges, dyld_info and arm64e SDK compilation agree. Native loaded image/framework pairing remains unknown. |
| J2: retained private state and declared PAC/vector/API models permit the indicated continuations | Finite source executions, cache, output and copy behavior | Thirteen fresh executions reproduce ordered original source, events, buffers and copy writes, including retained-state sequences. They use the same declared models, not an independent emulator or native APIs. |
| J3: the source-derived analyst inputs at the two callers select the stated local paths | Actual caller construction of helper records | Original caller code builds the callee records and enters the original helper. Encoded NULL, literal zero, invalid basis and null/zero span fields are separated. Native callers of these two callers and their record producers remain unknown. |
| J4: explicit query and per-provider IOKit objects describe the stated fixtures | Two-stage acquisition, connection flow and status observations | Four independent error/identity-response combinations use Avp name `0x580a` and primary name `0x5804`. These are private names; native object identities, rights and lifetimes remain unknown. |
| J5: transport error and identity-response controls bracket local source behavior | Completed selector-26/100 continuations and returned-size behavior | Identity-response returns zero without changing bytes; error returns `0xe00002c7`. Selector-100 returned sizes stay within input capacity. No driver transformation, native acceptance or successful protected operation is implied. |
| J6: output spans and post-context patches describe only the explicit controlled cases | Overlap handling, count publication and outer caller gates | Saved-byte copy oracle checks distinct/equal/overlapping buffers and sizes 0/1/16/95/96/256. Three post-context patches are explicitly analyst mutations; real writers and valid metadata remain unknown. |
| J7: local bit-vector reductions are used with their exact prefixes | Record/status/count codecs and helper-key correspondence | Six full-domain local proofs pass. An attempted unconditional Avp constructor-key equality was falsified for odd addresses; the exact masked result and the even-address corollary are retained. Original stack records satisfy that alignment. |
| J8: a whole-text syntactic candidate is not a resolved caller | Fifteen modifier candidates and seven observed sites | Independent raw-word scanning agrees with the candidate list; 12 pointer cells demonstrate modifier collisions. Eight sites remain unresolved in retained cases. Computed modifiers, other registers and other indirect forms are outside this candidate pattern. |
| J9: observed completed local paths delimit resource and concurrency claims | Warm behavior, lock API requests and cleanup observations | Retained-state runs distinguish helper reuse from outer result reuse and new method-100 requests. Native locks, once scheduling, object retention, close/exception/reentry and concurrency remain unknown. |

Artifacts: [source profiles](triage_evidence/adid_iokit_caller_profiles.json), [static contracts and candidate catalog](triage_evidence/adid_iokit_caller_contracts.json), [producer](triage_evidence/probe_adid_iokit_callers.py), [recoverer](triage_evidence/recover_adid_iokit_callers.py), [fresh checks](triage_evidence/adid_iokit_caller_checks.json), [validator](triage_evidence/validate_adid_iokit_callers_delivery.py), [quality gates](triage_evidence/adid_iokit_caller_quality_gates.json), [analyst ABI declarations](triage_evidence/adid_iokit_caller_layouts.c) and [compiled assembly](triage_evidence/adid_iokit_caller_layouts.s). Earlier producers, proofs and private profiles remain unchanged. No original IDB was modified.

## Architectural correction and two-stage flow [J1-J5]

```text
upstream caller / record producer: unknown
                     |
caller 0x1000590ac constructs stack record, basis 0x25
                     |
call 0x100059544 -> helper 0x1000208fc
                     |
     original once/query callback, cached VMM Boolean
                     |
              nonzero? -------- no -------+
                | yes                     |
      AvpFairPlayDriver, type 0            |
      connection -> 0x1002dcee4            |
      selector 26, direct 96 bytes        |
                |                         |
                +-------------------------+
                     |
      com_apple_driver_FairPlayIOKit, type 0
      connection -> 0x1002dcc84
      selector 26, descriptor 16 bytes -> record 96 bytes
                     |
       helper result -> caller's separate context gate
       context 0x1002dcee0, byte and u32 at +32

separate caller 0x100058654 constructs stack record, basis 0x10fd
                     |
call 0x100058958 -> helper 0x10002af70
      Avp connection cache 0x1002dd290 -> caller stack output
                     |
call 0x100058a1c -> selector 100, shared input/output buffer
                     |
returned size > 0? -> overlap-aware byte copy -> encoded count store
```

The Avp direct call is at `0x10004967c`; the primary descriptor call is at `0x10001f908`. Both use selector 26, but their structure extents are 96 and 16 bytes respectively. The matching/open stages are separately observed in order: `AvpFairPlayDriver` to cache `0x1002dcee4`, then `com_apple_driver_FairPlayIOKit` to cache `0x1002dcc84`. Both modeled enumerations use fresh iterator generations. Separate modeled connection names prevent their reuse from collapsing these two stages into one apparent object.

| Explicit Avp stage | Explicit later primary stage | Helper raw status | Outer caller raw status / byte |
| --- | --- | --- | --- |
| Identity-response | Identity-response | `0x0059248f` | `0x0059248f` / `0x1f` |
| Identity-response | Error `0xe00002c7` | `0x0059248f` | `0x0059248f` / `0x1f` |
| Error `0xe00002c7` | Identity-response | `0x00587c93` | `0x00587c93` / `0x1f` |
| Error `0xe00002c7` | Error `0xe00002c7` | `0x00587c93` | `0x00587c93` / `0x1f` |

Both transport stages are reached in all four completed cases. Their source-hook counts are 165147, 127370, 122019 and 84242 respectively. The result matrix establishes this local result selection under the modeled unchanged-byte responses. It does not prove that real replies have those semantics or that the later primary-stage error is always irrelevant. Each stage has observed service and iterator release requests at `0x1000217a0` and `0x10002184c`; native reference accounting remains unknown.

## Caller-built record and pointer correspondence [J1-J3,J7]

All native record fields below are little-endian. Extents are known accessed prefixes, not complete native type declarations. The analyst fixture reserves more bytes than those prefixes.

For caller `0x1000590ac..0x100059860`, let P be its input-record address:

```text
K0(P) = ((low32(P) XOR 0x834674ac) * 0x0a42990d) mod 2^32
```

| Input offset, bytes | Source-derived field |
| --- | --- |
| 0, width 8 | Output-byte pointer plus `0x7e1f59740c8f6451`, modulo 2^64 |
| 8, width 4 | `K0(P) XOR 0x237f` in the selected local path |
| 12, width 4 | Local encoded status output at `0x100059820` |

Encoded NULL for offset 0 is the additive constant. A literal zero is a different pointer value after decoding. The encoded-NULL case returns raw status `0x00587c8c` without entering the helper. Literal zero and an invalid basis stop at private memory boundaries; neither is a demonstrated native fault.

The caller builds its helper record at its own `SP+0x20`. The original store at `0x1000594ec` writes the first word; call `0x100059544` loads the original authenticated pointer cell `0x1002d8640`, enters helper `0x1000208fc` and returns to `0x100059548`. The observed record address is `0x7a037f80`. Its first word equals the helper's canonical address key XOR `0x25`. The helper executes original instructions; it is not replaced with an analyst result.

For caller `0x100058654..0x100058d48`:

```text
K100(P) = ((low32(P) XOR 0x4e89bd66) * 0x0b08355f) mod 2^32
```

| Input offset, bytes | Source-derived field |
| --- | --- |
| 0, width 8 | Encoded pointer to four-byte returned-count output: actual pointer plus `0x68a91db5735d89de`, modulo 2^64 |
| 8, width 4 | `(input_count + 0x4349792f - K100(P)) mod 2^32` |
| 12, width 4 | Unknown; no field role assigned |
| 16, width 8 | Destination for the returned-byte copy |
| 24, width 8 | Buffer passed as both method-100 input and output |
| 32, width 4 | Local encoded status output at `0x100058d08` |
| 36, width 4 | `(0x5f8 - K100(P)) mod 2^32` in the selected path |

The source guards encoded NULL count pointer, null destination, null buffer and decoded zero input size. Each controlled case returns raw status `0x00588068` without entering the connection helper. Main-port, empty-iterator and open failure cases enter that helper but avoid selector 100 and retain the same caller status. These cases do not establish the complete admitted record language.

The Avp helper record is built at caller `SP+0x28`; its encoded output pointer targets caller `SP+0x14`. The store at `0x1000588e8` supplies its first word. Call `0x100058958` loads original cell `0x1002d8998`, enters `0x10002af70` and returns to `0x10005895c`; the recovered helper status is then read at `0x10005895c`. The observed helper record address is `0x7a037f88`. Its first u32 equals the helper key plus `0x10fd` modulo 2^32. The output at `SP+0x14` receives the private connection name and supplies method 100's X0.

### Alignment counterexample and corrected proof

The Avp caller's record-constructor expression has this exact general reduction:

```text
constructor_key(A) = (((low32(A) XOR 0x834674ac) AND 0xfffffffe)
                      * 0x0a42990d) mod 2^32
```

An unconditional equality to the unmasked helper key was falsified by SMT at `low32(A)=0x84945e0f`. The mask can be omitted when `(A AND 1)=0`. The original stack record `SP+0x28` has an even address under the modeled 16-byte stack alignment; every retained helper-entry observation satisfies it. The new proof verifies both the exact general reduction and the aligned corollary. It does not silently extend an aligned pointer observation to arbitrary u32 inputs.

## New selector-100 API and data contract [J1-J7]

The original import pointer cell is `0x1002d8400`, with import ordinal 99 for `IOKit/_IOConnectCallStructMethod`. Source load `0x100058a00` selects it; the call is `0x100058a1c`. This is a provider API emission site, not a raw Mach send instruction. The existing [IOKit framework/trap report](user_trap_interface_report.md) supplies a separate reference external-method message boundary; actual loaded-framework and native port pairing remain unknown.

| Argument / output | Source/private contract |
| --- | --- |
| X0 | Connection returned by `0x10002af70`, from distinct cache `0x1002dd290`; fixture `0x5804` |
| X1 | Selector 100 (`0x64`) |
| X2 | Caller record's in/out buffer pointer at +24 |
| X3 | Decoded input byte count; u32 construction zero-extended to 64 bits |
| X4 | Same pointer as X2 |
| X5 | Pointer to caller stack's eight-byte `size_t` cell at `SP+0x18` |
| Initial size cell | Same decoded count as X3 |
| Model response | Explicit error or identity-response; buffer bytes unchanged, returned size no greater than supplied capacity |

The method-100 input is arbitrary analyst pattern data in these cases. Its native schema, operation meaning and response transformation are unknown. In particular, selector 100 belongs to the Avp path and is not assigned to a selector in the supplied FairPlayIOKit UserClient.

For a raw API result R, the original u32 arithmetic at `0x100058a20..0x100058a48` reduces to:

```text
local_status = R + 0x0059248f mod 2^32
```

Thus the explicit error result `0xe00002c7` produces raw local status `0xe0592756`; zero produces `0x0059248f`. The full-domain local proof does not establish a public error specification.

When the API result is zero and returned size N is positive, original code copies N bytes from the in/out buffer to the separate destination. For source address greater than destination it stores forward at `0x100058ba0`; otherwise it stores backward at `0x100058c88`. Saved initial bytes independently reproduce the result for distinct buffers, equal buffers and one-byte overlaps in both directions. The finite checked extents include 1, 16, 95, 96 and 256 bytes; whole-function equivalence for every possible pointer/count remains unproved.

After a positive-size copy, the original store at `0x100058cf8` writes four bytes through the decoded count pointer. Its u32 arithmetic reduces to:

```text
published_count = low32(returned_size) + 0x0046d726 mod 2^32
```

The API output-size cell is eight bytes; this published count is an encoded four-byte field. The count transform is also present in earlier local header processing, but reuse of arithmetic does not establish semantic identity of the fields.

| Explicit case | Source copy | Encoded count pointer | Raw caller status |
| --- | --- | --- | --- |
| Error result | No copy | Untouched | `0xe0592756` |
| Zero result, returned size 0 | No copy | Untouched | `0x0059248f` |
| Zero result, returned size N > 0 | Exactly N bytes in observed direction | `N+0x46d726 mod 2^32` | `0x0059248f` |

The zero-size success case does not publish encoded zero to the caller's count pointer. That distinction is established by complete private buffer comparisons. A native caller's initialization and response to this behavior remain unknown. Returned sizes above capacity are excluded by an explicit private model guard; the original source's behavior for a nonconforming provider, all native buffer extents and ownership remain open.

## Outer context gate and retained state [J1-J6,J9]

Caller `0x1000590ac` initializes the decoded output byte to `0x1f` at `0x100059304`. A zero-valued method-26 transport result is insufficient to establish this caller's final status or output byte. With the cold zero-query fixture, the original helper returns raw status `0x0059248f`, but the outer caller reads separate context byte `0x1002dcee0` at `0x1000595fc`, compares it to `0x41` at `0x100059600`, and returns raw `0x00587c85` when it remains `0x40`.

When that byte equals `0x41`, the original source reads the context u32 at +32 (`0x1002dcf00`) at `0x100059634` and compares it at `0x100059644` to `0x527e14b6` in the selected local path. The resulting flag participates in the later branch to output store `0x100059808`.

| Explicit local post-context control after helper completion | Raw caller status | Output byte |
| --- | --- | --- |
| Original cold context byte `0x40` | `0x00587c85` | `0x1f` |
| Analyst byte `0x41`, tag 0 | `0x0059248f` | `0x1f` |
| Analyst byte `0x40`, matching tag | `0x00587c85` | `0x1f` |
| Analyst byte `0x41`, matching tag | `0x0059248f` | `0x20` |

The last three rows are explicit private patches, with their original and modified bytes retained. They isolate local gates; no real producer of that valid context is established. Values `0x1f` and `0x20` are observed encoded outputs, not assigned public Boolean meanings. In the completed two-stage identity-response case, the source itself sets the Avp context byte to `0x41`, while its retained tag differs from the expected tag; that case produces raw status `0x0059248f` and output `0x1f` without a context patch.

The primary error/identity-response/warm sequence retains helper and caller memory. Hook counts are 44808, 81370 and 2124. The final call still constructs and enters the helper but makes no modeled IOKit call; its outer result remains `0x00587c85`. The separate Avp caller's warm sequence has counts 3091 and 2607: the second helper uses its connection cache, while the caller still emits selector 100 and copies 96 returned bytes. Cache reuse therefore does not mean that the entire outer operation was skipped.

Lock API requests and local wrapper calls remain in the retained evidence. Their success statuses are private fixtures. They do not prove native synchronization, initialization races or full connection retirement.

## Candidate coverage and unresolved control flow [J1,J2,J8]

The full `__text` byte range contains 2527592 bytes: 631898 four-byte units, of which two are undecoded by the pinned Capstone decoder. The scanner retains those units explicitly and continues after them. An earlier disassembly-only scan stopped short at an undecoded unit; it was replaced before publication with complete skip-data coverage and an independent raw-word candidate scan. No direct B/BL to either helper occurs in this text range.

The exact pattern `MOV X17, immediate` immediately followed by `BLRAA X8,X17`, with modifier `0x2ea7` or `0xe41b`, yields 15 candidates. The source pointer catalog has four targets for each of these modifiers; `0xe258` likewise has four targets, including IOConnectCallStructMethod and unrelated functions. A shared modifier does not establish callee identity.

| Call site | Modifier | Corroborated retained private target |
| --- | --- | --- |
| `0x100016cf4` | `0x2ea7` | `_ftruncate` |
| `0x10001a1f4` | `0xe41b` | `_signal` |
| `0x10002a1bc` | `0xe41b` | `_xpc_get_type` |
| `0x10002a37c` | `0xe41b` | `_xpc_get_type` |
| `0x100048c48` | `0xe41b` | Unknown |
| `0x100058958` | `0xe41b` | Avp connection helper `0x10002af70` |
| `0x100059544` | `0x2ea7` | Initialization helper `0x1000208fc` |
| `0x100092bf4` | `0x2ea7` | Unknown |
| `0x10010bd14` | `0x2ea7` | Unknown |
| `0x100112440` | `0x2ea7` | Unknown |
| `0x1001511cc` | `0x2ea7` | Unknown |
| `0x10016cb30` | `0x2ea7` | `_audit_token_to_euid` |
| `0x1001d45a0` | `0x2ea7` | Unknown |
| `0x1001fb804` | `0x2ea7` | Unknown |
| `0x10025d12c` | `0x2ea7` | Unknown |

The seven observed sites are supported by retained source events and matching original fixups; the two helper sites additionally have fresh selected-pointer read events and original callee-entry observations. This syntactic list is not a complete set of possible callers. Computed modifiers/targets, other register combinations, alternate pointer producers and feasible upstream paths require further recovery.

## Verification and bounded continuation

The [fresh validator](triage_evidence/validate_adid_iokit_callers_delivery.py) passes 11155 assertions across 38 private cases, 10612 unique original instruction records in 22 compiler ranges and 1079290 retained source visits. It checks 31 original caller-built helper-record observations, 15 selector-100 boundaries and 961 source copy-byte stores; solves six full-domain local proofs; reads back both complete caller ranges and the whole text scan; recompiles the analyst ABI declarations; and reproduces 13 complete source/event/state runs totaling 598256 hook steps. These counts describe the current increment. They do not establish native behavior or the full objective.

The inspected byte-copy loops take O(N) time and O(1) auxiliary storage for the recovered local copy path. This is a local structural interpretation, not a complete timing bound for the obfuscated function. The validator takes O(B+F+R+V) time/space in loaded bytes B, fixups F, retained records R and source visits V, with explicit finite caps per execution. Original supplied inputs remain unchanged; no native target, loader, IOKit, Mach, target-file/environment or synchronization operation was executed.

| Impact | Remaining interface | Concrete next evidence |
| --- | --- | --- |
| High | Feasible request-to-caller paths | Recover all upstream producers/callers of `0x1000590ac` and `0x100058654`, their record bases and actual selector/data provenance; resolve remaining indirect candidates through original tables |
| High | Real Avp and primary response semantics | Locate the Avp implementation, recover selector-26/100 schemas and transformations, then connect responses to the primary descriptor path and selected protected kext operation |
| High | Native image/peer/port and deeper RPC pairing | Correlate actual service/UserClient/framework/credential identities and messages; prove which raw record operations reach `PRnut72j9`, host slot 17/34 and RPC502/700 |
| Medium | Context byte/tag and independent result axes | Recover every writer/consumer of `0x1002dcee0` and `0x1002dcf00`, including valid initialization data and the meanings of output bytes `0x1f`/`0x20` |
| Medium | Two-stage failure and lifetime semantics | Establish complete error selection, retry/close/exception behavior, per-stage connection ownership, all iterator/service references and concurrency |
| Medium | Returned-count and copy contracts | Recover native caller output initialization, count decoder/consumers, all allocated capacities and behavior on real provider size/error outcomes |
| Low | Remaining syntactic caller families | Expand target-register/computed-modifier coverage while keeping unbound candidates separate from confirmed source edges |

QG1-QG7 pass for this explicitly bounded increment: descriptive findings; J1-J9 assumptions/probes; concrete routine, port-name, ABI/control/data progress; reproducible widths/proofs/copy extents; corrected prefix interpretation and explicit alignment counterexample; original source/fixup/SDK provenance; and impact-labeled continuation. Successful protected algorithms, complete request paths, native contracts and full architectural coverage remain unknown. The full goal remains active and incomplete.
