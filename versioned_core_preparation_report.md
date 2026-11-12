# Selector-21 preparation, block consumption and state frontiers

The admitted selector-21 path now has a source-bound continuation. Mode 2 runs the complete helper `0xfffffe000a6172b8`, performs three in-place write stages over the daemon-derived 16 B input-B, stores encoded status `0x31ae0066`, and returns to the caller. The caller then reaches an undefined frame word; execution stops before reading it. Mode 5 enters helper `0xfffffe000a5b4314` and stops before a 47 B `_IOMallocData` request. Neither path establishes a complete outer operation, native admission or daemon/kext pairing. [VP1-VP8]

```text
declared daemon API words and spans
  -> fresh original _UeFdbi / initial gate
  -> build internal 16 B at W+0x50
       +-> mode 2: fixed 16 B -> block helper -> encoded status
       |                                      -> STOP before SP+0x130 read
       +-> mode 5: record -> state helper -> compare leaf
                                              -> STOP before 47 B allocation
```

Subsequent scope extension: the [complete dispatcher-frame analysis](versioned_dispatcher_frame_report.md) finds three direct stores to SP+`0x130` beyond this report's bounded census. None occurs on its retained mode-2 prefixes. An independent symbolic slice preserves the unresolved word and identifies the next pending 32 B stream allocation; it does not continue or initialize these guest fixtures.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| VP-A1 | Exact original KC, normalized kext and daemon receipt identify these builds. All joins depend on it. | Hash-pinned parents and original/normalized byte equality; different builds invalidate this address correspondence. |
| VP-A2 | Successful distinct workspace/auxiliary allocations, ordinary preserved-register calls and valid PAC. Guest continuation depends on these inherited premises. | Two register-only heap models, caller-register clobbers, two placements and backing patterns; native authentication and heap success remain unknown. |
| VP-A3 | Copying prior daemon fixture fields into private kernel argument/spans describes a conditional ABI comparison. Cross-level payload interpretation depends on it. | Four pinned daemon cases supply the exact mode, marker, generated scalar and block; bit-change controls are separately labeled. No native IOKit serialization is claimed. |
| VP-A4 | Fixed cells and owner ranges do not alias unexpectedly or wrap. Symbolic record composition and byte epochs depend on it. | Independently reconstruct reads/writes and final known-byte masks; input/output guest spans are distinct. Native input/output kernel-buffer aliasing remains unknown. |
| VP-A5 | Global words use the stated file/noise fixtures and captured source updates. Mode-5 allocation size depends on the retained global state. | Original and declared-noise fixtures are separate; the additional virtual-tail cell uses eight original-KC zero bytes. A native nonzero value or earlier initializer could change this route. |
| VP-A6 | The mode-2 caller word remains unspecified at the observed frontier. No later instruction is attributed to the retained cases. | Stop before the load, retain zero known bytes, and scan the bounded function body for direct SP/FP writers and address producers. Computed aliases and other epochs remain unresolved. |
| VP-A7 | Finite block outputs describe only these inputs and source paths. Algorithm identity and general equivalence remain unknown. | Block-bit, generated-bit and optional-bit controls; no native or external cryptographic reference vector is asserted. |

## Source and record flow

The [core-entry report](versioned_core_entry_report.md) establishes workspace W, 16,384 B; auxiliary A, 4,096 B; wrapper SP F; argument record R=F+`0x48`; and operation `0x3da4b356`. This increment re-executes each prefix rather than restoring it. Four preceding daemon API fixtures supply input count N=16 and input-B bytes. Mode 2's unspecified optional-span origins are retained; no optional bytes are seeded for that mode. [VP1-VP3]

A reverse 16-byte image-table loop writes `6c437fc992dd4d2668f065033304d2c3` at W+`0x50` in every retained case. Its source reads are image bytes, not input-B. The loop starts at index 15, decrements to zero, and selects original transfer-table indices `0x570` / `0x58b` for repetition / exit, using IA modifier `0x55ab`. Both source pointer slots and the control equation are checked. This is an internal value for the selected operation, without an assigned key/IV meaning. [VP2-VP5]

| Mode | Preparation before the next stage | Boundary / continuation |
| --- | --- | --- |
| 2 | Writes `19296018ebe32481f2d5fe6dec30ed8e` at W+`0xc0`, then copies it to W+`0x40`. | Call `0xfffffe000a5a6294` -> helper `0xfffffe000a6172b8`, modifier `0x6a0f`. |
| 5 | Packs a record at W+`0x60` and calls `0xfffffe000a5b4314`. | Call PC `0xfffffe000a5a5e18`, modifier `0x085d`; normalized local operation `0x938`, u16 control `0x6019`. |

The mode-2 helper record C=W+`0x60` is distinct from R. Let B=W+`0x40`; its checked fields are: [VP4-VP5]

| C offset / width | Source role |
| --- | --- |
| `+0x00` / u64 | input-B pointer D |
| `+0x08` / u64 | B |
| `+0x10` / u32 | encoded local operation; normalized `0x0d17` |
| `+0x18` / u64 | A |
| `+0x20` / u64 | W+`0x50`, internal 16 B |
| `+0x28` / u32 | helper result, written before the observed return |
| `+0x30` / u64 | D again, establishing this helper's in-place buffer |
| `+0x38` / u64 | A+4,096, exclusive end |
| `+0x40` / u32 | encoded count |
| `+0x48` / u64 | W+`0x100`, another workspace view |
| `+0x50` / u64 | W+16,384, exclusive end |

For p=low32(C), the caller and helper source keys agree over all u32 addresses:

```text
K = (p XOR 0x280834b2) * 0xf87ec353                    mod 2^32
C[0x10] - K = 0x0d17                                mod 2^32
C[0x40] XOR K = N + 0x5bed6383                       mod 2^32
(N + 0x5bed6383) + 0xa4129c7d = N                    mod 2^32
```

The last equality is essential: the first XOR-decoded word is not itself the byte count. Source lifts separately prove caller/decoder key agreement, record fields and offset normalization. The optional-helper caller/decoder keys are also equal; its normalized `0x938` / `0x6019` controls remain distinct from the block helper's `0x0d17`. [VP4-VP5]

## Complete mode-2 helper and finite controls

The helper uses a 1,040 B frame. In all 12 retained mode-2 cases it reads/writes D in three stages, with 48 byte reads and 48 byte writes total per case. The first and last stages visit offsets 15 down to 0. The intervening core reads and writes every offset once in a different order. Its complete algorithm is unknown; the source establishes an in-place, table-based block transformation. [VP3-VP6]

| Stage | Representative original read/write locations | Checked observation |
| --- | --- | --- |
| First pass | read `0xfffffe000a617664`; write `0xfffffe000a6176a8` | 16 reverse byte updates; source projection includes image bytes and low8(-3*i). |
| Core | 16 distinct reads in `0xfffffe000a61a4f8..0xfffffe000a61a858`; 16 distinct stores in `0xfffffe000a61bc50..0xfffffe000a61c2cc` | Exactly one read/write per byte offset; no algorithm name assigned. |
| Final pass | read `0xfffffe000a617c3c`; write `0xfffffe000a617ce0` | 16 reverse updates; source projection includes three image bytes, low8(-77*(i&15)) and `0xd0`. |

The helper stores its result at C+`0x28` at `0xfffffe000a617d24`, then restores SP and X19-X29 before returning to `0xfffffe000a5a6298`. Its local result equation is `guard==0x67de9af5 ? 0x31ae0066 : 0xce515bbe`; all retained completed cases store the first word. This does not establish the final `_UeFdbi` return, UserClient structure status or updated output count. [VP4-VP6]

| Declared mode-2 input | Final D bytes in retained cases |
| --- | --- |
| Original daemon block `5817645ddc55fe54031c44a84e9b4d0f` | `cd36d495cdcdcdc9cdcdcdcc4dcdcdcd` |
| Flip only bit 0 of D[0] | `363c1c73c57060cd8bb9744813ec49da` |
| Flip only bit 0 of the generated scalar | Same D bytes as the baseline |

These outputs agree across the two daemon prefix fixtures and two kernel guest placements/global fixtures. They are finite observations. Mode 5 reaches its allocation boundary before reading input-B or the optional span; its block/optional/generated controls therefore do not demonstrate later input independence. [VP3,VP6]

## Environmental and control-flow frontiers

| Path | Exact frontier | Evidence and limit |
| --- | --- | --- |
| Mode 2 | `0xfffffe000a5a6e5c`: `LDR W24,[SP,#0x130]` | All four bytes remain undefined after the complete helper return. Stop before the load; no substituted stack value or subsequent transfer is credited. |
| Mode 5 | `0xfffffe000a5b4e00` -> `0xfffffe000c4ba60c`, modifier `0xca0c` | Matching KC symbols `_IOMallocData` / `_IOMallocData_external`; X0=47 B in all 16 retained mode-5 prefixes. The allocator is not modeled or executed. |

The scoped mode-2 frame census covers 1,922 original instruction words from `0xfffffe000a5a5494` to exclusive `0xfffffe000a5a729c`. With FP=body SP+`0x250`, it finds no immediate SP/FP store overlapping `[0x130,0x134)` and no direct ADD/SUB SP/FP producer of that pointer. This does not exclude computed aliases, other call epochs or missing admission conditions, and does not prove a native uninitialized read. [VP7]

The mode-5 helper reads global `0xfffffe000ccceaf4`. The normalized image's `__DATA` begins at `0xfffffe000ccc2a20`, has file size `0x8000` B and virtual size `0xc118` B; this cell lies in the virtual tail, outside its file-backed bytes. The original KC supplies eight zero bytes used explicitly by the private fixture. The earlier normalized-file-only guest mapping caused an unmapped read; adding these original bytes resolves that modeling gap. The native runtime value, prior initializer and effects of another value remain unknown. The 47 B request is conditional on this retained state. [VP1,VP6-VP7]

The optional helper also calls the complete 41-instruction unsigned comparison leaf `0xfffffe000a628060` at `0xfffffe000a5b4d20`, modifier `0xfae5`, before the allocation frontier. It is executed from original bytes without a result model. Its complete application-level record semantics remain outside this increment. [VP2,VP6]

No output-A/output-B user span, Mach message, port transfer or new emission site is produced in these cases. Input-B mutation does not establish native input/output buffer aliasing. The previously recovered daemon API boundary remains `0x100478a04`; runtime port ownership and routing remain unknown.

## Evidence, reproduction and quality gates

| ID | Primary provenance |
| --- | --- |
| VP1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`; preceding daemon source `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. |
| VP2 | [Extractor/replay](triage_evidence/recover_versioned_core_preparation.py): four disjoint new source regions, 8,737 instructions / 34,948 B, exact KC/normalized equality. Captured ranges exceed the executed paths; no execution credit is assigned to unvisited instructions. |
| VP3 | [Compressed checks](triage_evidence/versioned_core_preparation_checks.json.zst): 28 fresh cases, 13,608 prefix visits plus 117,964 continuation visits =131,572 total, 123,520 read bytes and 49,056 write bytes reconstructed independently. |
| VP4 | [Source audit](triage_evidence/audit_versioned_core_preparation.py): 12 fresh UNSAT obligations / 238 lifted instructions, with fixed-cell/epoch and shared-key composition premises. |
| VP5 | [Compressed audit](triage_evidence/versioned_core_preparation_audit.json.zst): 99 original chained-pointer records, two exhaustive bank rules / 512 byte inputs, 1,344 authenticated transfers checked against original target/diversity. Native PAC is unproved. |
| VP6 | Independent byte epochs, 18,480 final snapshot bytes, strict known-byte checks and 12 complete helper SP/preserved-register returns. Only the inherited two register-only allocator models execute; zero allocator-model memory writes. |
| VP7 | Original full-body bounded frame census, normalized Mach-O virtual/file extents and original-KC virtual-tail bytes. No blanket absence-of-writers or runtime initialization claim. |
| VP8 | [Publication verifier](triage_evidence/verify_versioned_core_preparation_publication.py): fresh source/replay/audit equality, logical archive hashes, exact owned delta, original-input preservation and decoded path/hex hygiene. No new IDA access or database mutation was needed. |

The 28 cases comprise baseline, block-bit and generated-bit profiles for four daemon cases in two guest placements, plus optional-bit profiles for the two mode-5 cases in both placements. Prefix and continuation counts are separate; all prefixes execute freshly. Reproduction uses the extractor, auditor and publication verifier in that order with their pinned Python dependencies. Extraction/replay costs O(C*(B+V+E)+256R) time/space; audit costs O(receipt bytes+V+E+256R) plus solver cost capped at 30 s/query. Each continuation is bounded at 20,000 instructions. [VP2-VP8]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Resolve mode-2 SP+`0x130` provenance or valid-path exclusion. | Computed aliases, incoming call/frame state and source-defined producing epoch; do not fill the word. |
| High | Follow mode-5 allocation, state initialization and helper return. | Original virtual-tail/global writers, allocator/lifetime contract and subsequent optional-span consumption. |
| High | Establish coherent native daemon/UserClient admission and ownership. | Matching build/task/connection/right epoch and an actual transaction. |
| Medium | Recover compact semantics of the complete mode-2 block helper. | Independent algorithm/reference evidence and broader valid-input contracts beyond finite outputs. |

- **QG1**: Pass. Factual source/interface analysis requires no normative content.
- **QG2**: Pass. VP-A1..VP-A7 register dependencies and falsification probes.
- **QG3**: Pass for this increment. Payload preparation/consumption, record/key/count, helper return, virtual-tail state and two frontiers are covered. The full goal remains active.
- **QG4**: Pass. Byte extents, modular widths, signed/unsigned distinctions, visit counts and complexity are explicit.
- **QG5**: Pass. Initial admission, local helper completion, outer completion, count/status, virtual versus file backing and native evidence are distinct.
- **QG6**: Pass. Exact primary bytes, source lifts, finite controls, models, unspecified origins and prior pinned receipts are separated.
- **QG7**: Pass. Impact-ranked data/control/environment and native-ownership continuations are bounded above.
