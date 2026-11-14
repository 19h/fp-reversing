# fairplayd: private resize caller ABI and record-coordinate selection

The later resize target 40 is the sum of two local spans, **20+20**. The new span comes from a biased caller word at record offset `0x2c`; its decoded contribution is zero in the retained instances, and the source adds a 20 B prefix. The saved old span is the scalar decoded from buffer offset 57. The resulting allocation request is **77+40-20=97 B**. This establishes the target's producer and caller-field custody, beyond the earlier exact target store/read. [RC1-RC5; RC-A1-RC-A4]

The successful result of helper `0x10045f984` is used as an encoded record coordinate on this path. Its selection block substitutes U+0x18 when the supplied coordinate denotes offset zero; otherwise it uses the supplied coordinate. The actual explicit coordinate denotes offset 57 and overrides the default coordinate denoting offset 1. A global status/error classification for this helper, native record schema and native daemon-kext transaction identity remain unknown. [RC1-RC5; RC-A2-RC-A5]

| Evidence | Primary source and scope |
| --- | --- |
| RC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Exact selected source words are retained in RC4. |
| RC2 | [Record-span report](daemon_record_spans_report.md), [checks](triage_evidence/daemon_record_spans_checks.json.zst), decoded SHA-256 `c86a7ff3de166cae5034ee4543dc13cd27f6fc13076221ecb94788491f1ffb99`, and [audit](triage_evidence/daemon_record_spans_audit.json.zst), `2e5259ad78e740d82a91d1310d8a3c4991d0f843427bf2ac93e09144b77c1a89`: codecs, local spans and selected resize arithmetic. |
| RC3 | [Descriptor-growth report](daemon_descriptor_growth_report.md), [checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), decoded SHA-256 `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`, and [replay](triage_evidence/daemon_descriptor_growth_replay.json.zst), `bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67`: conditional journals, owner/API premises and exports. Full prior admission corpora are not rerun. |
| RC4 | [Extractor](triage_evidence/recover_daemon_resize_callers.py), [checks](triage_evidence/daemon_resize_callers_checks.json.zst): caller fields, calls, source slices, byte custody, register continuity and export checks. All parent/dependency hashes are pinned. |
| RC5 | [Independent auditor](triage_evidence/audit_daemon_resize_callers.py), [receipt](triage_evidence/daemon_resize_callers_audit.json.zst): original instruction replay, 16 nonvacuous UNSAT obligations and three SAT interpretation controls. |
| RC6 | [Publication verifier](triage_evidence/verify_daemon_resize_callers_publication.py): fresh receipts, canonical solver queries, source/manifest/input checks and decoded path hygiene. |

## Caller records and local interfaces

Define outer SP=`0x6800060100`, local SP=`0x680005fb50`, caller record A=outer-SP+0x10cb8=`0x6800070db8`, helper record V=`0x6800060008`, U=`0x6600060000`, and H=`0x6600080000`. These are conditional journal addresses. The caller's observed record span reaches A+0x3c; this is a source access footprint, not a proven native allocation size or conventional C structure. [RC3-RC4; RC-A1, RC-A3]

| Call instruction | Target | X0 | X1 | IA modifier | Local role |
| --- | --- | --- | --- | --- | --- |
| `0x100710588` | `0x100b211f4` | A | `0x680006bec0` | `0xd07f` | Outer private wrapper; feedback cell carried in X1 |
| `0x100b21438` | `0x100b003c8` | A | `0x6800060090` | `0xe672` | Inner private entry; X1 is a reserved local cell |
| `0x1009d0fc8` | `0x10045f984` | V | `0xffffffff91bcf251` | `0x0290` | Nested helper producing the selected coordinate |

RC4 retains all X0-X7 arguments, SP, source call sites and matching next target visits for both classes. X5 at the second call is `0xffffffff85bfe8be`, not U; the inner code subsequently loads U from A+0x10 at `0x1009e4020`. X5 at the third call is U and X6 is local-SP+0x320. Logical call agreement does not establish hardware pointer-authentication acceptance or a native ABI. [RC3-RC5; RC-A3]

| A offset / B | Width / B | Actual value | Last writer | Callee reader | Established local use |
| --- | --- | --- | --- | --- | --- |
| `0x00` | 4 | `0x40ab5164` | `0x1007104e8` | `0x100bab320` | Biased scalar; wider semantic role unknown |
| `0x04` | 4 | `0xc4f577e6` | `0x1007104e4` | `0x100b00578` | Phase/input scalar |
| `0x08` | 8 | `0x68000648b4` | `0x1007104d0` | `0x100babb08` | Saved at local SP+0x138; distinct from U |
| `0x10` | 8 | U | `0x1007104cc` | `0x1009e4020` | Container pointer loaded into X5 |
| `0x18` | 4 | `0x8b3dc651` | `0x100b20fd8` | No post-call read on this retained path | Read at `0x1008a2798` before the outer wrapper call |
| `0x1c` | 4 | `0x9ef4810c` | `0x100710508` | `0x100bab35c` | Additional input scalar; wider role unknown |
| `0x20` | 8 | zero | `0x1007104d4` | `0x100c3ca28` | Saved at local SP+0x1e0 |
| `0x28` | 2 | `0xdf9f` | `0x1007104f4` | `0x100bab310` | Halfword input; wider role unknown |
| `0x2a` | 2 | unknown | unknown | No selected callee read | Gap in this access footprint |
| `0x2c` | 4 | `0x57ca8c68` | `0x1007104b0` | `0x100bab354` | Feeds biased new-span contribution |
| `0x30` | 8 | `0xe34daece3ad3357b` | `0x10071050c` | `0x100b0057c` | Additional 64-bit input |
| `0x38` | 4 | `0x730c4066` | `0x1007104c0` | `0x100bab32c` | Additional biased scalar |

Ten callee reads consume 54 B per class. Every byte has the listed current-interval writer. The separate four-byte pre-call word has its own verified writer/read custody; it is not counted among those 54 B. The access footprint therefore distinguishes 54 B consumed after the call, 4 B read before it, and a 2 B gap. Field names beyond these local uses remain unknown. [RC4-RC5; RC-A3, RC-A5]

At `0x100babb10..0x100babb28`, generic u64 source contracts derive three pointer cells from X5=U:

| Local frame cell | Stored pointer | Later consumer | Role on this path |
| --- | --- | --- | --- |
| SP+0x268 | U+8 | `0x100a44578` | Reader loads the H buffer pointer through this slot |
| SP+0x180 | U+0x10 | First half of LDP at `0x100c055b0` | Pointer to one encoded extent word |
| SP+0x188 | U+0x14 | Second half of the same LDP | Pointer to the duplicate encoded extent word |

The reader consumes the pointer-cell bytes from `0x100babb14`; the two LDP reads consume bytes from `0x100babb24` and `0x100babb1c`. U+8 resolves to H, and the two extent words both remain `0x10ecc45e`, decoded 77, at the pending allocation boundary. These joins establish private pointer/extent interfaces without assigning native ownership. [RC2-RC5; RC-A2-RC-A3]

## Coordinate selection and result custody

The V record is separate from A. Before the helper call, `0x1009d0f50` writes U to V+8, `0x1009d0f64` writes `0xdf1faba6` to V+4, and `0x1009d0f68` writes `0x55f82cf7` to V+0x10. The corresponding reads occur at `0x10045fa9c`, `0x10045fa98` and `0x1004983ec`. All bytes have exact current-interval custody. The result is eventually written to V+0. [RC4-RC5]

For arbitrary u32 input word f, bias b and default coordinate d, original `0x1004983ec..0x100498420` establishes:

```
q = u32(f + b)
selected = d                 if q == 0x76d8ea80
           q                 otherwise
offset = u32(selected + 0x89271580)
```

The source reads d from U+0x18. It also reads U+0x14 in the same LDP; that extent word does not affect the selected value. The generic proof fixes separate concrete V/U cells and leaves their data, the bias and the unrelated W1 phase input arbitrary. It proves the CSEL value, not a general native validation result. The offset conversion composes the proved reader-operand addition at `0x100a8bfdc..0x100a8bfe8` with RC2's reader normalization. [RC2, RC4-RC5; RC-A2]

| Retained quantity | Calculation | Result |
| --- | --- | --- |
| Explicit q | `u32(0x55f82cf7 + 0x20e0bdc2)` | `0x76d8eab9` |
| Explicit offset | `u32(0x76d8eab9 + 0x89271580)` | 57 B |
| Default offset | `u32(0x76d8ea81 + 0x89271580)` | 1 B |
| Sentinel offset | `u32(0x76d8ea80 + 0x89271580)` | 0 B |

The actual explicit q differs from the sentinel. Two SAT controls check explicit-57 overriding default-1 and sentinel-zero selecting default-1. They are interpretations of the proved local contract, not newly admitted target inputs. [RC4-RC5; RC-A2, RC-A5]

```
0x100498440: selected W5 -> helper SP+0x68
0x10048d3dc: helper SP+0x68 -> W2
0x1004aa840: W2 -> V+0
0x1009d0fe4: V+0 -> W8
  +-> 0x100a5dfb0: X8 -> X9 -> first coordinate conversion/reader
  +-> 0x1009d0fe8: W8 -> local SP+0x38c
        -> 0x100ca35b4: W9 -> second coordinate conversion/reader
```

Every memory edge in this chain has exact byte custody; the first register route has uninterrupted value continuity. Both readers consume H+57..60=`9e6fd1e4`. The first decode supplies encoded span20 to the save at `0x100d2bfcc`; the later decode supplies the same value to the resize arithmetic. Both complete decoder occurrences are replayed concretely. The universal final re-encoding contract remains unknown as documented in RC2. [RC2, RC4-RC5; RC-A4-RC-A5]

## New-span and target arithmetic

All following equations are modulo 2^32. Numeric span/extent values correspond to B on this retained path. Let k be the low 32 bits of the frame word loaded from local SP+0xe8, f=A+0x2c, p the decoded saved old span, and C the decoded current extent. [RC1-RC5; RC-A2-RC-A4]

```
x = u32(f + k)                         # 0x100bab354..0x100bab364
payload_contribution = u32(x - 0x0d38177c)
s = u32(payload_contribution + 20)      # 0x100ca350c..0x100ca35b0
t = u32(p + s - 0x167b8ca2)            # 0x100b32954..0x100b32a0c
a = u32(t + 0x167b8ca2) = u32(p+s)    # 0x100d95a6c..0x100d95a9c
N = u32(C + a - p) = u32(C+s)          # previously proved resize interface

retained instance:
f=0x57ca8c68; k=0xb56d8b14
x=u32(0x10d38177c)=0x0d38177c
payload_contribution=0; s=20; p=20; a=40; C=77; N=97 B
```

The 64-bit frame word is `0x8ac9c0d6b56d8b14`. Its read at `0x100bab314` traces to `0x100b00588`. W0=x survives from the caller-word addition until `0x100babb74` saves it at SP+0x260; `0x100a66e24` later loads exactly those bytes into W13. The new-span producer returns W12=`s XOR 0x8b3dc651`; that value remains intact until the sum prefix. A SAT counterexample rejects XOR-unbiasing of x: its input bias is additive. [RC4-RC5]

The old span's save at `0x100d2bfcc` writes SP+0x364. The sum reads those four bytes at `0x100b32960`. Its partial result survives to the tail, and the final W13=40 survives to `0x100d95aac`, which writes SP+0x3dc. The resize reads exactly those bytes at `0x100c055e8`. Separate universal obligations verify the three save addresses, widths and values for arbitrary u64 SP and u32 words. Generic arithmetic preserves wrap; arbitrary parameter values do not thereby establish valid records, payload bounds or successful allocations. [RC2, RC4-RC5; RC-A2-RC-A5]

## Validation, assumptions and limits

Two retained classes cover 304 successful-growth exports. Fresh checks compare seven retained state words per export, including U's H pointer, both old extent words, target40, saved span20, selected coordinate57 and biased span input. This totals 2,128 word checks, with one u64 and six u32 values per export, or 9,728 B. These checks occur at the existing pending malloc97 boundary; no allocator result is supplied. RC5 independently replays 1,450 selected instruction occurrences in 146 slices, checking 51,072 GP/SP values, 1,596 NZCV frames, 200 read events and 114 write events. Overlapping source selections are counted as occurrences. Sixteen nonvacuous UNSAT obligations and three SAT controls pass. [RC3-RC6]

Construction and replay cost O(parent receipt bytes + selected visits*32 + reads*writes + export bytes + proof DAG) time and O(parent bytes + selected evidence + proof DAG) space, excluding solver search. Each solver query has a 30 s limit. Archive publication uses `zstd --ultra -22 -q -T1` and decoded round-trip checks. Exact arithmetic widths, constants, source words, queries and dependencies are retained. [RC4-RC6]

No new target interval, guest input, owner/root definition or API-return premise is added. No native API, IPC, target filesystem, allocation/free, hardware PAC or IDB mutation executes. The requested image identifier had no matching open IDA Assist database when queried; retained original source and journals suffice for this increment. No new incoming/outgoing Mach port, right disposition, emission site or native daemon-kext buffer identity is established. The native initializer/caller epoch, pending allocation result, NULL-route S+0x30 read and earlier four-byte node gap remain unknown. [RC2-RC6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RC-A1: Original image and pinned receipts apply | Source identity and concrete local values | Verify original SHA, parent/dependency hashes, exact fresh extraction and each replayed instruction word. |
| RC-A2: Fixed source phases and stated cells apply | Universal addition, pointer, selector and save contracts | Leave data arbitrary, check nonvacuity, preserve u32/u64 wrap, fix disjoint V/U input cells, and replay actual phase values. |
| RC-A3: Prior conditional admission, owner and API premises apply | Caller records, pointer resolution and export coverage | Verify all current byte writers and call/target metadata, register continuity, seven state words per export and the unchanged pending return boundary; retain full prior admission pins. |
| RC-A4: Previously qualified scalar codec applies | Old span20 and byte-offset normalization | Replay both concrete readers/decoders and check actual bytes; retain RC2's universal reader/extraction proofs and its final-re-encoding unknown. |
| RC-A5: Successful-path local roles do not establish a complete native ABI | Coordinate, contribution and private-record interpretations | Preserve the pre-call/post-call lifetime distinction and footprint gap; test default selection and wrong unbiasing; require other return paths and native callers/consumers before assigning global types or error semantics. |
| RC-A6: Static local evidence is separate from transport evidence | Cross-layer scope | Require a matched native daemon/kext transaction, its actual buffer identity and lifetime continuity before joining these fields to IPC or hardware operations. |

| Impact | Bounded continuation | Present limit |
| --- | --- | --- |
| High | Join these caller records to the native initializer/caller epoch and actual IPC payload | Private source joins are established; native admission and daemon-kext identity remain unknown. |
| High | Trace U+0x18 writers and all helper return classes | The default-coordinate selection is proved; initialization, mutation policy and global error semantics remain unknown. |
| Medium | Decode the remaining biased A fields and their caller producers | The complete selected access footprint and byte custody are known; most semantic field names remain unknown. |
| Medium | Reduce the final decoder re-encoding network component by component | Both concrete occurrences pass; the full universal final encoding remains unproved. |
| Low | Compare other caller footprints against the 0x3c span | The observed two-byte gap is not a proven padding declaration or unknown native structure extent. |

**QG1**: factual technical analysis. **QG2**: RC-A1-RC-A6 register assumptions, dependencies and falsification probes. **QG3**: caller ABI, coordinate/default selection, target producer and data custody are covered; the larger interface goal remains active. **QG4**: widths, byte units, modular arithmetic, check counts and complexity are explicit. **QG5**: successful-path roles, pre-call lifetimes, generic arithmetic, conditional exports and native unknowns remain distinct. **QG6**: original source, pinned journals, fresh extraction, independent replay, solver receipts and publication checks establish provenance. **QG7**: bounded extensions have impact labels and explicit limits.
