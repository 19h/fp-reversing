# CoreFP word-header addresses and recurrence-input producers

All four word headers recover the same logical index from an encoded u32 counter and form `buffer + 8*index`, modulo 2^64. Original setup code also constructs the initial hash literal, recurrence parameters and fold metadata. A single upstream control, entry W22=`0xf82c`, produces the retained first word key, scan-shift control and both second-pass decoder controls through distinct register/stack epochs. This replaces several [word-recurrence premises](corefp_word_recurrence_report.md) with original source producers, conditional on normal control flow and the remaining master-control/backing interfaces.

The producer of that master W22, native buffer ownership, complete selector/target admission and arbitrary native lengths remain unknown. A header address theorem is not a claim that the addressed eight bytes are backed. The full investigation remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_word_inputs.py), [checks](triage_evidence/corefp_word_inputs_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_word_inputs.py), [audit](triage_evidence/corefp_word_inputs_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_word_inputs_publication.py) retain eleven source regions, four threshold resets, four counter-update regions, sixteen preservation censuses, 74 complete region frames/journals and six composed interface joins. Eighteen parent receipts and twenty-one source dependencies are SHA-256 pinned. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. The three supplied inputs are unchanged. Addresses are preferred-base-zero offsets; B denotes bytes.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WI1 | The pinned image, receipts and dependencies identify the source. All source results depend on these bindings. | Compare all primary, reset, counter and census instructions, decoded hashes and original inputs. |
| WI2 | Existing private caller/context/backing/PAC/sequential-CASAL fixtures apply. Whole-caller continuity depends on these interfaces. | Reconstruct six initial CPU/RAM states and freshly replay all 488136 visits/journals. Native ownership, authentication, concurrency and entry admission remain unknown. |
| WI3 | A header receives its declared u32 threshold literal, encoded counter and buffer base; required reads are backed. Its logical index/address theorem depends on these typed inputs. | Prove arbitrary counter/base/word equations; check all reset sites and writer-free corridors; run original-byte counter/word cases and 32 wrong-threshold prefixes stopped before the word load. |
| WI4 | First-setup entry W22=`0xf82c`. The retained fixed-key/control composition depends on this master value. | Prove each setup for arbitrary controls, compose the fixed case and sweep 1024 controls in each of thirty setup domains. Universal production of entry W22 remains unknown. |
| WI5 | Named stack stores reach their same-epoch reads without an overlapping write; FP=SP+`0x520`. Stack-control composition depends on these interfaces. | Prove source addresses/widths and check 24 stable control epochs. Distinguish SP+`0x410`'s earlier field use, first control and later control. |
| WI6 | Executed paths use only the declared writer-free instructions between the named interfaces, with no external register mutation. Register/metadata preservation depends on this normal-flow premise. | Check every W/X alias, all sixteen census intervals and all original branch kinds; compare the complete retained frame/handoff sequences. Native exceptions and arbitrary dispatch targets do not inherit this result. |

## Header index/address contract [WI1,WI3]

Let c and s be u32 values. With the declared threshold s, each header builds:

```text
extended = zero_extend_u32(c) + (c <u s ? 2^32 : 0)
index    = zero_extend_u32(u32(c - s))
```

Its subsequent biased additions satisfy `extended-s = index` at u64 width. The source forms the word address as `u64(buffer + 8*index)`. The comparison is unsigned. The carry term preserves u32 counter wrap without interpreting c as a signed counter.

| Header | Source interval | Instructions / B | Counter | Threshold | Buffer | Final word load |
| --- | --- | --- | --- | --- | --- | --- |
| First head | `[0x1b48a0,0x1b4900)` | 24 / 96 | W9 | `37a981c3` | X23 | `0x1b48fc`, X28 |
| First tail | `[0x1b4e9c,0x1b4efc)` | 24 / 96 | W20 | `37a981c3` | X23 | `0x1b4ef8`, X3 |
| Second head | `[0x1b56d8,0x1b5738)` | 24 / 96 | W1 | `20390963` | X25 | `0x1b5734`, X3 |
| Second tail | `[0x1b5d20,0x1b5d84)` | 25 / 100 | W16 | `20390963` | X25 | `0x1b5d80`, X3 |

Literals are hexadecimal. The second tail additionally reads one u32 at FP-`0xd0`, before the word load; that value controls an independent predicate and is arbitrary in the address theorem. Both biased-index registers in each [recurrence-body interface](corefp_word_recurrence_report.md) plus their declared offsets equal the recovered index. The intervening codec retains those registers, and all 32 retained header ends equal the corresponding frozen codec-entry frames.

Original first/second setup initializes its head counter to the corresponding threshold, hence initial index zero. Four source update regions increment the encoded counter at u32 width. The source theorem proves that the decoded u64 index increments by one when its preceding value is below `0xffffffff`; at that boundary it wraps to zero. This does not establish a native admitted length, backing extent or permitted split.

| Body | Threshold reset | Counter update source interval | Counter after update |
| --- | --- | --- | --- |
| First head | `0x1b4924..0x1b492c` | `[0x1b4d44,0x1b4d6c)` | X9=`zero_extend_u32(c+1)` |
| First tail | `0x1b5040..0x1b5048` | `[0x1b51c8,0x1b51cc)` | X20=`zero_extend_u32(c+1)` |
| Second head | `0x1b58bc..0x1b58c4` | `[0x1b5c10,0x1b5c38)` | X1=`zero_extend_u32(c+1)` |
| Second tail | `0x1b5f9c..0x1b5fa4` | `[0x1b63d0,0x1b63d4)` | X16=`zero_extend_u32(c+1)` |

Threshold reset ranges are half-open. Each consists of MOV/MOVK to W21, which zero-extends the threshold to X21. Writer-free post-reset intervals preserve it until the next admitted header. Backward header targets require the declared normal-flow interface; the census alone does not prove the target set.

## Setup and shared parameter producers [WI1,WI4,WI6]

| Component | Source interval | Instructions / B | Established interface |
| --- | --- | --- | --- |
| First setup | `[0x1b47cc,0x1b489c)` | 52 / 208 | initial h, a, b, head counter/threshold, first-head metadata and key control |
| First tail setup | `[0x1b4d74,0x1b4e98)` | 73 / 292 | W11, SP+`0x348` control and first-tail metadata |
| Copy a | `[0x1b51d4,0x1b51d8)` | 1 / 4 | X28=X24 |
| Second control seed | `[0x1b54d0,0x1b54e0)` | 4 / 16 | W13=W10+`864e`, W16=W10+`218e`, u32 |
| Second literal metadata | `[0x1b55b0,0x1b55e0)` | 12 / 48 | X8/X10 and W11/W21 literals |
| Second setup | `[0x1b5620,0x1b56d4)` | 45 / 180 | second head key, SP+`0x410`, b, buffer and head counter |
| Second tail setup | `[0x1b5c40,0x1b5d1c)` | 55 / 220 | second tail key/metadata and three stack-control stores |

First setup constructs initial h=`5f3bad8804febfc3` in X12, copies it to X19, sets a=`98c9b5333f174cc8` in X24 and b=`9f8ba664` in W25, and sets W9/W21=`37a981c3`. A census of `[0x1b4808,0x1b56d8)` finds no W12/X12 writer, so X12 supplies the same initial h to the second pass under WI6. It is then an evolving recurrence-state register within that pass; the initial-h census ends at its first header.

X24 is writer-free from `[0x1b47f8,0x1b51d4)`. Original `0x1b51d4` copies it to X28, which is writer-free through `[0x1b51d8,0x1b63e4)`. Thus a reaches both word passes. W25/X25 preserves first-pass b through its loop; second setup separately constructs identical b in W23, which survives the second loop. Second setup loads its buffer base into X25 from u64(FP-`0xb8`), equivalent to SP+`0x468`. The retained first X23 and second X25 bases agree; universal lineage from their earlier producers remains unknown.

First setup also writes six u32 stack fields. Their source widths matter: SP+`0x58` receives `u32(W27 >> 8)`, not a shift of full X27. The retained source proofs include all six store addresses and values. This auxiliary field is not assigned the role of a pointer or external ABI object.

The first-head fold metadata is constructed by first setup. The first-tail metadata comes from its setup, with X16 depending on the stored scan control below. The second-head metadata X8/X10 is literal and X20 is constructed by second setup. Second-tail metadata X24/X27 is literal. Writer-free loop intervals preserve the relevant fields. This replaces fixture-only metadata values with source producers while retaining master-control and normal-flow premises.

## One master control across separate epochs [WI4-WI6]

All operations in the first two columns below are u32, with wrap before reuse. Extensions and final metadata additions use u64. Let m be first-setup entry W22:

```text
k       = m XOR 7d45
w11     = u32(k - 1)
t       = u32(10 * (w11 XOR 82d1))
ctrl    = u32(t + 32f291f3) AND cd0d6df7
seed    = u32(ctrl + 864e)
one     = u32(seed + 5ce82c08) AND a3177c8d
scratch = one XOR c579
two     = u32(scratch + 46ae3c8e) AND b9515fbf
```

The multiply factor 10 is decimal; other literals are hexadecimal. The ctrl expression is the frozen [first initializer's source contract](corefp_scan_entry_report.md). The word-input proof composes it with the new setup equations. W10 preserves ctrl through the first preparation scan; the four-instruction producer converts it to seed in W13, which has no intervening writer before second setup consumes it.

| Value | m=`f82c` result | Original producer / consumer |
| --- | --- | --- |
| k | `8569` | first-setup W8; first-head codec key addition |
| w11 | `8568` | `0x1b4d7c`, before W8's later reuse |
| t | `4d3a` | u64 store `0x1b4e0c`, SP+`0x348`; u64 load `0x1b529c` |
| ctrl | `4d25` | first initializer W10; preserved through its preparation scan |
| seed | `d373` | `0x1b54d0..0x1b54e0`, W13 |
| one | `7c09` | u64 store `0x1b56ac`, SP+`0x410`; u64 load `0x1b5c64` |
| scratch | `b970` | u32 store `0x1b5cf4`, FP-`0xc8`; u32 load `0x1b63c0` |
| two | `55be` | u64 store `0x1b5d10`, SP+`0x410`, after the preceding control read |

The corresponding source metadata is:

| Interface | General expression | Retained u64 value |
| --- | --- | --- |
| First-head word XOR key | `zero_extend_u32(k) + cccccccccccc4763` | `cccccccccccccccc` |
| First-tail X16 | `zero_extend_u32(t) + b8442f8ce72af7a5` | `b8442f8ce72b44df` |
| Second-head codec X24 | `zero_extend_u32(one) + 1912e4b015aa7516` | `1912e4b015aaf11f` |
| Second-tail codec X8 | `zero_extend_u32(two) + 86aa3caf87653ad1` | `86aa3caf8765908f` |

First tail uses the literal word XOR key independently of k. The fixed master case gives the first initializer's variable shift of two and the preparation-scan tail shift of eight via the frozen control contract. For arbitrary m the new setups are still reduced, but the retained fixed-key/mixer equivalences do not follow automatically.

Second tail setup additionally stores `one XOR 1b64aff0` at u32(FP-`0xd0`), producing `1b64d3f9` in these callers. Its header consumes that same four-byte epoch at `0x1b5d20`. Four store/read pairs per caller, totaling 24, have exact address/width/byte equality and no intervening overlapping write. SP+`0x410` first holds an earlier u32 bank field, then u64 one, then u64 two. These are separate source lifetimes and must not be collapsed into one semantic field.

```text
entry W22
   |
   +--> k --> first word key
   |
   +--> w11 --> u64(SP+348)=t --> first initializer ctrl
                                      |
                         preserved W10; W13=ctrl+864e
                                      |
                           u64(SP+410)=one
                              |               |
                       head decoder key   tail setup read
                                              |
                                u32(FP-c8)=scratch
                                              |
                                 u64(SP+410)=two
                                              |
                                      tail decoder key
```

## Validation and continuation

Primary regions contain 339 instructions/1356 B. The census view contains 1791 instructions/7164 B; reset/counter slices contain 30 instructions/120 B and overlap existing views. Their unique source union is `[0x1b47cc,0x1b63e4)`, 1798 instructions/7192 B, within the frozen 59120 B bodies. The views must not be added as disjoint coverage. Across six callers the primary regions execute 2226 visits, 104 reads/736 B, 66 writes/336 B and no PAC models. Setups stop before their BRAA operations.

The auditor does not import the new producer. It reconstructs six initial CPU frames and 3313664 B of initial RAM; checks 488136 original visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM; and checks original workspace/preparation oracles. A separate integer interpreter compares all 74 complete primary CPU/stack frames and read/write journals, including NZCV.

Each of 32 original-byte header domains executes 1024 counter-byte cases and 2048 word-byte cases, giving 98304 header cases. Tests provide a private buffer base and back only each expected word address; temporary pages are reclaimed between cases. Thirty setup domains execute 1024 control-byte cases each, totaling 30720. These are component interfaces, not native allocation/admission tests. Pure literal-metadata and copy slices receive actual complete-frame checks without a redundant synthetic corpus. Source and declared unaffected bytes remain preserved.

Finite source visits total `3072*774 + 1024*6*(52+73+4+45+55)=3784704`, over 129024 component cases. Thirty-two wrong-threshold controls execute 742 further prefix visits and stop before the final word load. At c=s-1 with threshold changed to s-1, the source omits the carry repair: it produces u64 index `ffffffffffffffff` instead of `00000000ffffffff`, and private address `buffer-8` instead of `buffer+8*ffffffff`. This is a falsifier of the threshold premise, not a native memory-access or fault observation.

All 42 new and 1192 frozen obligations are independently UNSAT, totaling 1234 with a 30 s/query limit. The new set covers nine header load/index contracts, setup loads/stores/state preservation, parameter/control composition, four threshold resets, four counter increments and two non-wrapping logical successors. The sixteen writer-free censuses are separate structural checks, not solver claims about native control admission.

Replay time/space is conservatively `O(C*(Bsrc+V*J+P*Fpage+R))` for C profiles, source bytes Bsrc, visits V, journal/state cost J, touched pages P, page/frame payload Fpage and other retained bytes R. Component tests take `O(3072*Kh+1024*Ks)` time for retained header/setup visits Kh/Ks, with bounded private maps; solver costs are separate. Each reduced header/setup uses constant-size arithmetic.

No new incoming/outgoing Mach port, right, descriptor, message emission or daemon/kext pairing is established. No native target/API/IPC or IDA operation occurs; original files suffice. The remaining interfaces are explicit:

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Recover entry W22 and both buffer-base producers. | Join upstream source controls and SP+`0x468` cache construction to the admitted object/backing domain. |
| High | Reduce head/tail selectors, loop bounds and dispatch target sets. | Prove normal traversal, termination, permitted lengths/splits and confinement of the preservation paths. |
| High | Compose arbitrary raw preparation and word input with all consumers. | Establish same-epoch backing and the complete original producer/consumer lifecycle. |
| High | Establish native selector/context/holder ownership and admission. | Require coherent native entry, ownership and backing evidence. |
| Medium | Characterize incomplete words and zero/one-word inputs. | Establish source behavior outside the nonempty head/tail theorem. |
| Low | Join the local contracts to daemon/kext transport. | Require actual serializers, consumers and endpoint/right epoch joins. |

- **QG1**: No normative premise is required.
- **QG2**: WI1-WI6 identify dependencies and falsification probes.
- **QG3**: Header addressing, counter widths, setup metadata, shared parameters, control epochs, normal-flow preservation and external-interface limits are covered.
- **QG4**: U32/u64 wrapping, unsigned comparisons, extensions, source/byte extents, exact finite counts and complexity are explicit.
- **QG5**: Address expressions are separated from backing; wrong-threshold prefixes stop before loads; master production, admitted targets/lengths and native ownership remain unknown.
- **QG6**: Original bytes, pinned receipts, source obligations, writer censuses, fresh replay, independent scalar frames, unchanged-byte components and epoch/handoff joins provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains master/base producers, selectors, raw input, owners, short/partial inputs and cross-layer transport.
