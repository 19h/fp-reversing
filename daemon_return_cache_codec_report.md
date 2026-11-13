# Post-error cache roots, byte generation and optional-pointer gate

Related environmental helper: The [network identity report](daemon_network_identity_report.md) preserves the undefined S+0x858 root on eight retained process-path continuations and analyzes a separate six-byte network identity cache. The initializer-compatible cache-root fact is not promoted to a continuous caller-epoch join; the new IOKit main-port/iterator/parent interfaces retain separate entry premises.

The strict initializer writes the two cache-root pointers missing at the preceding caller boundary. A separate caller continuation, conditional on those two additional cells, consumes the existing mask/table globals, generates two private scratch bytes using cached words and self-text samples, reads each byte back to control the loop, and then reuses the same two bytes for a u16 count. It reaches a pointer/count gate whose input retains eight unknown byte origins. The initializer-to-caller lifetime join and native daemon-kext pairing remain unproved. [RC1-RC8]

```text
strict initializer paths -> SP+0x878 / SP+0x858 pointer stores
                   [unproved initializer/caller lifetime join]
prior caller prefix + two additional cache-root cell premises
  -> mask 255 -> cached u32 at table+132
  -> two self-text reads -> generate one scratch byte
  -> read that byte -> nonzero decrements loop counter
  -> repeat for second byte
  -> overwrite same scratch pair with u16 count18 or count26
  -> copy original unknown pointer -> STOP before CCMP

separate source-local gate classification:
  low16(count) != 0 AND pointer != NULL
    true  -> table[0x5c1c] -> 0x1007b3210
    false -> table[0x5c1d] -> 0x100746ab4
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RC-A1 | The pinned daemon and parent receipts identify this source build and epochs. All address/source claims depend on them. | Rehash source/dependencies, compare original opcodes and authenticated fixup words; native build/task/provider pairing remains unknown. |
| RC-A2 | The earlier twelve initializer environments remain separate from later caller fixtures. Initializer lifetime evidence depends on their declared inputs. | Independently replay all twelve under two backing patterns and verify both cache-root cells at each original boundary; equal SP offsets do not establish a cross-path lifetime join. |
| RC-A3 | The later caller receives two additional initializer-compatible pointer values. All new caller observations depend on these premises and the preceding two bank premises. | Preserve the parent unknown-root stop unchanged; retain exact added cells and their previous byte origins; require uninterrupted same-frame execution and an overlap audit before claiming continuity. |
| RC-A4 | Inherited private cache, mask, state, API-output and free-return premises remain applicable. Caller execution depends on their precise source/private-model provenance. | Replay the selected preceding prefixes, preserve the logically retired 32 B allocation guard and vary unspecified physical backing. No new API/output/free-return model is added. |
| RC-A5 | The cache and self-text data-read contracts describe valid readable spans in the retained private model. Codec equations depend on those contracts. | Check actual cache addresses, original self-text bytes, u32 wrapping and source read widths; the all-mask address equation does not assert a universally in-bounds table read. |
| RC-A6 | Unknown pointer bytes remain unspecified through copies and conditional comparisons. The new frontier depends on that distinction. | Retain all eight origins; stop before symbolic flags are serialized, and independently check the complete source-local gate for all u64 pointers/u32 counts plus finite A64 controls. No upstream ownership or external control is inferred. |
| RC-A7 | Source-local arithmetic proofs and finite caller traces have different scopes. Algorithm and gate claims depend on those explicit domains. | Rebuild six nonvacuous UNSAT obligations and replay exact instructions independently; do not infer arbitrary-path termination, global initialization coherence or native behavior. |
| RC-A8 | Publication covers only the owned increment. Validation/preservation claims depend on the exact delta. | Verify source/audit hashes, manifest differences, original inputs, compressed round trips and raw/typed/decoded-payload path hygiene. The full goal remains active. |

## Pointer writers and conditional admission

Let F be the initializer's large-frame SP and S the separate caller SP. The twelve upstream paths retained in the [bank-origin report](daemon_return_bank_origins_report.md) each contain exactly one overlapping u64 write to each cell below, with no later overwrite before their argument-read, audit-import or outer-RETAB boundary. Twenty-four fresh independent replays check both values at those boundaries. These are source lifetime observations within the declared environments. [RC1-RC4]

| Initializer cell | Original writer | Source-produced pointer | Later conditional read |
| --- | --- | --- | --- |
| F+`0x878` | `0x1004c2e14` | `0x1010c67d4`, mask cell | `0x100792b24` loads S+`0x878`; `...b28` reads signed u32 through it. |
| F+`0x858` | `0x1004c2d30` | `0x1010c8268`, cache-pointer cell | `0x1004dc3c8` loads S+`0x858`; `0x100792b2c` dereferences that cell. |

The current experiment restores each parent trace only through index 15,485, before its first cache-root load. It records exactly two additional eight-byte cell effects and starts original execution at `0x1004dc3c8`. This re-executes the parent's final 23 instructions with the declared roots, then continues past the former unresolved `LDRSW`. It neither rewrites the parent receipt nor changes X17/X19 directly. Original source loads supply those register values. [RC2-RC4]

## Cached-word and self-text codec

The [buffer-consumer report](daemon_buffer_consumer_report.md) already identifies the original cache-pointer and mask publications at `0x100315478` and `0x100315484`. The retained caller state contains mask 255 and a source-derived cache pointer D. The new path uses these existing bytes, rather than fresh file zero-fill or an added cache fixture. [RC1-RC4]

At `0x100792b28..0x100792b40`, the exact word-read address is `D + (s64(s32(mask32)) AND 0xffffffffa96e0c84)`. For mask 255 this selects D+132, a four-byte-aligned offset within the first 256 B of the retained table. The all-u32 address identity is proved; universal bounds for arbitrary mask values are not asserted. [RC3-RC5]

For destination address A, let W be that cached u32, V the incoming W14 raw value and C the incoming W23 choice. Define u32 wrapping before extending offsets to u64. The complete source body `0x100792b40..0x100792bc4` implements:

```text
M = encoded_window_mask64 XOR 0x00000000a7a730ec
B = encoded_window_base64 XOR 0x12af5504870a589f
o0 = u64(u32(W + low32(A) + 0xa96e0c87)) AND M
o1 = u64(u32(W + low32(A) + 0xa96e0c89)) AND M
t0 = byte[B + o0]; t1 = byte[B + o1]
byte[A] = low8(V XOR u32(-83 * low32(A)) XOR t0 XOR t1 XOR C)
```

The globals are loaded at `0x100792b5c` and `0x100792b84`. In these epochs, decoded B=`0x100822058` and decoded M=`0xfff0c01200007fff`. The high mask bits remain present in X1, but cannot affect the zero-extended u32 offsets; the effective retained mask is `0x7fff`, selecting a 32,768 B self-text window. The independent audit checks every actual original byte read. This is a process-local code/data dependency, not a claim of native text integrity or external-input validation. [RC3-RC5]

## Byte readback, loop control and storage reuse

Each retained caller writes two generated bytes, first S+`0x3a07`, then S+`0x3a06`. `0x100792bd0` reads back the just-written byte through the current S+`0x6c48` pointer and X15 offset. The following source decrements W22 if and only if the byte is nonzero, compares the new W22 with W3, selects the next table index by XOR `0x7d69` on equality, and increments W8 by 8. A separate all-u8/u32 source proof covers zero, nonzero and modular-counter underflow behavior;24 independent A64 controls include both branches. No arbitrary-state termination bound is inferred. [RC3-RC5]

All sixteen generated bytes in the eight caller cases are nonzero. Both bytes therefore affect loop control before later storage reuse. `0x1005ecd40` overwrites the pair with a u16 count, and `...cd44` retains its low16 bits. The generated byte values do not survive as the final scratch-pair contents. No public-response or payload interpretation is established. [RC3-RC5]

| Epoch | Mode | Generated byte at S+`0x3a07` | Generated byte at S+`0x3a06` | Later u16 overwrite |
| --- | --- | --- | --- | --- |
| 0 | Prefix | `0xce` | `0x97` | 18 |
| 0 | Extended | `0xb3` | `0x90` | 26 |
| 1 | Prefix | `0x06` | `0x4d` | 18 |
| 1 | Extended | `0x14` | `0x3a` | 18 |

Both error controls agree within each row. Other source writes adjust bookkeeping at S+`0x16d0`, save a continuation at S+`0x7ae8`, publish S+`0x8e8`, clear S+`0x4060`, and copy an unknown pointer to S+`0x6c48`. All nine writes per caller case are retained and independently checked. [RC3-RC5]

## Re-entry predicate and remaining unknown pointer

`0x1005ecd4c` reloads X27 from S+`0x8ad0`. Its eight bytes preserve the origins of the earlier common-block input S+`0x4a20`, copied by the [preceding error-return path](daemon_iokit_error_return_report.md). `0x10080e28c` copies the same pointer to S+`0x6c48`. The current trace stops before `0x10080e294`, `CCMP X27,#0,#4,NE`, because its resulting flags depend on those unspecified bytes. No effect of that instruction is committed. [RC2-RC5]

The separate complete source-local gate covers arbitrary u32 count N and u64 pointer P. It writes `active = ((N & 0xffff) != 0 && P != 0)` as u32 to S+`0x808`, then selects `index = 0x5c1c XOR active XOR 1`. The original authenticated entries and diversity are checked independently of executing either successor. [RC3-RC6]

| active | Table index | Original slot | Decoded target | IA diversity |
| --- | --- | --- | --- | --- |
| 0 | `0x5c1d` | `0x101067fd8` | `0x100746ab4` | `0x92c2` |
| 1 | `0x5c1c` | `0x101067fd0` | `0x1007b3210` | `0x92c2` |

Twenty-four A64 controls exercise zero/nonzero pointers, high pointer bits, zero/nonzero low counts and nonzero counts with low16 zero. The actual retained counts 18/26 are nonzero, so the unresolved predicate reduces to `P != 0`. Both successors remain unexecuted from this unknown boundary. Upstream pointer construction, allocation ownership, readability and external controllability remain unknown. [RC3-RC6]

## Provenance and validation

| ID | Primary evidence and role |
| --- | --- |
| RC1 | Original thin daemon `fairplayd.arm64e`, SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original instruction/data bytes and fixups. Addresses are preferred virtual addresses. |
| RC2 | [Parent bank-origin report](daemon_return_bank_origins_report.md), logical checks SHA256 `9e5d75cb4a1f452a8499a3a917351283e8763335a44f264809024aaaeded3c69`, and its pinned source/audit dependencies. No parent source/replay receipt is rewritten. |
| RC3 | [Source extractor](triage_evidence/recover_daemon_return_cache_codec.py) and [checks](triage_evidence/daemon_return_cache_codec_checks.json.zst): exact cut/premises, eight caller traces, twelve upstream field ledgers, six original-source obligations and successor fixups. |
| RC4 | [Independent auditor](triage_evidence/audit_daemon_return_cache_codec.py) and [audit receipt](triage_evidence/daemon_return_cache_codec_audit.json.zst): sixteen caller replays, 24 upstream replays, actual byte-codec oracle and exact loop readbacks/overwrite/pointer origins. |
| RC5 | Six freshly rebuilt/persisted UNSAT source queries in RC3, plus the auditor's separate all-u8 loop query; 24 gate and 24 loop A64 controls. Readable-cell/private-model premises remain explicit. |
| RC6 | Original type12 authenticated pointer words at `0x101067fd0` and `0x101067fd8`, checked against original fixup records; source gate computes their effective addresses and IA diversity. |
| RC7 | [Publication verifier](triage_evidence/verify_daemon_return_cache_codec_publication.py): exact owned delta, manifest/input preservation, evidence pins, source obligations and raw/typed/decoded-payload path hygiene. |
| RC8 | Existing [buffer-consumer](daemon_buffer_consumer_report.md), [cache-publication](daemon_cache_publication_report.md) and [PRNG](daemon_prng_output_report.md) contracts bound the earlier cache/global/byte-state roles. Current evidence comes from original file bytes and offline replay; no new live IDA byte readback is claimed. |

Eight cases retain 2,112 executed source visits, 360 reads and 72 writes. Of these visits,184 repeat the parent's 23-instruction tail across eight cases; 1,928 continue beyond the former frontier. Independent replay checks 4,224 caller visits, 4,672 read bytes, 832 write bytes, 3,808 register effects, 128 NZCV effects and 128 copied-unknown byte effects. It separately replays 287,792 preceding visits. Twenty-four fresh upstream replays check 42,792 visits and 48 cache-root cell values. Forty-eight local A64 controls add 432 visits. These counts are offline software observations, not durations or native operations. [RC3-RC5]

The fixed-width codec and gate are O(1) per iteration. A k-iteration generation loop is O(k); no unconditional finite k is proved. Extractor/auditor time and space scale with restored receipts, source visits, recorded effects and expression sizes; each source query has a 30 s limit. Large JSON receipts are archived with zstd level 22 and verified by exact decompression before publication. [RC3-RC7]

## Bounded next investigations

| Impact | Remaining question | Concrete evidence needed |
| --- | --- | --- |
| High | Original unknown pointer producer | Reaching definitions of S+`0x4a20`, its copies and native object/lifetime provenance; preserve all eight origins until defined. |
| High | Initializer-to-caller continuity | Uninterrupted same-frame source execution preserving all four bank/cache cells, including every overlapping write. |
| High | Daemon-kext transaction identity | Correlate matching-build source contracts with recorded task/connection/provider, selector, buffers and ordered return observations. Private scratch production alone does not establish transport. |
| Medium | Wider generation-loop behavior | Source-produced states that generate zero bytes, full retry scheduling, other count paths and eventual scratch consumers. Current finite caller cases cover two nonzero iterations only. |
| Medium | Other root writers | Broaden reaching-definition analysis across SP epochs, aliases, pair stores and partial overlaps. |
| Low | Shared codec families | Compare source constants, accessed widths and caller storage epochs across other recovered self-text/table consumers. |

## Scoped quality gates

**QG1** passes for factual analysis. **QG2** passes with RC-A1..RC-A8. **QG3** passes for this increment's routine, data/control-flow, ABI and emission accounting; the full goal remains active. These instructions add no Mach port, right operation or message-emission site.

**QG4** passes with explicit u32/u64 wrapping, eight-byte origins, one-byte codec outputs, two-byte overwrite and separate visit counts. **QG5** passes within the stated scope: generated bytes are read for control before overwrite; counts 18/26 differ by context; initializer continuity and native ownership remain unknown. **QG6** passes for original bytes/fixups, seven scoped source queries and independent CPU/byte-effect checks. **QG7** passes with the impact-ranked continuation table. No native API, Mach/IOKit transaction, free, hardware or pointer authentication is executed. [RC1-RC8]

## Related source-local scratch producer

The [scratch-pointer producer continuation](daemon_scratch_pointer_origin_report.md) now recovers a source-local writer of S+0x4a20, its admitted predecessor, status dispatch, cursor restoration and conditional clock ABI. The prior eight caller origins above remain unknown: the new component has not been joined to the retained IOKit caller.
