# CoreFP entry-record lineage to word controls and buffer bases

Original source connects decoded entry operation `0x7f48` to master W22=`0xf82c`, replacing the unexplained master input in the [word-input report](corefp_word_inputs_report.md). The first and second word-pass buffer bases also come from one cached decoding of entry record+`0x18`. This joins the earlier [pool-caller record contract](corefp_pool_caller_report.md) to both word passes.

The reverse byte prefix preserves the decoded operation register. The forward prefix rewrites it, but its source update has a fixed point at `0x7f48`. Those are distinct proofs. The operation's native producer/admission, buffer ownership/backing, complete dispatch target sets and arbitrary lengths remain unknown. Master equality alone does not identify the operation: the algebraic chain also maps `0x7f49` to `0xf82c`, without establishing native admission for `0x7f49`.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_input_lineage.py), [checks](triage_evidence/corefp_input_lineage_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_input_lineage.py), [audit](triage_evidence/corefp_input_lineage_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_input_lineage_publication.py) retain twelve primary regions, three forward-control slices, fifteen writer-free contracts, 72 complete primary frames/journals and six entry-to-word joins. Twenty parent receipts and twenty-three source dependencies are SHA-256 pinned. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets. B denotes bytes; unstated literals are hexadecimal.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IL1 | Pinned source, parent receipts and dependencies identify the image. All source claims depend on these bindings. | Compare primary/auxiliary/census bytes, query labels, dependency hashes and the three preserved original inputs. |
| IL2 | The existing private caller/context/backing/PAC/sequential-CASAL fixtures apply. Whole-caller joins depend on these interfaces. | Independently reconstruct six initial CPU/RAM states and replay all 488136 visits and journals. Native ownership, authentication, concurrency and entry admission remain unknown. |
| IL3 | Declared record, stack and companion reads supply the stated widths/values; FP=SP+`0x520`. Scalar field/control results depend on these typed interfaces. | Prove every load/store address and width; vary record addresses/fields, stack words, cache values and controls in unchanged-byte component runs. Address arithmetic does not establish backing or a public ABI. |
| IL4 | Execution follows the declared writer-free paths until their named consumers; forward prefix iterations use the separately defined control producers. Register lineage depends on this normal-flow premise. | Check fifteen source censuses, retained reverse-path confinement and all complete frames; prove the forward rewrite separately. Arbitrary native targets/exceptions do not inherit preservation. |
| IL5 | Stores reach their same-epoch reads without an overlapping write. Stack/master/base continuity depends on these lifetimes. | Check five exact store/read pairs per caller, totaling thirty; distinguish u64 control storage from its later u32 replacement and master storage. |
| IL6 | The admitted path carries decoded operation `0x7f48`; downstream word-input contracts apply. Fixed master/key composition depends on this selected operation. | Prove the arbitrary control stages and the selected composition; check the forward fixed point and a different-operation counterexample. Do not infer operation identity/admission from the master value. |

## Entry fields and source address key [IL1,IL3]

The 38-instruction region `[0x1af7dc,0x1af874)` uses entry record address R to construct the u32 key:

```text
K(R) = u32((low32(R) XOR 542fbf9b) * 4386951d)
d    = load_u32(R+0c) XOR K(R)
B    = u64(load_u64(R+18) + e4106ba853ce6c9e)
src  = load_u64(R+20)
L0   = load_u32(R+28) XOR K(R)
```

The original mixed Boolean arithmetic key is proved equal to K(R). The field proof substitutes this proved identity at `0x1af814` into W8; the normalization cut and source query are retained explicitly. No instruction bytes are changed in replay or finite component execution.

| Source instruction | Read / output | Local role |
| --- | --- | --- |
| `0x1af814` | u32(R+`0x0c`) | W9 becomes decoded operation d at `0x1af818` |
| `0x1af81c` | u64(R+`0x18`), u64(R+`0x20`) | X1 retains biased buffer field; X10 receives source pointer |
| `0x1af820` | u32(R+`0x28`) | W8 becomes decoded length field L0 at `0x1af824` |
| `0x1af848` | u32 store at SP+`0x430` | Retains L0, before the byte-count bias |
| `0x1af858` | u64 store at SP+`0x450` | Retains the biased buffer field |
| `0x1af85c` | X25=B | Decoded destination, later cached and used by both word passes |
| `0x1af860..0x1af874` | compare src with B; W14=`d OR (src >u B ? 12 : 0)` | Direction/control contribution, not a buffer-bound check |

The preceding caller report separately establishes byte count `n=u32(L0+f3d07647)` and the source-selected overlap-aware XOR traversal. R+`0x20` is a source pointer; its comparison with B selects direction. It must not be interpreted as an allocation limit or end pointer. This increment proves the record decoder and its downstream lineage, not arbitrary native count admission.

## Buffer cache and both word passes [IL3-IL5]

The four-instruction region `[0x1af8fc,0x1af90c)` loads a companion u64 from X19+`0xe750`, then executes `STP X8,X25,[FP-0xc0]` at `0x1af908`:

| Stored half | Address | Width | Value |
| --- | --- | --- | --- |
| First | SP+`0x460` = FP-`0xc0` | 8 B | Companion value loaded at `0x1af904` |
| Second | SP+`0x468` = FP-`0xb8` | 8 B | X25=B |

The second stored half is the buffer cache. Its first word-pass reload is `LDUR X23,[FP-0xb8]` at `0x1b4618`; its second word-pass reload is `LDUR X25,[FP-0xb8]` at `0x1b56c4`. Source censuses preserve X25 from its record decoding to cache storage, X23 through the first word loop, and the reloaded X25 through the second loop. These are register-preservation statements over admitted paths.

Each retained caller has one cache store and two same-address, same-width reads with no intervening overlapping write. The two epochs are checked separately, totaling twelve cache handoffs across six callers. The buffer contents evolve through the byte prefix and word encoding; stability of the cached address does not imply unchanged contents, allocation ownership or arbitrary backing extent.

## Operation to master through three stack lifetimes [IL4-IL6]

All expressions below wrap at u32 width before reuse. Define:

```text
a = d XOR 92b7
b = u32(a - 40fe)
c = u32(b + 7a57526e) AND 85a87fd8
e = u32((u32(c - 3484) XOR 4ac6) * 6322)
m = u32(e + c244327b) AND 3dbbff6c
```

For selected d=`7f48`, the values are:

| Stage | Value | Original producer / handoff |
| --- | --- | --- |
| a | `edff` | W10 at `0x1afc20`; u64 store `0x1afc40`, FP-`0xe8` = SP+`0x438` |
| Reload a | `000000000000edff` | u64 load `0x1afd94`; W10 reaches the subtract stage |
| b | `ad01` | W9 at `0x1afdbc`; preserved to mask stage |
| c | `7f48` | W8 at `0x1afe50`; preserved to multiply stage |
| e | `c644` | W12 at `0x1afeb8`; u32 store `0x1aff88`, same SP+`0x438` |
| Reload e / construct m | `f82c` | u32 load `0x1b0280`; u32 store `0x1b028c`, SP+`0x348` |
| Reload m | `000000000000f82c` | W22 load `0x1b41a0`; preserved to first word setup |

The first SP+`0x438` store is eight bytes, zero-extended from W10. The replacement at `0x1aff88` writes four bytes. The master consumer reads only those four bytes, and stores four bytes at SP+`0x348`. Later eight-byte word/scan controls at these reused offsets belong to different epochs; their meanings must not be propagated backward over these replacements.

```text
record+0c -- XOR K(R) --> decoded operation d
                              |
                 reverse: preserve W9
                 forward: separate fixed-point update
                              |
                       u64(SP+438)=a
                              |
                       u32(SP+438)=e
                              |
                       u32(SP+348)=m
                              |
                       first-setup W22
                              |
             previously proved word/scan/decoder controls

record+18 -- u64 bias decode --> X25
                                 |
                            u64(SP+468)
                              /      \
                    first-pass X23  second-pass X25
```

All six joins reach the frozen first-setup frame with master `f82c`, then reproduce its previously established control sequence `8569,8568,4d3a,4d25,d373,7c09,55be`. Their 32 word headers use the source-derived buffer B. The native producer of R and its selected operation remains unknown.

## Direction split and limits of operation identity [IL4,IL6]

A single writer-free interval cannot establish operation preservation across both prefix directions: the forward source contains four W9 writers. The census uses two reverse-path intervals, `[0x1af81c,0x1af92c)` and `[0x1afaa4,0x1afc1c)`, and freshly checks that every retained visit between record decode and the first control store lies in that union. These six callers use the reverse prefix.

Three separate forward source slices establish:

| Slice | Source interval | Contract |
| --- | --- | --- |
| Argument | `[0x1af940,0x1af94c)` | W14=`u32(d-4442)` |
| Literals | `[0x1af970,0x1af980)` | W9=`189444c9`, W15=`e76bff78` |
| Update | `[0x1afa60,0x1afa68)` | `F(d)=u32(d-4442+189444c9) AND e76bff78` |

The source theorem gives `F(7f48)=7f48`. Separate writer-free contracts preserve W14, literal W9 and W15 until the update; a forward traversal using these producers therefore retains the selected operation at its loop boundary. This is conditional control algebra, not a fresh complete forward caller run or proof of all dispatch targets.

The general identity `F(d)=d` is false: `F(7f49)=7f50`. The composed master function also gives `m(7f49)=f82c`. Thus neither the forward residue nor the master alone identifies the entry operation. This counterexample concerns the reduced functions outside the selected operation premise; it supplies no evidence that a native `7f49` record reaches the word body.

## Validation and continuation

Twelve primary regions contain 83 instructions/332 B and execute 498 visits, 60 reads/384 B and 42 writes/264 B across six callers. The three auxiliary forward slices contain 9 instructions/36 B. Fifteen censuses contain 2216 unique instructions/8864 B. The union of primary, auxiliary and census views is 2273 instructions/9092 B within the frozen 59120 B bodies. These overlapping views must not be added as disjoint coverage. Primary regions contain no PAC model.

The auditor imports no new producer. It freshly reconstructs six CPU frames and 3313664 B of initial RAM; checks 488136 source visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM; and checks the original workspace/preparation oracles. A separate integer interpreter compares all 72 complete primary CPU/stack frames and journals, including paired loads/stores, u32 zero extension and NZCV.

Original-byte component tests vary record addresses and every declared record field; cache pointer/companion values; both widths of control reloads; and arithmetic inputs. Each caller contributes 24576 component cases, totaling 147456 and 2002944 source visits. Per-record domains total 7168 cases; both cache inputs total 4096; remaining component domains use 1024 u32 or 2048 u64 byte cases. Synthetic record addresses stay in private emulator maps. Decoded pointer values are compared as scalars, never dereferenced by these components. Source and declared unaffected stack bytes remain preserved.

The three original forward slices additionally execute 1024 composed operation cases/9216 source visits and two selected/off-operation controls/18 visits. These do not execute dispatch or a native caller. All 29 new and 1234 frozen obligations are independently UNSAT, totaling 1263 with a 30 s/query limit. Thirty same-epoch control/buffer pairs and 32 downstream header handoffs pass.

Replay costs are conservatively `O(C*(Bsrc+V*J+P*Fpage+R))` time/space for C profiles, source bytes Bsrc, visits V, journal/state cost J, touched pages P, page/frame payload Fpage and other retained bytes R. Component time is `O(N*L)` for N cases and their source lengths L, with bounded private maps; solver costs are separate. Reduced record/control stages use constant-size arithmetic.

No native target/API/IPC or IDA operation occurs; original files suffice. No new incoming/outgoing Mach port, right, descriptor, message emission or daemon/kext pairing is established.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Recover original production/admission of the selected entry record and operation. | Join original record stores, address key and source-selected call to a coherent owner/entry domain. |
| High | Reduce word-loop selectors, bounds and dispatch target sets. | Prove normal traversal, termination, admitted lengths/splits and preservation-path confinement. |
| High | Compose arbitrary raw preparation/word input with downstream consumers. | Establish same-epoch backing and complete producer/consumer lifetimes. |
| High | Establish native selector/context/holder initialization and ownership. | Require original initialization, native entry and valid backing evidence. |
| Medium | Extend direction-specific source joins and short/partial-word domains. | Distinguish the selected forward fixed point from full forward caller execution and all lengths. |
| Medium | Treat converging control values as insufficient operation identifiers. | Require record-origin and dispatch evidence rather than matching master/residue values. |
| Low | Join local record/control contracts to daemon/kext transport. | Require actual serializers, consumers and endpoint/right epoch joins. |

- **QG1**: No normative premise is required.
- **QG2**: IL1-IL6 identify dependent claims and falsification probes.
- **QG3**: Entry fields, address key, direction control, master lineage, buffer cache, widths/lifetimes, downstream handoffs and native/transport limits are covered.
- **QG4**: U32/u64 wrapping, extensions, half-open source intervals, paired stores, exact finite counts and complexity are explicit.
- **QG5**: Source pointer differs from a bound; cache stability differs from content/ownership; reverse preservation differs from forward rewriting; master convergence does not establish operation admission.
- **QG6**: Original bytes, pinned receipts, explicit normalization identity, independent full replay/scalar frames, unchanged-byte cases and epoch joins provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains record admission, selectors, arbitrary raw input, ownership, forward/short domains, nonunique controls and cross-layer transport.
