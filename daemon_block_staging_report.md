# fairplayd: descriptor re-encoding and sixteen-byte boundary staging

The private wrapper at `0x100427b0c` re-encodes its control word for the inner descriptor's address. The callee at `0x100411480` decodes that word into a signed-index dispatch load. Source equations establish the exact codecs and the alignment condition under which their composition preserves the intended phase. The selected phase stages sixteen bytes through one position-dependent XOR mask, transforms the staged block, then copies sixteen result bytes through a different XOR mask. The complete block algorithm, native caller epoch and daemon-kext pairing remain unknown. [BS1-BS6; BS-A1-BS-A6]

The retained core makes 144 four-byte table reads from four nominal banks, followed by sixteen reads from four further banks. This is a source-access footprint, without a certified round decomposition or algorithm classification. The two staging masks are byte-representation contracts under the retained controller/bank context; they do not establish a protocol key, IV, mode or the complete transform's invertibility. [BS1-BS5; BS-A4-BS-A5]

| Evidence | Primary provenance and scope |
| --- | --- |
| BS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original instruction words, immutable windows and dispatch words. |
| BS2 | [Record-input provenance](daemon_record_input_origin_report.md) and its pinned checks/audit. The two conditional normal classes supply the retained source frames and effects. Prior complete admissions are not rerun. |
| BS3 | [Extractor](triage_evidence/recover_daemon_block_staging.py), [checks](triage_evidence/daemon_block_staging_checks.json.zst): descriptor slices, 64 boundary-loop iterations, masks, exact buffer values and core table-read footprint. |
| BS4 | [Auditor](triage_evidence/audit_daemon_block_staging.py), [audit](triage_evidence/daemon_block_staging_audit.json.zst): independent scalar replay, fifteen UNSAT queries, three certified source rewrites, alignment/relocation controls and original-byte checks. |
| BS5 | [Publication verifier](triage_evidence/verify_daemon_block_staging_publication.py): fresh extraction/audit/proof comparison, exact owned manifest delta, original-input preservation and decoded path hygiene. |
| BS6 | [ABI](interface_abi_report.md), [ports](mach_ports_report.md) and [record banks](daemon_record_banks_report.md): private source contracts remain distinct from public transport, actual native memory admission and the later missing-bank frontier. |

Decoded receipt SHA-256 values: `f544501de6a7ceefa17c5bba23a8f1de5137bbf8cd53d812e66b8e5e5a0e00a6` (BS3), `32c63b8e3feb6e3b780522f721ce65e1033e4a079f8aa7e1f74bc49b39cdeb89` (BS4).

## Pointer-dependent control interface

Pointers use u64 modular arithmetic. Lowercase r/d denote their low32 bits. All control-mask calculations below are modulo 2^32. B denotes bytes. Let R be the outer record, W the wrapper's SP, D=W+0x10 the new descriptor, and E the raw u32 at R+0x18. Define:

```text
KR(R) = (r XOR b5da7ac1) * 5de29be3
PDenc(D) = ((d XOR 94a3d320) OR 6) XOR 02cd8b34
PDdec(D) = d XOR 966e5812
KDenc(D) = PDenc(D) * 592e2f77
KDdec(D) = PDdec(D) * 592e2f77

intended_index = u32((E XOR KR(R)) + c906f030)
store32(D+0x0c) = intended_index XOR KDenc(D)
decoded_index = load32(D+0x0c) XOR KDdec(D)
```

The wrapper proof covers original `0x100427c4c..0x100427ce8`. Besides re-encoding the control field, it copies the input pointer from R+0x10 to D+0 and the output pointer from R+0 to D+0x10. These field mappings hold for arbitrary u64 pointer values as source load-value equations. Memory validity is a separate premise. The masks depend on the low32 pointer bits; upper pointer bits are absent from these control formulas. These are internal encodings, without a hardware-PAC or public operation interpretation. [BS1,BS3-BS5; BS-A1-BS-A3]

Original decoder `0x100411584..0x1004115f0` establishes the decoded-index equation. The intervening controller and byte-bank reads do not change its key/control operands; the proof leaves their read values symbolic. Dispatch at `0x10041160c` then uses:

```text
target = load64(dispatch_root + 8 * sign_extend64(decoded_index32))
```

The source uses SXTW, including for indices with bit31 set. This is an address equation, without a general bounds or target-admission theorem. The retained dispatch root is `0x101039ef0`; its selection/preservation under arbitrary native controller states remains unknown. [BS1,BS3-BS5; BS-A1-BS-A4]

The encoder and decoder masks agree exactly when `(D & 6)==0`. This condition is sufficient for `decoded_index=intended_index` for every u32 E. Eight-byte alignment is sufficient; the retained D is sixteen-byte aligned. The algebraic condition alone does not prove native object alignment or a valid descriptor. [BS3-BS5; BS-A2-BS-A3]

The equality condition is established compositionally. A bit-vector query proves `PDenc(D)==PDdec(D)` iff bits1/2 are clear. Multiplication by `0x592e2f77` is invertible modulo 2^32: its inverse is `0x6ec75a47`, and their product is 1 modulo 2^32. A universal roundtrip query checks that inverse; a separate left-inverse/injectivity certificate transfers pre-mask equality to multiplied-mask equality. A final XOR composition query establishes control roundtrip given that certified equality. The audit records this dependency chain explicitly. [BS4-BS5; BS-A1-BS-A3]

| Retained quantity | Value | Established source role |
| --- | --- | --- |
| R | `0x680005ff90` | Wrapper record |
| E = load32(R+0x18) | `0x8f94d014` | Original encoded control |
| KR(R) | `0xb96d41d3` | Record-address control mask |
| D | `0x680005fb20` | Wrapper-local descriptor |
| store32(D+0x0c) | `0x63fb8bc9` | Re-encoded descriptor control |
| KDdec(D) | `0x63fb0a3e` | Descriptor-address control mask |
| decoded index | `0x81f7` | Input-staging dispatch phase |

Copying the raw word `0x63fb8bc9` unchanged from D=`0x680005fb20` to D'=`0x680005fb30` changes the decoded index from `0x81f7` to `0xb2e39907`. This finite control demonstrates why equal raw bytes do not preserve the phase across descriptor relocation. Sixteen low-address variants separately exercise the bits1/2 condition: four roundtrip and twelve do not. This is a codec counterexample; it does not execute the resulting dispatch. [BS4-BS5; BS-A2-BS-A3]

## Staging buffers, masks and loop control

Let H be the inner helper's working SP. In both retained classes H=`0x680005f9b0`. The formatter frame from BS2 is F=H+0x1b0. Input/output reservations below are exact retained read/write windows, without a native allocation or ownership claim. [BS2-BS5; BS-A1-BS-A4]

| Buffer | Retained address | Extent | Touch points |
| --- | --- | --- | --- |
| External middle input | `0x680005fd2e` = S+2 | 16 B | D+0; input read `0x10004e954` |
| Staged core input A | H+0xd0 = `0x680005fa80` | 16 B | Input store `0x10004e9a8` |
| Core output B | H+0xe0 = `0x680005fa90` | 16 B | Output read `0x100085b10` |
| External transform output T | `0x680005fd1c` | 16 B | D+0x10; output store `0x100085bfc` |

```text
S[2:18] -- XOR Mi[position] --> A[16]
                                  |
                           retained core
                                  |
                                  v
T[16]   <-- XOR Mo[position] -- B[16]
```

The input phase receives literal X3=16 from `0x100411610`. For positive u64 C, its source tail predecrements to i=C-1, reads external_input+i and writes A+i. Under its read-value and retained phase premises, the byte equation is:

```text
A[i] = external_input[i] XOR U0[i] XOR U1[i] XOR U2[i]
                           XOR low8(111*i) XOR 67
```

The source comparison selects the core entry when i=0; otherwise it returns to the input loop with X3=i. A positive unsigned rank proof establishes decrement without underflow. With initial C=16 and admitted/preserved loop state, the sixteen writes cover offsets 15 down to 0. Directly entering this tail with C=0 would wrap to `0xffffffffffffffff`; the local equation is not a zero-count admission theorem. The selected source phase initializes sixteen rather than taking a length directly from the encoded control word. [BS1,BS3-BS5; BS-A2-BS-A4]

The output phase uses a different counter representation: u64 I starts at 0 and then represents -1 through -15 modulo 2^64. Its position is j=u64(I+15). The body reads B+j, writes T+j, compares I against -15, then postdecrements I. The value equation is:

```text
T[j] = B[j] XOR V0[j] XOR V1[j] XOR V2[j]
              XOR low8(23*j) XOR 216
```

The full-body source proof quantifies over arbitrary input/table bytes and I while retaining the recorded controller/pool context. For the admitted range `1 <= u64(I+16) <= 16`, j is in 0..15 and j=0 exactly when I=-15. Together with the source's I-1 update and terminal selection, this establishes the sixteen-position descending envelope. It does not establish memory admission or the core's semantics for arbitrary native inputs. [BS3-BS5; BS-A2-BS-A4]

| Stage / condition | Table index | Original slot | Selected target | IA diversity |
| --- | --- | --- | --- | --- |
| Input, i!=0 | `0x81f7` | `0x10107aea8` | `0x10004e8b8`, input loop | `0x8425` |
| Input, i=0 | `0x8205` | `0x10107af18` | `0x10010eabc`, core | `0x8425` |
| Output, I!=-15 | `0x3808` | `0x101055f30` | `0x100085b08`, output loop | `0x3b84` |
| Output, I=-15 | `0x6799` | `0x10106dbb8` | `0x1000d4910`, encoded-zero/result suffix from BS2 | `0x3b84` |

All four original authenticated fixups use key IA and address-diversity zero. Logical target/modifier correspondence is checked; hardware authentication remains unexecuted. The suffix's result transfer remains the separately established BS2 contract. No listed index is an established Mach message ID or IOKit selector. [BS2-BS5; BS-A1-BS-A3,BS-A6]

| Nominal mask window | Base | Bytes consumed |
| --- | --- | --- |
| U0 | `0x100e82790` | 16 B, offsets 0..15 |
| U1 | `0x100f976b1` | 16 B, offsets 0..15 |
| U2 | `0x10100d9d1` | 16 B, offsets 0..15 |
| V0 | `0x100e5fe00` | 16 B, offsets 0..15 |
| V1 | `0x100f24ec4` | 16 B, offsets 0..15 |
| V2 | `0x100ef1703` | 16 B, offsets 0..15 |

The actual read addresses in all 64 iterations match these six windows plus the position. Combining their original bytes gives:

| Stage | Mask, hexadecimal |
| --- | --- |
| Input Mi[0:16] | `98fdc2f89f01c6d23630627654655e2f` |
| Output Mo[0:16] | `9fb1b5bdec49526f614671848d4c02d2` |

Each boundary map is its own inverse at a fixed position. The masks differ, so composition across the intervening core does not cancel them. The current extraction proves their values for the retained controller/bank selections. An all-controller equivalence or native lifetime theorem is not established. [BS3-BS5; BS-A2-BS-A5]

| Stage vector | Retained hexadecimal bytes |
| --- | --- |
| External middle input, 16 B | `32988d38c3051e88f585cae6f566fcc1` |
| Staged A, 16 B | `aa654fc05c04d85ac3b5a890a103a2ee` |
| Core B, 16 B | `f259a66c1840dc815c37b7405f22821f` |
| External T, 16 B | `6de813d1f4098eee3d71c6c4d26e80cd` |

BS2 then inserts T between the serialized head and tail: `S[0:2] || T || S[18:20]`. These boundary masks are distinct from the later destination-offset mask at the constructor's missing-bank frontier. This increment does not define those missing banks or execute any post-frontier interval. [BS2-BS6; BS-A2-BS-A6]

## Core table footprint and evidence limits

Within original core source `0x10010eabc..0x1001112bc`, the independently checked indexed four-byte image reads use the following nominal banks. Each captured window contains 256 little-endian u32 entries, or 1024 B. The auditor checks all 2048 retained reference words against the image, while the access ledger contains only the actual selected reads. [BS1,BS3-BS5; BS-A1-BS-A2,BS-A5]

| Bank base | Reads per retained class | Nominal reference window |
| --- | --- | --- |
| `0x100e40e10` | 36 | 1024 B |
| `0x100f33b10` | 36 | 1024 B |
| `0x100fdec70` | 36 | 1024 B |
| `0x100e94720` | 36 | 1024 B |
| `0x100f400e0` | 4 | 1024 B |
| `0x100ed3a70` | 4 | 1024 B |
| `0x100f2e680` | 4 | 1024 B |
| `0x10101ab70` | 4 | 1024 B |

Thus each class has 4*36+4*4=160 selected word reads: 144 from the first group and sixteen from the final group. Every observed index is in 0..255, and every read matches the original four bytes at base+4*index. Counts and table geometry alone do not establish nine semantic rounds, an AES implementation, a particular key size or complete invertibility. Recovering the encoded state equations and table functions remains necessary. Arbitrary-input index bounds and native table/memory validity remain unknown. [BS3-BS5; BS-A4-BS-A5]

## Verification and assumption register

Independent replay checks 4580 original instruction visits in 68 selected chunks, 148736 GP/SP values, 4648 NZCV frames, 1360 ordered reads, 102 writes and 64 logical edges. Original-byte checks cover six sixteen-byte mask windows and eight 1024-byte word windows. Across the two classes, 192 actual mask-bank reads and 320 core word reads are checked separately from the retained reference windows. There are 16384 finite byte/position involution controls. These are reused retained source intervals and symbolic/finite arithmetic checks; no new CPU interval, root admission, native API/IPC or IDB edit occurs. [BS3-BS5; BS-A1-BS-A6]

Fifteen nonvacuous queries establish three source normalizers, wrapper field/control production, full decoder value, signed-index load geometry, pre-mask alignment equivalence, multiplier inverse, left-inverse injectivity, XOR composition, input-tail addresses/value/exit/handoff, positive input rank, full output-body value/addresses/exit/handoff, output position/rank domain and literal sixteen-byte initialization. The three register rewrites occur immediately before their original constant multiplies and are qualified by independently checked normalizer lemmas. The inverse/injectivity/composition queries are algebraic certificates instantiated by the source contracts; they are not additional native execution observations. [BS4-BS5; BS-A1-BS-A4]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| BS-A1: Pinned source, parent receipts and solver rewrite dependencies | All source coordinates, codecs and numeric mappings | Rehash dependencies, regenerate extraction, recapture original bytes/fixups, replay and recheck each qualifying lemma and query. |
| BS-A2: Retained parent allocator/owner/ABI model applies | Conditional two-class call/staging lineage | Inspect the pinned prior admissions and recover authentic caller state. These classes do not exhaust arbitrary native calls or clobber values. |
| BS-A3: Descriptor placement and source read-value premises apply | Wrapper/decoder roundtrip and field transfer | Check `(D&6)==0`, source-produced pointer fields and memory admission. Sixteen alignment controls and an unchanged-raw-word relocation counterexample reject unqualified copying. |
| BS-A4: Retained controller/bank selections, admitted memory and loop preservation | Exact masks and sixteen-byte envelopes | Recheck all selected original reads, count/index handoffs and source address equations. Analyze arbitrary controllers, overlap and full caller lifetime separately. |
| BS-A5: Boundary encodings and access footprint are distinguished from core identity | Limited function classification | Recover state/table equations, data dependencies, independent vectors and a complete semantic reference before naming an algorithm, key, mode or universal inverse. |
| BS-A6: Internal source composition is distinguished from native transport | No new Mach right, emission site or daemon-kext pairing | Join authentic caller/consumer objects and port/right histories to a matched daemon-kext transaction; current evidence does not establish that correspondence. |

Reproduction uses the established Python/Z3 environment: run `recover_daemon_block_staging.py`, then `audit_daemon_block_staging.py`; after manifest refresh run `verify_daemon_block_staging_publication.py`. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, with decoded hashes preserved. For the fixed 68 chunks, extraction is O(parent bytes + visits + effects + selected frames) time/space; replay adds O(32*selected visits), reference checks O(2048 words + 96 mask bytes), finite checks O(16384), and proof construction O(expression DAG). Solver search is additional, limited to 30 s/query. [BS3-BS5]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Classify the retained block core | Normalize its state encodings and four main table functions; certify layer dependencies and independently check complete vectors. |
| High | Generalize descriptor/controller admission | Establish actual dispatch-root selection, permitted phase domain, object extent/alignment and preservation for native callers. |
| High | Establish upstream serialized-message lineage and later bank definitions | Follow BS2's five word producers and prove reaching definitions at the constructor's current missing-bank frame. |
| Medium | Connect the private block result to native transport | Recover actual consumer publication and matched caller/port/IOKit transaction history. |

**QG1**: Factual technical scope. **QG2**: BS-A1 through BS-A6 register dependencies and falsification probes. **QG3**: Descriptor encoding, signed dispatch, staging buffers/masks/counters and table footprint are covered for this increment; the full goal remains active. **QG4**: Byte units, u32/u64 widths, modulo domains, stride, inverse and complexity are explicit. **QG5**: Alignment versus memory admission, positive versus modulo-negative counters, actual reads versus reference windows, boundary encodings versus core identity and private versus native transport are distinguished. **QG6**: Pinned original source/fixups, independent replay, exact-byte comparisons, certified rewrite dependencies and solver/finite controls provide primary provenance. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; the stated native/algorithm unknowns remain outside its established conclusions.

## Core-lookup follow-up

The [core-lookup increment](daemon_core_lookup_report.md) extracts an executable, context-specialized sixteen-byte transform with 192 data lookups. Universal source queries establish fixed read/write cells, lookup extents and the outgoing logical branch; changed-input source-model runs match the standalone graph evaluator. The primitive identity and native daemon-kext transaction mapping remain unknown.

## Core affine-table follow-up

The [affine-table increment](daemon_core_affine_report.md) establishes the initial sixteen byte/index codecs and exact forward AES S-box and encoded MixColumns identities for the four main word tables. Source projections, complete finite domains and explicit rejection witnesses qualify these component contracts. Full round/key semantics and the native daemon-kext transaction join remain unknown.
