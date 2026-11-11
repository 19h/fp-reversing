# LSKD element population, object representation and completion ABI

The start source contains a 1,024-slot population loop. After each returning element allocation and initial field/tag stores, its nonnull-slot arm rewrites 512 B, swaps 64 eight-byte words through 63 distinct-index exchanges, and overwrites the vector slot with a transformed word. The footer advances the slot index and repeats until 1,024 slots have been processed. This supplies the loop and representation context missing from the [vector-origin report](lskd_vector_origin_report.md). Complete stack-byte pointer-codec semantics and native population remain **unknown**. [EP1-EP7]

The loop exit selects helper `0xfffffe000a52f728` with a newly recovered record. The subsequent [SecureTime analysis](lskd_secure_time_report.md) establishes that helper as an eight-byte compiler-bounded `BTI C; RET` no-op, without record accesses. The caller supplies raw success `0x5e561849` to the shared cached-lock release path. A subsequent presence gate at cell `0xfffffe000ccc78c0` determines whether to return that raw success or allocate the now-identified 64 B SecureTime object. Native lock ownership and a daemon-facing reply remain unestablished. [EP3,EP8-EP9]

[Original source and checks](triage_evidence/lskd_element_population_checks.json.zst), the [extractor](triage_evidence/recover_lskd_element_population.py) and the [publication audit](triage_evidence/verify_lskd_element_population_publication.py) retain eight kext spans containing 407 instructions / 1,628 B, 23 operand anchors, two exhaustive banks covering 512 inputs, nine authenticated slots, and thirteen retained frames with eleven fields each. Twenty-two UNSAT queries cover 154 source-lifted instruction instances, including all 42 instructions of the sixteen-byte SIMD rewrite body. No new target, allocator, entropy, synchronization or IDA execution occurred.

```text
previous source: acquire -> vector allocation/publication -> index 0
  -> element allocation -> raw pointer stored in vector[index]
     -> 164 B of initial field writes; tag[index] = 0
     -> if reloaded slot is nonnull:
          seed-dependent prefix and local pointer save
          32 x sixteen-byte element rewrite
          63 x distinct eight-byte-word swap
          local pointer-word transform -> overwrite vector[index]
     -> index = index + 1
          index < 1024 -> next element allocation
          index = 1024 -> completion record -> helper A52F728
                           returning call -> saved raw success
                           -> cached RW release adapter
                           -> presence cell CCC78C0
                                nonnull -> raw-success result return
                                null    -> A5268DC [SecureTime allocation]
```

Diagram addresses abbreviate prefix `0xfffffe000`. The source can reach the footer directly on its reloaded-null-slot arm; that does not remove the earlier field writes or establish a successful null allocation. The diagram's repeated object effects assume accessible storage and the source memory/epoch premises below.

## Original provenance and retained frame roots

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every selected kext instruction is compared between those representations. Original chained-format-8 membership, target and diversity are checked separately for each dispatch slot. Hardware authentication is not exercised. [EP1]

Supplied C lines 29791-30081 expose both inner loops and the final slot overwrite in `sub_FFFFFE000A51B9D8`; lines 66904-66921 expose the outer footer. Lines 95747-95836 retain the completion record and call; lines 53708-53733 retain the post-release presence gate. The original instructions resolve their register contracts and precise address arithmetic. No IDA lookup was required; the original C, calls listing and analysis input remain unchanged.

The same thirteen finite start prefixes used in the preceding reports stop before entropy execution. Their ordered byte writes reconstruct the following additional frame roots. Eight distinct original producer PCs cover eleven fields per case. These retained prefixes do not execute the new suffix. [EP2-EP3]

| SP field | Retained value | New use |
| --- | --- | --- |
| `+0x10` | `0xfffffe000ccc78c0` | Post-release presence-cell pointer |
| `+0x78` | `0xfffffe000ccc78e0` | u32 flag used for the seed offset |
| `+0x80` | `0xfffffe000ccc78b8` | Seed-table pointer cell |
| `+0x128` | Workspace W`+0xa8` | Reused completion record |
| `+0x130` | W`+0x4000` | Completion record's limit argument |
| `+0x138` | W`+0x1c0` | Completion record's child argument |
| `+0x140` | Actual auxiliary A`+0x1000` | Auxiliary end |
| `+0x148` | A`+0xc0` | Auxiliary work pointer |
| `+0x150`, `+0x158` | `0xfffffe00079174c0`, `0xfffffe0007919db0` | Completion-helper byte banks |
| `+0x1a0` | u32 `0x3be` | Shared start-state value |

Workspace and auxiliary limits remain distinct in separated fixtures. Persistence of these fields through returning calls and the join to a native frame remain explicit premises.

## Element key and complete SIMD rewrite body

Under the preceding start publication's flag value 255 and seed pointer T=`0xfffffe000ccc78f4`, original source `0xfffffe000a51b9e0..0xfffffe000a51b9fc` selects

```text
seed_byte_offset = 255 & 0x030C5E1C = 0x1C
S = u32[T + 28] = seed[7]
K = u32(low32(P) * 0x030C5E1F) XOR S
```

Here P is the pointer reloaded from local FP`-0xb8` at `0xfffffe000a51bb68`. The original slot pointer was saved there at `0xfffffe000a51bb00`; joining that save to the reload requires the stated scratch-preservation premise because the intervening stack-byte codec is not fully lifted in this increment. The selected seed word is not one of the preceding report's sixteen modified word indices. Its actual value remains unknown. [EP4-EP5]

The SIMD induction variable starts at zero and advances by 16 B. Source vector-coordinate tables contain u32 lanes 12..15, 8..11, 4..7 and 0..3; every group advances by sixteen after each store. The counter compares with `0x200`, producing 32 iterations. The final store covers offsets 496..511. There are no gaps between those sixteen-byte stores. The source-write audit verifies that the prefix's only counter write is the initial zero.

For input byte b at element offset n, and key K fixed during this body, the exact source relation is

```text
u8(x) = x modulo 256
mask(n,K) = u8(K) XOR u8((u32(n)+K) * (u32(n)-K))
output[n] = u8(0x93 * (input[n] XOR mask(n,K)))
```

All u32 arithmetic is modulo 2^32; the final multiplication is modulo 256. The local interpreter consumes the original TBL index vectors, four-lane add/subtract/multiply, EOR3, byte multiplication, image loads, object load/store and coordinate updates. Its universal mismatch query checks all sixteen output bytes for arbitrary 128-bit input, key and block coordinate. A separate source query checks the coordinate step and the 512 B endpoint. This is static instruction interpretation, not target execution. [EP5-EP6]

| Property for a fixed K | Verified consequence |
| --- | --- |
| `mask(n+256,K) = mask(n,K)` | Offsets separated by 256 B use the same byte relation before the later word shuffle |
| `u8(0x93 * 0x9b) = 1` | Byte multiplication has inverse `0x9b` |
| `u8(output*0x9b) XOR mask(n,K) = input` | The local byte relation is reversible for a known key and coordinate |
| 32 stores of 16 B | The relation rewrites all 512 B under the accessible-storage premise |

These algebraic properties do not identify a standardized cipher, hash or security property. The 348 B not written by the preceding initial-field slice are opaque inputs to this rewrite. Rewriting them does not establish that the allocator had initialized them, or that their native values are known.

## Sixty-three word swaps and slot representation

After the byte rewrite, source `0xfffffe000a51bc48` initializes i=63. The original UDIV/MSUB sequence selects

```text
N = u32(((K + i) XOR K) * 0x01000193)
j = unsigned_remainder(N, i)
swap element_u64[i], element_u64[j]
i = i - 1
```

The signed branch tests the pre-decrement value plus one against 2. Its operands lie in 2..64, so the source loop processes i=63,62,...,1: exactly 63 swaps. Unsigned division gives `0 <= j < i`, ensuring distinct cells and excluding the self-alias case for the three-store XOR-swap sequence. The source lift proves that sequence exchanges two arbitrary u64 values under those distinct-cell premises. The remainder range is separately proved over the corresponding unsigned mathematical integers; the MSUB result fits u32 because the remainder is below 63. [EP6-EP7]

Each iteration has four eight-byte loads and three eight-byte stores. All indices lie in 0..63, within the already rewritten 512 B. The loop changes positions of the 64 words. It creates no additional allocation or tag entry. Its addresses and iteration count do not depend on object bytes once K is fixed.

The surrounding stack-byte prefix/suffix computes two local qwords. At `0xfffffe000a51bd34..0xfffffe000a51bd44`, the source XORs those qwords and stores their result to the freshly loaded vector base plus `8*index`. This overwrites the raw pointer stored by the allocator continuation. The full codec's byte permutations, inverse and equivalence to reader-side decoding are **unknown** in this increment. A slot observed after this stage must therefore retain its transformed-word provenance; equality to a raw pointer for a particular value has not been established or excluded.

## Outer loop and source resource envelope

The preceding element-entry fragment establishes W19=`0x7fe` and W20=`0x82c`. The transform's scalar phase expression writes W3=`0x4f7`; a static explicit/implicit-register audit finds no other X3/W3 write in the transform. It also verifies preservation of SP, X20, X21, X23, X24, X27 and X28, and that the transform contains no callee invocation. These preserved registers carry the index, dispatcher and allocator-bank inputs into the next element iteration. The reloaded-null-slot arm carries W3=`0x4f7` directly from the preceding allocation fragment. [EP3,EP7]

At footer `0xfffffe000a547fc8`, the source derives W26=`0x3be`, W19=`0x7fe` and limit

```text
limit = 0x3BE XOR 0x7FE XOR 0x40 = 0x400
index = index + 1
dispatch = 0x4F7 XOR ((index == 1024) * 0x1D6)
```

| Updated index | Original table index | Target and diversity |
| --- | --- | --- |
| 1..1023 | `0x4f7` | `0xfffffe000a5341f0`, `0xb064`; next element allocation |
| 1024 | `0x521` | `0xfffffe000a56e91c`, `0xb064`; completion preparation |

The earlier vector-allocation continuation initializes the index to zero. Under returning-call, memory and stable-frame premises, this establishes 1,024 element-allocation iterations. For each iteration whose reloaded slot is nonnull, the source executes the representation body before the footer. A completed loop and nonnull native objects have not been observed.

| Conditional source quantity | Calculation | Scope |
| --- | --- | --- |
| Element typed-allocation calls | 1024 | Population-loop count; later inspection establishes that the completion helper has no calls |
| Declared element payload total | `1024 * 512 B = 524288 B` | Sum of descriptor sizes; actual backing and overhead unknown |
| Vector plus element declarations | `8192 B + 524288 B = 532480 B` | 520 KiB nominal payload; excludes lock storage and the later 64 B SecureTime allocation |
| SIMD rewrite iterations | `1024 * 32 = 32768` | Assumes each reloaded slot takes the nonnull body |
| Word-swap iterations | `1024 * 63 = 64512` | Same nonnull-body premise |

The recovered acquire handoff precedes the vector allocation; the selected release handoff follows completion preparation. No additional acquisition/release call appears inside the captured population body or footer. Under a matched lock epoch, this places the repeated allocation/transformation work between those handoffs. It does not establish native ownership, contention, elapsed time or scheduling behavior.

## Completion record, release and remaining presence gate

For reused record R=W`+0xa8`, original source `0xfffffe000a56e920..0xfffffe000a56e974` reduces to

```text
key32 = u32((low32(R) XOR 0xDDD14603) * 0xB90EE68B)
record_u32[0] = key32 XOR u32(0x3BE + 0x1C8FF40A)
              = key32 XOR 0x1C8FF7C8
```

This is the caller's encoded-control relation. Subsequent compiler-bounded inspection establishes that the selected helper does not read or decode it. The remaining explicit caller stores are:

| Record offset | Width | Source-written argument |
| --- | --- | --- |
| `+0` | u32 | Encoded control above |
| `+8` | u64 | Auxiliary A`+0xc0` |
| `+0x10` | u64 | Auxiliary A`+0x1000` |
| `+0x20` | u64 | Child address W`+0x1c0` |
| `+0x28` | u64 | Workspace limit W`+0x4000` |

These stores cover 36 unique bytes in a 48 B field envelope. They do not newly write record `+4..+7` or `+0x18..+0x1f`; those prior contents remain separate epochs. The exhaustive SP`+0x150/+0x158` bank resolves original slot `0xfffffe0008471450` to `0xfffffe000a52f728`, diversity `0x6e7d`, at call `0xfffffe000a56e9e4`. The later [SecureTime report](lskd_secure_time_report.md) captures its complete eight-byte body and proves there are no record accesses or outputs in this selected callee. The original population artifact remains a frozen record of this increment's narrower scope. [EP8]

If that call returns, source `0xfffffe000a56e9ec..0xfffffe000a56e9f0` explicitly supplies W9=`0x5e561849`. There is no intervening comparison of the helper's returned status on this captured caller suffix. Saved index `0x15f` selects the shared status/release block `0xfffffe000a529758`, diversity `0x6a52`. That block saves the raw word in scratch W`+0x180` and enters the [previously recovered release preparation](lskd_vector_origin_report.md): selector `0x1d3`, null explicit lock pointer, cached-RW release adapter `0xfffffe000a551f38`. Its original slot is `0xfffffe0008471498`, diversity `0x84cc`. Actual `IORWLockUnlock` still requires a nonnull valid cached pointer and a matching owned lock epoch. [EP8-EP9]

After the release adapter returns, the source reloads the scratch word. Raw success selects index `0x458` and target `0xfffffe000a535844`, diversity `0x62dc`. This block reads the qword at `0xfffffe000ccc78c0` through retained SP`+0x10`.

| Fresh presence value | Table index / target | Established continuation |
| --- | --- | --- |
| Nonzero | `0x1fb` / `0xfffffe000a52e4b0`, diversity `0x2984` | Stores raw success at receiver `+0x38`, restores caller frame and returns |
| Zero | `0x74c` / `0xfffffe000a5268dc`, diversity `0x2984` | Supplies raw success in W8 to the later-recovered SecureTime allocation body; completed initialization remains unknown |

Cell `0xfffffe000ccc78c0` is distinct from the vector cell at `0xfffffe000ccc78d0`, the seed-pointer cell at `0xfffffe000ccc78b8` and RW cell at `0xfffffe000ccc78a8`. Its source producer is now established by the [SecureTime report](lskd_secure_time_report.md); the actual native value remains unknown. The no-op completion helper does not by itself prove the final start result, whole initialization or an outer transport response.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| EP1 | Pinned original KC and normalized kext identify this build. Addresses, data tables and slots depend on that identity. | Rehash both, compare every selected instruction and source table, and decode original chained slots and diversity. |
| EP2 | Thirteen retained prefixes describe their declared finite start fixtures. Frame-root attribution depends on their byte epochs. | Reconstruct last writes and producer bytes; establish actual native entry, frame and backing storage separately. |
| EP3 | Calls return normally, preserve the declared caller frame and callee-saved registers, and introduce no undeclared aliases. Loop composition and record persistence depend on this. | Recover every actual call/return and intervening frame write; the new transform register-write census tests its own preservation separately. |
| EP4 | The preceding seed publication remains in the selected flag/table epoch, and the local saved-pointer cell survives the unreduced prefix. The seed[7]/pointer-key join depends on this. | Recover all flag/seed writers and fully lift the prefix byte permutation, its scratch ranges and pointer save/reload; inspect native epochs separately. |
| EP5 | The reloaded element pointer designates 512 accessible bytes. The full rewrite and its data reads depend on that capacity premise. | Establish actual allocator outcomes, links, backing capacity and initialization policy; retain the prior slice's 348 unwritten bytes as unknown inputs. |
| EP6 | A64/AdvSIMD arithmetic, TBL out-of-range zeroing and unsigned UDIV/MSUB have the declared instruction semantics. Local formulas depend on those semantics. | Interpret original operands, image-loaded selectors and all 42 body instructions; solve byte, coordinate, inverse and remainder mismatch queries. |
| EP7 | The two swap addresses are distinct and the captured register/frame state reaches the footer. The permutation and 1024-iteration source count depend on this. | Prove `0 <= j < i <= 63`, re-lift the three-store swap and counter, and check preserved registers and exact continuation slots. |
| EP8 | The selected completion call returns normally through the pinned eight-byte no-op. The post-helper raw-success handoff depends on that return and caller state. | Recheck the later report's exact compiler bounds and `BTI C; RET` bytes; establish native control/authentication separately. There is no source record decoder in this callee. |
| EP9 | A stable cached-lock epoch and fresh presence load join the source suffix. Native release and a complete reply depend on additional evidence. | Match actual acquisition/release identity and ownership, enumerate competing writers, trace the zero-presence continuation and outer transport forwarding. |

## Bounded continuation

| Impact | Further question | Required evidence |
| --- | --- | --- |
| High | What is the complete vector-slot pointer codec, and how do readers decode it? | Prefix/suffix byte-permutation ranges, exact inverse and a source-pinned writer/reader equivalence under matching seed epochs. |
| High | How does SecureTime initialization complete after its clock query? | The later report resolves the helper as a no-op and the zero-presence arm as typed allocation/embedded-RW construction; follow clock consumer `0xfffffe000a51c0e0`, field writes and retirement. |
| High | How is a partially initialized published SecureTime object admitted by later consumers? | All producers/readers and native allocation/publication epochs; source null and constructor-failure arms return the same raw-success word. |
| High | Do native allocation and locking satisfy the repeated-body premises? | Matching runtime metadata, allocation results, accessible contents, lock identity and ownership. |
| Medium | How do the period-256 byte relation and word shuffle appear in retained readers? | Their inverse or equivalent source data flow; literal multipliers alone do not identify a standardized algorithm. |

## Reproduction and scoped quality gates

Run `recover_lskd_element_population.py --verify` with `triage_evidence` on the Python module path and Z3 available. It recaptures original instructions, frame roots, fixed tables and dispatch slots, re-lifts the selected scalar/SIMD slices, and compares the complete logical artifact. The publication audit rechecks all serialized queries and the owned manifest delta, original inputs, source excerpts and path hygiene. Substantial JSON is stored as verified Zstandard archives. Recovered target-defined state paths in existing architecture reports remain ABI evidence; analyst-machine path literals are excluded from the files committed in this increment.

Extraction costs O(B+I+E+256R) time and storage for consumed source bytes B, instructions I, retained write epochs E and bank rules R, plus original pointer-chain work. The expression graph costs O(I); each query has a 10 s solver limit, with solver complexity separate. The source algorithm performs O(1024*512) byte work and O(1024*63) word-swap work under its stated complete-body premises. A local element needs 512 B of accessible storage; native allocation overhead, timing and whole-process space remain unknown.

- **QG1** passes for factual source and interface analysis.
- **QG2** passes with EP1-EP9, dependent results and falsification probes.
- **QG3** passes for this increment's outer loop, exact SIMD byte relation, distinct-word swaps, slot overwrite and completion/release/presence interfaces. The full objective remains active.
- **QG4** passes with u8/u32/u64 widths, explicit modular arithmetic, byte offsets, iteration counts and descriptor-size sums.
- **QG5** passes with opaque preexisting bytes, distinct global roles, direct-null versus transformed footer entries, conditional source counts and the unreduced pointer codec. The later SecureTime report resolves the selected completion helper as a no-op.
- **QG6** passes with original bytes, C excerpts, data tables, chained slots, retained byte epochs, register-write audit and twenty-two checked queries.
- **QG7** passes with impact-ranked codec, SecureTime continuation, runtime and inverse-reader questions.


The [paired context representation](lskd_context_codec_report.md) now proves pointer recovery and the inverse 512 B data transform for matched seed/slot/object epochs. The decoded initializer has byte `+0x174`=0, byte `+0x175`=1 and a zero normalized comparison limit. Later field writers, representation restoration, native epoch matching and daemon request lineage remain open; earlier codec-unknown statements describe the earlier bounded increment.
