# CoreFP coherent cold fallback: environmental ABI, seed state and context extent

Subsequent state-lifecycle evidence: the [selector-gated reset report](corefp_optional_reset_report.md) identifies selector clear0x1f5650 and preparation-field reset0x1f5728 under the shared token. Eleven independent profiles establish conditional slot cleanup and full selected returns, without supplying a valid optional input or continuing the stopped root. Initializers and native ownership remain unknown.

Subsequent composition: the [caller-to-cold report](corefp_caller_cold_report.md) now reaches this constructor from original upstream caller0x2e4280 with source-produced metadata, VM backing and mode0x114e4318. Five independent prefixes preserve the same input frontier and119 B without suffix stores. Constructor locations shift by-576 B. Certificate allocation/decode/free already occurs in all nine zero-mode profiles below; no mode-only causal inference is made.

Original caller 0x8e81c8 now executes from its declared root record through cold fallback discovery, certificate processing, the local constructor, three entropy calls, clock sampling, complete 624-word seed expansion and two record predicates. Nine independent cases stop before the optional-input load at 0x8eba44. This joins the earlier local seed/predicate contracts to a coherent cold source path without skipping request1200 or restoring a later parent frame. Fallback flags zero bypass request1200 in original control flow. Native admission, successful primary RPC processing and daemon/kext pairing remain unknown.

The context extent is narrower than a complete initialized 128 B object: source defines nine prefix bytes, while the remaining 119 B retain the declared private stack fill. Clock failure with no output write likewise leaves scratch bytes that source copies into the time/random tuple. These are source/model data-flow observations, not native disclosure or fault results. The full investigation remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_cold_seed.py), [checks](triage_evidence/corefp_cold_seed_checks.json), [independent auditor](triage_evidence/audit_corefp_cold_seed.py), [audit receipt](triage_evidence/corefp_cold_seed_audit.json), [IDA snapshot](triage_evidence/corefp_cold_seed_ida.json) and [publication verifier](triage_evidence/verify_corefp_cold_seed_publication.py) retain this increment. Logical JSON paths resolve to lossless `.json.zst` storage. The [request1200 failure/fallback report](corefp_request1200_failure_report.md) supplies the preceding cold frontier; the [seed](fpsd1201_seed_report.md), [key-route](fpsd1201_key_routes_report.md) and [workspace](fpsd1201_workspace_report.md) reports retain the distinct earlier state-restoration experiments.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CE1 | Pinned original images, compiler extents and normalized authenticated pointer rows identify the source. | Verify image/dependency hashes, fourteen complete functions, every retained transfer and live instruction bytes. Native image pairing remains unknown. |
| CE2 | The root receives the preceding private 48 B record: decoded operation 0xc1f7, controlled field zero and nonnull private referents; entry X1 points to a zero u64 word. | Independently reconstruct all initial CPU/RAM. Recover an actual upstream producer before assigning public reachability or native object types. |
| CE3 | Once, allocator/free, bootstrap, locks/PAC and CASAL are declared sequential models. | Execute original callbacks, compare heap/static lock selection and caller-register clobbering, and verify token replacement/restoration. Native ordering and ownership remain unknown. |
| CE4 | Primary lookup result 1102 and fallback success/name 0x5034 are fixtures. | Verify both original lookup callsites, flags 0, no metadata/request1200 operation and cache retention. No native namespace or Mach right is supplied. |
| CE5 | Entropy returns are three explicit u32 values; clock success writes only the declared seconds/useconds fields, while modeled failure writes nothing. | Compare zero/one/max seeds, signed seconds boundaries, API register clobbering and failure/no-write cases. No native clock, entropy quality or native failure output contract is inferred. |
| CE6 | Initial private stack fills 0xa5,0x00,0x5a are diagnostic inputs. | Reconstruct each initial touched page, check every store and compare final context suffix/scratch bytes. A retained fill is not source initialization or a native process-memory sample. |
| CE7 | The seed state is a 624-word u32 array at image+0x1d4551c, with modulo-2^32 arithmetic. | Check all 5616 independently computed seed words, every sequential store and the separate first mixed-state update. Complete generator/output identity remains outside scope. |
| CE8 | Address-keyed predicate formulas apply only to their exact original helper bodies and record epochs. | Recheck source/dependency fingerprints and independently decode both source-generated 44 B snapshots, output offsets and all unchanged bytes. Do not transplant keys across stack placements. |
| CE9 | The next optional-input instruction is a frontier, not an executed read or native fault. | Retain the same-epoch zero pointer producer and computed address 4; assert that no low-address read occurs. Native caller inputs, full context and later IPC remain unknown. |
| CE10 | Finite replay, solver properties, SDK assertions and IDA evidence retain distinct scopes. | Check nine full client journals, eight source obligations and 1024 live instruction bytes. Preserve the selector-cell read returning zero available bytes; unavailable backing is not evidence of a live value. |

CoreFP arm64e SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; supplied daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. CoreFP offsets use preferred base zero. Fixture addresses/names are private values. Sizes are bytes; u32/u64 arithmetic wraps at its width. Clock fields are signed 64-bit seconds and signed 32-bit microseconds; 999999 us equals 0.999999 s. These artificial values are ABI probes, not captured timestamps.

## Coherent source path and interface boundaries [CE1-CE10]

```text
root 0x8e81c8, original input record
  -> entry-X1 u64 word +=0x100 at 0x8e830c
  -> original cold callbacks -> write-lock model
  -> primary lookup1102 -> fallback lookup/name 0x5034 [models]
  -> flags0; no metadata message and no request1200
  -> original certificate decode/shift/copy -> free model
  -> flags-bit1 branch -> local constructor0x8ea19c
  -> sequential CASAL model at 0x8ea868
  -> original selector0 -> optional-input slot :=0 at 0x8eb7a4
  -> token restored0x5d96 at 0x8eb7a8
  -> entropy R0 at 0x8eb800 [model]
  -> original 624-word seed expansion
  -> gettimeofday at 0x8eb8e0 [model]
  -> entropy R1 at 0x8eb94c, R2 at 0x8eb9a4 [models]
  -> tuple and first state[1] mixing update
  -> predicate 0x1abbe0 -> result 0x245a at record+0x20
  -> predicate 0x439734 -> result 0x252a at record+0
  -> optional-input pointer0 + byte offset 4
  -> STOP before LDR W13,[X12] at 0x8eba44
```

The baseline, seed variants and ordinary clock-failure case reproduce the preceding cold fallback frontier exactly: full CPU, all prefix source visits, reads/writes, PAC models and declared transitions match before the first entropy return. Register-clobber, static-lock and alternate-stack cases are instead independently reconstructed and replayed under their own declared inputs. No PC-range omission, post-prefix RAM restoration or child-record patch is supplied in these nine paths.

| Interface | Source location | Direction / recovered effect | Limit |
| --- | --- | --- | --- |
| Fallback bootstrap | 0x1ce448 | Returns fixture name 0x5034 into original common slot | API/namespace model |
| Entropy imports | 0x8eb800,0x8eb94c,0x8eb9a4 | Three u32 inputs R0,R1,R2 | No native entropy source executed |
| Clock import | 0x8eb8e0 | Pointer to16 B scratch, second argument zero | Explicit success 12 B/no-write failure model |
| Seed state | image+0x1d4551c | 2496 B global array; later state[1] update | Original source writes; no complete generator output |
| Record predicates | 0x1abbe0 /0x439734 | Separate +0x20/+0 u32 outputs in reused stack record | Exact address-keyed local ABIs |
| Optional-input read | 0x8eba44 | Computed X12=4 from same-epoch saved pointer0 | Instruction not executed |
| Mach boundary | None reached after fallback lookup | No metadata/request1200/request1201 transaction or right transfer | Does not pair a daemon/kext exchange |

Each stopped parent retains its selected heap/static lock in the declared ledger and cached name 0x5034. No unlock call, parent return, record-result publication or port deallocation occurs before the frontier. This is an active caller prefix, not evidence of a completed-call leak. The entry-X1 word is0x100 and the input48 B record remains unchanged.

## Context, clock scratch and tuple [CE2,CE5,CE6,CE9]

The active frame has SP=0x62016190. C=SP+0x1340=0x620174d0 and T=C+0x6f0=SP+0x1a30=0x62017bc0. Source stores the nine bytes `006664706300000001` at C[0:9]. No source store overlaps C[9:128] before the retained frontier. The entire 119 B suffix therefore equals the initial stack fill in each case:0xa5 by default,0x00 or0x5a in the two controls.

The earlier predicate/seed/key-route experiments supplied diagnostic zeros for those119 B. Their local contracts remain valid under that premise; the new coherent cold path shows those zeros were not a source-initialization guarantee. A complete native context object, remaining byte producers and subsequent serialization remain unestablished.

| T-relative range | Extent | Value after tuple construction |
| --- | --- | --- |
| +0..+3 | 4 B | R2 |
| +4..+7 | 4 B | Clock scratch microseconds bits |
| +8..+11 | 4 B | Low32 of clock scratch seconds |
| +12..+15 | 4 B | R1 |
| +16..+23 | 8 B | Retained clock scratch seconds field |
| +24..+27 | 4 B | Retained clock scratch microseconds field |
| +28..+31 | 4 B | Retained padding/fill; model does not write it |

The gettimeofday pointer is T+16, second argument zero. The current arm64e SDK assertions establish a 16 B timeval with seconds at+0/8 B and microseconds at+8/4 B, plus the u32/no-argument arc4random prototype. They corroborate the declared field layout, not an original runtime implementation. Source consumes clock fields without reading X0/W0 between the clock return and the next entropy call; that bounded instruction-level fact is independently checked.

| Profile / clock result | R0 seed | Initial stack byte | First four tuple words, in hexadecimal |
| --- | --- | --- | --- |
| Baseline /success | 0x12345678 | a 5 | 0fedcba9,0009fbf1,89abcdef,9abcdef0 |
| Zero seed /success | 0 | a 5 | 0fedcba9,00000000,00000000,9abcdef0 |
| One seed /success, seconds=-1 | 1 | a 5 | 0fedcba9,000f423f,ffffffff,9abcdef0 |
| Max seed /success, seconds=0x7fffffffffffffff | ffffffff | a 5 | 0fedcba9,000f423f,ffffffff,9abcdef0 |
| Failure/no write | 12345678 | a 5 | 0fedcba9,a 5a5a5a5,a 5a5a5a5,9abcdef0 |
| Baseline with volatile-register clobber /success | 12345678 | a 5 | Same first16 B as baseline |
| Static lock /success | 12345678 | a 5 | Same first16 B as baseline |
| Failure/no write, zero stack | 12345678 | 00 | 0fedcba9,00000000,00000000,9abcdef0 |
| Failure/no write, alternate stack | 12345678 | 5a | 0fedcba9,5a5a5a5a,5a5a5a5a,9abcdef0 |

The two signed-seconds cases share low32 seconds but retain different full seconds at T+16. Failure controls demonstrate dependence on declared scratch contents under a no-write model. They do not establish that a native gettimeofday failure preserves output bytes, occurs on this path or exposes those bytes externally.

## Seed, first mixing step and predicate contracts [CE1,CE7-CE9]

All nine paths store S[0]=R0 and perform 623 original iterations:

```text
S[i] = 1812433253 * (S[i-1] XOR (S[i-1] >>30)) + i mod 2^32
       for i=1..623

S[1] = (S[1] XOR ((S[0] XOR (S[0] >>30))*1664525)) + T[0] mod 2^32
       [one subsequent original mixing update]
```

The complete seed recurrence is MT19937-compatible as established in the preceding source report. This increment independently computes all 624 words per case and compares each source store and the complete array snapshot. It also compares the final 2496 B array after the one extra state[1] store at 0x8ebbd4. No complete generator, full key mixing or output payload is asserted. Default R0=0x12345678 and T[0]=0x0fedcba9 yield state[1]=0x26ce2cea after that step. The clock-failure controls share this one consumed tuple word, so equal first updates do not establish independence from later clock/key words.

The two original predicates receive source-produced records at 0x62017f38. Independent decoding yields0x245a at+0x20 for helper0x1abbe0 and 0x252a at+0 for helper0x439734. Each44 B before/after snapshot differs only in its established four-byte output. Their exact address keys differ from the older0x7a037f38 frame; the audit recomputes keys rather than copying encoded records.

The root stores the retained control at SP+0x418 through original 0x8e89f4; its value at the later gate is0xf1d46bcc. Original 0x8eb7a4 stores zero into SP+0x438 after the selector-zero branch. Source derives the corresponding low32 term at SP+0x428 as zero, then selects the optional-input arm. The next address is0+4. No pointer backing or alternate record control is fabricated, and no read from address 4 occurs. The missing upstream/native input contract remains a continuation requirement, not a reproduced native fault.

## Verification and reproduction

Nine initial CPU frames and 2879488 B of initial touched RAM are independently reconstructed from original segments/fixups and declared root/stack inputs. Separate replay checks 272877 client instruction visits,43684 reads,30415 writes,16370 PAC models,170 modeled transitions,54 callback/construction checkpoints,72 constructor checkpoints,18 lookup handoffs,9 lock acquisitions,18 certificate lifetime events and all 2879488 B of final touched RAM. All 27 entropy returns,9 clock returns,5607 loop iterations and 5616 independently computed seed words are checked. No daemon child or Mach transaction executes.

Fourteen complete compiler-bounded source functions total 105044 B. Complete-body retention does not imply complete branch coverage. Eight source UNSAT properties cover the recurrence/store/loop partition, clock truncation, context/scratch separation, pointer term and selector/control partitions under their recorded source phases. Sixty-two exact instruction assertions bind those expressions to original bytes. Current SDK assertions compile with exit zero and emit no target artifact.

Live MCP readback matches1024 original instruction bytes in three ranges. A fourth request at selector cell0x1d44409 returns zero available bytes for a one-byte request; no live selector-byte value is corroborated. Original pinned image bytes and private source execution instead supply the zero value in these cases. Bounded `seed` knowledge queries in both CoreFP and the supplied daemon return zero entries without truncation. Automatic annotations are not semantic proof; no IDB is mutated.

```text
python -P triage_evidence/recover_corefp_cold_seed.py
python -P triage_evidence/audit_corefp_cold_seed.py
python -P triage_evidence/verify_corefp_cold_seed_publication.py
```

Use the existing analysis environment with Unicorn, Capstone and Z3. A conservative time/space bound is O(C*(B+P*F+V*J+R+624)) for profiles C, image bytes B, touched pages P, fixups F, visits V, journal records J and touched RAM bytes R. The product terms account for per-page fixup reconstruction and frozen reaching-load scans; they are not assumed constant-time. Each client is bounded at 100000 instruction visits, each solver at 30 s. Nontrivial JSON is losslessly compressed with decoded-byte equality checks. Publication preserves original inputs and checks owned text, decoded typed RAM and commit metadata for analyst paths.

## Bounded continuation and self-red-team

| Impact | Discriminating continuation / significance |
| --- | --- |
| High | Recover actual upstream production of the root record and its optional-input/control relationship. A coherent private prefix alone does not establish native admission or valid public inputs. |
| High | Establish C[9:128] producers and later output/serialization in the same frame epoch. Diagnostic zeros or other stack fills cannot stand in for complete native context production. |
| High | Establish successful primary request1200 response handling and native service/image/right lineage. This fallback path legitimately bypasses that RPC and therefore cannot prove its successful contract. |
| Medium | Recover successful preparation-object lifetime and the pointer written to the optional-input slot, without substituting guessed backing. The selector-zero path supplies no such object here. |
| Medium | Continue whole mixing under a source-supported root input contract and compare complete state/output. Only one extra state word is updated before this frontier. |
| Medium | Establish native entropy/clock failure effects, token concurrency, caller completion and lock release. Current sequential models and stopped prefixes do not settle these lifetimes. |

**QG1** passes: factual analysis requires no normative judgment. **QG2** passes: CE1-CE10 state assumptions and falsification probes. **QG3** passes for this increment: coherent cold constructor continuity, environmental ABI/data flow, context extent, complete seed state, first mix, record predicates and source frontier are covered; full cross-level completion remains open. **QG4** passes: byte extents, signed time fields, modulo arithmetic, execution bounds and SDK/source checks are explicit. **QG5** passes: earlier zero-filled frames versus current source stores, clock model versus native effects, active prefix versus completed parent, distinct predicate offsets and stopped load versus fault remain separate. **QG6** passes: pinned original bytes/fixups, independent CPU/RAM replay/oracles, source/SDK receipts and bounded IDA corroboration support the claims; the unavailable cell is retained. **QG7** passes: the impact table bounds remaining work. Native ownership, complete successful context/output and daemon/kext/deeper topology remain unknown.
