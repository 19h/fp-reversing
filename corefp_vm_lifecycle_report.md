# CoreFP coherent VM-buffer construction, root call and cleanup

Subsequent continuation: the [caller-to-cold report](corefp_caller_cold_report.md) follows this original VM-success caller through the cold constructor with its source-produced nonzero-mode root record. Five independent prefixes decode/free the certificate, construct seed/tuple and complete both predicates, stopping before the optional-input read. No VM/metadata cleanup is reached on that deliberately incomplete continuation.

Original caller `0x2e4280` now runs through declared VM effects to four complete ingress/root/cleanup returns with source-produced mode `0x114e4318`. Two VM-allocation failure controls complete the earlier cleanup route without entering the root. This closes the selected source-continuity gap in the [ingress callers report](corefp_ingress_callers_report.md); no parent frame or root record is patched.

Cleanup routine `0x653c70..0x654104` uses separate descriptor words for the buffer overwrite count and `_vm_deallocate` size. It overwrites buffer bytes in descending address order, calls `_vm_deallocate`, overwrites all 32 metadata bytes, then calls `_free`. The byte pattern is address-derived and nonzero; it is not a zero-fill. The VM-failure route skips buffer overwrite but still calls deallocation with address/size zero. All API effects and backing retention are private models. Native allocation, ownership, right identity, successful protected processing and daemon/kext pairing remain unknown. The full goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_vm_lifecycle.py), [checks](triage_evidence/corefp_vm_lifecycle_checks.json), [independent auditor](triage_evidence/audit_corefp_vm_lifecycle.py), [audit receipt](triage_evidence/corefp_vm_lifecycle_audit.json) and [publication verifier](triage_evidence/verify_corefp_vm_lifecycle_publication.py) retain the increment. JSON links resolve logically to `.json.zst`. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Source addresses are preferred-base-zero offsets. Record offsets below are hexadecimal; extents use bytes (B). The original files suffice for these claims; no new live IDA or native corroboration is asserted.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| VL1 | Pinned images, compiler bounds, import/fixup rows and frozen dependencies identify the source. All results depend on them. | Independently compare 27 complete source spans totaling 119156 B, hashes, pointer rows and all executed bytes. Preserve the three original supplied inputs. |
| VL2 | The declared entry tag, scalar, backed private referents and normal aligned stack describe the analyzed caller configurations. Source continuity depends on them. | Rebuild six complete initial CPU/touched-RAM states; replay every original transition, read and write. Four source-produced ingress/root calls and six outer returns complete without PC gaps or frame restoration. Native admission remains unknown. |
| VL3 | `_malloc(32)` returns the declared metadata backing; `_vm_allocate` returns 0 with one output-address write, or 3/5 with no write. VM construction depends on those private API effects. | Check exact arguments and model memory journals. Original source performs all metadata, VM-prefix and root-record stores. No native allocation or external API executes. |
| VL4 | The private 4096 B VM backing starts zero and remains mapped for auditing after declared deallocation/free. Complete retained RAM depends on this model. | Reconstruct its initial page independently and compare every final byte. Distinguish source overwrites from allocator-model writes and retained backing from native lifetime. |
| VL5 | Cleanup phase W27 is `0x37da` at size calculation; loop seeds are the source stack-derived values. Local size/pattern equations depend on these states. | Check coherent CPU checkpoints and every iteration/store. Eight symbolic equation checks and 48 exact original instructions support the equations; these equation checks are not claimed to be original-instruction lifts. |
| VL6 | Once, lock, bootstrap, PAC and daemon-rejection effects retain their frozen private contracts. Root-failure compositions depend on them. | Compare primary certificate-allocation failure, lookup failure and caller-register clobber. Original callbacks and three daemon rejection children execute privately; native concurrency, authorization and delivery remain unknown. |
| VL7 | Deallocation returns 0/5, and void `_free` leaves declared residual X0 of0/`0xfeed`. Result-channel comparisons depend on these model choices. | Verify both status controls and ordinary epilogues. Preserve the raw caller-record marker separately from residual X0. Native free has no established scalar result. |
| VL8 | The scalar 16/patterned-referent case is one bounded input control. Its negative data-flow observation is finite. | Independently check its full source read journal and all20 staged VM bytes. No referent read is observed on that failure path; global field irrelevance or a length interpretation is not inferred. |

## Coherent construction and source root record [VL1-VL4,VL6]

```text
0x2e4280 original entry
  +-- 0x1ae0a4: construct32 B metadata descriptor
  +-- 0x43c4d8 -> 0x47e434 -> 0x1c9fac
  |     0x1ca598: declared _vm_allocate(task,&address,4096,1)
  |     failure -> raw marker -> caller cleanup
  |     success -> publish descriptor base/two span words
  |                source-stage20 B VM prefix
  +-- 0x2e490c -> 0x5f4584: construct root record
  |     -> 0x8fcfa0 adapter -> 0x8e81c8 protected root
  |     selected lookup/certificate failure -> matching-pointer unlock
  |     ingress+0x20 receives raw root marker
  +-- caller cleanup -> 0x653c70
        buffer overwrite -> _vm_deallocate -> metadata overwrite -> _free
  +-- raw marker -> outer J+0x18; ordinary caller return
```

The source-created ingress record is at `0x62017f68`, and its root record at `0x62017ea0` in these fixtures. Their extents are retained views, not inferred native allocation sizes.

| Source-created root field | Checked value / origin |
| --- | --- |
| Decoded operation at root `+0x14` | `0xc1f7` |
| Decoded mode at root `+0x18` | `0x114e4318`, from actual caller preimage `0x2d2a8321` |
| Decoded scalar word at root `+0x10` | `0x0484c46a`, from fixed ingress scalar preimage `0x1f03fdec` |
| Pointer at root `+0x08` | Caller output-cell pointer `0x62017f58`; pointed word is initially zero |
| Pointer at root `+0x20` | Source-created metadata object `0x64000800` |
| Metadata base pointer | Modeled VM backing `0x66000000`, source-published at `0x1ca8bc` |
| Root -> ingress -> outer result | Root `+0` -> ingress `+0x20` -> J `+0x18`, independently checked |

The four complete root paths therefore use a source-produced metadata object with a VM-buffer pointer, rather than the earlier diagnostic zeroed second referent. They remain selected failure paths and do not prove successful processing of that object.

## Descriptor fields and 20 B staged prefix [VL1-VL4,VL8]

| Descriptor offset | After VM success in these runs | Cleanup / observed use |
| --- | --- | --- |
| `+0x00`, u64 | `0x66000000` | Buffer base supplied to overwrite and deallocation |
| `+0x08`, u32 | `0x49742372` | Deallocation extent decodes to 4096 B at the checked cleanup phase |
| `+0x0c`, u32 | `0x49742372` | Overwrite count decodes to 4096 B |
| `+0x10`, u32 | `0x574de78b` | Difference from constructor bias `0x574de777` is 20; broader semantic name unknown |
| `+0x14`, u32 | `0x71349589` | Preserved constructor word; higher-level meaning unknown |
| `+0x18`, u32 | `0xba1df9db` | Metadata marker on this VM-success path |
| `+0x1c`, four bytes | Initial private zero fill | Not assigned a constructor field meaning |

The overwrite count is `u32[descriptor+0x0c] - 0x49741372` modulo `2^32`, zero-extended for the loop. Source `0x653ea4/0x653eb0` supplies that value. The deallocation size reads the distinct word at `+0x08` at `0x653fc4`; at observed W27=`0x37da`, source additions at `0x653fd0/0x653fd4` reduce to the same subtraction. Equal values here do not prove the two fields are interchangeable.

Before ingress, original source writes exactly 20 one-byte stores to VM offsets 0..19. `0x47e858..0x47e9b0` writes offsets 0..7; `0x43cbec..0x43cd50` writes offsets 8..19. The resulting bytes are:

```text
9a e5 7a 32 ba ba ba b6 00 a7 43 61 ba ba ba ba d9 ba b6 ba
```

Offsets 20..4095 retain the declared initial zero backing at this stage. This is an encoded source prefix with unknown full format, not a claimed Mach wire header. The scalar 16 control changes only prefix byte 11 from 0x61 to 0x71; descriptor and root-field values remain unchanged, and there are zero reads from the patterned second referent. This establishes scalar propagation into the encoded prefix, without assigning its higher-level meaning. The selected root failure occurs before any demonstrated consumption of that referent.

## Cleanup byte function, order and API boundaries [VL1-VL7]

For each loop, let `q` be its initial source stack-derived seed and `n` its byte count. At iteration `j` starting at zero, source stores to `base+n-1-j` and writes:

```text
g(q+j) = ((low8(q+j) XOR 0xba) * (low8(q+j)+0x11)) mod256
```

`g` is 256-periodic. The buffer loop uses `q=cleanup_SP+8=0x62017e78`, `n=4096`; the metadata loop uses `q=cleanup_SP+0x10=0x62017e80`, `n=32`. Original buffer stores occur at `0x653f1c`; metadata stores at `0x654070`. Independent oracles compare the exact descending address, byte and iteration sequence, not just final hashes.

| Event / source | Checked argument or state | Scope |
| --- | --- | --- |
| Buffer overwrite, `0x653f1c` | 4096 source stores on VM success; zero on VM failure | Complete finite source loops |
| `_vm_deallocate`, `0x654024` | Task fixture `0x4201`; VM address/4096 B on success,0/0 on allocation failure | Original slot `0x1d039d0`, IA diversity `0x7bce`; API effect modeled |
| Metadata overwrite, `0x654070` | 32 source stores after deallocation returns | Complete finite source loops |
| `_free`, `0x6540ec` | Metadata pointer `0x64000800` | Original slot `0x1d03570`, IA diversity `0x7c9f`; API effect modeled |
| Outer result store, `0x2e4ed0` | Raw marker at J `+0x18` | Independent of free-model residual X0 |

Deallocation return0/5 does not change the source-selected continuation into metadata overwrite/free in these controls. The local instructions after each API call select their branch without reading its scalar result. Retained private backing is still present for final comparison; neither a successful native release nor a leak is established.

| Profile | VM return | Deallocation return | Outer marker | Final residual X0 | Root reached |
| --- | --- | --- | --- | --- | --- |
| `vm_failure` |5 |0 | `0x45e2a20f` |0 | No |
| `vm_failure_release_error` |3 |5 | `0x45e2a20f` | `0xfeed` | No |
| `primary_null` |0 |0 | `0x45e2a20f` |0 | Yes |
| `lookup_error` |0 |5 | `0x45e2a2e3` | `0xfeed` | Yes |
| `clobber_primary` |0 |0 | `0x45e2a20f` |0 | Yes |
| `payload_16` |0 |0 | `0x45e2a20f` |0 | Yes |

## Validation and remaining cross-level questions

Fresh independent replay checks six initial CPU frames, 1814528 B of initial touched RAM and the same final RAM extent; 273798 original visits, 21819 reads, 35431 writes, 17036 PAC models and 91 declared/frozen effects. Six outer returns, four coherent root calls, 16384 buffer overwrite bytes and 192 metadata overwrite bytes pass independent oracles. Eight symbolic equation obligations,48 exact original instructions and 111 fresh original daemon visits support the stated scopes. Frozen daemon rejection fixtures are not native delivery or matched transactions.

Replay/enumeration has conservative upper bound `O(C*(B+P*F+V*L+R+N))` time/space, including per-page fixup reconstruction and reaching-load searches. C denotes profiles, B source bytes, P touched pages, F fixups, V visits, L retained loads, R retained state and N the 4096 B buffer. Each profile has a 100000-visit execution bound. SMT cost is separate, capped at 30 s/query; the eight equation proofs are explicitly not original-instruction lifts. Complete instruction replay and independent byte oracles supply the source-execution evidence.

| Impact | Remaining question | Next discriminating evidence |
| --- | --- | --- |
| High | What does the source-created object do beyond the selected root failure? | Continue the original nonzero-mode fallback/processing consumers with coherent descriptor and environmental state; preserve all input/ownership boundaries. |
| High | Which native caller admits this tag, scalar and its two referents? | Resolve upstream record producers, admission and actual input epochs; local source continuity does not establish public exposure. |
| High | How do descriptor base, the 20 B prefix and its encoded span words evolve on successful processing? | Recover original consumers and successful result contracts, with byte/field provenance and original release paths. |
| Medium | Can overwrite count and deallocation size differ in valid source states? | Identify all writers of descriptor `+0x08/+0x0c` and their invariants. Current equal 4096 B observations do not establish equivalence. |
| High | Does this chain match a daemon/kext exchange and native right lifecycle? | Establish endpoint/right, request/result and ownership lineage in one matched native epoch. VM task fixtures and frozen daemon rejections do not supply it. |

**QG1** passes: factual technical analysis. **QG2** passes: VL1-VL8 delimit assumptions and probes. **QG3** passes for this increment; the full objective remains incomplete. **QG4** passes: u32/u64/byte arithmetic, extents and execution/solver costs are explicit. **QG5** passes: VM success/failure, the two extent words, raw markers, void-free residuals and retained backing remain distinct. **QG6** passes: original bytes/fixups, complete independent replay and byte oracles support the stated results; no native or new live-IDA claim is made. **QG7** passes: impact-ranked continuation covers admission, successful data flow, descriptor invariants and cross-level pairing.
