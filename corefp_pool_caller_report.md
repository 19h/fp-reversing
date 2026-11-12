# CoreFP pool caller, address-keyed records and overlap-aware XOR stage

Subsequent complete-path evidence: the [pool-transform report](corefp_pool_transform_report.md) adds seven complete private returns with declared context and nonzero pool retirement. The nonzero calls establish reverse allocation order: `0x1b0168` retires the second result, then `0x1b01e8` retires the first. Earlier NULL controls could not distinguish pointer order. Native initialization and the complete algorithm remain unknown.

Original `0x1af6b8` now supplies two established incoming calls to the [pool allocator](corefp_pool_allocator_report.md): `0x1affb0` requests 1027 B and `0x1b0080` requests 1031 B, both through row `0x1d037d0`. It constructs both operation-`0x2b9b` records in the same stack workspace. Three backed private prefixes obtain two distinct interior pointers from one 5000 B backing allocation and stop before the large transform body. Twelve private paths return completely through length rejection, selector bypass or allocation failure. Two further controls stop at token/raw-holder boundaries.

The preceding byte stage reduces to a fixed 16-byte periodic XOR mask, with source-selected forward/reverse order supporting the retained overlapping-buffer controls. The paired cleanup calls `0x1b0168` and `0x1b01e8` target `0x5c87d4`, a different IA-`0x478b` callee, and complete with NULL arguments in the failure paths. Nonzero cleanup, the larger transform algorithm, selector activation, native caller/holder construction, preparation-root compatibility and daemon/kext pairing remain unknown. The full goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_pool_caller.py), [checks archive](triage_evidence/corefp_pool_caller_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_pool_caller.py), [audit archive](triage_evidence/corefp_pool_caller_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_pool_caller_publication.py) retain the evidence. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; offsets are hexadecimal and extents are bytes (B). Original image bytes, chained fixups and current SDK declarations are primary evidence. No new live IDA corroboration is claimed.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PC1 | The pinned image, compiler bounds and frozen readers identify the analyzed code. All source claims depend on them. | Compare three complete source bodies totaling 59120 B, every executed byte and authenticated reaching load. Complete function-byte coverage does not mean every instruction executes. Preserve all three supplied inputs. |
| PC2 | The private 48 B entry record, nonzero opaque word, separate arena and source/destination buffers describe this diagnostic entry. Caller claims depend on these premises. | Independently reconstruct 17 initial CPU/RAM states; retain every record overlay. Exercise length 0/1/15/16/32 and both pointer orders, including overlap. Upstream native admission and a public signature remain unknown. |
| PC3 | Source record construction, selected operation phases and address keys retain their widths. Child-call and gate claims depend on these bindings. | Check both allocation/cleanup record epochs and reaching pointer rows; prove six pre-multiply reductions, the counter XOR identity and the conditional length-gate partition. Gate algebra is not a symbolic proof of the whole parent. |
| PC4 | Explicit empty holder and malloc NULL/backed returns delimit allocation state. Arena claims depend on that declared state. | Check two NULL attempts per selected failure case, one backing allocation for both successful requests, all 8192 arena bytes in each backed prefix, both result extents and volatile clobber. Original raw holder stops before dereference. |
| PC5 | PAC and per-child sequential CASAL retain the frozen models. Control/lifecycle claims depend on them. | Check every original authenticated row, 44 child entries/atomic models, token restoration, null cleanup and complete outer-return state. Native atomic ordering, ownership and nonzero retirement remain unknown. |
| PC6 | The byte-stage reduction and finite prefix scope remain distinct from the larger algorithm and native exposure. Role attribution depends on these limits. | Independently enumerate six mask banks and all 8192 direction/index/input-byte combinations; compare exact forward/reverse output stores and overlap controls. Backed paths stop before `0x1b0270`; no successful processing or source activation is supplied. |

## Source-continuous caller and record epochs [PC1-PC6]

```text
0x1af6b8, entry operation 0x7f48
  -> decode length / source / biased destination
  -> source-selected forward or reverse periodic XOR stage
  -> separate 16 B stack preparation
  -> nonzero, 16 B multiple length gate (selected phase)
       reject -> raw marker 0x45e2a203 -> return
       admit  -> R = FP-0x78
          -> construct allocation operation 0x2b9b, extent 1027 B
          -> 0x1affb0 -> 0x1bc12c -> R+0 result
          -> reconstruct same R, extent 1031 B
          -> 0x1b0080 -> 0x1bc12c -> R+0 result
          -> save both pointers at FP-0xf8
          -> both nonzero?
               yes -> stop before 0x1b0270 large transform body
               no  -> R reused for cleanup operation 0x88cd
                   -> 0x1b0168 -> 0x5c87d4, NULL result
                   -> 0x1b01e8 -> 0x5c87d4, NULL result
                   -> raw marker 0x45e2a203 -> return
```

The parent frame has FP=`0x62017ff0`, SP=`0x62017ad0`, child record R=`0x62017f78` and result pair `0x62017ef8`. Allocation entries use this source-produced child address and original return addresses; no child bytes, PC or parent frame are substituted. Initial diagnostic X1/OUT storage remains unchanged and supplies no new cursor contract.

| Entry record field | Established local contract |
| --- | --- |
| `+0`, u64 | Opaque nonzero word in retained controls; wider object semantics unknown |
| `+8`, u32 | Raw outer marker written at `0x1b0234` on completed paths |
| `+0x0c`, u32 | XOR with `K_e(record)` gives selected entry operation `0x7f48` |
| `+0x10`, u64 | Pointer used by separate 16 B stack preparation; native content type unknown |
| `+0x18`, u64 | Add `0xe4106ba853ce6c9e` modulo 2^64 to obtain XOR-stage destination |
| `+0x20`, u64 | XOR-stage source pointer |
| `+0x28`, u32 | XOR with `K_e(record)`, then add `0xf3d07647` modulo 2^32, to obtain selected byte count n |

`K_e(R)=(low32(R) XOR 0x542fbf9b)*0x4386951d mod 2^32`. Its independently checked source pre-multiply reduction matches the earlier version-reader key family; that equality alone does not identify function semantics or caller admission.

| Child epoch | Original stores / call | Decoded arguments / result |
| --- | --- | --- |
| First allocation | `0x1aff24`, `0x1aff40`; call `0x1affb0` | Tag `0x2b9b` at R+`0x10`, request 1027 B at R+8; result R+0 |
| Second allocation | `0x1b001c`, `0x1b0028`; call `0x1b0080` | Same tag, request 1031 B, same result cell |
| Pair capture | `0x1b008c` | First result retained in X19; second loaded from R+0; both stored at FP-`0xf8` |
| First cleanup | Call `0x1b0168` | R+0 NULL pointer, operation `0x88cd` encoded at R+8 |
| Second cleanup | Call `0x1b01e8` | R+0 NULL pointer, same cleanup operation |

Allocation uses the u64 key `K_a(R)=(R XOR 0xcf834db9ae8c9498)*0x9e8a2055 mod 2^64`, with the allocator's additive size bias retained. The requests are exactly 1027 and 1031 B; their wider meanings are unknown. Cleanup uses `K_f(R)=(low32(R) XOR 0x309487ae)*0x87cfdb29 mod 2^32`; `load_u32(R+8)-K_f(R)=0x88cd`. Six new universal pre-multiply obligations cover parent entry, both allocation constructors, both cleanup constructors and the cleanup reader. Equality is preserved by the shared respective multipliers; no whole-parent symbolic proof is claimed.

Both allocation and cleanup helpers acquire image+`0x1d33108` with compare `0x5d96` and replacement `0xa94ef`. The cleanup prefix resolves the same selector at image+`0x1d44409` and count at image+`0x1d36090`. The original count is 1; selector 0/2/255 and selected empty-holder controls reach the retained null-return route. In those calls the record's first u64 is zero; no nonzero object retirement or native free executes. The source caller preserves the two return values before reusing R.

## Overlap-aware periodic XOR stage [PC1-PC3,PC6]

For the selected entry operation, source greater than destination selects the ascending loop; source less than or equal to destination selects the descending loop. The byte index j is `i AND 15`. Different table expressions reduce to the same mask:

```text
M[0..15] = 06 4c 76 25 14 92 cc 1a 65 93 e6 d6 c5 3d 50 42
out[i]  = input_snapshot[i] XOR M[i AND 15]
```

| Direction / original store | Original table row | Sixteen source bytes begin at |
| --- | --- | --- |
| Ascending, `0x1afa68`, first term | `0x1d144a0` | `0x1a28d00` |
| Ascending, second term | `0x1d101c0` | `0x1b2afd1` |
| Ascending, third term | `0x1d10440` | `0x1687b31` |
| Descending, `0x1afbdc`, first term | `0x1d11790` | `0x1beab40` |
| Descending, second term | `0x1d0ba70` | `0x1abf4f0` |
| Descending, third term | `0x1d0b0f0` | `0x1abf711` |

The ascending mask expression is `(-23*j) XOR A[j] XOR B[j] XOR C[j] XOR 0xd7`; the descending expression is `(69*j) XOR D[j] XOR E[j] XOR F[j] XOR 0x30`, each truncated to u8. The independent auditor resolves all six pointer banks, reads all 96 original table bytes, proves the 16 mask bytes coincide and checks every direction/j/input-u8 combination: `2*16*256=8192` byte cases. This is a fixed XOR stage, not an identified cipher or secret-key derivation.

The count expression reduces over all u32 n to `n+0x49e1df96-((n<<1) AND 0x93c3bf2c) = n XOR 0x49e1df96`, modulo 2^32. On retained paths the later gate word is `n XOR 0x458e3e59`. Given that source phase, its `CMP/CCMP` partition reduces to `n!=0 && (n AND15)==0`. The XOR loop and separate 16 B preparation occur before that gate: length 1/15 controls transform bytes and then reject. Actual external input admission and safety over the full length/pointer domain remain unknown.

| Buffer control | Pointer relation | Source store order / result |
| --- | --- | --- |
| Separate reverse buffers | Source < destination | Descending; exact snapshot-XOR result for n=0/1/15/16/32 |
| Separate forward buffers | Source > destination | Ascending; same 16 B result |
| Overlap, destination=source+8 B | Source < destination | Descending; all 16 output bytes match original input snapshot XOR mask |
| Overlap, source=destination+8 B | Source > destination | Ascending; all 16 output bytes match original input snapshot XOR mask |

The oracle checks exactly n one-byte stores, their order, all destination bytes and retained suffix bytes. The 17 profiles transform a total of 288 B. The separate 16 B stack preparation is replayed from original source but has no new algorithm-level interpretation in this report.

## Backing reuse, outcomes and interfaces [PC1-PC6]

The backed controls declare H+`0x48` and H+`0x50` equal to H+`0x30`, H=image+`0x1d32dd0`, and return a distinct private arena A=`0x64002000` from the first 5000 B malloc request. Both original allocation calls then complete using the same backing. No second malloc is requested.

| Source-produced result | Value | Requested extent |
| --- | --- | --- |
| First result | A+`0x0f60` =`0x64002f60` | 1027 B |
| Second result | A+`0x0b34` =`0x64002b34` | 1031 B |
| Pair storage | `0x62017ef8` | Two u64 words, 16 B |
| Backing | A=`0x64002000` | 5000 B within an 8192 B private mapping |

Both requested ranges lie within backing and do not overlap. Independent arena construction checks the two split nodes, boundary tags, reverse-fill bytes, reciprocal backing-node links and unchanged bytes across the full 8192 B mapping, for all three backed controls. Holder+`0x28` increases by 2132; both endpoints become A. The caller's stack geometry changes the fill parameters relative to isolated allocator entry: it performs 2260 reverse-fill byte stores across the two calls, and the finite metadata constant is `0x0fd0175a3240227d`. These are checked at the actual caller SP; earlier isolated-entry fill constants are not reused.

| Profile group | Cases | Outcome |
| --- | --- | --- |
| Length 0/1/15 | 3 | Complete return, raw marker `0x45e2a203`; no child allocation |
| Length 16/32, selector 0 | 2 | Two zero allocation results, two null cleanup calls, complete return |
| Selector 2/255 | 2 | Same selected failure contract; no malloc |
| Empty holder, malloc NULL, length 16/32 | 2 | Two 5000 B NULL attempts, two null cleanup calls, complete return |
| Backed length 16/32 and volatile clobber | 3 | One 5000 B allocation, two nonzero results, stop before `0x1b0270` |
| Forward / both overlap directions | 3 | Exact XOR output, zero allocation results, null cleanup and complete return |
| Busy token / original raw holder | 2 | Stop before retry / unbacked node+8 read |

The raw outer marker is a source value, not a claimed public error enumeration. All returned paths retain other entry-record bytes and restore SP/callee-saved registers. Backed prefixes have no outer marker store and do not establish transform success or later allocation retirement. The selector remains unchanged in every profile.

No retained path invokes Mach send/receive, port allocation, MIG reply-port handling or descriptor transfer. The backing and interior pointers are private process-local modeled addresses. The new calls establish local allocator/caller/cleanup interfaces, not native rights or a matched daemon/kext exchange. Four entries in the earlier 537-site literal inventory now have reaching-target evidence: two allocation calls target `0x1bc12c`, two cleanup calls target `0x5c87d4`. This increment leaves the other 533 inventory entries unresolved.

## Bounded continuation and quality gates

| Impact | Next investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Follow the backed path after `0x1b0270` to its result and nonzero cleanup. | Retain original same-epoch child buffers, establish actual consumers and cleanup arguments, then independently verify complete effects. Current stopped prefixes supply no processing success. |
| High | Locate upstream record production and selector/holder initialization. | Require original record stores, selector-set-to-1 and valid same-epoch endpoints; private fixtures do not establish native admission. |
| High | Compare the source-produced list node with protected-root preparation consumers. | Establish their required layout and epoch before assigning compatibility or cross-layer readiness. |
| Medium | Resolve further IA-`0x478b` inventory sites. | Check reaching loads and record formats; shared modifier alone still selects four possible callee rows. |
| Medium | Characterize the larger transform and separate 16 B preparation. | Recover source-supported structure and independent vectors before naming an algorithm. A fixed XOR prefix does not identify the whole routine. |
| Low | Correlate local lifetimes with prior daemon/MIG evidence. | Require an actual source handoff and matched interface epoch; no port identity follows from allocator reuse. |

Fresh independent replay passes 17 profiles, 171865 original instruction visits, 28772 data reads, 15810 writes, 7777 PAC models, 51 API/CASAL models and 164 state points. It checks 44 child entries (26 allocation, 18 null cleanup), seven declared malloc attempts, 17 independently reconstructed initial CPU frames and 3436544 B each of initial/final sparse RAM. Three complete source bodies total 59120 B. Twelve outer returns, three backed prefixes and two explicit boundary stops retain distinct outcomes.

Eight new algebraic obligations and one freshly rechecked frozen allocator obligation are UNSAT; 5632 original-bank inputs, 82 exact instruction assertions, 8192 byte cases, 24576 B of compact arena oracle and fresh SDK syntax-only checks pass. The auditor imports no new producer. Conservative replay cost is `O(C*(B+P*F+V*J+R))` time/space with 60000 original visits/profile; bank work is `O(256*K)`, byte enumeration is `O(2*16*256)`, and SMT is separately bounded to 30 s/query. No native target/API/IPC or IDB mutation executes.

- **QG1**: No normative premise is required; conclusions are local evidence claims.
- **QG2**: PC1-PC6 specify assumptions, dependent results and falsification probes.
- **QG3**: Incoming allocation calls, record epochs, byte/control flow, paired cleanup, environmental bounds, ports and continuation are covered.
- **QG4**: U8/u32/u64 widths, modular keys, B extents, store direction, disjoint payload bounds and stack-dependent finite arena values are explicit.
- **QG5**: Source-produced records differ from supplied entry/holder fixtures. XOR transformation is distinct from plain copying; the original gate occurs after preprocessing. NULL cleanup and nonzero future retirement remain separate.
- **QG6**: Pinned complete source/fixups, independent original-byte replay and current SDK declarations provide provenance; no live IDA or native interaction is claimed.
- **QG7**: Impact-ranked continuation preserves unresolved algorithm, initialization, ownership and cross-layer questions. The full investigation remains active.
