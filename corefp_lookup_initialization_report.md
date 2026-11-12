# CoreFP cold lookup initialization and lock fallback

Cold execution of CoreFP lookup 0x1cdb24 invokes original pthread_once callbacks that earlier warm-state fixtures omitted. Callback 0x4a21e0 attempts two 200 B lock constructions and clears both cached service names and metadata. A lock is published only after successful allocation and zero pthread_rwlock_init result. When the first heap lock is absent, source selects a statically initialized fallback at image+0x1d27bf0. Three completed private lock-acquisition models then reach the original bootstrap lookup of `com.apple.fpsd`, including allocation-failure and init-error cases. No native lock, bootstrap operation, Mach right or daemon/kext transaction executes.

## Evidence and assumptions

The [producer](triage_evidence/recover_corefp_lookup_initialization.py), [checks](triage_evidence/corefp_lookup_initialization_checks.json), [independent auditor](triage_evidence/audit_corefp_lookup_initialization.py), [audit receipt](triage_evidence/corefp_lookup_initialization_audit.json), [live-IDB snapshot](triage_evidence/corefp_lookup_initialization_ida.json) and [publication verifier](triage_evidence/verify_corefp_lookup_initialization_publication.py) retain the evidence. Logical JSON links resolve to `.json.zst` artifacts. Earlier [lookup/client-path evidence](corefp_client_paths_report.md) remains authoritative for subsequent transport; the separate [network-cache report](corefp_network_identity_report.md) covers another initializer and cache.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| LI1 | The pinned original CoreFP bytes and format12 pointers identify this source. | Check universal/slice SHA-256, all seven complete compiler-bounded functions and every reaching authenticated-pointer row. |
| LI2 | Lookup receives a valid private record with decoded tag 0xba27 and flag 9. | Independently reconstruct its complete bytes, address key, output pointers and initial CPU/RAM. Recover a native caller before assigning external reachability. |
| LI3 | Both pthread_once predicates start uncompleted in the declared sequential model. | Execute both original callbacks, check callback entry/return frames and model bookkeeping. Native predicate layout, concurrent ordering and interrupted execution remain unknown. |
| LI4 | Allocation and pthread results are explicit private fixtures; pthread_rwlock_init changes no modeled RAM. | Vary null allocation, init results 0/12/16/22 and caller-register clobbering. Do not interpret the diagnostic lock bytes as a valid initialized native object. |
| LI5 | Protected calls/branches bypass PAC after original pointer resolution. | Independently verify the exact reaching read, slot, target, IA diversity, address-diversity choice and complete CPU. Native authentication remains unknown. |
| LI6 | Initial cached names, metadata and bootstrap name are diagnostic scalar inputs. | Retain every input byte and source reset store. Source overwriting a u32 does not prove native Mach-right retirement or ownership. |
| LI7 | The first heap lock or static fallback reaches acquisition; three cases model that API returning zero. | Stop eleven cases before acquisition and three before bootstrap. Native lock success and the effects of all nonzero acquisition results remain unknown. |
| LI8 | Current arm64e SDK declarations support layout interpretation, not historical native implementation identity. | Compile size/alignment/prototype/static-signature assertions and retain SDK-relative header hashes. Pair the actual original runtime separately. |
| LI9 | Live IDA bytes and xrefs corroborate source and recorded references only. | Compare all readback bytes with the original file; retain query limits and empty knowledge results. Computed calls and incomplete analysis prevent a dead-code conclusion. |
| LI10 | Fourteen finite profiles establish their complete prefix behavior, not all possible initializer inputs. | Check complete CPU/RAM journals, a separate compact oracle and source-level branch/algebra identities. Preserve arbitrary-input, native and cross-layer limits. |

Universal SHA-256: `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; arm64e slice SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are relative to preferred image base zero. All native names/objects remain unknown unless explicitly identified as model inputs.

## Original call sequence and state publication [LI1-LI7,LI10]

```text
lookup 0x1cdb24, valid private record
  |
  +-- pthread_once at 0x1cdd74
  |     predicate image+0x1d34f90
  |     callback 0x4a21e0
  |       +-- 0x59e33c -> attempt first 200 B lock
  |       |                 success -> image+0x1d444a8
  |       +-- 0x59e33c -> attempt second 200 B lock
  |       |                 success -> image+0x1d47fb8
  |       +-- 0x57a67c -> clear cached names and metadata
  |
  +-- lock-acquisition helper 0x20f37c
  |     +-- pthread_once at 0x20f5a8
  |     |     predicate image+0x1d37f50
  |     |     callback 0x59e868 -> token updates -> ret-only leaf 0x438d40
  |     +-- heap slot nonzero: use first heap lock
  |     |   heap slot zero: use static lock image+0x1d27bf0
  |     +-- pthread_rwlock_wrlock at 0x20f6cc [eleven profiles stop here]
  |
  +-- bootstrap_look_up at 0x1ce1bc [three profiles stop here]
        name = source-produced "com.apple.fpsd"
        output = image+0x1d44448
```

| Routine | Complete source extent | Recovered bounded role |
| --- | --- | --- |
| 0x1cdb24..0x1ce4ef | 2508 B | Existing metadata/lookup client; this increment executes its cold prefix |
| 0x4a21e0..0x4a25d7 | 1016 B | First once callback: two lock constructors and cache reset |
| 0x59e33c..0x59e6ab | 880 B | Address-keyed private lock-construction record |
| 0x57a67c..0x57aa77 | 1020 B | Existing cleanup/reset-capable helper; selected cold input takes reset without deallocation calls |
| 0x20f37c..0x20f6fb | 896 B | Once-protected lock selection and write-lock call |
| 0x59e868..0x59eabf | 600 B | Second once callback: encoded-token updates and no-op call |
| 0x438d40..0x438d43 | 4 B | Single RET instruction |

These seven retained bodies total 6924 B. A complete retained body is not a claim that every branch in it executed. Callback 0x59e868 writes encoded state at image+0x1d33450 and the shared token cell +0x1d37f68; it does not initialize the earlier optional-input holder or selector in these profiles.

## Lock-construction record and result partitions [LI1-LI5,LI8,LI10]

For record address R, p=low32(R), define all arithmetic modulo 2^32:

```text
K = (((p OR 0x3747a74c) + 0xc8b858b3 - (p OR 0xc8b858b3))
      XOR 0x035a67fd) * 0xdb676c6f
control = raw_control + K
```

| R-relative field | Width | Source role |
| --- | --- | --- |
| +0x00 | 8 B | Pointer to a global destination slot; source tests this pointer for null |
| +0x08 | 4 B | Raw result word written at 0x59e5a8 |
| +0x0c | 4 B | Encoded control; decoded value is 0xc1a5 in both calls |

The accessed record extent is 16 B; a native object type or external wire layout is not established. Both calls reuse the same private stack record and target different output slots. Constructor status is not read in the retained prefixes, and the outer callback follows the same original instruction sequence in all fourteen cases. The result is a private record word, not an errno return or Mach message status.

| Allocation / init result | Raw result at R+8 | Global destination effect |
| --- | --- | --- |
| Allocation null | 0x45e2a20f | No pointer publication |
| Allocation nonnull, init=0 | 0xba1df9db | Publishes allocated pointer at 0x59e668 |
| Allocation nonnull, init=12 | 0x45e2a20f | No pointer publication |
| Allocation nonnull, init=16 | 0x45e2a208 | No pointer publication |
| Allocation nonnull, init=22 | 0x45e2a209 | No pointer publication; example of remaining nonzero branch |

Allocation null and init=12 collapse to the same record word; their call journals distinguish them. Allocation requests exactly 200 B at 0x59e56c. On nonnull return, four original halfword stores clear the first 8 B before `_pthread_rwlock_init(pointer, NULL)` at 0x59e63c. The model leaves the remaining 192 B as poison and performs no native lock initialization. Original code publishes the pointer only on the zero-result arm.

A fresh arm64e SDK compile checks sizeof(pthread_rwlock_t)=200 B, alignment=8 B and the exact pthread_rwlock_init prototype. It also checks `_PTHREAD_RWLOCK_SIG_init=0x2da8b3b4`. Original static backing at image+0x1d27bf0 is that little-endian eight-byte signature followed by 192 zero bytes, consistent with the SDK's `PTHREAD_RWLOCK_INITIALIZER`. Compiler stdin, exit code and the two SDK-header hashes are retained in the receipt. This supports the fallback's ABI role under LI8; no original native pthread implementation is executed.

## Cache reset, API directions and boundaries [LI2-LI7,LI10]

| Store site | Image-relative destination | Width / value |
| --- | --- | --- |
| 0x57aa3c | 0x1d44448 | u32 primary cached name := 0 |
| 0x57aa40 | 0x1d37838 | u32 secondary cached name := 0 |
| 0x57aa44 | 0x1d37990 and 0x1d37998 | Two u64 stores := 0, clearing 16 B metadata |
| 0x57aa48 | 0x1d379a0 | u32 control := 0 |
| 0x57aa54 | 0x1d37870 | u32 constant := 0x59fece35 |
| 0x59e668 | 0x1d444a8 or 0x1d47fb8 | u64 allocated lock pointer, successful init only |

The private inputs start with cached names 0x5017 and 0x5034 and nonzero metadata. Both names and the 20 B metadata/control region become zero in every delivered case. The selected reset path makes no mach_port_deallocate call. Therefore these stores establish cache invalidation, not retirement of the diagnostic names as native rights. Other branches in the complete reset-capable helper remain outside the selected cold path.

| API boundary | Source call site | Outgoing source arguments / incoming model result |
| --- | --- | --- |
| pthread_once | 0x1cdd74 | Predicate image+0x1d34f90, callback 0x4a21e0; declared callback execution/return |
| malloc | 0x59e56c, twice | Extent 200 B; fixture pointer or null |
| pthread_rwlock_init | 0x59e63c, when allocated | Allocated pointer, null attributes; fixture status 0/12/16/22 |
| pthread_once | 0x20f5a8 | Predicate image+0x1d37f50, callback 0x59e868; declared callback execution/return |
| pthread_rwlock_wrlock | 0x20f6cc | First heap lock or static fallback; eleven cases stop before API execution, three model zero return |
| bootstrap_look_up | 0x1ce1bc | W0=diagnostic bootstrap name 0x1b57; X1=source stack string `com.apple.fpsd`; X2=image+0x1d44448; all three cases stop before API execution |

The bootstrap output cell is the same u32 primary cache cleared by the first callback. This joins source-produced cold invalidation to lookup preparation without supplying a lookup result. No incoming native service port is returned, no Mach send/receive body executes, and no additional native right disposition or message-emission instruction is established. The [existing Mach-port report](mach_ports_report.md) retains the separately recovered serializer and transport sites.

The three bootstrap-boundary profiles cover normal heap lock, first allocation failure and first init=16. The latter two use the static fallback. The retained boundary is before bootstrap, so no model manufactures a new cached service name or daemon reply.

## Live-IDB corroboration and network-reference follow-up [LI1,LI9]

The retained read-only MCP discovery lists ten databases, including CoreFP, fairplayd and FairPlayIOKit. CoreFP target `c3d025e56a86` supplies six readback ranges: 440 B each at 0x86c0 and 0x8754, and 1024 B each at 0x4a21e0, 0x59e33c, 0x57a67c and 0x59e868. All 4976 compared bytes match the pinned original file. This is a sum of requested comparisons and includes overlap; it is not a count of unique source bytes. The four initializer ranges cover the complete corresponding functions.

| Queried address | Recorded incoming xrefs | Observation |
| --- | --- | --- |
| 0x86c0 | 0 | No recorded caller of the network getter |
| 0x8708 | 1 | Getter's own cold-path branch at 0x86cc |
| 0x1d443c0 | 5 | Cache references at 0x86e8, 0x86f0, 0x8818, 0x8820 and 0x8848 |
| 0x1d443c8 | 3 | Predicate references in getter and dispatch_once thunk |
| 0x1d44409 | 1 | Original pointer cell 0x1d0fe78 |
| 0x1d0fe78 | 0 | No recorded incoming xref to that pointer-table cell |

Queries allowed up to 1000 xrefs per input; none reaches that limit. These exact-address observations do not cover arbitrary subrange aliases or computed protected references. The getter's absence from the export trie and absence of an exact decoded format12 entry pointer were also checked against the original image during investigation. They do not prove the getter is unreachable or unused.

CoreFP knowledge queries `IOMACAddress` and `initialization` each returned zero results without truncation. This establishes only those query results, not an empty knowledge store. MCP's supplemental automatic-analysis annotations report partial/budget-limited analysis; they are retained as observations and excluded from semantic proofs. No database is changed. Earlier target-unavailable snapshots are historical and are not the current availability claim.

Neither the complete selected cold prefix nor its retained original global stores initializes image+0x1d44409 or image+0x1d32e18. The network cache at +0x1d443c0 is also a separate object. The [optional-input frontiers](fpsd1201_key_routes_report.md) remain unresolved.

## Independent validation and reproducibility

The auditor does not import this increment's producer. It independently rebuilds all initial touched pages from original segment bytes, zero backing, normalized fixups and explicit input records. It checks every initial CPU register, original visit, read/write, API effect, authenticated reaching load and pointer row, constructor checkpoint, callback return and final touched page. A separate oracle predicts API order, all 28 constructor records, lock publication, fallback arguments and reset state.

| Verification | Result |
| --- | --- |
| Profiles | 14; eleven pre-acquisition stops and three pre-bootstrap stops |
| Original visits / reads / writes | 19528 / 4776 / 1817 |
| PAC models / external and once models / points | 287 / 110 / 84 |
| Full initial CPU frames | 14 |
| Independent initial / final RAM comparisons | 2088960 B / 2088960 B |
| Complete original source bodies | 7, totaling 6924 B |
| Live-IDB byte comparisons | 4976 B, including overlap |
| Exact instruction checks / UNSAT identities | 19 / 2 |
| arm64e pthread ABI compile | Exit 0, syntax/layout only |
| Reads overlapping constructor result fields | 0 across all profiles |

The two UNSAT obligations establish the zero-only publication predicate expressed by the inspected branch partition and an algebraically simplified address-key expression. They are not a universal proof of the complete constructor for arbitrary controls, source state or API effects. Native pthread behavior, callback concurrency and endpoint/right identity remain untested.

The selected target prefix has finite fixed work; external API work is excluded. Producer/auditor time and space are conservatively O(C*(B+F+V+J+R)) for cases C, original image B, fixups F, visits V, journals J and retained RAM R. Each case has a 12000-visit bound. Each solver query has a 30 s timeout; the compiler has a separate 30 s timeout and emits no compiled file.

## Bounded continuation and quality gates

| Impact | Remaining question | Discriminating evidence |
| --- | --- | --- |
| High | Does native cold lookup acquire the fallback/heap lock and return a service right? | Version-matched original pthread/bootstrap behavior and a source-pinned native trace with right history. |
| High | Which code initializes the optional-input holder and selector? | Reaching writes to image+0x1d32e18 and +0x1d44409; these callbacks do not provide them. |
| High | How does source-produced cold metadata affect subsequent request1200/1201 preparation? | Continue matched lookup/query returns and preserve the exact state epoch through admission checks. |
| Medium | What are the second lock's consumers and both lock lifetimes? | Original reaching references, later release/destruction and native ownership evidence. |
| Medium | Is the network getter reached through computed calls? | Resolve protected target construction and actual caller/consumer state; missing conventional xrefs are insufficient. |
| Low | What changes under repeated/concurrent initialization or registry mutation? | Version-pinned native once/lock behavior and separately retained observations. |

**QG1** passes for factual technical content. **QG2** passes with LI1-LI10 and falsification probes. **QG3** passes for cold lookup initialization, lock/cache data flow and live-reference corroboration; the full investigation remains active. **QG4** passes with explicit byte widths, u32 arithmetic, exact extents, counts and complexity. **QG5** passes with static fallback versus missing heap allocation, record results versus errno, cache clearing versus right retirement, and historical versus current IDA availability separated. **QG6** passes with original byte/fixup hashes, fresh live readback, complete independent journals and primary SDK/compiler evidence. **QG7** passes with the impact-ranked continuation table. This is partial progress toward the cross-layer interface goal.
