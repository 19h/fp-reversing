# KBCrypt context retirement: original close entry through return

The normal `_oh70aLVr` branch treats the token-resolved owner as `site.KBCrypt`, whose original typed-free description has size `0x440` (1088 bytes). With explicit warm/private-list/object premises, original execution now reaches close return0 through lookup, mapped-child cleanup requests, doubly linked-list removal, a complete 1088-byte overwrite and the owner typed-free request. This replaces the earlier mid-function cleanup entry with continuous original close-entry execution for the tested family. It does not establish native initialization, VM/free effects, synchronization or reference balance. [CR1-CR8]

Two further component compositions execute the original page wrapper to an error return, retain its source-produced state, and enter original close through an explicit outer caller transition. Both close calls return0 and retire the same private owner. These are page-error/close compositions, not completed native page decryption or proof of the text pager's native callback order.

Evidence: [original close/helpers, type views, selectors and byte proof](triage_evidence/kext_context_retirement_source.json), [28 private cases and two compositions](triage_evidence/kext_context_retirement_profiles.json), [independent replay/list/byte/order checks](triage_evidence/kext_context_retirement_checks.json), [preservation](triage_evidence/kext_context_retirement_delivery.json), and [scoped gates](triage_evidence/kext_context_retirement_quality_gates.json).

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CR1 | Original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` supplies code, names, type views and logical format-8 pointers. | Rehash and recapture original ranges/slots. Every visited word is separately rechecked. Native executable pairing remains unknown. |
| CR2 | Private warm flag `0xfffffe000ccca078`=1 and registry cell `0xfffffe000cccca58` contains the declared list head. | Cold initialization remains a separate path. Establish the native startup writers and consistency of warm flag, head and record fields. |
| CR3 | One to three disjoint 1088-byte private nodes form a terminating, mutually consistent previous/next list. Matching nodes carry tag `0x42059342`, encoded token and declared child fields. | Singleton/head/tail/middle cases cover both NULL/non-NULL neighbor combinations. Miss/empty cases preserve the list. Native node construction and concurrent readers are unproved. |
| CR4 | Owner+`0x188` is NULL; other unassigned private owner bytes are zero except explicitly populated constructor-compatible fields. Child is NULL or a readable 152-byte FPAppSecurityInfo fixture. | Vary child absence and all primary/secondary pointer-presence combinations. Recover non-NULL +`0x188` cleanup and other owner families separately. This is not coverage of every close branch. |
| CR5 | Kernel-map operand and page-shift14 are explicit private image fields; VM and typed-free requests are no-effect return/clobber models. | Validate all call arguments and ordering. VM models return0/4; typed-free models do not retire storage. Obtain native map/allocator/reference effects before claiming real resource release. |
| CR6 | Logical PAC steps and source A64 arithmetic model the selected path. The overwrite's source entry has count1088 and decrement step-1. | Independent CPU replay checks instructions/flags; every store address/byte is checked. A scalar proof covers all u32 overwrite counter words. Hardware PAC and other control seeds are not established. |
| CR7 | The two page-error compositions use a declared outer caller to supply the close token after original page return. It changes registers, not memory, and preserves restored SP. | Replay verifies the transition and unchanged node/head/child bytes. Actual native callback sequencing and successful page/close composition remain unknown. |
| CR8 | Observed bytes after typed-free requests belong to retained private storage because free models have no effects. | Do not infer native post-free contents, allocator guarantees or exclusion. Recover native synchronization, complete optional-resource cleanup and reference accounting. |

Original inputs, IDBs and saved memories were preserved. No native task, Mach operation, VM mapping, heap allocation/free, metadata decryption or hardware PAC operation was executed. Original-file evidence was sufficient; no additional IDA query was needed.

## Typed owner and child interface

| Role | Original descriptor | Name / extent | Source use |
| --- | --- | --- | --- |
| Matched owner | `0xfffffe000847ba20` | `site.KBCrypt`, 1088 bytes | `_IOFreeTypeImpl` request at `0xfffffe000a5c15e0` |
| Security child | `0xfffffe000847bc60` | `site.FPAppSecurityInfo`, 152 bytes | `_IOFreeTypeImpl` request at `0xfffffe000a5c1170` |

Both original descriptors have flags `0x64`; their native initialized zone/statistics fields are unknown. The requested owner-free extent matches the source overwrite extent, but its original allocation/publication is not proved here. The [security-record report](kext_security_record_report.md) separately establishes the child's allocation-view metadata and fixed RPC-record capacity.

| KBCrypt offset | Established field use |
| --- | --- |
| +0 | Normal close-family tag comparison against `0x42059342` |
| +4 | Shared lookup's encoded u32 token word |
| +8 | Previous-node pointer |
| +`0x10` | Next-node pointer |
| +`0x28` | Page consumer's tested flag byte; the earlier metadata path uses bit`0x80` |
| +`0x188` | Optional pointer, NULL in this case set; non-NULL cleanup unestablished here |
| +`0x2e8` | FPAppSecurityInfo child pointer |
| +`0x2f0` | Constructor-compatible child-description word, 152 when the declared child is present |
| +`0x2f8` | Fixture word `0x6487a9a6`, matching the captured constructor store; native purpose unassigned |

The [page-context report](kext_page_context_report.md) recovers the shared match `node_word4 = low32(token) XOR0x31ae0066`, the address-keyed lookup record and the same registry cell. Original close entry now consumes that lookup under the private node premises. The supplied C export's apparent `void oh70aLVr()` declaration is insufficient: this path consumes incoming X0's low32 token and produces a zero-extended u32 result in X0. Tested matching cases return0; misses return `0xffff5b36`. No symbolic/business error name is assigned.

```text
token -> shared registry lookup -> KBCrypt owner (1088 bytes)
                                    |
                                    +-- +0x2e8 -> FPAppSecurityInfo (152 bytes)
                                    |               |
                                    |               +-- primary mapped region
                                    |               +-- optional secondary region
                                    |
                                    +-- previous / next list links
```

## Cleanup requests, unlink and overwrite order

For the declared normal family, original source requests the following operations. The [mapped-region report](kext_mapped_cleanup_report.md) retains the exact VM adapters/imports and the earlier range proofs. [CR4-CR6]

| Source call | Present when | Arguments / role |
| --- | --- | --- |
| `0xfffffe000a5c0f7c` | Child primary pointer non-NULL | Unwire(kernel-map, rounded start/end,0) |
| `0xfffffe000a5c0fe8` | Same primary branch | Deallocate(kernel-map, exact primary address, u32 extent) |
| `0xfffffe000a5c10cc` | Child secondary pointer non-NULL | Deallocate(kernel-map, secondary address, u32 extent) |
| `0xfffffe000a5c1170` | Child non-NULL | IOFreeTypeImpl(FPAppSecurityInfo view, child) |
| `0xfffffe000a5c15e0` | Matching normal owner retired | IOFreeTypeImpl(KBCrypt view, owner), after unlink and overwrite |

The original owner-free selector checks all256 byte inputs: banks `0xfffffe0007949ed0` / `0xfffffe000792fec0`, key`0x92`, additive`0xe89`, select slot `0xfffffe000847a878` -> `_IOFreeTypeImpl` `0xfffffe000c4ba368`. The owner-view selector uses the same banks, key`0x32`, pool additive`0x38`, selecting `0xfffffe0008472888` -> view `0xfffffe000847ba20`. Original pointer-chain words and modifiers remain in the source artifact; hardware authentication is untested.

The source link updates are the standard previous/next relations below, under readable mutually consistent private nodes. Exact original stores are retained; no atomicity/exclusion guarantee follows from them. [CR3,CR8]

```text
if next != NULL: next.previous = previous   @ 0xfffffe000a5c12b0
if previous == NULL: registry_head = next  @ 0xfffffe000a5c1350
else: previous.next = next                @ 0xfffffe000a5c13e4
```

Singleton, head, tail and middle cases verify the surviving list's complete node bytes, not only the root pointer. Only the expected neighboring link fields change; non-target node contents are preserved. Matching owner bytes are subsequently overwritten. Empty/missing-token cases perform no link update, overwrite or close-backend request.

```text
lookup match
  -> optional primary unwire/deallocation
  -> optional secondary deallocation
  -> child typed-free request, if child exists
  -> repair list head / neighbor links
  -> overwrite owner[0x43f] through owner[0]
  -> owner typed-free request
  -> original local cleanup helper -> return0
```

All22 child typed-free requests precede the first list-repair store. All26 matching cases finish list repair before the first overwrite store and finish all1088 overwrite stores before requesting the owner's typed free. This is source request/store ordering under the models, not proof of native release completion or reference safety.

The overwrite loop's `ADDS X10` at `0xfffffe000a5c14c0` controls termination through the later `CSET` at `0xfffffe000a5c1528`. The intervening counter `ADD X9` does not set flags. In each matching case, the initial count is1088 and the source-derived step is-1; the stores descend from offset1087 to0 exactly once each. The loop has no old-owner-byte load.

Let S be the close wrapper SP after its 0x140-byte frame allocation. The source-derived counter seed is the following u64 expression, modulo2^64:

```text
seed = ((S+0x68) XOR 0xbffb8c1fde3fdf76)
     + (((S+0x68) << 1) AND 0x7ff7183fbc7fbee0)
     + 0x51e6f7fbbfe77eec

for j = 0 .. 1087:
    owner[1087-j] = F8(low8(seed+j))
```

The [source proof and reference](triage_evidence/recover_kext_context_retirement.py) define F8 and prove equality with the original u32 calculation's low byte for every u32 counter word. Its 256-byte table is retained; every private store byte is checked against it. This is a deterministic overwrite pass, not a claim of zero filling, native post-free contents, erasure guarantees or a recovered cryptographic primitive. [CR6,CR8]

## Page-error compositions and VM return models

Two original page executions start from the same private KBCrypt/child objects later consumed by close. One rejects the cleared owner flag with return `0xffff5bef`; the other rejects offset1 with return `0xffff5bd9`. Both restore caller SP. The declared outer caller then supplies the same token to `_oh70aLVr`, clobbering caller-saved registers and preserving memory. Replay checks all nodes, registry head and child bytes at that transition. There is no intervening fixture reset or object rewrite. [CR7]

Both compositions subsequently execute original close to return0, repair the list and perform the same bounded overwrite/release requests. The actual native caller transition, successful page decryption and concurrency semantics remain unestablished.

Two paired VM-return cases change modeled VM return0 to4 for primary-only and primary-plus-secondary cleanup. The complete source PC sequences and final private list/owner bytes remain identical; close still returns0. The inspected source thus does not propagate these modeled VM results through its final return. No actual VM failure, mapping lifetime or native resource balance is inferred. [CR5,CR8]

## Validation, reproduction and remaining interfaces

Six original ranges retain2239 instructions; two original type views, two exhaustive256-input selectors and one all-u32 scalar proof are captured. Twenty-eight independently replayed cases execute1016058 original visits. Replay checks38150 reads /281437 bytes,59029 writes /271670 bytes,29772 logical PAC steps,101 declared backend returns,28 final boundaries and two outer caller transitions. [CR1-CR8]

| Verified event | Count |
| --- | ---: |
| Zero-return closes | 26 |
| Lookup-miss returns | 2 |
| Primary unwire requests | 14 |
| Primary deallocation requests | 14 |
| Secondary deallocation requests | 13 |
| FPAppSecurityInfo typed-free requests | 22 |
| KBCrypt typed-free requests | 26 |
| Checked overwrite bytes | 28288 =26*1088 |
| Unlink -> overwrite -> owner-free order checks | 26 |
| Child-free -> unlink order checks | 22 |
| Page-error/close compositions | 2 |
| Paired VM-return paths | 2 |

The case set covers singleton/head/tail/middle positions, absent child, empty child, primary-only, secondary-only and both-region children, two VM-return variants, upper token bits, maximum u32 token, empty list and missing token. It does not cover all optional resources, owner families or native environmental states. No new Mach right or emission site is established: the recovered VM calls are direct kernel interfaces, and the remaining external operations are declared allocation/free models.

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kext_context_retirement.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kext_context_retirement.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
  Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
  /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_context_retirement.py
```

Source recovery takes O(B+I+256K) time plus bounded SMT solving, with B image bytes, I captured instructions and K selectors. Original lookup/retirement takes O(L+1088) local steps for a terminating L-node list on this branch, excluding modeled backend costs. Recording/replay takes O(B+V+E) time and O(B+J) space, where V is visits, E events and J journals. Native wall-clock latency is not measured.

| Impact | Remaining interface | Discriminating next evidence |
| --- | --- | --- |
| High | KBCrypt allocation/publication | Recover the matching allocation descriptor, node+4 writer, previous/next insertion and registry-head publication in one constructor execution |
| High | Optional resource+`0x188` | Establish its producer/type/extent and complete non-NULL cleanup before assigning full finalization semantics |
| High | Native exclusion/reference lifetime | Trace locking, acquisition/release and concurrent page/close rules; ordering of private requests alone does not prove reference safety |
| Medium | VM/backend effects | Join original lower VM/typed-free behavior to actual initialized map/zone state before claiming resource retirement |
| Medium | Successful page-to-close lifetime | Continue metadata/crypto to completion and establish the real outer callback sequence; current compositions deliberately end the page phase on error |
| Low | Overwrite pattern provenance | Correlate the source pass with original compiler/type context; no cryptographic or erasure-purpose label is inferred from the byte function |

- QG1: Factual source/ABI analysis; no normative conclusion required.
- QG2: CR1-CR8 record premises, dependent claims and falsification probes.
- QG3: Normal close entry, shared lookup, VM/typed-release requests, four list positions, overwrite, return and two explicit compositions are covered. The full interface goal remains incomplete.
- QG4: Byte extents, u32/u64 arithmetic, page-shift premise, loop flags,1088-byte extent and complexity are explicit; source proof and independent replay pass.
- QG5: Misses, NULL fields, neighbor boundaries, VM-return models, optional-resource exclusions and caller-transition premises are distinguished. Private zero returns do not establish native success.
- QG6: Original words, names, views, fixups, reference byte model and actual source-produced state/order are independently checked. Backend/PAC/native gaps remain explicit.
- QG7: Impact-labeled continuation remains bounded to allocation/publication, optional resources, synchronization, backend effects and successful callback lifetime.
