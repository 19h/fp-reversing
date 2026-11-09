# RPC502 outgoing OOL normalization, copy factory and prefix cleanup

The daemon's successful reply flags `0x01000101` survive the original 64-bit descriptor normalizer and select direct VM copyin in the matching kernel. For positive extents, original body conversion calls `0xfffffe000bdd15a4` with source map, user VA, zero-extended u32 extent, options1 or`0x201`, and a copy-object output pointer. The deallocate byte supplies bit0; source-map+`0xb0` bit25 supplies optional bit9. [RC1-RC4]

Under explicit small-copy map/range/global predicates, original factory instructions construct type3 objects and request removal of the sender region before publishing each object. The body signs its pointer using the descriptor address and discriminator `0x5d4f`. Failure on descriptor1 reaches original prefix cleanup, which discards descriptor0's already-created object and clears its descriptor pointer. These are private original-code results with modeled VM/allocator effects; actual application success, native source removal and a complete FairPlay transaction remain unknown. [RC2-RC8]

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| RC1 | Original daemon and collection are the intended static images | Producer flags, addresses and matching implementation | Rehash originals and recapture inspected functions; attest actual module pairing separately |
| RC2 | The original MIG response fixture plus declared count substitutions represents the stated application outputs | Reply descriptor and inline-body inputs | Reach real application success and compare all outputs; application execution is not supplied by these cases |
| RC3 | Prior header/namespace processing yields the declared internal send header and two normalized descriptors | Body-converter entry state | Join the original full Mach2 copyin path and actual namespace objects; the header conversion remains a fixture here |
| RC4 | Source map has page shift14, supplied min/max bounds, null+`0x58`, and declared+`0xb0`; global `0xfffffe0007e6a01c`=0 | Selected type3 factory or type2 frontier | Observe actual map/global state and execute other policy paths; small size alone does not establish the native copy type |
| RC5 | Private objects and source/backing buffers are valid and disjoint; allocation/copy/lock/removal models apply | Copied bytes, ordering and cleanup continuations | Validate native allocation provenance, aliases, errors and partial copies; failed-copy models write no bytes |
| RC6 | Explicit logical PAC and pre-cleanup/release models return normally | Signed-pointer storage and cleanup continuation | Verify native authentication, message-integrity checks and complete allocator retirement separately |
| RC7 | Zone-view size48 and private metadata describe these fixtures | Header construction/zeroing/discard witnesses | Read native zone size and metadata; actual runtime allocation extent remains unknown |
| RC8 | Independent CPU/effect/field oracles apply to these finite cases | Verification totals and conditional composition | Rebuild source, replay every read/write and reconstruct effects from fresh arguments; runtime reachability is separate |

Primary source is collection `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The retained daemon-emitter fixture belongs to thin image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. [Source capture](triage_evidence/rpc502_reply_copyin_source.json) contains seven compiler-bounded functions /2,688 instructions and14 exact instruction-role checks. Descriptive names of stripped helpers are roles, not exact symbols. [RC1,RC2]

```text
original MIG-emitted descriptor bytes + declared output counts
       -> original normalizer BCC3FE8, 64-bit form
       -> declared internal send-header/body assembly
       -> original OOL body converter BCC42F0
       -> original VM copyin BDD15A4
            |
            +-- small/map predicates -> backing copy -> type3 construction
            |                           -> sender-region removal request
            |                           -> publish copy -> sign descriptor
            |
            +-- large input -> working type2 header -> lookup frontier

descriptor1 error -> original BCC2A1C prefix cleanup
                   -> original type3 discard of descriptor0
                   -> clear descriptor0 pointer
```

## Normalization and VM boundary

The 16-byte descriptor layout is `{address:u64, flags:u32, extent:u32}`. The original normalizer at `0xfffffe000bcc3fe8` accepts the64-bit form with W3=1 and stores `flags & 0xff0001ff`. For the MIG flags this leaves `0x01000101` unchanged. Its physical-copy staging accumulator remains0 for all five tested count pairs, including32769. This is specific to these virtual-copy/deallocate flags. [RC1-RC3]

| Original site | Established local contract |
| --- | --- |
| `0xfffffe000bcc40ac`-`...40f8` | Normalize type1 memory descriptor; accumulate large staging only when copy/deallocate low bytes are both zero |
| `0xfffffe000bcc44a4`-`...44e4` | Extent0 clears descriptor address without VM copyin; positive extent selects direct copyin for MIG flags |
| `0xfffffe000bcc44c0`-`...44d4` | VM option bit0 = nonzero deallocate byte; optional bit9 derives from source-map flags |
| `0xfffffe000bdd16b4`-`...16d8` | Small path requires selected option bits clear, extent<=32768 and aligned start >= map minimum |
| `0xfffffe000bdd183c`-`...1868` | Rounded end < map maximum, rounded end >= minimum, aligned start < maximum; global gate selects the tested direct factory |
| `0xfffffe000bdd1eb4` | Copy bytes from source map into allocated backing; this leaf's effects are modeled |
| `0xfffffe000bdd1f0c`-`...1f2c` | Construct extent-preserving type3 header; sign backing pointer with discriminator `0xb7af` |
| `0xfffffe000bdd1f30`-`...1ffc` | Option bit0 selects page-rounded source-region removal request before publication at `...1f38` |
| `0xfffffe000bcc4a30`-`...4a44` | Sign nonnull copy pointer using descriptor address and discriminator `0x5d4f` |

Original VM-entry arguments are X0=source map, X1=user address, X2=zero-extended extent, W3=1 or`0x201`, X4=copy output pointer. Both option values follow the same tested small-copy path. For extent0, body conversion bypasses this entry altogether. The wire extent remains u32 while the generated object's+`0x20` extent is u64. [RC4,RC8]

## Construction, source removal and failure-prefix ownership

| Type3 header offset | Extent | Source-produced value in these cases |
| --- | --- | --- |
| +0 | 8 bytes | Logical allocated backing pointer; native DA signing is modeled |
| +8..`0x1f` | 24 bytes | Zero |
| +`0x20` | 8 bytes | Original input extent |
| +`0x28`..`0x2b` | 4 bytes | Zero |
| +`0x2c` | 1 byte | Zero, rather than an asserted source-map page shift |
| +`0x2d` | 1 byte | Type3 |
| +`0x2e` | 1 byte | Fast-path flag0 |
| +`0x2f` | 1 byte | Zero |

For source VA A, extent N and supplied page shift14, the removal request covers `[A & ~16383, (A+N+16383) & ~16383)`. The tested arithmetic does not wrap. Source map differs from the private `kernel_map` cell and has null+`0x58`, producing raw removal mode2. Native removal is not executed: private source bytes remain readable in the observer, and that continued readability is not evidence of a surviving native mapping. [RC4,RC5]

| Body-conversion case | Local result / frontier | Resource protocol observed |
| --- | --- | --- |
| Both OOL extents0 | Return0; both descriptor pointers0 | No VM copyin or source-removal request |
| Positive small extents, predicates satisfied | Return0; pointers to produced type3 objects | Backing copy, source-removal request, then publish/sign each object |
| Backing allocation model fails | Return `0x400` | No object for failed descriptor; clean previously converted prefix |
| Backing byte-copy model returns5 | Return `0x1000000c` | Release unpublished backing; clean previously converted prefix |
| First extent32769 | Stop before entry-list lookup | A working type2 header is constructed; no completed/published copy or source-removal request established |

These are local body-converter results, not a claim about final Mach2 API status after all higher layers. The type2 frontier is original call `0xfffffe000bdd17a0` to `0xfffffe000be318e8`. At that boundary the working header has source VA at+`0x10`, extent32769 at+`0x20`, page shift14 at+`0x2c` and type2 at+`0x2d`; the body descriptor still contains its user VA. Its completion and publication are unresolved. [RC3-RC6]

On a second-descriptor failure, original cleanup at `0xfffffe000bcc4af0` passes the converted-prefix count1 to `0xfffffe000bcc2a1c`. That helper authenticates descriptor0 with discriminator `0x5d4f`, invokes original `_vm_map_copy_discard` at `0xfffffe000bdc6308`, then clears descriptor0's pointer at `...bcc2a60`. The discard clears the payload pointer before release calls and models header zeroing before the header-release request. Descriptor1's failed conversion is not treated as a committed object. [RC5-RC8]

This order separates two lifetimes: descriptor0's sender-region removal request has occurred before descriptor1 fails; discarding its kernel copy afterward does not itself restore that source mapping. The model establishes requested operations and ordering, not actual source unmapping, allocator retirement, successful sends, or daemon cleanup behavior after a send failure. See [type3 copyout/discard](kernel_reply_copyout_report.md) for the corresponding receiving-side protocol. [RC3-RC8]

## Validation and remaining joins

[Profiles](triage_evidence/rpc502_reply_copyin_profiles.json) contain10 original normalizer components and36 body components:16 successes, eight allocation failures, eight byte-copy failures and four type2 frontiers. Extent pairs are `(0,0)`, `(1,37)`, `(4096,8192)`, `(32768,1)` and `(32769,1)`. The tests vary embedded/external kmsg storage classes0/2 and the source-map option bit. Error fixtures use `(1,37)` and fail descriptor0 or1 separately. These counts are explicit substitutions into a retained original MIG-emitted response fixture; they do not establish real application outputs. [RC2,RC8]

[Checks](triage_evidence/rpc502_reply_copyin_checks.json) freshly recapture source and independently replay12,430 original instruction visits,2,276 reads /15,832 bytes,2,446 writes /18,124 bytes and46 final boundaries. They verify52 VM-entry argument records,64 logical data-sign steps,240 declared callback models and40 independently rebuilt effect patches /180,772 bytes. The field/ownership oracle checks32 type3 constructions,32 removal-before-publication joins, eight prefix discards,16 backing-release requests, eight header-release requests and four pending type2 headers. [RC8]

Successful copies total180,388 bytes: four fixture combinations per successful extent pair give `4*(1+37+4096+8192+32768+1) = 180380` bytes; eight descriptor0 prefixes add8 bytes. Eight modeled header-zeroing effects add `8*48 = 384` bytes, yielding180,772 effect bytes. No target VM region or allocation is actually removed/freed. Finite execution and exact source inspection are identified separately; no SMT theorem or full-domain native claim is made. [RC5-RC8]

Reproduce in order:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_reply_copyin.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_reply_copyin.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_reply_copyin.py
```

Time is O(captured bytes + source visits + copied bytes); space is O(private RAM + retained journals). Original files, IDBs and saved memories are not modified. No native target, IPC, VM, hardware authentication, source-region removal or allocator release executes. The full investigation remains active. [RC1-RC8]

| Impact | Remaining bounded interface | Required evidence |
| --- | --- | --- |
| High | Native map/global predicates and actual reply type | Attest source map/global state and real application-produced OOL extents |
| High | Type2 builder completion | Recover range lookup, entry construction, publication and failure ownership beyond the retained frontier |
| High | Full outgoing header/namespace -> queue -> kext join | Execute original complete copyin and transport with established object/right provenance |
| High | Post-send-error daemon ownership | Trace framework destruction/deallocation after partial body conversion; do not assume rollback |
| Medium | Receiving mapped-region lifetime | Join produced copy objects to kext copyout, context publication and close/unwire/free |
| Low | Zero-length result semantics | Trace whether application/downstream consumers assign special meanings to null OOL results |

- QG1: Pass. Factual IPC/VM interface analysis.
- QG2: Pass. RC1-RC8 identify assumptions, dependent results and falsification probes.
- QG3: Pass for outgoing descriptor normalization, conditional factory and prefix cleanup; native joins and type2 completion remain open.
- QG4: Pass. u32/u64 widths, byte layouts, page arithmetic, exact counts and complexity are explicit.
- QG5: Pass for scope. Zero, threshold, type2 frontier, per-descriptor failures, partial cleanup and modeled source removal are separated.
- QG6: Pass. Original hashes/functions/roles, retained producer bytes, fresh replay and independent effect/field oracles are retained.
- QG7: Pass. Impact-labeled continuation follows the immediate unresolved cross-layer interfaces.

Publication checks: [preservation](triage_evidence/rpc502_reply_copyin_delivery.json), [scoped gates](triage_evidence/rpc502_reply_copyin_quality_gates.json).
