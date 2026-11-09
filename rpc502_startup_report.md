# RPC502 startup prerequisite, private arena and embedded certificates

The earlier RPC502 result `0xffff5bd4` follows a readiness/NULL-allocation path in the retained certificate fixture. Executing the original registered startup callback `0x10045053c` to its actual return, then entering the original RPC502 worker in the same private guest, passes that gate. Two original result carriers point into a 90000-byte arena. The worker subsequently parses the synthetic certificate and two embedded Apple certificates, executes further integer arithmetic, and returns `0xffff5bdb`. This later numeric result is not assigned an authentication-error name.

The readiness byte is published before startup finishes. A byte value of 1, or the initialized encoded status cell alone, does not establish completed startup. The probe requires the original callback return before entering the worker. No readiness byte, internal frame, parser PC, branch, or result carrier is forced. No native target, loader, filesystem, Mach, IOKit, credential, dispatch or synchronization API executes. The full interface investigation remains active.

## Provenance and assumption register

The primary source is the original arm64e image `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Addresses below are preferred virtual addresses in this image. The source matches the arm64e slice at universal-file offset 3407872 in `/Users/___/Downloads/fpx/fairplayd`. Source reads and local compile/parser/solver operations are analysis operations; the target executable is not launched.

[Contracts](triage_evidence/rpc502_startup_contracts.json) retain 23 explicit instruction spans in 10 physical compiler intervals, 1507 consumed pointer/import records, four local proofs, all 256 inputs of the readiness-pointer selector, original encoded certificate arrays and SDK layout compilation. A physical compiler interval is not assumed to delimit a complete semantic routine. [Eight profiles](triage_evidence/rpc502_startup_profiles.json) retain compressed source-visit, state, byte-store and API journals; [independent checks](triage_evidence/rpc502_startup_checks.json) reconstruct source-written arena/certificate bytes and replay each case freshly. The preceding [certificate report](rpc502_certificate_report.md) and all published producers remain frozen.

| ID | Assumption | Dependent results | Stress test / falsification probe | Evidence boundary |
| --- | --- | --- | --- | --- |
| U1 | This exact arm64e image is the intended implementation | All addresses, arrays, tables and recovered roles | Rehash thin/universal files, UUID, original opcodes, fixups and compiler metadata | Source identity checked; actual installed daemon/kext pairing unknown |
| U2 | The registered void callback can be examined from its original entry under the ordinary callback ABI | Startup-to-worker predecessor state | Verify registration literal and call site, entry prologue, preserved SP and actual return; recover all earlier process/loader writers | Callback entry and return established; complete process startup not executed |
| U3 | Declared malloc, entropy, time and logical lock results describe only these private fixtures | Finite initialized/failure paths | Vary entropy/time, NULL allocation, failed time and lock results; stop on unknown outputs/imports/owners | Explicit models; native outcome, scheduling and contention unknown |
| U4 | Original zero-fill/data/fixup state and explicitly seeded worker ABI are the starting environment | Cold gate, global state and worker behavior | Compare lifecycle writers, relocated images, alternate stack/register state and native initialization | Private zero-filled stack initially; original startup stack/image/heap state is carried forward |
| U5 | Heap bytes become known only through modeled defined outputs or actual source writes | Arena reconstruction and subsequent reads | Poison allocations, track knownness, compare every source-store byte, reject unwritten/retired/out-of-extent reads | Unknown heap and failed-time outputs remain blocked; arbitrary stack observer bytes are not definedness proofs |
| U6 | MAX's private single-thread implementation suffices for these executed atomic instructions | Actual post-CASAL continuation | Recheck original opcode/word transitions; compare hardware and concurrent executions separately | Original CASAL executes privately; native PAC, synchronization and ordering remain unknown |
| U7 | Quantum boundaries change observation partitioning only | Continued execution and bounded-memory journals | Compare the complete original-source prefix and completed startup state with 250000 versus 500000 instruction quanta | Retained prefix/state equality checked; no instruction skip or guest-state reset |
| U8 | Independent DER/OpenSSL/RSA/hash readers interpret the recovered bytes as stated | Embedded certificate names and signature relationships | Re-extract original arrays, compare every constructor byte/shift, parse independently and recompute modular exponentiation | Byte and mathematical relationships established; target/native trust acceptance unknown |
| U9 | The synthetic supplemental record is a structural exploration input | The changed worker result and downstream candidate paths | Supply an authenticated record, recover each selection/authentication predicate and actual reply fields | Synthetic certificate is unsigned; later numeric result remains semantically unassigned |
| U10 | A completed bounded increment does not close the broad cross-layer objective | Reporting coverage and continuation priorities | Require the first actual record+28 consumer, accepted protected operation and linked native transport transaction | No new port/IOKit emission or record+28 read is established |

## Registered predecessor and publication order

The earlier [registration analysis](daemon_registration_report.md) establishes the original caller chain. Current source readback includes the callback literal and once call again:

```text
main -> wrapper
          pthread_once(0x1010b70c8, 0x10045053c) at 0x1004414e8
                                   |
                                   v
                     original callback entry 0x10045053c
                       status cell <- 0x8b3dc651
                       malloc(90000), arena descriptor publication
                       readiness byte <- 1
                       entropy/time, arena/state preparation, locks, more state
                       original callback return, SP restored
                                   |
                       explicit public-worker ABI fixture entry
                                   v
                     RPC502 -> certificate parser -> readiness gate
                       -> original arena result carriers
                       -> embedded certificate parsing / integer arithmetic
                       -> error result 0xffff5bdb in this fixture
```

This executes the callback itself, not the wrapper, process loader, main routine, service registrations or complete process lifecycle. X0-X7 are initially zero; the callback has no declared arguments. Its original prologue saves the ordinary preserved registers. The worker ABI entry seeds its documented argument slots/registers while retaining the original callback's guest stack, image globals, heap and logical API state. [U2-U4]

| State / action | Exact source location | Established value or effect |
| --- | --- | --- |
| Callback literal / passed X1 | 1004414d0..1004414dc | 10045053c, with explicit PAC instruction |
| Once call | 1004414e8 | Previously recovered control 1010b70c8 |
| Status publication | 1004506d4 | Store 8b3dc651 at 1010b6360 |
| Initial arena allocation | 10032a4dc..10032a4e8 | W0=00015f90 -> size_t64 value 90000 bytes |
| Arena pointer publication | 10032a520 | Store malloc result at 1010b5ef8 |
| Readiness publication | 10046c748..10046c750 | Load frame+200 pointer; STRB 1 at 1010c5798 |
| Declared startup time query | 1002dc308 | gettimeofday(pointer,NULL); source reads outputs next |
| Normal original callback return | Actual return to private LR trampoline | 5682957 tracked steps in the default environment; X0 is not interpreted as a void return status |

The readiness store occurs at tracked step 486; the default time call occurs at step 43813. The complete callback returns at step 5682957. These are software observation counts, not durations. The entropy/time variant returns at step 5668088; its different state and path length are retained rather than normalized away. [U3,U7]

## Readiness gate and original allocation results

The worker's pointer producer `0x100969118..0x100969170` resolves `frame+0xe0` to `0x1010c5798`. Its two 256-byte bank addresses are `0x100fc4130` and `0x101031ea0`; all 256 input values collapse to index `0x100e` in pointer pool `0x1010a1960`. Slot `0x1010a99d0` has original raw word `a602f52a00000800`, decoded target `0x12af502a6`, and signed bias `-0x29e8ab0e`. Their sum is the readiness address. Original format12 decoding is checked independently. [U1,U4]

At `0x100a03408`, X25 is explicitly zeroed. The source loads the readiness pointer from frame+e0, reads one byte at `0x100a03424`, and compares it with 1. The full-width local arithmetic proof keeps all inherited dispatch-seed/W27 values symbolic; only byte value 1 enables the readiness-dependent term. The following concrete destinations apply to the retained seed `W9=0x4891`, `W27=0xa`:

| Condition | Table index / original slot | Target / local effect |
| --- | --- | --- |
| Readiness byte !=1 | 4891 / 10105e378 | 1009757d0; restore shared word, X25 remains NULL |
| Readiness byte ==1 | a22f / 10108b068 | 1006521d4; original allocator continuation |
| Later X25==NULL, seed a7ed | a83b / 10108e0c8 | 100890ff4; local NULL-result error path |
| Later X25!=NULL, seed a7ed | a7ed / 10108de58 | 100a448b0; non-NULL continuation |

The common block at `0x100a5c3ec` materializes `0x74c29d85` regardless of the selected destination. Its presence alone does not establish an error: the non-NULL case also visits this block. On the cold NULL path, the encoded status reaches outer record+32 and decodes by XOR `0x8b3dc651` to `0xffff5bd4`. The full64 candidate-pointer and all-u8 readiness formulas are separate proof obligations. [U1,U6]

The original shared word at `0x1010b5de0` remains protected by the observed CASAL/restore sequence. On initialized paths, the original restore at `0x1009757d0` carries X25=`0x5000014bec`, then X25=`0x5000014564`; both lie inside the private arena starting `0x5000000000`. These are source result carriers inside an arena, not Mach names or independent host malloc allocations. Their full object schemas and requested suballocation extents remain unknown. The first later candidate carrier is saved at frame+258 by `0x100a5c3cc`; the second observed allocation takes another original continuation. No unobserved common return is invented. [U5,U6]

## Arena, opaque locks and environment ABI

The observed arena descriptor begins at `0x1010b5ef0`. This partial view is based on original stores; unknown fields do not receive type or policy names.

| Descriptor offset, bytes | Width | Source initialization |
| --- | --- | --- |
| 8 | 64 bits | Arena pointer; STR at 10032a520 |
| 16 / 20 | 32 / 32 bits | 0 / 10; STP at 10032a528 |
| 32 / 36 | 32 / 32 bits | 1 / 0; STP at 10032a530 |
| 40 | 64 bits | 1aa4071f0801765b; STP at 10032a544 |
| 48 / 56 / 64 | 64 bits each | Zero stores at 10032a544/548 |
| 72 / 80 | 64 bits each | Arena-list pointer publications at 10032a56c/568 |

The original constructor writes arena head words at offsets 0 and 8, links at 24/32, and end-region words at 89976/89984. The initial head values include `0x5e878c613b8123ea` and `0x5e878c613b828362`; encoded word meanings are not assigned from their appearance. Only 3522 of the 90000 arena bytes are source-known at normal startup return. The arena is not treated as fully initialized or zero-filled. Independent verification reconstructs every retained arena source-store byte and the complete final knownness mask. [U5]

| Boundary | Exact local ABI / observation | Scope limit |
| --- | --- | --- |
| malloc | size_t64; first request 90000 bytes at 10032a4e8 | Fresh private poisoned owner; no native allocator |
| arc4random | u32 results at 100409574,1002dc3a0,1002dc400 | Default sequence 12345678,89abcdef,fedcba98; declared entropy |
| gettimeofday | 16-byte SDK timeval; sec64 at+0, usec32 at+8; second argument NULL | Model defines 12 bytes on status0; padding remains unknown |
| Actual time consumption | LDR W at 1002dc30c reads+0; LDR W at 1002dc334 reads+8 | Only low32 seconds and 32-bit microseconds observed here |
| Startup lock allocation | Four dedicated 200-byte malloc objects at 10019385c | Source writes only first8 bytes before init |
| Startup lock init | pthread_rwlock_init(object,NULL) at 100130fcc | Logical serial state/status; 192 opaque bytes remain unknown |
| Worker once/lock objects | Two 200-byte objects, init site100de69f8 | Original worker path zeroes all200 bytes before init |

Default time outputs are `tv_sec=1760000000 s`, `tv_usec=123456 us`; the variant supplies `0 s`, `999999 us`. These are declared API outputs, not observations of the user's host clock. The failed-time model writes no outputs and stops at the immediate first source read. It does not promote existing stack bytes to valid time data. The random-state loop at `0x100346520..0x10034656c` is retained as original shifts/masks/table loads/XOR/stores; no complete named PRNG identification is claimed. [U3,U5]

The new lock model accepts live owned SDK-sized storage and NULL attributes, records its pre-call bytes/knownness and represents initialization logically. It does not synthesize opaque native lock bytes. This allows the actual startup predecessor, which has only eight known bytes, without changing the frozen earlier model's narrower all-zero fixture precondition. Target concurrency, lock ordering under contention and initialization-failure feasibility are unknown. [U3,U6]

## Embedded certificate producer and independent byte relationships

The initialized worker allocates 1219 and 1035 bytes at original site `0x100346714`. Its descending byte stores at `0x1003f0e5c` construct the complete original arrays XOR `0x98`, including four leading bytes. Its ascending stores at `0x10030980c` shift bytes `[4,N)` onto `[0,N-4)`. The final four bytes retain their prior tail values. Those residual bytes are outside the recovered DER certificate and are not included in its hash or signature computation. [U5,U8]

| Embedded bytes | Original encoded address / extent | Decoded prefix4 | DER extent / SHA-256 |
| --- | --- | --- | --- |
| Apple Root CA | 100e9eee0 / 1219 bytes | 00000000 | 1215 bytes; b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024 |
| Apple Key Services Certification Authority | 100f45a60 / 1035 bytes | 01000003 | 1031 bytes; 642e9d2366c496f1ecf09b3e88b4c16e10a92cb2340f4557c92b25063f0ff531 |

The four-byte prefixes' semantics are unknown. [Root DER](triage_evidence/rpc502_startup_root.der) and [Key Services DER](triage_evidence/rpc502_startup_key_services.der) are extracted reproducibly from the original file arrays, independently of guest output snapshots. Every one of the 2254 original constructor bytes and 2246 shifted DER bytes is checked against the source-store journals. Original root-schema callbacks subsequently receive each resulting heap DER pointer. These are actual original-code continuations, not observer-injected certificate callbacks. [U8]

| DER field / relationship | Root | Key Services |
| --- | --- | --- |
| Subject identifying string | Apple Root CA | Apple Key Services Certification Authority |
| Issuer identifying string | Apple Root CA | Apple Root CA |
| Serial bytes | 02 | 22 |
| Validity strings, raw UTCTime | 060425214036Z .. 350209214036Z | 120201002257Z .. 270201002257Z |
| Public modulus / exponent | 2048 bits / 65537 | 2048 bits / 65537 |
| Independent RSA/SHA-1 byte equality under Root key | Root self-signature: true | Key Services signature: true |

An independent bounded TLV reader and a fresh local OpenSSL parse agree on the retained fields. Python integer modular exponentiation under the issuer key yields the exact `00 01 FF...00` block and SHA-1 DigestInfo bytes computed from each original TBS span. This establishes a mathematical signature relationship between these public byte records. It does not establish target trust-anchor selection, current system trust, revocation, date-policy acceptance or successful RPC authorization. Those require the target's own predicates and a feasible protected operation. [U8,U9]

## Finite outcomes and verification

| Case | Tracked steps | Original startup returned | Final readiness | Actual boundary / result |
| --- | ---: | --- | --- | --- |
| Cold worker | 331248 | No callback entered | 00 | Worker return ffff5bd4 |
| First arena malloc returns NULL | 406 | No | 00 | Unmapped write at10032a55c, STR X9,[X0] |
| Time API returns -1, no outputs | 43814 | No | 01 | Unknown-output read blocked at1002dc30c |
| Startup lock init returns17 | 2240039 | No | 01 | Unmapped read at1003868d8, LDUR X10,[X10,-16] |
| Startup budget10000 | 10000 | No | 01 | Budget stop; worker never entered |
| Initialized worker | 12598351 | Yes | 01 | Worker return ffff5bdb |
| Quantum250000, worker prefix500000 | 6182955 | Yes | 01 | Declared worker instruction-budget stop |
| Alternate entropy/time, worker prefix500000 | 6168086 | Yes | 01 | Declared worker instruction-budget stop |

The failed-API cases describe counterfactual model outputs and the resulting original-code boundaries; they are not native defect or exploitability claims. No successful authentication or protected operation is established by either complete worker return. The later status is written as encoded `0x74c29d8a` at outer record+32 and decoded to `0xffff5bdb`. Across these paths the outer record still reads only offsets0/4/16/24/36; offset28 remains unconsumed. No Mach name, destination, right transfer, IOKit call or new port-emission location is added. [U3,U9,U10]

All **27841267 independent assertions** pass. The finite corpus covers **27574672 retained original-source visits**, the same number in complete fresh replays, 59399 distinct original instructions, 23 source spans, 10 physical compiler ranges, 1507 consumed pointer/import records, four unsatisfiable local obligations, two embedded DER records and two independent signature-byte relationships. General compressed journals reset at declared quanta; inherited specialized body/callback/core-store observers retain their sequence. The last worker tail retains the frozen engine's specialized/source-owner journals, not an invented complete general stack-store log. Startup stack-store journals are complete for the retained startup quanta. All source visits remain ordered and byte-attested.

The quantum-subdivision check compares the entire 6182900-visit retained prefix against the longer initialized sequence and checks identical completed startup snapshots, readiness points and callback/worker-entry events. Changing the declared entropy/time inputs changes actual original state and startup path length. Software complexity is O(C*(B+V+E+S)) for cases, input bytes, visits, events and snapshots, plus bounded solver and integer modular-exponentiation costs. Solver timeout is60000 ms per obligation. Source spans and widths are in bytes/bits; no hardware duration is inferred from instruction counts.

Reproduction from `/Users/___/dev/dylex/extracted`:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_startup_cases.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_startup.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_startup.py
```

[Preservation](triage_evidence/rpc502_startup_preservation.json) checks all1000 preceding artifacts:994 remain byte-identical, with only the four reporting indexes, active-status file and delivery aggregator updated. The three original supplied inputs remain unchanged. [Scoped delivery gates](triage_evidence/rpc502_startup_quality_gates.json) retain source/UUID, dependency, replay, preservation and local-link evidence. No binary or IDB is written.

| Gate | Scoped result |
| --- | --- |
| QG1 | Pass: descriptive technical analysis; no normative premise. |
| QG2 | Pass:U1-U10 identify dependencies and falsification probes. |
| QG3 | Pass for this increment:registered predecessor, readiness/NULL gate, arena, environment/lock ABI and embedded certificate byte relationships; broad goal remains active. |
| QG4 | Pass:u8/u32/u64, signed pointer bias, byte extents, timeval units, source-store reconstruction, SDK compilation and bounded algorithms explicit. |
| QG5 | Pass:early readiness versus completed startup, callback versus process startup, allocator NULL versus certificate error, opaque lock paths, budget versus return, DER versus authentication remain distinct. |
| QG6 | Pass:original source/fixups/metadata/arrays, all eight fresh replays, complete source-visit digests, independent byte/DER/RSA/hash checks and four local proofs. |
| QG7 | Pass:bounded continuation table below. |

## Bounded continuation opportunities

| Impact | Next evidence | Consequence resolved |
| --- | --- | --- |
| High | Trace the producer and use of encoded74c29d8a through the completed initialized worker. | Meaning and exact predicate of ffff5bdb without importing an error name. |
| High | Recover the actual candidate/issuer selection, embedded-certificate roles, integer operand codecs and signature predicates. | Whether these records are anchors, intermediate candidates or another fixed certificate policy; target acceptance versus independent signature validity. |
| High | Follow the first feasible original consumer of outer record+28 and accepted output record. | Protected operation ABI and next daemon/kext/Mach boundary. |
| High | Recover all readiness/global writers and full once/loader/process lifecycle. | Whether early publication is externally observable or serialized by another prerequisite; no concurrency conclusion follows from publication order alone. |
| Medium | Recover arena block headers, suballocation extents, ownership and exhaustion/retirement paths. | Complete local allocator contract beyond the two actual result carriers. |
| Medium | Trace time/entropy mixing and source-state consumers. | Seed representation, low32 time behavior and any relation to operation output; PRNG identity remains unknown. |
| Medium | Recover native lock-init failure handling and actual platform feasibility separately. | Meaning of the guarded unmapped-read continuation under declared status17. |
| Low | Compare these spans with the active IDB when its bridge is available. | Current database correspondence; original file-backed evidence is already reproducible. |
