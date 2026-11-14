# Conditional constructor validation, 57-byte growth and NULL cleanup

The original initializer establishes the previously unresolved SP+0x260 value as `u64(SP+0x44b9fd860c43a9f6)`. Supplying that one additional 8 B field as a separate conditional entry permits recovery of a private U validation record, an original `malloc(57)` request, and distinct NULL/success lifecycle paths. All twelve retained initializer profiles satisfy the address-dependent equation. A continuous initializer-to-current-caller epoch remains unknown. [CB1-CB6; CB-A1-CB-A3]

Four inherited controller classes, sizes 34/4/34/4, cover all 76 parents. Each allocation outcome is crossed with two explicit ABI clobber patterns. Forty-four original instruction intervals produce 304 parent-specific terminal exports. The allocator returns, fresh model owner and exact owner retirement at declared void frees are premises; no native allocation or free executes. [CB1-CB6; CB-A2-CB-A5]

```text
76 inherited conditional states at 1005f149c
  + additional SP+260 / 8 B address-dependent root premise
  -> U validation through private record R
  -> raw extent 10ecc426 -> 10ecc44a; malloc argument 21 -> 57
  -> pending malloc(57) at 10083dd38
     + declared NULL return
     | -> pending free(T) at 1003174d0
     | -> declared free(T); acquire/release shared gate; fill all U bytes
     | -> pending free(U) at 100336dec
     | -> declared free(U); S+0 = 0 at 1006d1354
     | -> STOP 10074abc8 before undefined S+30 / 8 B
     + declared fresh F/57 B return
       -> descending T/21 B copy; rewrite F+1..4
       -> U+8 = F; U+10 and U+14 = 10ecc44a
       -> pending free(T) at 100514c64
       -> declared free(T); 38 further F byte stores
       -> F/57 B fully defined; S+0 still U
       -> STOP 1008a2704 before undefined SP+2b0 / 8 B

J/552 B is unchanged. Native epochs and transport-buffer identity are unknown.
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CB1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_constructor_buffer.py) retains source words, fixups, byte/frame journals and explicit premises. |
| CB2 | [Constructor-gate parent](daemon_constructor_gate_report.md), its [checks](triage_evidence/daemon_constructor_gate_checks.json.zst), and twelve initializer profiles in [bank-origin checks](triage_evidence/daemon_return_bank_origins_checks.json.zst). |
| CB3 | [Current checks](triage_evidence/daemon_constructor_buffer_checks.json.zst): four prefixes, sixteen continuation classes, 44 intervals and 304 terminal exports. |
| CB4 | [Independent replayer](triage_evidence/replay_daemon_constructor_buffer.py) and [receipt](triage_evidence/daemon_constructor_buffer_replay.json.zst): complete GP/SP/Q/NZCV frames, byte events, logical authentication and exact saved-pointer custody across declared ABI returns. |
| CB5 | [Auditor](triage_evidence/audit_daemon_constructor_buffer.py) and [receipt](triage_evidence/daemon_constructor_buffer_audit.json.zst): all-parent dependency admission, ABI/owner transitions, fault controls, lifecycle contracts, initializer provenance and six source equations. |
| CB6 | [Publication verifier](triage_evidence/verify_daemon_constructor_buffer_publication.py): pinned replay, fresh admissions/contracts/equations/origins, exact manifest delta, original-input preservation and decoded path hygiene. |

## Address-dependent root and private validation interface

Initializer instructions `0x10061a5c8..0x10061a5d4` build `0x44b9fd860c43288a`; instructions `0x10061a5dc..0x10061a5e8` add SP+0x816c and store the result at SP+0x260. The intervening unrelated byte store is excluded from the scalar root equation. Each of twelve initializer profiles has exactly one overlapping 8 B writer at `0x10061a5e8`. The universal equation accommodates four distinct frame placements instead of substituting a single captured pointer. At current outer SP=`0x6800060100`, the supplied root is `0x44b9fdee0c49aaf6`. [CB1-CB6; CB-A1-CB-A3]

This is 8 B of additional definition per parent, `76*8=608 B` across the admission cohort. The eleven earlier pointer premises remain inherited: 88 B earlier plus 8 B here gives 96 B in the combined conditional entry. No payload byte is supplied by the new root premise. Logical branch `0x1005f14a4` targets `0x1005015e8`, IA modifier `0x0f65`, through the actual inherited load at `0x1005f1498`. Stores at `0x1005015fc`, `0x100501600` and `0x100501618` retain callback `0x100751f0c`, U and the encoded root in private stack fields. [CB1-CB6; CB-A2-CB-A4]

Internal call `0x10057f5ec -> 0x10045f984`, IA `0x0290`, receives private record R=`SP+0x10cb8`. Its source decoder and validation path read U fields and selected T bytes. Exact conventional operation identity remains unknown. [CB1-CB6; CB-A1-CB-A4]

| R offset / width | Retained raw value | Original writer |
| --- | --- | --- |
| +0x00 / u32 | `0x76d8ea81` | Callee status store `0x1004aa840` |
| +0x04 / u32 | `0x1c6f73b6` | Caller `0x10057f57c` |
| +0x08 / pointer64 | U=`0x6600060000` | Caller `0x10057f564` |
| +0x10 / u32 | `0x9347f4ce` | Caller `0x10057f56c` |

The returned raw status differs from the `0x8b3dc651` word used at other adapter boundaries. Store `0x100501608` also writes raw word `0x76657273` at SP+0x6fc4. The word alone does not establish wire serialization, byte order on a transport or a conventional record format. U remains a 48 B model object with 40 defined bytes and eight unknown bytes at this stage. [CB1-CB6; CB-A4-CB-A6]

## Encoded extent and allocator ABI

`LDP W9,W8,[U,#0x10]` at `0x100709a2c` reads the duplicated raw extent `0x10ecc426`. Given source phase W20=`0x8b3dc645` and W14=`0x6cf4`, instructions `0x100709a64..0x100709ad0` establish, for every u32 capacity c and append operand a, `new_raw=u32(c+a-20)`. The retained a is `0x38=56`, giving a 36 B increase. Count-producing arithmetic at `0x10083dd08..0x10083dd1c` establishes `size_t_request=zero_extend64(u32(raw+0xef133bef))` under its declared source phase constants. The intervening table load affects a different subsequent computation and is excluded from this count-only equation. [CB1-CB6; CB-A1-CB-A4]

Thus `u32(0x10ecc426+0xef133bef)=21 B`, and `u32(0x10ecc44a+0xef133bef)=57 B`; `21 B+36 B=57 B`. These local equations establish the allocator extent interpretation for these fields and source phases. They do not prove all consumers use the same decoding. Pending call `0x10083dd38` resolves through the original fixup load at `0x10083dd30` to `libSystem/_malloc`, logical IA `0x6aa4`, with full X0=`57`. [CB1-CB6; CB-A1-CB-A5]

| Pending imported emission | Arguments | Declared continuation |
| --- | --- | --- |
| `0x10083dd38`, malloc, IA `0x6aa4` | X0=57 B | X0=0 or fresh F=`0x6600070000`/57 B, initially undefined |
| `0x1003174d0`, free, IA `0x46a2` | X0=T=`0x6600050000`/21 B | Void return; retire exactly T |
| `0x100336dec`, free, IA `0x46a2` | X0=U/48 B | Void return; retire exactly U |
| `0x100514c64`, free, IA `0x46a2` | X0=T/21 B | Void return; retire exactly T |

All declared returns preserve SP, X18..X29 and low64(Q8..Q15), set X30 to call+4, and supply explicit caller-clobbered GP/Q/NZCV fixtures. Two SIMD/flag patterns are crossed with both allocator outcomes. Void free leaves a deliberately non-status X0 fixture. Borrowed errno-cell bytes are invalidated at each declared return; retired-owner bytes become undefined and their model owner is removed. No native API or allocator behavior is measured. [CB1-CB6; CB-A3-CB-A5]

## Failure and growth lifecycle contracts

The NULL route first requests free(T). After its declared return, it fills every U byte in descending address order at `0x1002a9a04`, including the eight previously unknown bytes. The byte values vary; a zero-fill interpretation is false. The same interval acquires shared gate `0x1010b5de0` by `CASAL W13,W10,[X8]` at `0x1003adb90`, `0x5d96 -> 0xa94ef`, and releases it with the plain store at `0x1002a7dcc`, restoring `0x5d96`. This identifies another source lifecycle use of the previously recovered gate; native concurrency behavior remains unknown. [CB1-CB6; CB-A1-CB-A5]

Between acquisition and release, original byte writer `0x1001fb314` fills `0x65001151be..0x650011525b` descending, 158 B; `0x1002e7418` fills `0x650010011c..0x65001001c9` descending, 174 B. The total is `158 B+174 B=332 B`. Three 8 B stores update the same descriptor/header interfaces used during construction. These establish conditional source cleanup effects; complete arena allocation/coalescing and native ownership semantics remain unknown. [CB1-CB6; CB-A1-CB-A5]

| Original cleanup writer | Address / width | Raw stored value |
| --- | --- | --- |
| `0x1002c61b4` | D+40=`0x1010b5f18` / 8 B | `0x1aa4071f08018377` |
| `0x100223e14` | `0x6500100008` / 8 B | `0x5e878c613b827646` |
| `0x1001eab24` | `0x650011525c` / 8 B | `0x5e878c613b827646` |

After pending free(U) and its declared void return, `0x1006d1354` writes zero to S+0. T and U are retired in the model. Execution stops at `0x10074abc8` before reading undefined S+0x30/8 B. S retains 53 defined and eleven undefined bytes. The pending field was already among the inherited unknown S bytes; no substitute data is supplied. [CB1-CB6; CB-A2-CB-A5]

The successful allocation route executes an original descending 21 B copy: `LDRB` at `0x100758b8c` reads T+i and `STRB` at `0x100758b90` writes F+i, i=20..0. Four byte writers then rewrite F+1..4 to `b9 67 06 b1`. U+0 becomes zero, U+8 becomes F, and U+0x10/U+0x14 become raw `0x10ecc44a`; these stores occur before pending free(T). At that boundary F has 21 defined and 36 undefined bytes. [CB1-CB6; CB-A1-CB-A5]

| U field | Original publication site | Retained value before free(T) |
| --- | --- | --- |
| +0x00 / u64 | `0x10070f4a8` | 0 |
| +0x08 / pointer64 | `0x10070f4b4` | F/57 B |
| +0x10 / u32 | `0x10070f4bc` | `0x10ecc44a` |
| +0x14 / u32 | `0x1006b1960` | `0x10ecc44a` |

After the declared free(T), 38 original byte stores define all 36 suffix bytes F+21..56 and rewrite F+15/+16. The final 57 B is identical across the retained success classes and ABI patterns:

```text
06b96706b135bd9145be84e9f3294b56ee8a446d91be78bca6f224f6ead548dc1
edc4606892f2c7089bf1be39ed56dc2be8568ed1d86b43775
```

S+0 remains U. U retains eight unknown bytes at offsets +0x1c..+0x1f and +0x2c..+0x2f. T is retired. The final stop is `0x1008a2704`, before undefined private SP+0x2b0/8 B at `0x68000603b0`. The complete original success successor requires 144739 instruction visits; raising the extractor observation slice from 100000 to 1000000 permits that interval to finish without changing any guest instruction or state. This is an observation-limit correction, not evidence of a native hang. [CB1-CB6; CB-A2-CB-A6]

Neither branch writes J/552 B. No new Mach-port name, right transfer, Mach/IOKit emission or transport-buffer identity is established. The completed F bytes are local constructor output; their complete format and downstream external role remain unknown. [CB1-CB6; CB-A6]

## Verification, assumptions and bounded next evidence

The 44 intervals retain 1410944 original instruction visits, 254300 reads, 73860 writes, 62628 logical edges and 364 internal calls. Prefixes contribute `4*2414=9656` visits; NULL successors `8*14247=113976`; success successors `8*160914=1287312`; sum `1410944`. Full independent replay checks `32*(1410944+44)=45151616` GP/SP values and the same number of Q values, plus 1410988 NZCV frames. Exact 64-bit pointer tags are killed by ABI clobbers and overlapping invalidations; equal numeric values alone do not establish pointer custody. [CB3-CB6; CB-A1-CB-A5]

Fresh admission checks 836 parent/interval joins and 304 final exports against source-ordered byte demands, corrected compare-alias register dependencies and owner/configuration equality. Changed/missing demanded bytes, changed required registers and changed owners are rejected; unused Q0 and private-byte differences survive. Six nonvacuous source equations cover the address-dependent root, raw growth, allocator count, one descending-copy iteration, U publication and S clearing. Arithmetic is modulo 2^8/2^32/2^64 as declared; all addresses, offsets and extents are bytes. [CB3-CB6]

Audit time is O(V+P*D+K*M*log(M)+query DAG), with V visits, P admissions, D demanded bytes/registers, K state joins and M defined bytes per state. Storage is O(receipts+largest interval+parent byte maps). Full replay is O(V*(register state+byte effects)+joins) time. Solver timeout is 30 s/query. These are algorithmic bounds, not native timing measurements. Large receipts and the manifest use `zstd --ultra -22 -q -T1` with decoded round-trip checks. Original inputs remain unchanged; raw, decoded, packed and hexadecimal content is checked for analyst-local paths. Existing retained source suffices for this increment; IDA is not accessed. [CB1-CB6]

Logical SHA-256: checks `fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07`; replay `61f012a43cbae9cf2ff8a5207603a30b9bbf82c7b2d92811e0c1a2ff7505c107`; audit `47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252`.

Path checks interpret the exact typed Base64 payload schema after strict decoding, decompression and decoded hash/size verification, then scan both structured fields and hexadecimal byte payloads. Incidental pathname-like character sequences inside compressed Base64 are encoding artifacts; all decoded content is still checked. Ordinary report, script and JSON keys/values retain the direct path checks. [CB3-CB6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CB-A1: Exact original source/fixups apply | Opcodes, dataflow, dispatch and equations | Check source SHA, each visited word, actual original fixup reads, target modifiers and retained writer fragments. |
| CB-A2: The inherited 76 entries are conditional | Cohort coverage and object state | Check required whole registers/bytes, PC, configuration and owners at every join; preserve unknown bytes and each parent export. |
| CB-A3: The address-dependent root and imported returns are explicit premises | All post-frontier results | Verify all twelve initializer writers and the all-u64 equation; reject changed/missing root demand; keep the actual initializer epoch join unknown. Check each ABI transition and precise allocation/retirement extent. |
| CB-A4: Sequential source state and logical authentication apply | Frame/event replay and pointer continuation | Follow exact 64-bit pointer transfers through original slots and saved cells; kill clobbers/overlaps. Native PAC, scheduling and concurrent mutation remain unknown. |
| CB-A5: Exact dependency admission permits representative reuse | 76 prefixes and 304 terminal exports | Reject demanded-byte/register/owner perturbations, preserve unused input changes, compare complete terminal byte maps and GP/Q/NZCV values. |
| CB-A6: Local pointer publication and byte completion do not establish transport exposure | Native ownership and cross-layer conclusions | Require caller/lifetime continuity and actual transport-buffer joins; retain J preservation and undefined successor fields. |

| Impact | Bounded next evidence | Present limit / falsification target |
| --- | --- | --- |
| High | Establish SP+0x2b0 provenance in the success caller | Current full successor stops before its undefined 8 B load; a separate initializer match alone cannot establish the current epoch. |
| High | Establish S+0x30 provenance in the NULL lifecycle | It is undefined in the inherited S/64 B owner; source producer and lifetime need a continuous join. |
| High | Join S/U/F identities to actual Mach/IOKit buffers | Current paths establish local object effects and allocator interfaces; daemon-kext transaction pairing remains unknown. |
| High | Establish continuous initializer/caller custody for all twelve root fields | Present combined conditional definition is 96 B; initializer profile agreement does not replace an epoch proof. |
| Medium | Reduce the validation record and complete 57 B format to compact semantics | Raw tag/status/extent equations are recovered, but complete operation and conventional format identity remain unknown. |
| Medium | Inventory gate users and allocator/arena lifetime transitions | New cleanup acquisition/release sites extend the gate census; native synchronization semantics remain unmeasured. |

**QG1**: factual source/interface analysis. **QG2**: CB-A1-CB-A6 enumerate dependencies and falsification probes. **QG3**: this bounded constructor/lifecycle increment is covered; the full interface goal remains active. **QG4**: explicit widths, byte extents, modular equations, counts and complexity. **QG5**: separate root/ABI premises, owner retirement, definedness and native boundaries. **QG6**: delivery requires full replay and fresh publication verification of pinned primary artifacts. **QG7**: impact-labeled adjacent evidence and unresolved interfaces are explicit.

Follow-up: The [constructor-descriptor report](daemon_constructor_descriptor_report.md) establishes the SP+0x2b0 pool-pointer producer, the aligned frame/counter descriptor at SP+0x9e0, its consumer subtraction, and feedback-wrapper arithmetic with a 16-256 B dynamic stack reservation. Eight source equations and twelve initializer profiles are checked; all 304 inherited exports retain their previous undefined-field boundaries. The current initializer epoch, feedback store destination and native Mach/IOKit pairing remain unknown. No new guest definitions or execution intervals are added.

The [constructor halfword follow-up](daemon_constructor_halves_report.md) establishes the earlier zero-scalar route, unsigned q<21 gate, encoded 0->1 update and shared producer/writer format. It checks two fields across 152 successful constructor exports; native field meaning and daemon-kext identity remain unknown.

The [scalar serialization follow-up](daemon_scalar_serialization_report.md) proves the common periodic mask for recovered word/halfword fields, traces the gate word q to T+1..4 and checks header-scalar/extent agreement across 532 model snapshots. The word decoder includes its count-zero shift case; native field types and daemon-kext identity remain unknown.

The [constructor extent/header follow-up](daemon_constructor_extent_report.md) proves the generic allocation update N=C+a-p and prepared header D=a+p-q. Equal old-header copies make D=a and preserve the numeric extent/header gap; the retained 21/20 -> 57/56 instance has gap one. The earlier packed-word producer and sixteen writer residues share the recovered scalar format. Twenty-seven nonvacuous obligations, two interpretation controls and 6,580 independently replayed instructions qualify the result; all 152 successful exported headers are checked. Native schema, caller epoch and daemon-kext identity remain unknown; the full goal remains active.

The [local record-span follow-up](daemon_record_spans_report.md) proves the constructor span calculation 4*count+20 and its addition to the old header, decodes four payload scalars 0/1/0/1, and joins the later 97 B request to the scalar20 at offset57 rather than the enclosing scalar76 at offset1. Contiguous span endpoints and the record-start+14 values support a nested record and child-count interpretation; complete native schema and daemon-kext identity remain unknown. Twenty-three nonvacuous obligations, 20,112 independently replayed instructions and 3,192 field checks across 456 exports qualify this increment. No new target interval or API-return premise is added; the full goal remains active.
