# Original-entry early TLV decoding and typed-node request

Subsequent original-entry evidence: The [earlier node report](userclient_early_node_report.md) continues 60 exact predecessor prefixes through a fourth register-only allocation return. Original source retains the node, clears 16 B, publishes a 4 B extent and requests L+10 B from IOMallocData. Ten source proofs, 113172 independently interpreted visits and two rejected mutations pass. The pinned external typed wrapper masks incoming flags with 0x7. A synthetic NULL result stops before an unbacked load; native allocation effects/failure reachability, marker production and matched daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

The earlier `_PRnut72j9` parser now executes from its original compiler entry through declared input bytes. It reads a big-endian 4+2+4 B header, checks the body extent before reading tag/type, selects 4 B scalar, 8 B scalar or retained-span handling, and reaches an earlier 32 B `site.FPTTLVNode` request. A zero-tag span selects parser success without consuming an outer suffix. This is source execution in a private guest: input bytes and three allocator register returns are predeclared fixtures. Node allocation, container retirement, whole-operation completion and a matched daemon/kext transaction remain unexecuted or unknown. [EH1-EH9]

This extends the [earlier FPTTLV entry report](userclient_fpttlv_entry_report.md), which stopped before the first input byte. The new evidence gives the early and [later staged parser](userclient_record_metadata_report.md) an exact conditional wire-field correspondence. It does not identify their runtime objects or substitute the later [constructor](userclient_record_nodes_report.md) and [writer](userclient_record_writer_report.md) for this early parser.

## Evidence and claim mapping

| Artifact | Decoded SHA-256 | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instruction/data image |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, symbols, descriptors and chained pointers |
| Complete `_PRnut72j9` | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` | 202536 B / 50634 words; `0xfffffe000a635208` through `0xfffffe000a666930` exclusive |
| [Checks](triage_evidence/userclient_early_header_checks.json.zst) | `7ee41a58e79feb63c87fb5642245eb2328afb6f7acb355271553884d4547fdf1` | 72 cases, 13 selected continuation spans / 873 words, two 256-input bank rules |
| [Audit](triage_evidence/userclient_early_header_audit.json.zst) | `b8834843c39433e4e3fa6b1bbed8c275e7c5d0d51f09260a651a975ca6a8b2ef` | Independent replay, ten source obligations, excluded-cursor witness and two source mutations |

The [extractor](triage_evidence/recover_userclient_early_header.py) rehashes the full routine, compares selected words against both images and retains original pointer/metadata evidence. The [producer](triage_evidence/probe_userclient_early_header.py) initializes only declared input bytes before original entry; it adds no CPU/phase repair or further allocator-return cut. The [independent interpreter](triage_evidence/replay_userclient_early_header.py) imports neither the producer nor Unicorn and checks every integer/NZCV/memory/control epoch. New explicit operations are halfword memory access, CCMP, TST and register-controlled shifts with architectural shift masking. The [audit](triage_evidence/audit_userclient_early_header.py) adds semantic, byte-provenance and phase oracles plus original-word symbolic lifting. The [delivery verifier](triage_evidence/verify_userclient_early_header_delivery.py) rebuilds the receipts and checks publication custody.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| EH1 | Original-entry continuation and 48 exact predecessor prefixes with declared input custody | EH-A1-EH-A4 |
| EH2 | Raw header layout, length-first access order and exact encoded fields | EH-A1-EH-A5 |
| EH3 | Candidate cursor and unsigned body-extent rejection before tag/type reads | EH-A1-EH-A5 |
| EH4 | Three early type classes and scalar/span result channels | EH-A1-EH-A5 |
| EH5 | Zero-tag span success, committed cursor and unread suffix | EH-A1-EH-A5 |
| EH6 | Packed node-request ABI, count gate, descriptor and bank custody | EH-A1-EH-A5 |
| EH7 | Exact conditional correspondence to the later staged header domains | EH-A1, EH-A5, EH-A7 |
| EH8 | Independent replay, bounded source proofs and rejected mutations | EH-A1-EH-A6 |
| EH9 | Input/native/IPC limits and bounded continuation | EH-A1-EH-A7 |

## Entry, byte custody and header order

I, A and Q are entry X0, X1 and X2. N=low32(A), c is the u64 cursor, F the source frame, S the 16384 B workspace, C the 4096 B typed region and H the earlier 16 B FPTTLV result. Those epochs retain the original entry/probe/allocation/initialization chain. Every case declares H non-NULL. The first three allocator models change registers only and write no RAM. New input bytes are separate pre-entry fixtures at a private, disjoint I extent; provenance2 denotes those bytes, provenance1 original source stores, provenance0 unknown storage. Input bytes are never written by the target prefix. [EH1]

The matrix contains twelve profiles across three controller fixtures and two stack placements: unknown type, oversized body, zero/nonzero-tag spans, short scalar lengths, an unread suffix, short header, valid span/u32/u64 payloads and a high32 size variant. Forty-eight cases match existing N=9/N=10/N=16 predecessors. Their complete old visits, CPU frames, reads/writes, logical edges, API cuts and frontier CPU state match exactly. Twenty-four cases introduce N=14/N=18 or the declared high32 variant. These finite fixtures do not establish native input ownership or admission.

```text
original entry -> retained H / original source zeroing
    |
cursor c < N; ten-byte header fits?
    +--- no --------------------------> failure / typed retirement request
    |
read length bytes at I+c+6..+9
candidate = c+10+L; candidate <= N?
    +--- no --------------------------> failure before tag/type reads
    |
read tag at I+c+0..+3; type at I+c+4..+5
    |
classify type and length -> scalar decode or retained span
    |
commit cursor; zero-tag span? ---------> parser success / retirement request
    |
pack early node metadata -> count gate -> before 32 B typed-node allocation
```

| Raw offsets at I+c | Width / byte order | Early internal value |
| --- | --- | --- |
| +0..+3 | BE u32 D | T=D XOR0x31ae0066 |
| +4..+5 | BE u16 V | Ue=V XOR0xa2e3, consumed as low16 |
| +6..+9 | BE u32 L | First temporary R=L XOR0x652d5642; later E=L XOR0x31ae0066 |

The first four input loads are `0xfffffe000a660dcc`, `...0dd8`, `...0de0`, `...0df0`, in offset order6,7,8,9. The tag loads follow at `0xfffffe000a660ef4`, `...0f10`, `...0f20`, `...0f2c`; the type loads are `...0fc0`, `...0fc8`. The source assembles raw bytes directly here. It does not apply the later staged-buffer address mask at these sites. These arithmetic channels do not identify tag business semantics. [EH2]

At `0xfffffe000a660e34` through `0xfffffe000a660e4c` exclusive, source computes body offset c+10 and candidate c+10+zero_extend64(L). The next 14 instructions implement an unsigned CMP/CCMP gate. Under c<N<=2^32-1, candidate cannot overflow u64. Candidate<=N selects index0x7c6, target `0xfffffe000a660e94`; candidate>N selects index0x82d, target `0xfffffe000a661bfc`, modifier0x89ee. The oversized-body fixture reads only four length bytes and leaves cursor0. Tag/type remain unread. Selected header/body bounds do not attest native capacity. [EH3]

## Types, payloads and conditional staged correspondence

| Raw V | Early Ue | Early source behavior | Corresponding later Ul=V XOR0x365e |
| --- | --- | --- | --- |
| 0x9777 | 0x3594 | Require L=4; decode BE u32 payload | 0xa129 |
| 0x8485 | 0x2666 | Require L=8; decode BE u64 payload | 0xb2db |
| 0x50db | 0xf238 | Retain span pointer I+c+10 and L | 0x6685 |

The type comparisons occur at `0xfffffe000a661008`, `...1014`, `...1028`. Selected scalar-length comparisons occur at `...1044` and `...1980`. Unknown type, L=0 for either scalar type, short header and oversized body select failure with raw status0xce515bb8 at S+0xc94. These five rejected profiles retain cursor0 and use cleanup cell C+0x3d0. This is finite control evidence plus local source predicates; every possible type/length path is not executed. [EH4]

| Channel | Original source publication | Recovered value |
| --- | --- | --- |
| u32 payload | `0xfffffe000a661134`, S+0x4, 4 B | BE32(body) XOR0x31ae0066 |
| u64 payload | `0xfffffe000a661b40`, S+0xc60, 8 B | BE64(body) XOR0x8f98c6acce5848ca |
| Span | `0xfffffe000a661914`, C+0x690, 8 B | I+c+10 under the normal pointer branch |
| Span cursor | `0xfffffe000a661918`, S+0xa10, 8 B | candidate |
| Scalar cursor | `0xfffffe000a661b60`, S+0xa10, 8 B | candidate |

The scalar proofs include exact body-byte addresses and big-endian decoding for arbitrary payload values under their extent bounds. A span retains a pointer without reading its payload. For L=0, that pointer may be one-past the declared input extent; no payload byte is implied readable. The span path checks pointer high-bit agreement at `...1908`; the alternate word at `...1910` replaces high16 with0xc8a2. Delivered private cases take the normal branch, and the span-publication proof states the corresponding mask premise. No native pointer equivalence across that alternate transformation is inferred. [EH4]

The later metadata report independently establishes Ul=V XOR0x365e after protected staging-byte recovery. Therefore, conditional on the same raw type bytes:

```text
Ue XOR Ul = 0xa2e3 XOR 0x365e = 0x94bd
Ul = Ue XOR 0x94bd
```

Both tag channels use D XOR0x31ae0066, and both retained length channels use L XOR0x31ae0066. The later span class0x6685 therefore corresponds to early0xf238 through the same raw0x50db field. This is a field-domain correspondence, not proof of temporal staging completion, equal runtime buffers, common node allocation or native request identity. The [staging report](userclient_container_staging_report.md) retains its separate copy/epoch premises. [EH7]

## Zero-tag selection and node-request ABI

For the span class, `0xfffffe000a66191c` through `...193c` exclusive selects index0x5a1 exactly when D==0 and index0x386 otherwise. Original pointers target `0xfffffe000a661948` and `0xfffffe000a661b70`, modifier0x0d34. The success block stores SUCCESS=0x31ae0066 at S+0xc94. Both zero-tag fixtures commit cursor10 and then reach typed retirement through cleanup cell C+0x418; the N=16 fixture leaves six declared suffix bytes unread. No success return from the whole routine is asserted. [EH5]

Nonzero-tag accepted records retain source-produced metadata for the early node request. The eight source stores at `0xfffffe000a6614b4` through `...14d4` exclusive define:

| Cell | Width | Value at node request |
| --- | --- | --- |
| C+0x260 | 8 B | Callback `0xfffffe000a661ba0` |
| C+0x20 | 8 B | H; distinct from the still-unknown S+0x20 marker |
| S+0x1d0 | 4 B | D XOR SUCCESS |
| S+0x1b2 | 2 B | Ue |
| S+0x94 | 4 B | L XOR SUCCESS |
| S+0x110 | 4 B | Encoded u32 payload, or SUCCESS when unused |
| S+0xad0 | 8 B | Encoded u64 payload, or0x8f98c6acce5848ca when unused |
| C+0x168 | 8 B | Span pointer, or0 when unused |

The 31-word arithmetic gate at `0xfffffe000a661514` through `...1590` exclusive selects allocation index0xce0 exactly when L<=0xfffffff5, otherwise index0x63d. This is the u32 L+10 representability bound. The preceding body-fit invariant already implies that bound for the selected initial parse; the fresh gate proof covers every u32 L under its explicit phase premises. The source does not request a node for the zero-tag span. [EH6]

| Interface | Original source contract |
| --- | --- |
| Typed-node request | Before `0xfffffe000a661664`, `_IOMallocTypeImpl` at `0xfffffe000c4ba154`, modifier0xd0c8, X0=`0xfffffe000847b4a0` |
| Earlier descriptor | `site.FPTTLVNode`, signature `1121`, flags0x64, declared size32 B |
| Later descriptor | Separate address `0xfffffe000847c020`; identical normalized64 B metadata, name/signature/flags/size |
| Allocation bank | Two complete256 B arrays; key0x93, constant0xec, add0xe27, index0xf13, original slot `0xfffffe000847a7b8` |
| Descriptor bank | E-array pair; key0x32, constant0xf9, subtract0x98, index0x61, original slot `0xfffffe0008472208`, bias-8 B |

The descriptor correspondence establishes matching allocation-site metadata, not a shared runtime node or completed allocation. No fourth allocator return is supplied. All 30 accepted nonzero-tag cases stop before this call; the other42 cases stop before the existing FPTTLV retirement call at `0xfffffe000a6605c4`. Original allocator/free bodies remain unexecuted. [EH6]

## Independent checks and scope falsification

| Check | Verified count |
| --- | --- |
| Continuous cases / exact predecessor prefixes | 72 / 48 |
| Source visits / distinct visited PCs | 128538 / 2330 |
| Reads / read bytes checked | 11520 / 59256 B |
| Writes / write bytes checked | 27150 / 203148 B |
| GPR values / NZCV epochs | 3986910 / 128610 |
| Final D-register values / logical edges | 2304 / 1560 |
| Frame/workspace/typed snapshot bytes | 1786752 B |
| Additional H/input snapshot bytes | 1152 B / 924 B |
| Declared input bytes actually read | 744 B;180 B remain unread |
| Register-only allocator returns | 216; three per case, zero API-model RAM writes |
| New bank-array inputs | 512 |
| Fresh nonvacuous source obligations | 10 / 333 lifted instruction instances |

The selected continuation spans contain873 words:870 visited continuation PCs plus three captured, unexecuted words. Some selected PCs also appear in older local analyses; this count is source custody for the current continuation rather than a claim that every PC is newly discovered. Proofs cover raw length/candidate, body gate, raw tag, raw type/encoded length, scalar32, scalar64, span publication, zero-tag selection, node metadata pack and count gate. [EH8]

An unrestricted tag-address formula is false. With hypothetical c=0x4000000000000000 and I=0x1000, original tag-offset arithmetic yields first address0xc000000000001000, rather than the linear0x4000000000001000. The receipt retains that algebraic witness. Such c violates c<N<=2^32-1 and cannot enter this proved header path. The successful address proofs include the actual nonempty/header/body bounds; the witness is not a reachable native access claim.

Two private NOP controls remove one source instruction each. Removing the final length-byte load at `0xfffffe000a660df0` changes the accepted-span fixture to the retirement frontier and fails its read-order/outcome oracle. Removing the type store at `0xfffffe000a6614c0` still reaches the node-allocation frontier, but leaves required S+0x1b2 metadata undefined and fails the typed-output oracle. Independent replay checks both altered prefixes without consuming any undefined value. The latter control demonstrates why matching a frontier alone does not establish its ABI.

Production costs O(B+I+256R+C*(B+V+E)) time/retained space for image bytes B, captured words I, bank rules R, cases C, visits V and byte events E. Independent replay costs O(V+E+M) time/space per case, M the snapshots. Cases have a30000-visit bound; none reaches it. Lifting is linear in its instruction/DAG representation; solver search cost is separate with30 s/query limits. No native target operation or IDB mutation executes.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EH-A1: The pinned images, original pointer-format-8 interpretation and frozen predecessor evidence apply. | EH1-EH9 | Rehash full images/routine; compare selected words, bank arrays, chained pointers, descriptor strings/scalars and dependency digests. |
| EH-A2: Original-entry CPU state and separated private F/S/C/H/input extents apply. | EH1-EH9 | Rebuild72 cases across controller/placement/profile fixtures; compare every epoch and48 exact predecessor prefixes. Native admission is unknown. |
| EH-A3: PAC/AUT and authenticated branches are logical transfers here. | EH1-EH9 | Verify original branch words, slots, modifiers and complete logical edge journals; native authentication needs independent machine state. |
| EH-A4: Three allocator register-return cuts and declared pre-entry bytes preserve their specified storage and other state. | EH1-EH9 | Check all call arguments/clobbers, zero API RAM writes and distinct input/source provenance. Replace fixtures only after establishing authentic effects/custody. |
| EH-A5: Source phase, bounded cursor/header/body invariants, pointer branch and stable disjoint epochs hold where each local proof states them. | EH2-EH9 | Re-solve ten satisfiable-premise obligations; replay source production/intervening writes. The excluded-cursor witness falsifies overbroad address reuse. |
| EH-A6: The explicitly interpreted integer/NZCV/memory/D-register subset matches visited source words. | EH8 | Compare every event/epoch, including CCMP/TST/halfword/variable-shift effects, and both source mutations; unsupported/differing effects fail closed. |
| EH-A7: Cross-parser field mapping assumes identical raw/decoded field bytes; static/private source facts do not establish native identity. | EH7, EH9 | Join the original protected copy, caller admission, runtime buffer/node epochs and actual transport before composing a native daemon/kext transaction. |

## Bounded continuation and interface limits

| Impact | Discriminating next work | Result sought |
| --- | --- | --- |
| High | Continue this earlier node allocation return with explicit NULL/non-NULL cuts and preserved packed metadata. | Establish early node initialization, source value storage, callback/list publication and next lower interface. |
| High | Follow original pointer/tag uses and S+0x20 writers beyond these frontiers. | Locate the tunnel-marker producer without confusing C+0x20 with S+0x20. |
| High | Join authenticated caller admission and actual input provenance to this early header and protected staging epoch. | Establish the field correspondence on an admitted request and retain transaction/object identity. |
| Medium | Continue the original retirement return under an explicit lower contract. | Establish clearing, callback, subsequent staging reachability and function status without assuming native free effects. |
| Medium | Establish input/allocator/PAC and concurrent controller contracts. | Replace declared private storage/register cuts and logical authentication premises. |
| Low | Search original symbols or type metadata for the recovered wire field roles. | Improve names without assigning unsupported tag business semantics. |

S+0x20 remains unknown and unread; no marker-production claim is added. Q remains an opaque saved argument. This increment establishes input parsing, field-domain transforms, cursor/publication and typed-memory request ABIs. It establishes no new incoming Mach port, outgoing message, transferred right, identifier or emission site. Confirmed transport evidence remains in the [Mach-port report](mach_ports_report.md); native daemon/kext pairing and the full interface goal remain open. [EH9]

## Quality gates

**QG1** Pass: factual technical analysis. **QG2** Pass: EH-A1-EH-A7 list dependencies and falsification probes. **QG3** Pass for this increment: original routine purpose, data/control and typed-request ABIs, external-input/environmental assumptions and Mach/interface limits covered; full goal active. **QG4** Pass: u16/u32/u64 widths, BE assembly, modular encodings, bounds, exact counts and costs are reproducible. **QG5** Pass: actual path bounds versus excluded cursors, raw versus internal field domains, C+0x20 versus S+0x20, selected parser success versus whole return, and metadata correspondence versus runtime identity are distinguished. **QG6** Pass: pinned original/normalized words, arrays, descriptors/pointers/symbols, fresh source proofs, independent replay and source controls support the stated claims. **QG7** Pass: impact-ranked continuation above. `full_goal_complete=false`.
