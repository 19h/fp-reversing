# fairplayd: alternative header writer, U publication and caller handoff

The alternative initializer's saved continuation now has a complete source contract through header writes, U-field initialization, a store of U into its parent slot, cursor rewind and the saved return. Three invocations of `0x10047c6a4` write masked big-endian words 20, u32(X+`0xeceb3944`) and 1, where X is the saved word at outer-SP+0xb24. The remaining eight bytes of the 20 B record retain the preceding masked zero fill. U+0 receives the alternative buffer, U+8 and U+0x20 are zero, and U+0x28 selects the alternative readers. This is a source-level postcondition under the stated entry/memory/ABI premises; no alternative execution or native publication is observed. [AH1-AH6; AH-A1-AH-A8]

The earlier selected clear-route caller constructs X=`0x867a282a` from immediate instructions and saves it. Substituting that value into the alternative equation yields `0x7365616e`, big-endian ASCII `sean`. Neither the literal nor the matching saved continuation establishes that a native alternative call uses those same inputs. Their native format meaning and daemon-kext identity remain unknown. [AH2, AH4-AH5; AH-A3,AH-A7-AH-A8]

| Evidence | Primary provenance and scope |
| --- | --- |
| AH1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. AH4 retains 739 instruction words in 15 spans and 14 original authenticated pointer words. |
| AH2 | [Alternative allocation/fill](daemon_alternative_fill_report.md), [storage selector](daemon_storage_flag_report.md), [state-container construction](daemon_state_container_construction_report.md) and [conditional clear initializer](daemon_constructor_gate_report.md). Exact frozen checks/audits are pinned in AH4. |
| AH3 | [Alternative word reader](daemon_alternate_word_report.md), [halfword reader](daemon_record_storage_report.md), [coordinate/extent selection](daemon_record_selection_report.md) and [counted walk](daemon_record_walk_report.md). Reader equations and private-coordinate meanings qualify the composition. |
| AH4 | [Extractor](triage_evidence/recover_daemon_alternative_header.py), [checks](triage_evidence/daemon_alternative_header_checks.json.zst): source, fixups, 76 retained clear snapshots, literal/store/coordinate custody and four earlier clear U exports. |
| AH5 | [Auditor](triage_evidence/audit_daemon_alternative_header.py), [receipt](triage_evidence/daemon_alternative_header_audit.json.zst): 36 nonvacuous UNSAT queries, 15 universal normalizer lemmas, 60 checked cut applications, five scalar controls, 456 independent replay visits and the 1,524-instruction source composition. |
| AH6 | [Publication verifier](triage_evidence/verify_daemon_alternative_header_publication.py): fresh extraction/audit, canonical SMT comparison, report/source assertions, exact manifest delta, original-input preservation and decoded path hygiene. |

## Inputs, coordinate custody and literal provenance

Pointers and address arithmetic use u64 modulo 2^64. Scalar arithmetic is u32 modulo 2^32 unless narrowed; B denotes bytes. E is the saved encoded coordinate, c=u32(E+`0x89271580`) is its decoded offset, and N=u32(E+`0x89271594`) is the preceding allocation/fill extent. All symbolic contracts quantify arbitrary E32/X32, u64 addresses and cached words under valid separated memory. The earlier retained clear cases supply particular values, not alternative allocator returns or native addresses. [AH1-AH5; AH-A1-AH-A4]

| Saved field | Producer or established role | Retained clear value |
| --- | --- | --- |
| SP+0x3608 / u32 | `0x10070a320` stores W22; no later W22 write before the pending allocation | E=`0x76d8ea81` |
| SP+0xb24 / u32 | `0x100596008`/`0x10059600c` construct W11; `0x10083c8bc` saves it | X=`0x867a282a` |
| SP+0x36e8 / u64 | `0x10083c8c0` saves parent-pointer X9 | S=`0x6600040000` |
| SP+0x8ca8 / u64 | `0x10083c8b8` saves selected continuation X12 | `0x1007812e8` |
| SP+0x26e0 / u64 | Earlier encoded parent pointer, decoded later by additive inverse | S+`0x4aba552460e435c6`, modulo 2^64 |
| SP+0x16d0 / u64 | Private cursor | `0x480` |

For every one of the 76 selected constructors, byte custody identifies the current-interval coordinate, type-word, parent-pointer and continuation stores. No W11 write intervenes between the literal construction and its save. No W22 write intervenes between the coordinate save and the pending allocation. Six saved fields per case give 456 value checks. Independent replay covers the literal pair, three entry saves and coordinate copy: 228 slices, 456 instruction visits, 304 writes, 21,888 GP/SP values, 21,888 unchanged Q values and 684 NZCV frames. All these retained constructors take the clear route; the present alternative composition is separate. [AH2, AH4-AH5; AH-A2-AH-A3]

This closes a current-interval producer gap for SP+0x3608: the caller saves the very W22 used by the allocation prefix. It does not identify the earlier native initializer/caller epoch or prove that this clear-route state continuously reaches the alternative branch. AH2 supplies the general selector partition and alternative allocation/fill source contracts. The current path starts at their saved post-fill continuation `0x1007d39f0`, with arbitrary valid alternative-buffer/U pointers and the saved selector zero. [AH2-AH5; AH-A2-AH-A4]

## Universal masked word writer and repeated-call ABI

The source at `0x10047c6a4` writes four bytes. For decoded writer offset o and incoming payload P32, its postcondition is:

```
for j = 0..3:
    A[j] = base + ZeroExt32(u32(o+j))
    K[j] = load64(table + J(A[j],M))
    raw[A[j]] = byte_BE(P32 XOR 0x36cad8b3,j)
                XOR reader_mask_byte(A[j],K[j])
```

J and `reader_mask_byte` are the eight-round address-dependent equations in AH2-AH3, with the same global cells `0x1010c67d4` and `0x1010c8268`. All four load/store addresses and bytes are freshly proved for arbitrary offset, payload, mask, base, table and cached words, including u32 offset wrap. The writer's first three index expressions add `0x1cecdea9`, mask, sign-extend and clear the bottom three bits; the fourth uses a mixed Boolean expression. They are all proved equal to the readers' J equation, whose aligned sum uses `0x1cecdea8`. The low-bit difference is removed by alignment; it is not a different table-index contract. [AH1, AH3-AH5; AH-A1,AH-A4-AH-A5]

Fifteen universal normalizer lemmas cover the obfuscated round expressions. One longer expression spans `0x10047c998..0x10047c9ec`: its internal XOR constant differs from the reader key, but the complete expression equals the expected round XOR. Treating that internal constant as a separate round key would be incorrect. Every read-before-write constant is verified at each cut against the original initializer/composed state. The generic writer uses 15 applications; the three-call composition uses 45 more. No target bytes, IDB state or retained journals are rewritten. [AH4-AH5; AH-A5]

The writer loads its return target from the incoming signed W21 dispatch index and branches with IA diversity `0x1ac9`. It leaves the base and constant context needed by later invocations intact. Internally X16 changes from key[6] to key[4], while X25 retains key[6]. The repeat bridge at `0x10057c168` restores X16 from X25 before the next invocation. The fresh return/context proof and all composed cut-context checks verify this restoration; assuming X16 remains unchanged would break the repeated-call ABI. [AH4-AH5; AH-A2,AH-A5]

## Header construction and bounded decoded view

The 1,524-instruction source composition covers twelve authenticated transfers, 84 loads and 21 stores. It executes the three complete writer bodies symbolically, with original source bytes and separately proved expression cuts. It contains no imported call, CAS/readiness sequence or arena-node work. Cache initialization and concurrency remain independent prerequisites. [AH1-AH5; AH-A2-AH-A6]

| Writer use | Setup | Record-relative offset | Payload P32 | Intermediate decoded word |
| --- | --- | --- | --- | --- |
| First | `0x1007d39f0`, `0x1005c5b70` | 0 | `0x36cad8a7` | 20 |
| Second | `0x1005189b4`, repeat bridge | 4 | u32(X+`0xeceb3944`) XOR `0x36cad8b3` | u32(X+`0xeceb3944`) |
| Third | `0x10050a808`, repeat bridge | 8 | `0x36cad8b2` | 1 |

The second setup's carry circuit is proved equivalent to its stated affine/XOR expression for every X32. The selected earlier caller has X=`0x867a282a`; u32(`0x867a282a`+`0xeceb3944`)=`0x7365616e`. A scalar control confirms that arbitrary X does not force this word. `sean` is an exact big-endian ASCII interpretation of the scalar substitution; a public FourCC registration, schema name, policy meaning or native alternative use is unknown. [AH4-AH5; AH-A3,AH-A7-AH-A8]

Under the preceding fill contract and unchanged per-address cache-mask inputs, the resulting intermediate decoded record view is:

| Offset from record start c | Width | Decoded contents |
| --- | --- | --- |
| +0x00 | 4 B | Big-endian span 20 |
| +0x04 | 4 B | Big-endian u32(X+`0xeceb3944`) |
| +0x08 | 4 B | Big-endian word 1; higher-level role unknown |
| +0x0c..+0x13 | 8 B | Zero bytes retained from the fill |
| +0x0e..+0x0f | 2 B, within the preceding row | Count field zero under the recovered halfword reader |

These are decoded bytes, not raw zero-filled storage: raw bytes include address-dependent masks. The final word-reader scalar still XORs its assembled value with `0x8b3dc651`; the span gate cancels that XOR before using span 20. Later code may overwrite fields after the source boundary studied here. [AH2-AH5; AH-A4-AH-A8]

The range premise c<=`0xffffffeb` gives nonwrapping N=c+20. It proves all 20 record bytes lie within the N B request; the twelve header stores modify only c..c+11. The extra eight bytes remain from the initial fill under separation/stability premises. Without this range premise, source arithmetic can wrap and allocation size alone does not establish room for the record. Valid readable/writable mappings and allocator feasibility are separate premises. [AH4-AH5; AH-A4-AH-A6]

For the retained coordinate substitution, c=1 B and N=21 B. The earlier selector's first scalar gate gives 1 B+1 B=2 B<21 B. Span 20 B gives endpoint 1 B+20 B=21 B, strictly above the start and equal to capacity; count zero selects the saved coordinate in the recovered reader equations. This is a conditional compatibility calculation using AH3, not a new helper execution or native admission. The decoded byte before c also remains zero under the fill/epoch premises. [AH2-AH5; AH-A3-AH-A4,AH-A7]

## U fields, parent publication and saved return

Let F=u32(E+(`0x6cf4` XOR `0x9a13b551`)). Store `0x100817ca8` first writes zero at U+0x20. The common publisher at `0x100825880` then writes the remaining fields below and stores U into the saved parent slot at `0x1008258d8`. [AH1, AH4-AH5; AH-A2-AH-A6]

| U offset / width | Alternative source postcondition | Earlier conditional clear export |
| --- | --- | --- |
| +0x00 / u64 | Alternative buffer base | 0 |
| +0x08 / u64 | 0, under the saved companion-zero premise | T=`0x6600050000` |
| +0x10 / u32 | F | `0x10ecc426` |
| +0x14 / u32 | F | `0x10ecc426` |
| +0x18 / u32 | E | `0x76d8ea81` |
| +0x1c / 4 B | Unwritten by this composition | Undefined in the earlier model |
| +0x20 / u64 | 0 | Arena node+24=`0x650011519c` |
| +0x28 / u32 | `0xd299e646`, mask4 set | `0xd299e642`, mask4 clear |
| +0x2c / 4 B | Unwritten by this composition | Undefined in the earlier model |

Seven U stores write 40 B; eight bytes are not written by this path and cannot be assigned zero. All seven U events precede the parent-pointer store. The generic equations prove u32(U[0x14]+`0xef133bef`)=N and u32(U[0x18]+`0x89271580`)=c, tying the published reader capacity/default coordinate to the earlier allocation and header position. The four clear views are existing separate conditional exports, not newly joined alternative states; their native equivalence or ownership is unknown. [AH2-AH5; AH-A2-AH-A6]

The publisher sets W8=1. The common return at `0x10068ae70` subtracts 32 B from the private cursor and branches through SP+0x8ca8 with IA diversity `0x5ae9`; SP is unchanged. Its generic contract quantifies every saved continuation. The retained clear snapshot's cursor `0x480` would become `0x460`; these are private cursor values, not native stack-depth measurements. No context J+0x68 publication is established here. [AH2, AH4-AH5; AH-A3,AH-A6-AH-A8]

```
saved post-fill continuation
  -> word writer at c, c+4, c+8
  -> U+20 = 0
  -> U base/extent/default/flag fields
  -> store U into saved parent slot
  -> W8=1; cursor -= 32 B; saved return

if saved return is the earlier caller's 0x1007812e8:
  -> odd-result route
  -> decode parent pointer
  -> reload U from parent+0
  -> save U and result-record pointer
  -> non-NULL U dispatch to 0x100762e48 (next source boundary)
```

## Immediate caller interface and original pointer words

The caller at `0x1007812e8` tests the returned low bit, not equality with 1: odd selects `0x1006b2200`, even selects `0x1006ad0a8`. The odd route cancels parent-pointer bias using inverse `0xb545aadb9f1bca3a`, then prepares an output-record pointer SP+0xd98. `0x1006bdb98` reloads the child pointer from parent+0. Stores at `0x1006bdbac` and `0x1006bdbb0` save the child and output-record pointers at SP+0xaf18 and SP+0xaf20. A third store saves a future continuation at SP+0x3980. Non-NULL child dispatches to `0x100762e48`; NULL dispatches to `0x1008c25f4`. These are separate generic caller contracts, connected to the header postcondition only under matching continuation, parent and memory-epoch premises. [AH1, AH4-AH5; AH-A3,AH-A6-AH-A8]

| Index32 | Target | IA modifier |
| --- | --- | --- |
| `0x17fb` | `0x1005c5b70` | `0x423d` |
| `0x5054` | `0x10047c6a4` | `0x8241` |
| `0xcaa` | `0x1005189b4` | `0x1ac9` |
| `0x3a28` | `0x10057c168` | `0x4f3e` |
| `0xcac` | `0x10050a808` | `0x1ac9` |
| `0xc91` | `0x100817c94` | `0x1ac9` |
| `0x93e6` | `0x100825880` | `0xdc2a` |
| `0x6a14` | `0x10068ae70` | `0xff01` |
| `0x64d7` | `0x1006b2200` | `0x63a3` |
| `0x6504` | `0x1006ad0a8` | `0x63a3` |
| `0x602e` | `0x1006bdb90` | `0x5c3f` |
| `0x1a3` | `0x10072c448` | `0x9325` |
| `0x9344` | `0x100762e48` | `0xe3b` |
| `0x92f1` | `0x1008c25f4` | `0xe3b` |

Index `0x1a3` is loaded and saved as a future continuation in the caller; this increment does not branch through it. The table records original pointer diversities, not successful hardware authentication or new Mach emissions. All 14 words are checked against the original format-12 fixup decoder. The 56 caller-follow-up instructions are distinct from the 1,524-instruction header composition and the 456 independent retained replay visits. [AH4-AH5]

## Assumption register and bounded continuation

| Assumption / dependent results | Premise | Stress test or falsification probe |
| --- | --- | --- |
| AH-A1: build-specific source | Original image, fixups, source spans and pinned upstream receipts | Reject source/hash/dispatch/context mismatches; do not transfer addresses to another image. |
| AH-A2: constructor phases and ABI | Saved phase `0x6cf4`, b=0 post-fill entry, valid returned buffer/U pointers and ordinary call preservation from AH2 | Verify complete original setup and all repeated-call contexts. No concrete alternative allocator return or owner is added. |
| AH-A3: conditional custody and caller reuse | Retained clear source supplies literal, coordinate, parent, cursor and continuation evidence | Check all 456 saved values, last writers and non-clobber intervals; independently replay producer/store slices. Matching bits do not establish a native alternative entry or continuous epoch. |
| AH-A4: mask/cache epoch and separation | Valid stable mask/table/cached words; output, U, parent, frame and dispatch storage separated; later reader obtains the same per-address mask inputs | Prove all cache/store addresses and bytes. AH2's changed-mask control falsifies zero decoding across changed epochs. Native cache lifetime, concurrency and M=255 admission remain unknown. |
| AH-A5: source-proof composition | Fifteen universal XOR normalizers with original constant contexts | Verify 60 cut contexts, the extended round expression and X16/X25 restoration. Generic writer proofs quantify offset wrap and every payload bit. |
| AH-A6: allocation/field bounds | Shared E for W22 request, saved coordinate, header position and U fields; c<=0xffffffeb for a nonwrapping 20 B record | Replay coordinate copy; prove capacity/default identities and record bounds. Wrap control rejects unconditional room claims; eight unwritten U bytes remain unknown. |
| AH-A7: reader and caller compatibility | Pinned reader/gate equations and matching saved return/parent/private-frame epoch | Show c=1,N=21 scalar compatibility; keep the post-return caller contracts separate. Follow the child/result pair at 0x100762e48 before asserting the next operation or external result. |
| AH-A8: external identity | Source-local header and publication only | Establish native selector/caller/cache epochs and paired daemon-kext bytes before assigning wire/schema/policy meanings. No new Mach send/receive, right transfer or port-emission site is established. |

| Impact | Next discriminating work | Information gained |
| --- | --- | --- |
| High | Follow `0x100762e48` and the SP+0xaf18/+0xaf20 child/result pair | Immediate processing of the newly published U and later parent/context publication |
| High | Establish native alternative caller/tag and cache publication epochs | Which literal, coordinate, buffer and synchronization premises hold in a real alternative invocation |
| High | Trace the literal-derived second word's actual consumers | Meaning and restrictions of the header word without assigning an unproved schema |
| Medium | Match the completed object contract to daemon-kext buffer evidence | Whether these private records cross the recovered external interfaces |
| Low | Inventory other callers of the generic masked writer | Reuse of the full-u32 writer and return-context ABI beyond this constructor |

## Quality gates and reproduction

**QG1** passes: factual source, ABI and data/control-flow analysis. **QG2** passes: AH-A1-AH-A8 identify premises, dependent results and falsification probes. **QG3** passes for this increment: literal/coordinate custody, generic writer, three-word construction, U fields, parent publication, saved return and immediate caller interface are covered; the full investigation remains active. **QG4** passes: B units, u32/u64 narrowing, signed dispatch/index extension, nonwrapping bounds and complexity are explicit. **QG5** passes: decoded/raw bytes, internal round constants, restored X16, low-bit result gate, unknown U holes and clear/alternative/native epoch distinctions are explicit. **QG6** passes: original words/fixups, frozen admissions, fresh source queries and independent producer/store replay provide primary provenance. **QG7** passes: impact-labeled extensions are listed.

Run the extractor, auditor and publication verifier with the evidence directory on the Python module path and existing Capstone/Z3 dependencies. Extraction/replay costs O(parent receipt bytes + selected state bytes + source words + replay visits*32) time/space; symbolic construction costs O(source DAG), with solver search separately limited to 30 s/query. This post-fill header/publisher path is O(1) time/auxiliary space; combined with AH2's N-byte fill it is O(N) time plus N B output and 48 B U. No native timing or allocation feasibility is inferred. All 36 source queries are nonvacuous UNSAT and all five scalar controls match. There are 15 normalizer lemmas, 60 checked applications, zero target instruction rewrites, zero new target intervals/guest input bytes/owner-root definitions/API-return premises, and no native allocation/free, hardware PAC test or IDB mutation. Original references suffice; all three original primary inputs remain byte-identical.

The [child-operation follow-up](daemon_child_operation_report.md) resolves the earlier 0x100762e48 prelude: it writes raw token bytes 98 99 98 99, reloads the saved U/result pair, prepares raw tag 0x76657273 and advances a private cursor by 32 B. Base availability and low-two-bit guards precede the existing validation boundary; both clear flag 0xd299e642 and alternative flag 0xd299e646 pass those guards under their separate source premises. The saved outer result gate at 0x10072c448 accepts exactly raw W27=0x8b3dc651. Eighteen universal source obligations and 876 independent replay visits across four retained clear classes qualify the result. The alternative execution, native root/cache/caller epochs, J+0x68 publication and daemon-kext transaction identity remain unknown. No new port emission is established; the full goal remains active.
