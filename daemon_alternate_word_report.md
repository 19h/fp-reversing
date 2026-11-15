# fairplayd: alternative fixed-width word reader and saved-context ABI

The obfuscated body at `0x100357e2c` is an address-dependent, cached-word mask reader for four bytes. It reads through U+0, reconstructs a big-endian u32, XORs the result with `0x8b3dc651`, and hands it to the same caller-selected continuation as the clear-storage reader. Its full source contract now includes load addresses, eight-round masks, final assembly, saved-caller reload and restored phase registers. The alternative representation exposes all 32 decoded bits; the clear representation uses a packed-width decoder whose output is at most `0x7fffffff`. Native representation admission, producer restrictions and daemon-kext transaction identity remain unknown. [ALT1-ALT6; ALT-A1-ALT-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| ALT1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. ALT4 retains 545 instruction words and four original authenticated dispatch words. |
| ALT2 | [Counted-walk report](daemon_record_walk_report.md), [record selection](daemon_record_selection_report.md) and their frozen receipts; exact hashes are pinned in ALT4. These establish selectors, clear readers, common span gates and caller continuations. |
| ALT3 | [Alternative halfword/storage report](daemon_record_storage_report.md), checks decoded SHA-256 `08dd5c2d5d3c14efd4ec744f35267c1d9f879d2a93c3d4ea8ca68f3c22e31337`, audit `1be9029f3b67f0d543db412982617378cae7064ff4a9ade39f503b4da5f0eac4`. The word reader's index and eight-round model are freshly compared against the same functions here. |
| ALT4 | [Extractor](triage_evidence/recover_daemon_alternate_word.py), [checks](triage_evidence/daemon_alternate_word_checks.json.zst): six retained helper cases, saved-cell last-writer custody, original source words and dispatch words. |
| ALT5 | [Auditor](triage_evidence/audit_daemon_alternate_word.py), [receipt](triage_evidence/daemon_alternate_word_audit.json.zst): 45 nonvacuous UNSAT source obligations, four interpretation controls, 32 explicitly justified proof cuts and 330 independently replayed instruction visits. |
| ALT6 | [Publication verifier](triage_evidence/verify_daemon_alternate_word_publication.py): fresh extraction/audit, canonical SMT comparison, report assertions, exact manifest delta, original-input preservation and decoded path hygiene. |

## Byte-to-word contract

Addresses and mask words are u64 modulo 2^64. Offsets and scalar operations are u32 modulo 2^32, with narrowing or sign extension stated explicitly. B denotes bytes. `load8` reads one byte; `load64` reads an eight-byte little-endian word. B64 below is a symbolic base pointer, distinct from the byte unit B. These equations describe private implementation representations. [ALT1, ALT4-ALT5; ALT-A1-ALT-A3]

| Input or cell | Meaning |
| --- | --- |
| U+0 | Alternative byte base B64 |
| `0x1010c67d4` | u32 mask M32 |
| `0x1010c8268` | u64 cached-word table pointer T64 |
| Incoming X22 | Zero-extended decoded offset c32 |
| Incoming W15 | `u32(c32-0x89271580)` |
| Helper SP+0xa8 | Saved caller pointer, reloaded into X0 inside the reader |
| X27 | Caller-selected continuation |

```
for j = 0..3:
    A[j] = u64(B64 + ZeroExt32(u32(c32+j)))
    J[j] = SignExt32(u32((low32(A[j]) & 0xfffffff8)
                        + 0x1cecdea8) & M32)
    K[j] = load64(T64 + J[j])
    raw[j] = load8(A[j])
    x = A[j] & 0xfffffffffffffff8
    y = K[j]
    for r = 0..7:
        x = u64(ROR64(x,8) + y) XOR key[r]
        if r < 7: y = x XOR ROR64(y,61)
    d[j] = low8(LSR64(x,8*(A[j] & 7))) XOR raw[j]
q32 = BE32(d[0],d[1],d[2],d[3])
W16 = q32 XOR 0x8b3dc651
```

| Round r | Common key[r], u64 |
| --- | --- |
| 0 | `0x473c853ae26b7ab8` |
| 1 | `0x8f0490db2637da4e` |
| 2 | `0x639ff74d03d39428` |
| 3 | `0xa34408d6869aa02f` |
| 4 | `0x0a23823d71e7a74e` |
| 5 | `0x6c2f97ea7411e380` |
| 6 | `0x3d107423d6820c5f` |
| 7 | `0x71ef41f1f2e87b90` |

The first three source byte cores equal the common word model directly. The fourth source core uses final key `0x0f913f8f8c9605ee`, equal to key[7] XOR `0x7e7e7e7e7e7e7e7e`. Its mask byte therefore differs by `0x7e` for every address residue. The final obfuscated assembly cancels that difference. Both the byte-extraction identity and the final source assembly are separately proved. Omitting the cancellation cannot produce the same assembled word for any decoded byte tuple. The equations above include the cancellation and use the common key sequence for all four bytes. A standard cipher identity is unknown. [ALT3-ALT5; ALT-A3-ALT-A4]

The full 487-instruction arithmetic/load body, ending immediately before its authenticated branch, is symbolically executed. Thirty-two universal normalizer lemmas replace equal output expressions in the proof DAG. At every cut, all read-before-write constant-register premises are checked against the actual composed source state; the receipt records those contexts. Four whole-core equivalences and the final u32 equivalence then quantify arbitrary c32, B64, M32, T64, cached words and raw bytes, including u32 offset wrap. No target bytes or retained states are rewritten. The 488th instruction is the retained authenticated branch, whose target word and modifier are checked without claiming hardware authentication acceptance. [ALT4-ALT5; ALT-A2-ALT-A4]

For M32=255, J is 8 B aligned in [0,248], so every eight-byte cached-word load fits within the first 256 B of a valid table. Alignment is universal for every M32. The 256 B bound is conditional on the mask: a retained SAT control falsifies the unrestricted bound. Readability, canonical address validity, pointer lifetime, cache initialization and concurrent stability are independent premises. In particular, the equations do not establish that a native initializer actually supplies M32=255 at this reader's epoch. [ALT3-ALT5; ALT-A2-ALT-A3]

| Reader representation | Byte base | Decoded word | Decoded count | Source domain |
| --- | --- | --- | --- | --- |
| Flag mask4 clear | U+8 | Packed-width decoding, q<=`0x7fffffff` | Packed-width decoding, h<=`0x7fff` | ALT2 |
| Flag mask4 set | U+0 | Direct BE32, q<=`0xffffffff` | Direct BE16, h<=`0xffff` | ALT3-ALT5 |

The decoder-domain comparison does not establish producer use of the larger ranges. The two representations use different bases and masking rules. Identical serialized bytes, interchangeable storage and mixed-representation epoch compatibility are unknown. [ALT2-ALT5; ALT-A5-ALT-A6]

## Saved context, data flow and continuation

| Source, end exclusive | Recovered effect |
| --- | --- |
| `0x10049f780..0x10049f784` | Save caller X0 to helper SP+0xa8 |
| `0x1005320f8..0x1005321d0` | Rebuild word-reader phases, global-cell pointers and select clear/alternative body |
| `0x100357e2c` | Load alternative base from U+0 |
| `0x100357e6c`, `0x100357e70` | Load mask and table pointer from the two global cells |
| `0x100357f50`, `0x100358104` | Save X10 in X20, then restore X10 |
| `0x10035808c` | Reload X0 from helper SP+0xa8 |
| `0x1003580dc..0x1003580e4` | Restore W19=`0x89271582` |
| `0x100358108..0x100358110` | Restore W20=`0x89271583` |
| `0x100358120` | Restore W21=`0xffff9684` |
| `0x100358334..0x10035833c` | Restore X9=`0x1010a1960` |
| `0x1003585c0..0x1003585cc` | Load return-bridge target at index `0x602d`; branch with IA modifier `0x143b` |
| `0x1003ec410..0x1003ec418` | Set IA modifier `0x352e`, then branch through preserved X27 |

The arithmetic body performs 13 loads and zero stores: base, mask, table pointer, four cached words, four raw bytes, saved caller pointer and dispatch word. The proof preserves X10, X11, X12, X13, X14, X25, X26, X27, X28, SP, W15, W6 and X7. W19/W20/W21 are explicitly rebuilt, and X9 is restored. X8 is scratch and is rebuilt by reader setup before another call. X0 is restored from the saved slot; equality with the current incoming scratch value is not assumed. The saved pointer is a private caller-state transfer, not evidence of native ownership or external pointer exposure. [ALT4-ALT5; ALT-A2-ALT-A4]

| Index | Target | IA modifier | Role |
| --- | --- | --- | --- |
| `0xc00f` | `0x100357e2c` | `0x43b0` | Alternative word reader |
| `0xbff7` | `0x100405d98` | `0x43b0` | Clear word reader |
| `0x602d` | `0x1003ec410` | `0x143b` | Shared word-return bridge |
| `0xc4` | `0x1003fb284` | `0x352e` | Counted-walk positive-advance continuation |

```
U+0 --> raw bytes ----+
globals --> K[j] ----+--> address mask --> BE32 --> W16 XOR bias
SP+0xa8 --> saved X0 ------------------------------------+
                                                        |
return bridge --> X27 --> initial span minimum / child advance
```

Initial use supplies X27=`0x100333948`, whose minimum-span gate requires p>=20 B. A counted child read supplies X27=`0x1003fb284`; its subsequent positive-advance and enclosing-endpoint gates consume q32=`W16 XOR 0x8b3dc651`. The alternative reader preserves the endpoint/count/cursor and restored phases required by those source-local gates. The common counted-walk scalar proofs quantify arbitrary u32 span values, so their arithmetic applies to these returned values under the stated caller, readability and phase premises. A native alternative invocation or complete matched producer-to-walk epoch is not established. [ALT2, ALT4-ALT5; ALT-A2-ALT-A6]

The count remains u16: the source nonzero variant decreases to zero, giving at most 65,535 iterations for the alternative count domain. Fixed-size mask and control work gives O(h) walk time and O(1) auxiliary space; the reader alone uses O(1) time and space. This is a conditional source termination argument. No native scheduling or elapsed-time claim follows. The inherited walk still allows a short positive earlier span and zero-count trailing extent, and does not recursively validate child headers. [ALT2-ALT3; ALT-A5]

## Retained evidence and interpretation controls

| Retained group | Cases | Saved cells | Saved bytes / B | Alternative reader executed |
| --- | --- | --- | --- | --- |
| Constructor-prefix | 4 | 8 | 64 | No |
| Later growth | 2 | 4 | 32 | No |

Each case establishes current-interval last-writer custody for SP+0xa8 and SP+0xb0. The former equals that case's caller X0; the latter holds `0x1010c8268`, also consumed by the alternative halfword setup. Twelve one-instruction writer slices and six reader-setup slices are independently replayed: 330 visits, 11,136 GP/SP values, 348 NZCV frames, 60 reads and 18 writes across 18 slices. The 318 setup visits end before the authenticated selector branch. All retained invocations select the clear reader; none observes the alternative body. Symbolic read values are universal proof variables, not constructed guest bytes or API-return premises. [ALT4-ALT5]

| Control | Result | Interpretation |
| --- | --- | --- |
| Direct decoded word can equal `0x80000000` | SAT | Full-width scalar model differs from the clear decoder's range; native producer admission unknown |
| Arbitrary global mask implies a 256 B table bound | SAT falsifier | The bound needs a mask premise |
| Saved caller pointer can differ from current X0 scratch | SAT | Restoration follows SP+0xa8, not incoming-X0 preservation |
| Omit fourth-byte `0x7e` cancellation and retain the same assembled word | UNSAT | The whitening correction is necessary for the recovered contract |

There is no Mach message send, receive, port allocation, port-right transfer, user-client call or new port-emission site in this reader. This increment adds an internal byte/base/cache/caller ABI contract; assigning the decoded fields to an external daemon-kext transaction still requires paired evidence. [ALT1, ALT4-ALT5; ALT-A6]

## Assumption register and bounded continuation

| Assumption / dependent results | Premise | Stress test or falsification probe |
| --- | --- | --- |
| ALT-A1: build-specific addresses | Pinned image, exact source/fixup words and upstream receipts | Reject every image, source-span, fixup or receipt-hash mismatch; cross-build mappings are unknown. |
| ALT-A2: source call admission | Correct helper frame, caller phases, readable cells and stable mask/table/base per call | Six retained setup/custody cases and all 13 address equations are checked. Trace actual alternative flag/base writers and their caller epoch before asserting native admission. |
| ALT-A3: address and cache semantics | u32 offset narrowing, u64 address arithmetic, valid eight-byte table reads | Quantify all offset bits, raw bytes, cached values and masks. M=255 bounds and arbitrary-mask falsifier separate alignment from extent. Initial readability remains a premise. |
| ALT-A4: composed source equivalence | Exact lifted instructions and every normalizer's live-in constant context | Independently prove all 32 lemmas; check all read-before-write premises at each application; reparse and rerun delivered SMT queries. No target rewrite. |
| ALT-A5: framing and range | Inherited common scalar gates and representation-specific readers at each invocation | Full-width/high-bit control and fourth-byte cancellation test distinguish formats. Count-zero retained cases do not establish a nonzero or alternative execution. Producer restrictions and mixed-format compatibility are unknown. |
| ALT-A6: external interpretation | Private ABI recovery only, without assigning protocol names or ownership | Require matched daemon-kext bytes, caller epoch and native ownership/synchronization evidence before claiming shared transaction identity. |

| Impact | Next discriminating work | Information gained |
| --- | --- | --- |
| High | Recover the [selector follow-up](daemon_storage_flag_report.md)'s b=0 constructor branch and its alternative base producers | Alternative representation admission and whether storage conversion occurs |
| High | Establish mask/table initialization and publication lifetime at the reader epoch | Which conditional table bounds and cache consistency premises are actually met |
| Medium | Recover producer restrictions on full-width word/count values | Difference between reader domain and admitted native schema |
| Medium | Pair these private records with retained daemon-kext request/response buffers | Whether this codec participates in the observed external interface |
| Low | Join scratch restoration to further caller families | Reuse boundaries for the recovered internal calling convention |

## Quality gates and reproduction

**QG1** passes: factual source, ABI and data-flow analysis. **QG2** passes: ALT-A1-ALT-A6 identify assumptions, dependent results and falsification probes. **QG3** passes for this increment: byte masks, index arithmetic, final assembly, saved context, shared continuation and representation comparison are covered; the full investigation remains active. **QG4** passes: byte units, u32/u64 narrowing, signed index extension, count bounds and algorithm complexity are explicit. **QG5** passes: fourth-byte whitening is canceled, restored phase registers are checked, retained clear calls are distinguished from static alternative contracts, and native epoch/schema gaps remain unknown. **QG6** passes: original image words, dispatch fixups, pinned upstream receipts, fresh solver checks and independent replay provide primary provenance. **QG7** passes: impact-labeled bounded extensions are listed.

Run the extractor, auditor and publication verifier with the evidence directory on the Python module path and existing Capstone/Z3 dependencies available. Extraction/replay costs O(parent receipt bytes + selected journal bytes + source words + replay visits*32) time and space; symbolic work costs O(source DAG plus solver resources), with a 30 s limit per query. All 45 source obligations are nonvacuous UNSAT; the four interpretation controls have expected results SAT, SAT, SAT, UNSAT. There are 32 verified proof-cut contexts, zero target-instruction rewrites, zero new target intervals, zero new guest input bytes, zero owner/root definitions and zero API-return premises. No native target operation, allocation/free, hardware PAC test or IDB mutation occurs. Original primary inputs remain byte-identical.

## Storage-selector production and retained custody

The [storage-selector follow-up](daemon_storage_flag_report.md) traces the private pointer/header/tag decision to outer SP+0x662f and the later U+0x28 reader flag. The 76 retained constructors read context J+0x1c word 6 with tag `0x4e40e176`, produce selector byte 1, and retain it through 606 intervals/1,620,162 visits and 456 phase snapshots. All 608 checked successful U exports have U+0 zero and mask4 clear. Sixteen source proofs, eight scalar controls and 4,916 independent replay visits qualify the increment. The b=0 allocation and fill prefix is resolved by the subsequent alternative-fill report; later header/publication work, native caller/cache epoch and daemon-kext pairing remain unresolved; no new port emission is established.

## Alternative allocation and address-masked zero fill

The [alternative-fill follow-up](daemon_alternative_fill_report.md) resolves the b=0 allocation prefix: it requests N B, saves its result in the future U+0 cell and selects a cached-word byte initializer after the shared 48 B object allocation. Each byte is the same address-dependent mask used by the alternative readers, giving zero intermediate decoded bytes if the cache epoch is unchanged. The word reader still applies its final scalar XOR. Twenty-one source obligations, three checked normalizer cuts, ten scalar controls, 512 bank rows and 152 independent zero-store replay visits qualify the result. All 76 retained snapshots remain clear-route cases. Later alternative header writes/publication, native caller/cache epoch and daemon-kext pairing remain unknown; no new port emission is established and the full goal remains active.
