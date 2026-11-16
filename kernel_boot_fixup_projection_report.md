# Boot fixup contracts and page-boundary correction

Subsequent evidence: the [full boot initializer report](kernel_boot_initializer_execution_report.md) executes all 1036413 fixup stores and returns through bank/range/slide publication in a raw-image private case. The projection-only and unexecuted-boot statements below describe this earlier increment; its artifacts remain frozen. Native boot and the continuous startup handoff remain unknown.

Original boot code consumes chained fixups before publishing its collection-header bank. Source relations and an independent decoder now corroborate all 1036413 fixups in the pinned collection. This exposed eight pointers crossing a 4096 B page boundary: the retained logical-page reader produces 4100 B for their first pages and leaves the encoded upper halves in their next pages. A separate corrected reader reproduces the complete independently projected image, changing exactly 16 pages. All 29 retained signing cases replay with identical source journals/registers/private RAM/PAC events; only one mapped-page digest changes. The current continuous logging case maps none of the affected pages. Full boot and native PAC remain unexecuted. [BP-A1-BP-A7]

```text
raw collection -> boot initializer -> first fixup boundary (CPU prefix)
                                      |
                        source-proved packed-word relations
                                      |
                       independent decode of 1036413 fixups
                                      |
              681 chain-page receipts -> 2565 projected 4 KiB pages
                                      |
                  8 crossing slots -> 16 corrected page fragments
                                      |
                   separate corrected-reader signing rechecks
                   continuous startup: preserved, not advanced
```

Primary evidence: original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [source/chain receipts](triage_evidence/kernel_boot_fixup_projection_checks.json.zst), [proof/CPU/projection audit](triage_evidence/kernel_boot_fixup_projection_audit.json.zst), the frozen [page reader](triage_evidence/kernel_vm_mig_tools.py), [signing report](kernel_initializer_pointer_signing_report.md) and [continuous logging report](kernel_early_logging_execution_report.md). The new [recovery module](triage_evidence/recover_kernel_boot_fixup_projection.py) supplies CorrectedImage separately; prior reader, artifacts and original inputs remain byte-identical. No IDB was queried or changed.

| Source | Established role / limit |
| --- | --- |
| `0xfffffe000c65c078` | Previously captured cold-entry call to boot initializer |
| `0xfffffe000c66058c..0xfffffe000c660ad4` | 338-word boot initializer: header discovery, chained-fixup loop, publisher and later helper call |
| `0xfffffe000c660948` | Per-word format gate and repeated next-link boundary |
| `0xfffffe000c660958` | Load original encoded u64 word from X0 slot |
| `0xfffffe000c660974` | Store resolved or signed pointer back to its slot |
| `0xfffffe000c6609dc` / `0xfffffe000c6609f4` | IA / IB signing of X17 using modifier X16 |
| `0xfffffe000c6609ec` / `0xfffffe000c6609fc` | DA / DB signing of X17 using modifier X16 |
| `0xfffffe000c660a04` / `0xfffffe000c660a14` | Unsupported-format/missing-cache exit / end-of-chain boundary |
| `0xfffffe000c660a54` | Kind-1 header/slide publisher call, source-proved separately |
| `0xfffffe000c660a8c` | Subsequent helper call; unexecuted in this increment |

The retained source includes the initializer and 143-word publisher, 481 words/1924 B total. A raw-image CPU prefix begins at the initializer and stops before the first format-gate instruction after 5616 source visits. It derives slide X19=0, root header X20=`0xfffffe0007004000`, first slot X0=`0xfffffe0007e2c270` and segment-start metadata X13=`0xfffffe000e85c048`. X12 points to its stack cache-base array. This prefix writes only its 160 B frame; it neither applies the million fixups nor reaches bank publication. The later publisher call is a source relation, not a claimed executed return. [BP-A1-BP-A3]

Let W be the encoded u64 word, A its slot address, C[0..3] the cache bases and B=C[(W>>30)&3]. The loop admits low-16-bit formats 8 or 11 and exits when B=0. It forms target T=`(B + (W & 0x3fffffff)) mod 2^64`. Bit 63 selects signing. For signed words, D=(W>>32)&0xffff, address-diversity bit a=(W>>48)&1 and key k=(W>>49)&3. Modifier M is D when a=0; when a=1 it is A for D=0, otherwise `(A & 0x0000ffffffffffff) | (D<<48)`. Key values 0/1/2/3 select IA/IB/DA/DB. Unsigned words store T; signed words store the corresponding opaque key-specific sign(T,M). Hardware keys and signature values are unknown. [BP-A2-BP-A4]

After the store, N=(W>>51)&0xfff selects the next link. N=0 reaches the end-of-chain boundary. Format 8 advances by 4N B; format 11 advances by N B. The source retains W across the store and extracts the next field from that original word. All concrete collection records are format 8 and cache level 0; IB/DB and format-11 witnesses are separately declared synthetic cases, not claims about this collection's native contents. The metadata decoder rejects multi-start entries for this pinned profile; no such entry is present. [BP-A2-BP-A4]

| Pinned corpus property | Exact count |
| --- | ---: |
| Fixups / nonoverlapping 8 B slots | 1036413 |
| Target bytes projected | 8291304 B |
| Unsigned words | 124710 |
| Signed words | 911703 |
| Signed key IA / DA | 908962 / 2741 |
| Signed address diversity clear / set | 29019 / 882684 |
| 16384 B chain-page records | 681 |
| Corrected 4096 B output pages | 2565 |
| Compared output-page extent | 10506240 B |
| Crossing slots / changed legacy pages | 8 / 16 |

For each chain page, the recovery retains segment/page metadata, first/last slot, pointer count and a digest of every ordered record. The digest stream uses little-endian Q slot, Q raw word, Q target, Q effective modifier, I next-step bytes, B auth, B key, B address-diversity: 39 B per record, with modifier zero for unsigned words. The independent audit matches every record against the pre-existing parser's metadata and reproduces all chain receipts. A separate byte-at-a-time projection from raw bytes then checks every corrected page. No duplicate or overlapping slots occur, so earlier stores cannot overlap later encoded words in this pinned profile. This corroborates target projection and local source semantics; it is not a proof of complete native boot execution or general malformed-metadata handling. [BP-A1-BP-A4]

The legacy reader indexes a fixup only by its starting page and assigns all eight target bytes to a bytearray slice there. At offset 4092, Python grows the array to 4100 B. Loading the next page independently uses its original encoded leading four bytes, without the incoming target fragment. CorrectedImage clips each store to the current 4096 B page and additionally indexes the eight incoming fragments on their following pages. It always returns exactly 4096 B. Of the 16 changed projections, eight first pages retain identical first 4096 B but lose their erroneous four-byte extension; eight following pages receive four corrected leading bytes. The underlying shared reader remains frozen for historical reproducibility; new boot projection and the rechecks explicitly use the corrected view. [BP-A4-BP-A5]

| Crossing slot | Correct logical u64 target |
| --- | --- |
| `0xfffffe0008390ffc` | `0xfffffe0008390b50` |
| `0xfffffe0008457ffc` | `0xfffffe00078f5c0f` |
| `0xfffffe0008459ffc` | `0xfffffe00078f5bf9` |
| `0xfffffe000845cffc` | `0xfffffe00078f5f31` |
| `0xfffffe000845effc` | `0xfffffe00078f5bf9` |
| `0xfffffe0008461ffc` | `0xfffffe00078f5c02` |
| `0xfffffe0008616ffc` | `0xfffffe0007afa329` |
| `0xfffffe000cc0dffc` | `0xfffffe000920bd84` |

For example, concatenating the legacy first-page tail and next-page head at slot `0xfffffe0008390ffc` gives bytes `500b390800001800`; corrected bytes are `500b390800feffff`. Eight retained boundary controls reproduce these mismatches and reject the 4100 B legacy page size. This is a defect in the analysis projection, not an observed target-kernel fault. [BP-A4-BP-A5]

Thirteen nonvacuous QF_AUFBV source obligations cover format/cache admission, target calculation, address/diversity blending, four key-specific signing paths, format-8/11 end/next relations and the publisher-call ABI. They cover 78 instruction instances at 51 distinct PCs. The signing functions remain uninterpreted. Eighty-six private CPU cases cover the raw prefix, original word samples including all eight crossings, both supported formats, all four keys/cache levels, diversity/address-diversity combinations, zero/maximum next fields, missing cache bases and unsupported formats. The original-word cases use declared private slots; source proofs supply the arbitrary-slot modifier relation. They do not replay the words at their original native epochs. [BP-A2-BP-A5]

Fresh independent CPU replay checks 8122 visits, 1061 reads, 94 writes, 71 PAC envelopes, all 31 final GPRs/SP/NZCV, 90177536 private bytes and 401408 raw image-page bytes. The host oracle supplies 586 assertions. Two NOP controls remove the original pointer store or the format-8 next-offset shift; both retain the same initial configuration/registers/RAM and are rejected. [BP-A3-BP-A5]

The corrected-reader recheck reruns all 29 retained [signing cases](kernel_initializer_pointer_signing_report.md), including the original collection. Their source visits/reads/writes, PAC envelopes, signer entries, registers, private-RAM hashes and independent semantic-oracle results remain exact. Fresh replay checks all 311801 visits, 60467 reads, 27977 writes, 12998 PAC envelopes and 1872 signer entries, plus 30408704 private bytes and 3362816 image bytes. None of these cases reads or writes an incoming four-byte correction. Only the original-collection case maps an affected page: `0xfffffe0008391000`; its final digest changes from `b9db6c060b77805f094c7421c5dc8c6ee17f2c6e695c23ff72c4218272801b59` to `980a699cc86c6b156ce273d8d82623fb0676ca85fd07c1fe4c12019099f583d5`. Prior journals are reused by digest reference with this explicit page-hash delta; no duplicate journal is presented as a new startup epoch. [BP-A5-BP-A6]

The current [continuous logging case](kernel_early_logging_execution_report.md) maps none of the 16 affected pages and remains unchanged. This scope audit covers that case and the 29 signing cases only; other historical consumers of the legacy reader remain unaudited. Existing successful self-consistency checks alone do not prove their page projections correct. Full boot fixup execution, later range publication, replacement of the poisoned header premise, outer logging completion and native FairPlay IPC remain open. No incoming/outgoing Mach right, message ID or port-emission site is added by this increment. [BP-A6-BP-A7]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_boot_fixup_projection_checks.json` | `e1b16525a37cb32a273cca02ced516896abe4be83bcfa418f0510760c29ac3f8` |
| `kernel_boot_fixup_projection_audit.json` | `6d8438ec606fffae6fdf9cbb3f10bdb8f8488fb039ed2df22ddbec7d42ad7692` |

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BP-A1: Pinned collection fixes source, metadata and encoded words | Corpus and address claims | Rebuild both original bodies, all 681 chain receipts and the image digest |
| BP-A2: Supported instruction semantics and opaque key-specific signing functions bound local proofs | Target/modifier/key/next relations | Rederive 13 nonvacuous obligations; native cryptographic outputs unknown |
| BP-A3: Declared raw/private fixtures define CPU cases | Prefix, finite cuts and boundary counts | Independent host oracle/replay; distinguish private original-word witnesses from native slots/epochs |
| BP-A4: Format-8/cache-0 nonoverlapping chains define this corpus | All-record target projection | Independent metadata equality, slot uniqueness/separation and byte-at-a-time output over every page; broader formats/metadata unproved |
| BP-A5: Separate corrected view and frozen dependencies define rechecks | Page correction and retained-case equivalence | Eight old-reader rejection controls, two source mutations and complete fresh signing replay |
| BP-A6: Scoped consumer audit does not cover all historical reader users | Preservation and remaining-work claims | Check current logging mapped pages and all 29 signing journals; audit additional consumers separately |
| BP-A7: Fixup source/projection is not full boot or FairPlay transport | Startup/Mach limits | Execute/qualify remaining boot control, header handoff, callbacks and matching rights/messages/statuses; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Use corrected projection in boot-state composition | Explicit raw-to-logical custody, header/slide publication and preserved poisoned regression |
| High | Qualify remaining boot loop/control and later range helper | Actual or fully proved transitions through bank publication and initializer return |
| High | Audit additional legacy-reader consumers that map affected pages | Original affected bytes, read/write intervals and corrected replay; no universal historical claim |
| High | Continue initialization and pair FairPlay IPC | Callback admission, class lifecycle and actual right/message custody across matched epochs |
| Medium | Broaden fixup admission and native authentication | Other cache levels, multi-start metadata, malformed bounds, mapping permissions and actual IA/IB/DA/DB outcomes |

Recovery/projection and retained-journal checks are O(collection bytes + fixups + source/journal/page bytes), with sorting O(F log F) for slot separation and O(F + page bytes) retained storage. CorrectedImage adds only the eight incoming-fragment entries to the existing image index. SMT search is separate with a 30 s query limit. CPU prefixes/cuts and finite rechecks remain distinct from applying a universal source contract to all metadata records.

**QG1**: Factual technical analysis; no normative content required. **QG2**: BP-A1-BP-A7 list dependencies and falsification probes. **QG3**: Source fixup contract, all-record projection, eight-slot defect, corrected view, scoped prior-case rechecks and boot/Mach limits covered; full goal active. **QG4**: Exact widths, 39 B digest records, page/slot extents, strides, modular arithmetic and separate proof/CPU/corpus counts explicit. **QG5**: Legacy/corrected/raw views, source cuts/full boot, logical/native PAC and scoped/universal consumer claims distinguished. **QG6**: Original source/metadata, all-record and byte-wise independent comparisons, source proofs, CPU replay and negative controls retained. **QG7**: Impact-ranked bounded continuation included.
