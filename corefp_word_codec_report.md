# CoreFP paired u64 word storage and compensated hash inputs

The first arithmetic pass stores each retained destination word XORed with `0xcccccccccccccccc`. Both second-pass word decoders recover the same hash input as the first pass: the original word multiplied by `0xabdf5fe3f3ef5db9`, modulo 2^64. Their obfuscated arithmetic introduces different additive biases, canceled by the following multiply-add constants. This establishes a local producer/consumer interface inside the earlier passes. The complete per-word hash recurrence, accumulator-bank preservation and equal scan-initializer seed production remain unknown.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_word_codec.py), [checks](triage_evidence/corefp_word_codec_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_word_codec.py), [audit](triage_evidence/corefp_word_codec_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_word_codec_publication.py) retain four source slices, 32 complete component frames/journals, 16 word epochs and eleven UNSAT obligations. Fourteen parent receipts and seventeen source dependencies are SHA-256 pinned. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. The three originally supplied inputs are unchanged. Source addresses are preferred-base-zero offsets; B denotes bytes.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WC1 | The pinned image, receipts and dependencies identify the analyzed source. All source results depend on these bindings. | Compare original instructions, decoded hashes, preserved inputs and dependency hashes. |
| WC2 | Existing private caller/context/backing/PAC/sequential-CASAL fixtures apply. Whole-caller continuity depends on these interfaces. | Freshly reconstruct six initial CPU/RAM states and replay all 488136 visits and journals. Native ownership, input admission, authentication and synchronization remain unknown. |
| WC3 | First-head X8=`0x8569`; second-head X24=`0x1912e4b015aaf11f`; second-tail X8=`0x86aa3caf8765908f`. The common-key and decoder reductions depend on these controls. | Compare every retained entry, prove the first-head general-control expression and run 22 one-bit control falsifiers against unchanged instructions. Universal control production remains unknown. |
| WC4 | Named raw-read, store and encoded-read epochs refer to the same eight backed bytes, with no intervening overlapping write. Cross-pass word lineage depends on this epoch premise. | Check address, width, event order, exact bytes, all intervening writes and component register values in all sixteen retained epochs. Native aliases, concurrent mutation and arbitrary-length traversal remain unproved. |
| WC5 | Algebraic cuts may substitute only separately proved source expressions. Composed decoder/product proofs depend on that equality. | Independently rerun every retained query, compare a separate integer source interpreter and execute the original full slices without substitutions for 131072 finite component cases. |

## Source interfaces [WC1-WC3,WC5]

All operations below are on u64 values; addition and multiplication wrap modulo 2^64 before reuse. Let `K=cccccccccccccccc` and `M=abdf5fe3f3ef5db9`, in hexadecimal. Let W denote the raw word, E the stored encoded word and H an arbitrary incoming hash state.

| Slice | Source interval | Instructions / B | Word/hash input | Data output |
| --- | --- | --- | --- | --- |
| First head | `[0x1b4900,0x1b4934)` | 13 / 52 | X28=W, X19=H; X27=destination | store E at `0x1b4930`; X28=W*M; X19=H XOR (W*M) |
| First tail | `[0x1b4efc,0x1b4f1c)` | 8 / 32 | X3=W, X19=H; X2=destination | store E at `0x1b4f00`; X2=W*M; X3=H XOR (W*M) |
| Second head | `[0x1b5738,0x1b57d0)` | 38 / 152 | X3=E, X12=H | X3=(E XOR K)*M; X12=H XOR ((E XOR K)*M) |
| Second tail | `[0x1b5d84,0x1b5e1c)` | 38 / 152 | X3=E, X12=H | X20=(E XOR K)*M; X12=H XOR ((E XOR K)*M) |

The slices contain 97 instructions/388 B. Their word loads occur immediately before the listed intervals: `0x1b48fc`, `0x1b4ef8`, `0x1b5734` and `0x1b5d80`, respectively. The selected slices themselves have no loads or control transfers. Their only memory writes are the two encoder stores. The first-tail slice ends before the separate X16 hash bias at `0x1b4f1c`; its X3 result must not be confused with the later X19 state.

The first head has the general source contract:

```text
E = W XOR (X8 + cccccccccccc4763)
hash_input = W*M
hash_after = H XOR hash_input
```

At X8=`8569`, the key sum equals K. This control restriction affects the stored encoding; the raw-word hash input remains W*M independently of X8. The first tail uses literal K and needs no corresponding key-control premise.

The second-pass decoders have these source-normalized intermediates:

| Decoder | Source cut | Pre-multiply X3 | Following additive compensation |
| --- | --- | --- | --- |
| Head | `0x1b57a8` | `(E XOR K) + 91499b0ece9271b0` | `5737958f518ee7d0` |
| Tail | `0x1b5df4` | `(E XOR K) + 12f88b4c91857f78` | `7ff561c46e304a48` |

For each row, `bias*M + compensation = 0`, modulo 2^64. Hence:

```text
((E XOR K) + bias)*M + compensation
  = (E XOR K)*M
  = W*M                         when E = W XOR K
```

Two arbitrary-u64 source obligations establish the pre-multiply expressions under WC3. Two constant modular obligations establish compensation. Two composed source obligations establish the product and hash XOR after substituting only the separately proved pre-multiply expressions. This cut is a proof composition; the independent original-byte executions retain all obfuscated instructions.

The two first-pass contracts, first-head control normalization, the six decoder/compensation/product contracts, word round-trip and common-hash XOR preservation give eleven new obligations. The common hash-input identity holds for arbitrary u64 words and hash states under WC1/WC3/WC5. Equal incoming hash states therefore yield equal states immediately after these selected XORs; any pre-existing hash XOR difference is preserved there. Subsequent arithmetic is outside this identity.

## Cross-pass word epochs and control flow [WC2-WC4]

| Retained extent | First head / tail executions | Second head / tail executions | Matching u64 epochs |
| --- | --- | --- | --- |
| 16 B, four profiles | 1 / 1 per profile | 1 / 1 per profile | 8 total |
| 32 B, two profiles | 1 / 3 per profile | 3 / 1 per profile | 8 total |
| Total | 6 / 10 | 10 / 6 | 16 |

The first pass writes every retained word in increasing address order. The second pass reads the resulting words in that order. Each raw load precedes its encoder store; each encoded load follows that store and observes its exact eight output bytes. No intervening overlapping write occurs. Each component's incoming word register is joined to its immediately preceding named load. These are observations of the six frozen caller fixtures and freshly reproduced journals, not an arbitrary-length traversal theorem.

```text
raw destination word W
        |
        +--> first-pass product W*M --> hash XOR --> unreduced arithmetic
        |
    store E = W XOR K
        |
    same eight-byte epoch, no overlapping write
        |
    second-pass load E
        |
    obfuscated decode + bias --> multiply + compensation
        |
    recovered product W*M --> hash XOR --> unreduced arithmetic
```

The component cuts exclude the surrounding BRAA dispatches and address-generation arithmetic. Their provenance is supplied by whole-caller replay under the existing PAC/table fixtures. Neither a recovered key nor the matching epochs establishes native buffer ownership, an external writable interface or a cryptographic classification of the full routine.

## Validation and continuation

The auditor does not import the new producer. It independently reconstructs six initial CPU frames and 3313664 B of initial RAM; checks 488136 original visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM; and compares every selected CPU/stack frame. A separate integer interpreter compares all 32 complete source-slice frames and stores. Original table workspace and preparation oracles are also rechecked.

Each of 32 original-byte component domains executes `8*256` word-byte cases and `8*256` hash-byte cases, totaling 4096 cases per domain and 131072 cases overall. All 32 domains preserve the original source bytes and stack. Their finite source visits total `4096*(13*6+8*10+38*10+38*6)=3137536`. Twenty-two off-premise one-bit controls execute a further `13*6+38*10+38*6=686` source visits: six first-head controls reject the common stored key while preserving the raw hash input; sixteen decoder controls reject the common recovered product/hash. Exact falsifiers and ordered ending-frame/store digests are retained. Counts describe component tests, not distinct native inputs.

All eleven new obligations and 1144 frozen obligations are independently UNSAT, totaling 1155 with a 30 s/query limit. Whole-caller replay, arbitrary-scalar proofs, finite components, control falsifiers and native behavior have separate scopes. Replay time/space is conservatively `O(C*(B+V*J+P*F+R))` for C profiles, source bytes B, visits V, per-visit journal/state cost J, touched pages P, frame/page payload F and other retained bytes R. Component testing takes `O(4096*Kc)` time for Kc retained component visits, with bounded private maps; solver complexity is separate. The reduced scalar codec uses constant time and space.

No new incoming/outgoing Mach port, right, descriptor, message emission or daemon/kext pairing is established. No native target/API/IPC or IDA operation occurs; original file evidence suffices. The [scan-entry report](corefp_scan_entry_report.md) retains its earlier-pass join premises. Only the word-storage/product boundary within those passes is discharged here. The full investigation remains active.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Reduce the arithmetic following each recovered word product. | Derive a common per-word recurrence, including index terms and hash biases, and join bank-XOR preservation and equal initializer seeds. |
| High | Replace fixed codec controls and retained address epochs with producer contracts. | Prove control production, full address traversal, backing and same-epoch input lineage for declared caller domains. |
| High | Establish native selector/context/holder ownership and admission. | Original initialization and coherent native entry/backing evidence are required. |
| Medium | Exploit the split reversal as an analysis boundary. | Compare first-head/second-head and first-tail/second-tail recurrence transfers independently; split-count symmetry alone does not prove equality. |
| Low | Connect the local codec to daemon/kext transport. | Require actual serializers, consumers and endpoint/right epoch joins. |

- **QG1**: No normative premise is required.
- **QG2**: WC1-WC5 identify dependencies and falsification probes.
- **QG3**: Word storage, hash input, data epochs, controls, selected flow, environmental premises and external-interface limits are covered.
- **QG4**: U64 arithmetic, modular compensation, eight-byte extents, exact case/visit counts and complexity are explicit.
- **QG5**: Fixed controls, algebraic cuts and finite traversal are distinguished; full recurrence, native ownership and cross-layer linkage remain unknown.
- **QG6**: Pinned original bytes/receipts, fresh replay, independent scalar interpretation, unchanged-byte execution, epoch checks and retained queries provide reproducible provenance.
- **QG7**: Impact-ranked continuation includes recurrence, controls/backing, native owners, split structure and transport.
