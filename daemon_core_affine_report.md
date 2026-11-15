# fairplayd: initial byte codecs and AES S-box/MixColumns table contracts

The core's initial sixteen word-table indices are an exact permutation of the sixteen input bytes followed by four invertible affine byte encodings. All four main word tables factor through the forward AES S-box. After explicit word normalizers, they equal the four forward AES MixColumns contributions under one shared word encoding, plus constant biases. Thirty-two universal source projections and complete finite-domain checks establish these contracts for the two retained contexts. Complete round composition, a key schedule, the full primitive and native daemon-kext transaction pairing remain unknown. [CA1-CA6; CA-A1-CA-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| CA1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`: source instructions, original word/byte windows and Mach-O mapping metadata. |
| CA2 | [Core lookup model](daemon_core_lookup_report.md), [block staging](daemon_block_staging_report.md), and their pinned receipts. The previous complete core graph, address/exit proofs, scalar replay and 156 vector comparisons remain dependencies; they are not rerun here. |
| CA3 | [Extractor](triage_evidence/recover_daemon_core_affine.py), [checks](triage_evidence/daemon_core_affine_checks.json.zst): source projections, complete byte maps, affine coefficients, candidate witnesses, explicit left inverses and encoded MixColumns identities. |
| CA4 | [Auditor](triage_evidence/audit_daemon_core_affine.py), [audit](triage_evidence/daemon_core_affine_audit.json.zst): thirty-two UNSAT projections, original-byte checks, independent finite-field reference construction and all positive/negative finite certificates. |
| CA5 | [Publication verifier](triage_evidence/verify_daemon_core_affine_publication.py): fresh extraction/audit, canonical query comparison and re-solving, exact manifest delta, original-input preservation and decoded path hygiene. |
| CA6 | [NIST reference capture](triage_evidence/daemon_core_affine_reference.json.zst), [capture tool](triage_evidence/capture_daemon_core_affine_reference.py), and [FIPS 197-upd1](https://doi.org/10.6028/NIST.FIPS.197-upd1). The official PDF supplies the S-box and forward MixColumns reference; it supplies no claim about the target binary. |

Decoded SHA-256 values: `d46e946d6acca5be5f2a599544bde0dae5a755b2b8a2011a244ac2865be09c8f` (CA3), `ec0188120431ee0d83f7bc606e4122197f3a5ae97d0a5703656411ae663418e6` (CA4), `7fe2e9953f620e6d7c210f177197cb8d4b537ade926bdba7d8085969aaf49553` (CA6 capture). The NIST PDF has SHA-256 `62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1` and size 1184436 B. Its Table 4, printed page 14/PDF index 21, is parsed into all 256 byte values; the auditor independently regenerates them from GF(2^8) inversion and the standard affine step. The offline auditor checks the capture and its generator hash without refetching the PDF. [CA3-CA6]

## Initial input/index contract

Let A[16] denote the staged core input at H+0xd0=`0x680005fa80`, with retained H=`0x680005f9b0`. For each initial word read j:

```text
index_j = M_bank(A[input_offset_j]) XOR c_j
```

Each M is an 8-by-8 matrix over GF(2), represented below by eight output-byte columns in order of input bits 0 through 7. All numbers in the column strings are hexadecimal bytes. XOR combines the columns selected by set input bits. All four matrices have rank 8 and map the complete u8 domain bijectively. [CA1-CA5; CA-A1-CA-A4]

| Bank label | Main table base | Matrix columns, bits 0..7 |
| --- | --- | --- |
| A | `0x100e40e10` | `69 47 dd 0b a8 67 02 8e` |
| B | `0x100f33b10` | `8d d3 59 91 2c 44 09 e6` |
| C | `0x100fdec70` | `ab 2d b2 a1 d7 9a 71 35` |
| D | `0x100e94720` | `69 73 d4 f6 30 1b a4 25` |

| Read j | Original read PC | Input offset | Bank | c_j | First S-box input XOR kappa |
| --- | --- | --- | --- | --- | --- |
| 0 | `0x10010f2e0` | 5 | A | `a9` | `a6` |
| 1 | `0x10010f338` | 10 | B | `bd` | `9a` |
| 2 | `0x10010f3a8` | 0 | C | `44` | `db` |
| 3 | `0x10010f3e8` | 4 | C | `52` | `f1` |
| 4 | `0x10010f41c` | 9 | A | `bf` | `60` |
| 5 | `0x10010f42c` | 14 | B | `76` | `27` |
| 6 | `0x10010f434` | 3 | D | `e3` | `ae` |
| 7 | `0x10010f458` | 13 | A | `bb` | `92` |
| 8 | `0x10010f4b0` | 15 | D | `e8` | `f7` |
| 9 | `0x10010f4d4` | 8 | C | `72` | `a2` |
| 10 | `0x10010f500` | 1 | A | `15` | `30` |
| 11 | `0x10010f508` | 2 | B | `36` | `b1` |
| 12 | `0x10010f5c4` | 7 | D | `94` | `66` |
| 13 | `0x10010f5d8` | 12 | C | `f9` | `f0` |
| 14 | `0x10010f5f4` | 6 | B | `f2` | `66` |
| 15 | `0x10010f608` | 11 | D | `67` | `87` |

The proof is compositional. Each initial byte-table index depends on one input byte; complete enumeration checks its XOR-index encoding. Each word-index source expression is then projected to that byte and the corresponding byte-table return value, setting every other symbolic operand to zero in the candidate expression. A universal query proves equality with the full expression for arbitrary values of all original operands. Complete enumeration of the retained byte-table values establishes the affine map for all 256 inputs. This removes spurious syntactic dependencies without assuming that unrelated input bytes are zero during use. [CA3-CA5; CA-A1-CA-A4]

The sixteen input offsets form a permutation and each component map is bijective. Consequently the initial sixteen-index vector is a bijection of the 128-bit staged input under these source contexts. This does not decide whole-transform invertibility. [CA3-CA5; CA-A2-CA-A5]

## Exact S-box factorization

Let T_b[i] be the little-endian u32 stored at table b, index i. Let S be the forward S-box in FIPS 197-upd1. For every u8 x, the original table bytes satisfy:

```text
T_b[M_b(x)] = L_b(S(x XOR delta_b)) XOR K_b(x) XOR bias_b
```

L_b embeds eight bits into a 32-bit word with rank 8. K_b is linear into the low byte of a u32. Every coefficient is retained in the checks receipt. An explicit 32-to-8 linear left inverse D_b satisfies `D_b(L_b(y))=y` for every u8 y. Thus removing K_b(x) and bias_b from the raw word and applying D_b recovers exactly `S(x XOR delta_b)`. These are complete 256-entry identities. [CA1,CA3-CA6; CA-A1-CA-A5]

| Bank | delta_b | bias_b, u32 | K_b(x) | Rank L_b |
| --- | --- | --- | --- | --- |
| A | `6d` | `ead4f6e7` | 0 | 8 |
| B | `82` | `508be0fd` | zero-extended M_B(x) | 8 |
| C | `1b` | `5ac27ccd` | 0 | 8 |
| D | `36` | `9f62fce4` | zero-extended M_D(x) | 8 |

The search covers 4096 candidates: four fixed recovered input matrices, forward/inverse reference, every u8 delta, and either a plain affine output or an affine output with an additional linear input term. Six candidates fit: A and C fit both forms, B and D fit the extended form. Each bank has exactly one forward-reference delta in the extended family. All inverse-reference candidates fail. Uniqueness is confined to this explicitly searched family; arbitrary alternative input matrices are outside it. [CA3-CA6; CA-A3-CA-A5]

For each of the 4090 rejected candidates, the receipt retains a finite contradiction witness: XORing the selected feature vectors gives zero, while XORing the corresponding original table words gives a nonzero u32. Such a combination cannot occur under a linear map of those features. The auditor checks all witness terms independently, rather than trusting a failed fit flag. The six positive fits are checked on all 256 rows. [CA3-CA5]

Combining the initial-index contract with the factorization gives the exact first nonlinear argument:

```text
kappa_j = inverse(M_bank)(c_j) XOR delta_bank
S-box argument = A[input_offset_j] XOR kappa_j
```

In input-offset order, kappa is `db30b1aef1a66666a2609a87f09227f7`. It is a component input-offset vector. Cryptographic key status, key length, expansion and native material lineage remain unknown. Composing the already established input staging gives argument `S_serialized[2+p] XOR Mi[p] XOR kappa[p]` for each offset p; that formula retains the prior staging/context premises. [CA2-CA5; CA-A2-CA-A5]

## Forward MixColumns table identity

Define a shared invertible word encoder, with row 0 in bits31..24:

```text
E(v0,v1,v2,v3) = M_C(v0)<<24 | M_A(v1)<<16 | M_B(v2)<<8 | M_D(v3)

MC = [ 2 3 1 1 ]
     [ 1 2 3 1 ]
     [ 1 1 2 3 ]
     [ 3 1 1 2 ]
```

MC multiplication is over GF(2^8) using polynomial `0x11b`. This is the forward MixColumns matrix specified in FIPS 197-upd1 section 5.1.3. With e_r selecting one input row, every main table satisfies:

```text
i = M_b(x)
H_b(i, T_b[i]) = E(MC * (S(x XOR delta_b) * e_r)) XOR beta_b
```

| Bank | r | H_b(i,y), u32 operations |
| --- | --- | --- |
| A | 1 | Let z=ROR32(y,18); return z XOR ((z<<3) AND `e19e3e68`) |
| B | 2 | y XOR zero_extend32(i) |
| C | 0 | y XOR LSR32(y,2) XOR LSR32(y,6) |
| D | 3 | y XOR zero_extend32(i) |

Here `beta_b=H_b(0,bias_b)`; exact values are retained with the normalized-table certificates. All 1024 rows are checked using the original words. The auditor independently constructs multiplication by 2 and 3 using xtime and compares the resulting encoded words. [CA1,CA3-CA6; CA-A1-CA-A5]

These equations establish finite identities for the original tables. Establishing how every source consumer reconstructs and combines the normalized contributions remains a separate obligation. The identities therefore support forward AES S-box/MixColumns ingredients while leaving complete semantic rounds, AddRoundKey values, key expansion, final-layer decoding and whole-primitive equivalence unknown. [CA2-CA6; CA-A4-CA-A5]

## Architectural context and verification

The Mach-O `LC_SEGMENT_64` at file offset `0x68` declares `__TEXT` initial/maximal protections `0x5` (read and execute). All sixteen core data windows, including the eight byte and eight word windows, lie within that segment. The auditor independently checks the command fields and window containment. These are declared image mappings; current native page protections and runtime table mutation remain unknown. [CA1,CA3-CA5; CA-A1-CA-A2]

```text
staged A[16]
     |
16 affine index codecs -- 32 source projections / complete u8 domains
     |
forward S-box embeddings -- all four original word tables
     |
encoded forward MixColumns contributions
     |
remaining source composition / final decoding: unknown
```

The new audit checks 8192 prefix-index rows, 8192 projected source rows, 8192 affine-map rows, 32 bijective byte codecs, 1024 original word entries, 4096 factor candidates, 1536 positive-fit rows, 25942 rejection-witness terms, 1024 decoded S-box rows, 1024 encoded MixColumns rows and 8192 first-S-box argument rows. Thirty-two nonvacuous source projection queries are UNSAT. The parent core's complete replay and admission proofs are pinned rather than rerun. No new target interval, root admission, native API/IPC, hardware PAC or IDB mutation occurs. [CA2-CA5]

The internal core phase and its outgoing branch remain those of CA2. This increment establishes no additional Mach right, message-emission site or daemon-kext pairing. The [port report](mach_ports_report.md) retains the transport evidence and its unresolved joins. [CA2-CA5; CA-A6]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| CA-A1: Pinned source, dependencies and source-lift semantics apply | Original coordinates, source projections and finite identities | Rehash inputs; regenerate projections and table words; replay the pinned parent independently or compare another ISA implementation. The current source lift shares provenance with the parent model. |
| CA-A2: The two retained entry/read-value contexts and literal windows apply | Conditional byte/index and component data flow | Recover authentic caller/controller epochs, placements and runtime mapping state. Initial header protections and two retained contexts do not exhaust native environments. |
| CA-A3: Bit order, GF(2) column convention and NIST reference apply | Matrix inversion, S-box identification and factor search | Parse all Table 4 rows from the pinned official PDF; independently regenerate S and inverse S; check all 256 matrix inputs, explicit left inverses and MixColumns products. |
| CA-A4: Source projections and complete finite composition qualify the cuts | Initial 128-bit bijection and first nonlinear arguments | Re-solve each arbitrary-operand projection, enumerate each full byte domain and check original bank bytes. An affine fit to sampled blocks alone would not establish this contract. |
| CA-A5: Table identities are distinguished from complete round/key semantics | AES ingredients with whole primitive unknown | Recover source combinations, round boundaries/constants and final decoding; compare a separately specified complete primitive before assigning cipher/key/mode semantics. Candidate uniqueness is limited to the recorded family. |
| CA-A6: Private component data flow is distinguished from transport | No new Mach/IOKit or native transaction correspondence | Join authentic result consumers and caller/port/IOKit histories to a matched daemon-kext exchange. Current table constants and indices do not establish that join. |

Reproduction in the established Python/Z3 environment runs `recover_daemon_core_affine.py`, then `audit_daemon_core_affine.py`; after manifest refresh run `verify_daemon_core_affine_publication.py`. Reference recapture accepts a supplied pinned PDF or performs read-only HTTPS retrieval from the official alternate NIST endpoint. Nontrivial JSON uses `zstd --ultra -22 -q -T1` with decoded hashes/roundtrip checks. For C=4096 candidates, 256 rows and at most 17 feature bits, elimination takes O(C*256*17) fixed-width row operations; retained witnesses and coefficients use linear receipt storage. Source lifting/DAG work and solver search are additional, with 30 s per query. [CA3-CA6]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Establish complete round-state semantics | Certify source consumers of normalized terms, state encodings, next-layer index equations and round constants. |
| High | Identify the full primitive and key schedule | Recover final-layer decoding and compare complete independent algorithm vectors plus expansion identities. |
| High | Connect component results to native daemon-kext traffic | Recover authentic consumer objects and matched port/right/IOKit transaction history. |
| Medium | Generalize the fixed source context | Establish actual controller selection, object lifetime, placements and table preservation beyond the retained cases. |

**QG1**: Factual technical scope. **QG2**: CA-A1 through CA-A6 register dependencies and falsification probes. **QG3**: Initial source/index codecs, nonlinear reference factorization, encoded column contributions, declared mapping context and transport limits are covered for this increment; the full goal remains active. **QG4**: u8/u32 domains, bit order, matrix dimensions, field polynomial, endian order, byte extents, counts and complexity are explicit. **QG5**: Arbitrary-operand source projections versus sampled fits, component offsets versus key semantics, finite table normalization versus source round composition and declared versus runtime mappings are distinguished. **QG6**: Pinned original bytes, official PDF/Table 4, independent field arithmetic, explicit finite witnesses and source solver certificates provide provenance. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; the full primitive and native interaction join remain unknown.

## Core round-composition follow-up

[The nine-layer composition report](daemon_core_rounds_report.md) proves the source consumer equations for all nine main substitution/ShiftRows/MixColumns layers and all sixteen terminal word indices. The source interleaves layers and terminal/output lookups. Eight recovered offset vectors exactly match an AES-128 expansion subsequence, giving a nine-layer encryption prefix under an explicit core input whitening. Final decoding, full encryption equivalence and native daemon-kext/material correspondence remain unknown; assumptions, source proofs and independent checks are retained there.
