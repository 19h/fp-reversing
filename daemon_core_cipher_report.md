# fairplayd: complete AES-128 block component and wrapper XOR contract

Under the two retained source contexts and pinned literal tables, the complete 128-bit core is AES-128 encryption with explicit input/output XOR encodings. Composing the established staging loops cancels their position-dependent masks into the same repeated byte on both sides: `T = AES128_K(S_serialized[2:18] XOR H) XOR H`, where H is sixteen `0x98` bytes and K=`db55ebcef63f382c0cc860693c6fe140`. This is a compositional all-input component result, supplemented by 136 complete block comparisons against the source-derived graph and host OpenSSL. Native caller/controller admission, native key-object lineage, protocol mode and daemon-kext transaction pairing remain unknown. [CC1-CC6; CC-A1-CC-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| CC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`: source instructions, terminal word banks and output byte banks. |
| CC2 | [Core graph](daemon_core_lookup_report.md), [affine tables](daemon_core_affine_report.md), [nine-layer prefix](daemon_core_rounds_report.md), [staging](daemon_block_staging_report.md), and their pinned receipts. Initial byte projections, main-layer composition and complete entry/address/exit admissions remain dependencies; their complete original replays are not rerun here. |
| CC3 | [Extractor](triage_evidence/recover_daemon_core_cipher.py), [checks](triage_evidence/daemon_core_cipher_checks.json.zst), [standalone AES model](triage_evidence/daemon_core_cipher_kernel.py): terminal factorizations, inverse embeddings, complete output byte maps and exact component/wrapper contracts. |
| CC4 | [Auditor](triage_evidence/audit_daemon_core_cipher.py), [audit](triage_evidence/daemon_core_cipher_audit.json.zst): 64 nonvacuous source queries, original-byte/finite-domain checks, negative fit witnesses, 136 source-model comparisons and an independent host OpenSSL reference. |
| CC5 | [Publication verifier](triage_evidence/verify_daemon_core_cipher_publication.py): fresh extraction/audit, canonical query comparison/re-solving, exact manifest delta, original-input preservation and decoded path hygiene. |
| CC6 | [FIPS 197-upd1](https://doi.org/10.6028/NIST.FIPS.197-upd1), sections 5.1/5.2, Algorithm 1/2 and Appendix B; [pinned reference capture](triage_evidence/daemon_core_affine_reference.json.zst). The standard defines the reference cipher; target identification comes from CC1-CC5. |

Decoded checks SHA-256: `5fff08a8f1e2748a344a86ac84e0533e9a0cb690234dde77e07cafc6dee7dc71`. Decoded audit SHA-256: `90c46d9e6c06598e84d8f7e754e907eaa809306f74016bd5612ae3bdf32696f5`. The pinned NIST PDF has SHA-256 `62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1`, size 1184436 B. Its Appendix B supplies the independent complete-cipher checkpoint. [CC3-CC6]

## Complete block and staging contracts

All quantities below are 16 B in column-major AES state order. Let A/B be the staged core input/output and X=`S_serialized[2:18]` the external input window. Define:

| Quantity | Hexadecimal bytes | Established role |
| --- | --- | --- |
| K | `db55ebcef63f382c0cc860693c6fe140` | Mathematical AES-128 seed for the recovered component |
| Wi | `00655a6007995e4aaea8faeeccfdc6b7` | Core input XOR |
| Wo | `07292d2574d1caf7f9dee91c15d49a4a` | Core output XOR |
| Mi | `98fdc2f89f01c6d23630627654655e2f` | Previously proved input staging mask |
| Mo | `9fb1b5bdec49526f614671848d4c02d2` | Previously proved output staging mask |
| H=Mi XOR Wi=Mo XOR Wo | `98989898989898989898989898989898` | Combined wrapper XOR, on both sides |

```text
A = X XOR Mi
B = AES128_encrypt_K(A XOR Wi) XOR Wo
T = B XOR Mo

therefore:
T = AES128_encrypt_K(X XOR H) XOR H
```

The result holds for every 16 B input under the source/literal/context premises, rather than only the retained vector. XOR by a constant is bijective, and the recovered complete primitive is the AES-128 forward cipher, so the conditional component and wrapper block maps are 128-bit bijections. This is an internal block-function identification; a multi-block mode, IV, padding, request operation or public encryption API is not established. [CC1-CC6; CC-A1-CC-A5]

```text
serialized X[16] -- XOR 98 repeated -- AES-128 under K -- XOR 98 repeated -- T[16]
                                         |
                              complete conditional component
```

## Terminal word identities

The terminal indices from CC2 have form `i=M_r(x)` after decoding their fixed offsets. M_r is the previously recovered row encoder. For each original little-endian u32 word table T_r and every u8 x:

```text
N_r(M_r(x), T_r[M_r(x)]) = (M_r(Sbox(x XOR delta_r)) << (24-8*r)) XOR beta_r
```

All arithmetic additions/subtractions/shifts in N use u32 modular results. The source-observed index-dependent corrections are:

| Row r | Word bank | delta_r | beta_r | N_r(i,y) |
| --- | --- | --- | --- | --- |
| 0 | `0x100ed3a70` | `a8` | `65ad4823` | y XOR (y<<2) |
| 1 | `0x100f400e0` | `47` | `d0fd7342` | y + (i XOR `27`) + `494ca6e5` |
| 2 | `0x10101ab70` | `22` | `cf939809` | y XOR i |
| 3 | `0x100f2e680` | `38` | `c0f0a981` | Let z=i XOR `85`; y XOR z XOR (z-((2*z+`2ae`) AND `308`)+`a70652db`) |

All 1024 original rows satisfy the identities. Searching the explicitly fixed input matrices/normalizers against every forward/inverse S-box delta gives 2048 candidates, exactly four positive forward fits and 2044 negative certificates. The auditor checks all 10660 negative-witness terms and all 1024 positive rows. Uniqueness is confined to this candidate family. These word identities and the downstream source equations establish their use; a resemblance between table bytes alone would not. [CC1,CC3-CC4; CC-A1-CC-A4]

The row-3 raw table has only 203 distinct words. Its corrected result also depends on the source index. Consequently a test requiring all raw entries to be distinct would reject a genuine S-box component here. The complete indexed word embedding, checked on all 256 source indices, restores the proper byte contribution. [CC1,CC3-CC4]

Combining each terminal delta with the corrected index offset establishes the last SubBytes input as `V[9][p] XOR K9[p]`, with K9=`3e0a2858a01fd426d9fffee5edf57dfb`. All sixteen bytes equal AES expansion index 9 from K. This resolves the preceding prefix report's predicted index 9. [CC2-CC4]

## Final consumers and output byte interfaces

For each terminal read, the auditor replaces its raw return by an independently constructed inverse-normalizer embedding of a fresh unrestricted u8 S-box-output symbol. Complete 256-entry checks prove that every original table return is represented by that embedding. Fresh source queries also re-establish the terminal-index cuts used in those embeddings. The larger symbolic domain is an overapproximation of all actual terminal table outputs, not an assumption that unrelated source bytes are zero. [CC3-CC4; CC-A1-CC-A4]

For every output position p, the source then satisfies:

```text
input_position = 4*((output_column+row) mod 4)+row
byte_index = M_row(terminal_Sbox_output[input_position]) XOR c[p]
output[p] = post_store_function(byte_bank[byte_index])
          = terminal_Sbox_output[input_position] XOR D[p]
```

The 32 final-byte queries prove these index equations for both contexts with sixteen independent u8 terminal outputs and all remaining original input/lookup operands unrestricted. Each store expression contains exactly its own byte-table return variable. Exhaustive u8 evaluation checks its full post-store function and decoder composition; several post-store functions contain nonlinear addition/squaring terms and are not simple XORs. [CC1,CC3-CC4]

| Output p | Byte lookup PC | Byte bank | c[p] | D[p] | Store PC |
| --- | --- | --- | --- | --- | --- |
| 0 | `0x10011122c` | `0x100e6c8f0` | `5d` | `e9` | `0x100111250` |
| 1 | `0x100110e0c` | `0x100f28b60` | `3f` | `dc` | `0x100110e40` |
| 2 | `0x10011109c` | `0x100e55890` | `a2` | `0a` | `0x1001110c0` |
| 3 | `0x100110ebc` | `0x100fd6530` | `13` | `28` | `0x100110ed4` |
| 4 | `0x1001110f8` | `0x100e6c8f0` | `36` | `3a` | `0x100111118` |
| 5 | `0x100110c4c` | `0x100f28b60` | `e0` | `3b` | `0x100110c70` |
| 6 | `0x1001111bc` | `0x100e55890` | `b4` | `39` | `0x1001111d4` |
| 7 | `0x100111194` | `0x100fd6530` | `d6` | `dc` | `0x1001111a0` |
| 8 | `0x100111034` | `0x100e6c8f0` | `c3` | `6e` | `0x100111054` |
| 9 | `0x100110d4c` | `0x100f28b60` | `4c` | `cb` | `0x100110d60` |
| 10 | `0x10011115c` | `0x100e55890` | `4f` | `e4` | `0x10011117c` |
| 11 | `0x1001111e4` | `0x100fd6530` | `53` | `d2` | `0x1001111f8` |
| 12 | `0x100111128` | `0x100e6c8f0` | `26` | `6f` | `0x10011114c` |
| 13 | `0x100111000` | `0x100f28b60` | `53` | `34` | `0x100111014` |
| 14 | `0x100111260` | `0x100e55890` | `29` | `ea` | `0x100111280` |
| 15 | `0x1001110e0` | `0x100fd6530` | `a5` | `7f` | `0x1001110e8` |

D is `e9dc0a283a3b39dc6ecbe4d26f34ea7f`. Standard AES expansion gives K10=`eef5270d4eeaf32b97150dce7ae07035`; defining Wo=D XOR K10 yields the complete AES block contract above. D is the source-established final XOR. Its separation into standard K10 and Wo is the stated mathematical decomposition, without a claim that the source exposes a distinct native K10 object. [CC2-CC4; CC-A3-CC-A5]

## Architectural placement and independent validation

| Original coordinate | Recovered role and boundary |
| --- | --- |
| `0x100427b0c` | Private descriptor wrapper; the retained selected route passes the block input/output pointers to the inner descriptor. Other routes are not classified by this cipher result. |
| `0x100411480` | Descriptor callee containing the retained staging/core/output phases; its complete dispatch space is not equated with AES. |
| `0x10010eabc` through `0x1001112bc` | Flattened internal core phase: complete AES-128 block map with Wi/Wo under the two contexts. This interval is not a newly discovered callable entry point. |
| `0x1001112bc` | Existing BRAA exit, logical target `0x100135758`, modifier `0x5277`; target admission and hardware PAC retain CC2's scope. |
| `0x10004e954` / `0x100085bfc` | External input-byte read / result-byte store in the separately proved staging loops. |

The sixteen-byte source/result windows and their pointers retain CC2's exact placement/lifetime premises. No new memory root, target interval, caller admission, API invocation, Mach right, message-emission site, IOKit selector or native daemon-kext correspondence is established. The [port report](mach_ports_report.md) retains the transport evidence and unresolved joins. The complete block contract now supplies a semantic fingerprint for those future joins. [CC1-CC5; CC-A1-CC-A2,CC-A6]

The fresh audit checks 64 source queries, 2048 factor candidates, 1024 original terminal embeddings, 8192 complete post-store rows, 8192 complete decoder rows and 32 source key-9 bytes. The 136 changed/retained block comparisons check 2176 core output bytes and 2176 staged external output bytes. Every source-derived graph execution includes its original 192 lookups; both retained outputs are preserved. Parent complete instruction replay, initial projections, main-layer proofs and address/exit admissions are pinned dependencies. [CC2-CC5]

The standalone AES model and independent host reference both match FIPS Appendix B: input `3243f6a8885a308d313198a2e0370734`, key `2b7e151628aed2a6abf7158809cf4f3c`, output `3925841d02dc09fbdc118597196a0b32`. Host reference metadata records OpenSSL 3.5.9 and executable SHA-256 `a0ca619bc4a38178f54bf00ac2c4389812fca1d74fef46003dce342e09999d45`. The host command uses unpadded AES-128 ECB solely to obtain independent single-block encryption results, 137 blocks including the standard checkpoint. It supplies no evidence for a target multi-block mode. No native fairplayd/kext, target API/IPC, hardware PAC or IDB operation is executed. [CC3-CC6]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| CC-A1: Pinned source, parent source lift and cut semantics apply | Conditional complete component identity | Rehash all dependencies; freshly lift the terminal cuts and re-solve the original index/embedded consumer equations; compare the parent ISA lift with another implementation. |
| CC-A2: Two retained contexts, literals, placements and table preservation apply | Same K, masks and source layout across all input blocks | Recover authentic caller/controller epochs, table/mapping state and object lifetimes beyond the retained contexts. All-input byte coverage does not generalize the environment. |
| CC-A3: Column-major state, fixed row matrices and FIPS conventions apply | AES direction, key schedule, masks and final decomposition | Check all terminal table rows, complete post-store decoders, independent S-box construction, Appendix B and host complete-block results. K10/Wo separation is explicitly mathematical. |
| CC-A4: Terminal embeddings cover actual words and final source cuts hold | Compositional universal output theorem | Enumerate every original index; check the independent inverse embedding; prove indices with unrestricted terminal u8 symbols and other original operands. A sampled vector match alone does not discharge these cuts. |
| CC-A5: Mathematical component K/H are distinguished from protocol/key-object claims | AES-128 block identity without native mode or key lineage | Establish authentic key/caller selection, invocation loops, padding/IV/state and complete consumer behavior before assigning those external semantics. |
| CC-A6: Component/staging flow is distinguished from daemon-kext traffic | No new native transport correspondence | Join authentic input/result objects and matched Mach-right/IOKit transaction histories to the established block window. |

Reproduction uses the established Python/Z3 environment and host `openssl`: run `recover_daemon_core_cipher.py`, then `audit_daemon_core_cipher.py`; after manifest refresh run `verify_daemon_core_cipher_publication.py`. Source queries use QF_BV with 30 s limits. The compact AES model uses O(Nr*16) byte/field work for Nr=10; logical storage includes 176 B of expanded keys, a 16 B state and a 256 B S-box. Python object overhead is additional. Source DAG evaluation, finite candidate/witness work and solver search are additional. Nontrivial JSON is stored with `zstd --ultra -22 -q -T1` and decoded hash/roundtrip checks. [CC3-CC5]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Connect the complete result to native callers and transport | Authentic descriptor/controller selection, result consumers, object lifetime and matched daemon-kext exchange. |
| High | Generalize beyond the retained literal environment | Native table/mapping preservation and selection of other phases or material instances. |
| Medium | Compare related kext/CoreFP components by semantics | Independently recover their block equations and caller/format contracts; K/H resemblance alone does not establish an interface join. |
| Medium | Detect similarly disguised final tables | Preserve index-dependent normalization and nonlinear post-store functions; raw-table uniqueness and XOR-only decoder assumptions fail here. |

**QG1**: Factual technical scope. **QG2**: CC-A1 through CC-A6 record dependencies and falsification probes. **QG3**: Complete core, terminal source consumers, byte decoders, wrapper composition and interface limits are covered; the full interface goal remains active. **QG4**: u8/u32/u64, byte order, field/state conventions, exact extents, counts and complexity are explicit. **QG5**: Conditional all-input coverage versus environmental generalization, raw table collisions versus indexed embeddings, nonlinear post-store maps versus final XORs, K9 recovery versus K10 decomposition and host block mode versus native protocol mode are distinguished. **QG6**: Original bytes, finite witnesses, universal source queries, independent complete-block results and the official standard provide provenance. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; native admission, material lineage and daemon-kext pairing remain unknown.
