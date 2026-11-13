# Arena-reference decoder and context unsealing from the network gate

Failure-cycle follow-up: The [context state-publication report](daemon_context_state_publish_report.md) follows the original NULL second-allocation route through complete context resealing and encoded-reference republication at 0x1009a2014. Both concrete failure controls match the earlier constructor codec; source ordering and native exclusion remain distinct.

The selected network-gate branch at `0x10048192c` decodes the arena-context reference stored at `0x1010c9298`, reverses the constructor's 552-byte sealing transform, and publishes the raw context address at `0x100481d98`. This connects the gate to the previously recovered arena constructor and its lock field. The cell is an encoded reference in one phase and a raw address in another; its nonzero value alone does not identify its representation. [CU1-CU4]

Twenty original-source continuations restore every producer context byte and its raw lock field. These combine thirteen preserved constructor outcomes with eight retained caller contexts as a cross-shaped case set, not a Cartesian product. Constructor output, backing, image state and the caller's missing root are explicit premises transferred between separate epochs. Native reachability, shared epoch, ownership, successful synchronization and daemon-kext delivery remain unknown. [CU2-CU5]

```text
Preserved arena construction                 Retained network-gate branch
  raw context C, lock at C+8                   control32=0, reference nonzero
  -> seal 552 bytes                           -> STOP before undefined S+0x878
  -> encode C -> cell 0x1010c9298               + separate root/state/owner premises
              |                               |
              +-- declared state transfer ----+
                                              v
                                    decode reference into scratch
                                    reverse 68 word swaps
                                    reverse 552 byte transforms
                                    -> original raw context and lock token
                                    -> publish raw C through same global cell
                                    -> STOP at 0x100481d9c
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CU1 | Original thin image SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_context_unseal.py) retains decoder, vector/tail inverse and constructor-reference instruction bytes. |
| CU2 | Preserved [constructor profiles](triage_evidence/daemon_context_lock_profiles.json.zst), [extended success](triage_evidence/daemon_context_lock_success.json.zst), [snapshot](triage_evidence/daemon_context_lock_snapshot.json.zst), [seal contracts](triage_evidence/daemon_context_seal_contracts.json.zst) and [prior checks](triage_evidence/daemon_context_lock_checks.json.zst). Fresh audit checks all 43,843 producer instruction words and thirteen reference publications. |
| CU3 | Frozen [network-gate receipts](triage_evidence/daemon_network_gate_checks.json.zst), decoded SHA-256 `734dab1b800e9c528a2073b9c093d9fe481565308f48b72ea9af178764561884`; original root writers are retained separately in [initializer receipts](triage_evidence/daemon_return_bank_origins_checks.json.zst). |
| CU4 | [New source receipts](triage_evidence/daemon_context_unseal_checks.json.zst): 20 caller continuations, 72 isolated reference-codec controls, complete scalar/AdvSIMD frames, effects, owner extents and separate entry premises. |
| CU5 | [Independent auditor](triage_evidence/audit_daemon_context_unseal.py) and [audit receipts](triage_evidence/daemon_context_unseal_audit.json.zst): byte-addressed scalar/lane replay, constructor/reader joins, 83 nonvacuous UNSAT obligations and 630 byte-permutation certificates. |
| CU6 | [Publication verifier](triage_evidence/verify_daemon_context_unseal_publication.py): source/receipt/dependency hashes, exact owned delta, preserved inputs, manifest and raw/typed/decoded path checks. |

## Representation and source interfaces

| Location | Established role | Width or extent |
| --- | --- | --- |
| `0x1010c9298` | Raw arena reference published at `0x1002ef978`, encoded at `0x1003c43b4`, restored raw at `0x100481d98` | u64; raw/encoded phases are distinct |
| `S+0x878` | Pointer to metadata cell `0x1010c67d4` | u64; initializer writer `0x1004c2e14`; separate caller-root premise |
| `0x1010c67d4` | Metadata word used to select a cached-table word | Signed32 load; constructor-compatible value 255 |
| `0x1010c8268` | Cached-table base-pointer cell | u64; constructor-compatible target `0x6500115d6c` |
| Cached table +200 | First u32 for the eight-read self-text fold | Four bytes within a declared 512-byte table |
| `0x1010c6800` | XOR-encoded self-text mask | u64; recovered mask `0x7fff` |
| `0x1010ca2a8` | XOR-encoded self-text base | u64; recovered base `0x100822058` |
| `S+0xb6a8` / `S+0xb6b0` | Reference-codec scratch pair | Two u64 words; local memory, no wire ABI |
| `0x100481c1c` | Reference decoder has produced raw C in scratch | Stop before context-address use |
| `0x100481c2c..0x100481c78` | Ascending inverse word permutation | 68 swaps across 69 u64 words |
| `0x100481cb4..0x100481d38` | Vector byte inverse | 34 iterations *16 B =544 B |
| `0x100481d54..0x100481d90` | Tail byte inverse | Two iterations *4 B =8 B |
| `0x100481d98` | Store raw C through `0x1010c9298` | Eight bytes; after all 552 bytes are restored |
| Raw context C+8 | Constructor's lock-token field after unsealing | u64; token value and valid native lock object are distinct claims |

For the retained producer-compatible environment, C=`0x6500115b20`, the table is `0x6500115d6c`, and the context ends at `0x6500115d48`. The gap to the table is 36 B. Their explicit owner extents are 552 B and 512 B; page mapping does not define intervening or neighboring bytes. The reader's eight self-text reads yield fold T=`0xc41c69cd`, matching the producer. Context seed is `u32(low32(C)*0xeb36c1ca) XOR T = 0x78396e8d`. These addresses and values are private model state. [CU1-CU5]

The new caller premise replaces both the global encoded word and X9, which the earlier gate loaded from that cell. All other retained GP registers, SP and NZCV remain joined to the frozen gate boundary. Entry SIMD contents are separately declared model fixtures because the parent did not record them; every subsequent Q-register value is checked. Twenty cases restore the preserved raw context exactly: fifteen have allocator token `0x6600001000` at C+8 and five retain opaque word `0xf64ac418c20e70bc` after first-creator failure. None has a NULL raw lock field. No 200-byte lock-object contents are read or inferred. The earlier zero/nonzero wording was a reporting error; the preserved receipts are unchanged. [CU2-CU5]

## Compact reference codec

Let T be the u32 self-text fold, K=`u32(T*0xeb36c1ca)`, F=`0x01000193`, and P a 64-bit pointer word. Treat P as eight little-endian bytes. The constructor permutes those bytes using the following source-derived descending swaps:

```text
for i = 7 down to 1:
    j = u32((u32(K+i) XOR K)*F) mod i
    swap(byte[i], byte[j])
```

The indices for i=4,2,1 are zero. The other four indices have 7*6*5*3=630 bounded combinations; all permutation/inverse certificates are retained. The source's reciprocal quotients for divisors 7,6,5,3 are checked over every u32 numerator with integer certificates. The `FNEG D6,D6` at `0x100481a60` flips the sign bit of the packed constant: the resulting low64 lanes are `[0x80000000,0]`, so only the divisor-7 lane uses the half-difference correction. It is a bit-level constant construction in this source. [CU1,CU5]

Let B0/B1 be the permuted low/high u32 words. Define A0=`u32(K*K) XOR K` and A1=`u32((K OR 1)*K) XOR K`. The encoded words are:

```text
E0 = u32(A0 + B0*F) XOR A0
E1 = u32(A1 + B1*F) XOR A1
```

The reader XORs each E with its A, subtracts A, multiplies by `0x359c449b` modulo `2^32`, then reverses the byte swaps in increasing i order. `F*0x359c449b == 1 mod 2^32`. The odd lane multiplier and byte permutation establish a bijection for fixed K; zero maps to zero. This is a reversible representation codec; no cryptographic property or native-pointer validity is inferred. [CU1,CU4-CU5]

Seventy-two isolated source controls vary six pointer words, six folds and two retained frame placements. Pointer words include zero, one, `0xffffffffffffffff`, an arbitrary mixed word, C and C+1. They execute the original constructor-reference preamble and publication, followed by the reader's reference decoder. The intervening 552-byte sealing body is omitted in these component controls; the complete preserved producer journals and caller/context cases cover that separate composition. No isolated pointer word is dereferenced. [CU2,CU4-CU5]

## Context inverse and verification bounds

With context seed s, original byte mask is `low8(s XOR u32((i+s)*(i-s)))`. The constructor multiplies the masked byte by `0x93`; the reader multiplies by its inverse `0x9b` modulo256, then XORs the same mask. The reader first reverses the word permutation, visiting word indices1..68 and selecting a strictly lower index. Distinct indices make the source XOR swaps valid; the remainder/non-overflow certificates cover every loop divisor. [CU1,CU5]

The independent vector theorem covers arbitrary 128 input bits, u32 seed and u32 byte index for an original 16-byte body iteration. A separate original tail theorem covers arbitrary32 input bits. The integer quotient/remainder certificates avoid treating solver timeout as a proof result. Together with original loop replay and all-byte producer equality, these qualify the complete 552-byte inverse. The raw address is published only after both inverse loops finish. Publication order alone does not prove native exclusion or inter-thread visibility. [CU4-CU5]

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CU-A1: Pinned image and logical fixups identify the intended source | All source roles and addresses | Verify SHA-256, every new visited opcode, all producer journal words and selected fixups. |
| CU-A2: Frozen caller GP/SP/NZCV state and separate SIMD fixtures admit this branch | Caller continuation | Exact state/byte joins; explicitly replace the same-cell/X9 pair; vary eight caller contexts. Native entry state remains unknown. |
| CU-A3: Initializer-compatible S+0x878 root applies in a separate caller epoch | Cached-table input | Preserve the undefined root; check twelve exact writer ledgers and no later overlap; do not infer an epoch join. |
| CU-A4: Constructor-compatible image cells, sealed bytes and table backing apply | Reference decode and unseal | Transfer exact recorded bytes, enforce owner bounds and compare all raw outputs. Actual native state can differ. |
| CU-A5: Stack scratch bases are eight-byte aligned and source SIMD constants hold | Reference codec | Check actual placements, OR-based byte addressing, index bounds, 72 original component controls and all630 bounded permutations. |
| CU-A6: Scalar/AdvSIMD semantics match the recorded original operations | Source/formal interpretation | Independent lane replay, all GP/Q/NZCV checks, vector/tail proofs and quotient certificates. Unsupported operations fail closed. |
| CU-A7: Self-text bytes and logical preferred image addresses match the producer environment | Fold and context seed | Recheck eight reads against original image and compare producer fold; runtime slide/text changes remain unknown. |
| CU-A8: Raw lock field holds an allocated token or preserves an opaque prior word after creator failure; imported initializer effects remain opaque | Lock-field relationship | Compare C+8 in every raw producer context and distinguish eight allocated-token profiles from five preserved-word profiles; NULL raw-field coverage is absent. Require separate evidence for native validity, initialization and ownership. |
| CU-A9: The stop at 0x100481d9c bounds this increment | Subsequent control and transport | Continue the actual post-publication counter/cleanup/cached-context consumers; no later behavior or complete investigation is claimed. |

Source receipts cover 296 intervals, 70,572 original visits, 12,268 read events and 10,532 write events. Independent replay checks 2,267,776 GP/SP values, 2,267,776 full vector-register values, 70,868 NZCV states, 71,340 read bytes and 54,664 written bytes. Vector loads/stores are compared as the two eight-byte events emitted by the emulator, while full128-bit register states remain checked. Complexity is O(receipt bytes + cases*(visits+effects)) for extraction and replay. The reference codec is O(8) time/space; context sealing/unsealing is O(n) time with O(1) in-place auxiliary storage, n=552 B. Solver DAG construction and bounded permutation enumeration are separate; each of 83 queries has a 30 s limit. [CU4-CU6]

## Bounded continuation and quality gates

| Impact | Next evidence | Purpose |
| --- | --- | --- |
| High | Follow raw-reference publication through the counter/cleanup and subsequent C+8 consumer | Establish an actual context-field use with backed raw representation. |
| High | Recover matching reseal/raw-state transitions and control writers | Determine when each reference/context representation is valid. |
| Medium | Connect the arena lock token to the source-selected primitive and native initialization | Distinguish token flow from successful lock ownership. |
| Medium | Correlate producer/caller admission and runtime image state | Replace the separate-epoch premise with observed or continuously sourced state. |
| Low | Continue to a concrete transport boundary | Associate later IOKit/Mach emission without treating local pointer publication as IPC. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: CU-A1-CU-A9 identify dependencies and falsification probes. **QG3** passes for this increment: producer, reference decoder, context inverse and publication are covered; the full goal remains active. **QG4** passes: modular widths, SI byte extents, owner bounds, loop counts and complexity are explicit. **QG5** passes: raw/encoded phases, allocated versus preserved words, absent NULL-field coverage, component gaps and native unknowns remain separate. **QG6** passes after source, independent replay, proof, receipt and publication checks. **QG7** passes: impact-ranked continuation and representation/lifetime limits are bounded above.

Decoded checks SHA-256: `b4f3b10a7c3b5f57d9a680c1e88a4fb2a9b473af27fb0b353e23fd7ab87048fe`. Decoded audit SHA-256: `ddc6d19ff112ee651d234e1ab8c0daf7a606d0b199f97084d123427e6a449173`.
