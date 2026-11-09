# CoreADI adid: address-derived state word and complete local 64-byte codec

The region `0x100199778..0x100199894` now has a compact model covering its pointer-derived state word, eight-word permutation and byte phase. Under the inspected constants and an 8-byte aligned record address, the computed swap indices are all zero: the permutation is a one-word right rotation. Combining that reduction with the previously recovered byte transform gives an explicit inverse for the complete local 64-byte operation.

Original code decodes 32 freshly prepared blocks, covering every aligned low-byte address class, to independently specified views. Three unaligned controls produce different swap sequences and falsify the unrestricted rotation model. This establishes a local state representation; valid native context grammar, accepted IOKit requests and complete feasible request paths remain unknown.

## Identity, assumptions and evidence

Addresses are preferred virtual addresses in `/System/Library/PrivateFrameworks/CoreADI.framework/adid`, selected arm64e slice base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The [preceding gate/state-view report](adid_context_gate_report.md) establishes the byte phase, mutation epochs and guard operands. This report adds the preceding producer and permutation, without assigning a complete native object type.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| V1: pinned original provider bytes and fixups describe the inspected image | Addresses, instructions and source-input observations | Fresh instruction/range/window and independent dyld_info readbacks agree. Native loaded-image/runtime integrity remains unknown. |
| V2: the frozen private peer/API/PAC/vector models permit the retained callback prefixes | Original-code execution and phase observations | Complete baseline callback preserves the prior source path; six fresh runs reproduce complete source/event streams. These share declared models and do not prove native execution or independent-emulator equivalence. |
| V3: the observed scalar prefix constants apply to the reduced local region | State-word formula and fixed rotation | All 39 retained prefixes have M=`0xb15198a9`, D=`0x2a379458`, C=`0x01000193`. Their invariance across every possible whole-function predecessor is unproved. Constants are explicit preconditions, not inferred native key identities. |
| V4: the record address is 8-byte aligned | Rotation and compact public model | Full-domain arithmetic proves the reduction under alignment. All 32 aligned low-byte classes are exercised; three unaligned original-code controls have nonzero swap indices and different permutations. The compact model rejects that domain. |
| V5: captured pointer/word/vector stages delimit the local data transformation | Complete permutation/byte/inverse correspondence | A separate general permutation oracle follows actual indices; byte arithmetic and reverse swaps recover every input block. Earlier pointer-cell construction and other representation transitions remain unknown. |
| V6: owned relocation/input fixtures describe only the stated local experiments | Fresh encoded block construction | The original callback runs to the producer; an explicit fixture writes owned bytes and changes its pointer cell before the original load. No instruction-PC jump selects the region. Prepared blocks are not claimed to be valid native objects or authenticated records. |
| V7: original frame/address observations describe their respective fixtures | Pointer input and original state view | Source reads a u64 at frame+`0x3fb0`; the unmodified fixture points to `0x1002dcb68`. Ownership, alignment and lifetimes in every native caller remain unknown. |
| V8: mathematical codec/inverse describe one local representation contract | Reuse of compact model and arithmetic placement corollary | Four new local proofs and two reused byte proofs are freshly solved. No separate native inverse routine, complete persistent-file/message grammar or protected algorithm is inferred. |
| V9: bounded source completions delimit behavioral claims | Source boundary, baseline reply and unaligned counterexamples | The normal callback retains `ffff501f`; representation controls stop at the end of the local view. Driver transformations, context acceptance, final successful replies, native rights/concurrency and full architecture remain open. |

Artifacts: [compact codec](triage_evidence/adid_state_codec.py), [source profiles](triage_evidence/adid_state_producer_profiles.json), [contracts/proofs](triage_evidence/adid_state_producer_contracts.json), [producer](triage_evidence/probe_adid_state_producers.py), [recoverer](triage_evidence/recover_adid_state_producers.py), [fresh checks](triage_evidence/adid_state_producer_checks.json), [validator](triage_evidence/validate_adid_state_producers_delivery.py) and [quality gates](triage_evidence/adid_state_producer_quality_gates.json). Earlier source/proof/profile artifacts, original inputs and IDBs remain preserved.

## Original local interface and phase sequence [V1-V3,V5,V7]

This is an instruction-region contract inside the large protected routine, not an asserted complete function prototype.

| Original site | Observed operation / operand |
| --- | --- |
| `0x100199778` | Load record address A from u64 frame slot `SP+0x3fb0` |
| `0x10019977c` | W14 = low32(A) * W5 modulo 2^32 |
| `0x100199780` | W14 XOR W12 supplies state word k |
| `0x100199784` | Initialize loop index to 1 |
| `0x100199788..0x1001997d4` | Seven computed-index swaps of eight-byte words |
| `0x1001997d8..0x100199894` | Four 16-byte vector chunks supply the local view |

The source inputs at the producer are:

```text
M = 0xb15198a9
D = 0x2a379458
C = 0x01000193
k = ((low32(A) * M) mod 2^32) XOR D
```

The unmodified observed address A=`0x1002dcb68` produces k=`0xb8de93f0`. The arithmetic constant is a source state word; no secret-key provenance is assigned.

```text
frame+0x3fb0 -> A
                |
      low32(A)*M XOR D -> k
                |
input64 -> computed eight-word swaps
                |
         [A aligned8: rotate right one word]
                |
         position/state byte transform
                |
             observed view64
                |
    context guards / remaining original processing

inverse model: view64 -> inverse byte transform -> rotate left one word
```

The unmodified callback still reaches the existing error reply. The representation fixtures stop before following consumers can interpret their arbitrary view bytes. These pointer/state fields are not assigned Mach port names or rights.

## Why the swap loop collapses [V1,V3,V4,V8]

The general original index expression, for iteration r=1..7, is:

```text
v = ((((r+k) mod 2^32) XOR k) * C) mod 2^32
j = v - floor(v/r)*r
swap_u64(words[r], words[j])
```

UDIV and MSUB implement the unsigned remainder. For aligned A, the state word has `k AND 7 = 0`: an aligned low32(A) times M still has zero low three bits, and D is also divisible by 8.

For r in 1..7, adding r cannot carry out of those three zero bits, so `((r+k) XOR k)=r`. Further, `7*C = 117443333 < 2^32`; the product has no u32 wrap in this range. Therefore `v=r*C` and `j=0` in every iteration. The full-domain proof retains arbitrary u32 k with those low bits clear and all r in the stated range.

The original source uses three XOR stores to exchange two words. A full u64 proof establishes the swap; the addresses are distinct because r>=1 while j=0. The seven swaps have this effect for arbitrary original words:

```text
before: [w0,w1,w2,w3,w4,w5,w6,w7]
after:  [w7,w0,w1,w2,w3,w4,w5,w6]
```

Thus the apparent permutation is a fixed right rotation under this prefix. Its inverse is a left rotation. Neither the fixed rotation nor the original XOR-swap sequence is assigned an application-level operation meaning.

## Complete local codec and inverse [V3-V5,V8]

Let R be the 64 input bytes and T the eight-byte-block right rotation. For byte position i=0..63:

```text
k = ((low32(A) * 0xb15198a9) mod 2^32) XOR 0x2a379458
s(i,k) = ((i*i - k*k) XOR k) mod 256
view[i] = ((155*T[i]) mod 256) XOR s(i,k)
```

To construct the corresponding encoded input for a desired view:

```text
T[i] = (147*(view[i] XOR s(i,k))) mod 256
R = rotate_left_one_eight_byte_word(T)
```

Since `155*147 = 89*256+1`, the byte inverse is exact. The prior byte proofs cover arbitrary u32 i/k and u8 input. New key, swap-index, u64 XOR-swap and eight-word composition proofs complete the reduction under V3/V4. Fresh source observations independently check the general permutation, all bytes and the inverse; they do not merely compare the compact encoder with its own decoder.

The pure analyst functions `open64` and `close64` enforce a 64-byte span and 8-byte aligned address. They return new byte strings and execute no native API. They take O(64) time and O(64) output/temporary storage. An in-place implementation of the proven word/byte operations would require fixed auxiliary storage, but that is not the implementation claim for these Python functions.

After the alignment reduction, the byte operation depends only on the low byte of k, and hence only on the low byte of A under the fixed M/D. There are 32 aligned low-byte address classes. Adding a multiple of 256 to A leaves this local arithmetic mapping unchanged. This is a derived mathematical placement property, not a native ASLR, PAC, loaded-image or integrity attestation.

## Original-code construction and alignment controls [V2,V4-V6,V9]

The producer retains the complete original callback prefix. Immediately before the original pointer load, each owned fixture writes a prepared 64-byte block to mapped private memory and changes the source frame's pointer cell to that address. The relocation event retains the original/new pointers, prepared bytes, requested view and an explicit `native_valid_context_inferred=false` field. No analyst-selected instruction-PC jump selects the region.

The 32 aligned fixtures use addresses `0x7b01c000+L` for L=0,8,...,248. Each has a separately specified asymmetric 64-byte view. The inverse codec constructs its input; original machine instructions perform all seven swaps and four vector chunks. Every decoded result equals its requested view. All 32 state-low-byte classes are observed.

Three additional owned controls use the same asymmetric raw-byte pattern at unaligned addresses. Their original swap sequences are:

| Address low byte | Original j values for r=1..7 | Fixed-rotation reduction |
| --- | --- | --- |
| `0x01` | 0,0,1,0,3,0,3 | Falsified for this source case |
| `0x02` | 0,0,2,0,0,4,2 | Falsified for this source case |
| `0x07` | 0,0,2,0,4,2,3 | Falsified for this source case |

The general integer/word oracle matches these permutations and their byte results, and reverse swaps recover their original raw inputs. The aligned compact model rejects these addresses. These controls demonstrate the scope boundary; they do not establish a native alignment fault or admissible unaligned object.

The source set has 39 cases: four unmodified source-prefix observations, 32 fresh aligned representations and three unaligned controls. One unmodified observation completes the callback with the existing `ffff501f` data reply; the remaining representation cases stop at `0x100199894`. The two retained nonroot-ready request fixtures add original prefix observations without asserting successful operation semantics.

## What this resolves and leaves open

The state word and complete local mapping can now be derived from the record address under explicit scalar/alignment conditions. This removes the need to replay the word-permutation arithmetic when interpreting that local state view. It also permits correctly encoded local test data, in contrast to editing an isolated physical word before a representation transition.

The upstream formation of the pointer cell, other scalar prefixes, valid record grammar and invariants of the tag/pointer fields remain unknown. The prepared views are arbitrary representation tests. They are not provisioning records, authentication results, accepted driver packets or successful native contexts. The [guard report](adid_context_gate_report.md) still supplies the evidence for the error partitions and inconsistent-state stops.

## Verification and bounded continuation

The [fresh validator](triage_evidence/validate_adid_state_producers_delivery.py) passes 16655 assertions across 39 private cases, 15634 unique original instruction records in 13 compiler ranges and 1565735 retained original visits. It checks 273 source swap steps and 2496 bytes through a general permutation/byte/inverse oracle, then compares the aligned cases with the compact codec. Four new full-domain local proofs and two prior byte proofs are freshly solved. Six complete source/event replays reproduce 246317 hook steps.

The complete baseline source stream matches the earlier callback case. Source constants are observed and retained per case; their whole-function/native invariance is not assumed. The source harness/verifier takes O(B+F+R+V) time/space over loaded bytes B, fixups F, retained records R and source visits V; each execution has a finite cap. No native target, loader, IOKit, Mach, target-file/environment or synchronization API was invoked. Original supplied inputs and IDBs remain unchanged.

| Impact | Remaining interface | Concrete next evidence |
| --- | --- | --- |
| High | Valid record/context construction | Recover the meaning and consistency of decoded fields, pointer ownership/list/record grammar and accepted persistence inputs; then use source-derived encoding at the correct transition |
| High | Feasible request-to-driver path | Prove metadata/predecessor gates and selector-to-state mapping, then follow actual driver responses and subsequent reply/control effects |
| High | Native provider and deeper operation contracts | Locate the Avp implementation and actual service/UserClient/port pairing; connect selector26/100 data to protected kext operations, host slots and RPC families |
| Medium | Producer generalization | Recover the pointer-cell and scalar-constant writers across other predecessors and representation families; match any actual inverse implementation independently |
| Medium | State lifecycle and placement | Account for all representation epochs, allocation/rebase domains, synchronization, retries, ownership and retirement before interpreting persistent/raw snapshots as fields |
| Low | Reusable analysis artifact | Apply the compact codec only at corroborated local prefixes, retaining source identity and alignment checks for each use |

QG1-QG7 pass for this bounded increment: descriptive findings; V1-V9 dependencies/probes; compact source-semantic/interface progress; exact modular arithmetic/word/byte bounds; explicit prefix/alignment/relocation/native-type distinctions; primary source/fixup/oracle provenance; and impact-labeled continuation. Valid native contexts, complete request feasibility, successful algorithms and full architecture remain unproved. The full goal remains active and incomplete.
