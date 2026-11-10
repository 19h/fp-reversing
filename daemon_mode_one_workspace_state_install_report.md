# Workspace traversals, state-plane installation and saved-slot lifetimes

Two successors traverse the unchanged 74-word workspace once each. A short adapter advances the second traversal. The following initializer installs two input-dependent 64-byte planes into the former Q and inverse-P regions, preserving 800 arithmetic/codec cells. It also replaces several saved pointer/cookie representations with scalar state. These are private continuation and frame-layout contracts; native ownership, whole-algorithm identity and daemon/kext pairing remain unknown. [WS1-WS8]

Evidence: [source and authenticated edges](triage_evidence/daemon_mode_one_workspace_state_install_source.json.zst), [proofs and effect ledgers](triage_evidence/daemon_mode_one_workspace_state_install_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_workspace_state_install.py), [validator](triage_evidence/validate_daemon_mode_one_workspace_state_install.py), [preservation](triage_evidence/daemon_mode_one_workspace_state_install_delivery.json), [quality gates](triage_evidence/daemon_mode_one_workspace_state_install_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_workspace_state_install.py), [publication audit](triage_evidence/verify_daemon_mode_one_workspace_state_install_publication.py). Context: [nibble-operation suite](daemon_mode_one_nibble_operation_suite_report.md), [earlier workspace passes](daemon_mode_one_workspace_passes_report.md), [checkpoint and LOCAL](daemon_mode_one_record_checkpoint_report.md), [saved image roots](daemon_mode_one_record_rounds_report.md), [interface ABI](interface_abi_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image | `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source | Four complete BRAA-terminated ranges; 5,679 instructions /22,716 B; 5,675 nonbranch sites translated |
| Prior source | Seven ranges /3,920 B recaptured from the pinned image |
| Dispatch | Five authenticated records /six source slot-modifier bindings |
| ISA checks | 12 bitfield encodings, eight register-LSR encodings and eight comparison GPR-write corrections; zero SP writes |
| Accepted solver results | 12 UNSAT /two abstract SAT; includes one replayed encoder-boundary proof |
| Traversals | Two74-word /296 B reads; 148 word loads /592 B total; 73 second-loop adapter executions |
| Initializer | 318 loads /1,288 B; 398 stores /1,228 B; 668 distinct destination bytes |
| Store widths | 128 u8,265 u32,five u64; three computed accesses proved before normalization |
| State layout | 128 distinct plane bytes; 32 permutation cells replaced; 800 arithmetic/codec cells preserved |
| Integrity | Eight altered source/control/bitfield/shift/lineage/native claims rejected |

F denotes the private frame. All offsets and extents are bytes. Arithmetic follows the source's modular u32/u64 widths. Valid coherent nonwrapping mappings, the recorded incoming continuation, preserved roots and absence of outside mutation remain premises. No target execution, emulation, API/IPC request, IDA access, IDB mutation or hardware PAC test occurred. [WS1-WS4,WS7]

## Two workspace traversals

The encoder successor is `0x100d845e0` (392 instructions). Its initial four-word state is W4=`0x2a65c9df`,W12=`0xa77b2501`,W22=`0xf402e748`,W24=`0xc5141de1`. The incoming encoder certificate is replayed; the new loop proofs allow arbitrary state and loaded word values. For index i:

```text
0 <= i < 74
X2 = 0x0a15c815+i
word_address = F+0x768+4*i
X2_after = X2+1
```

The word load is at `0x100d8460c`. At `0x100d84bfc`,BRAA uses modifier0xbdfd and selects slot0x3489 -> the same continuation for i<73,or0x34a3 -> `0x100d9c40c` for i=73. W15 remains0x3489. Two u32 stores,at `0x100d84b64` and `0x100d84b70`,update F+0x730 and F+0x728 on every iteration. Their old role as earlier-phase values ends; they carry current scalar state. Workspace and byte tables are untouched. The full unreduced state expressions are retained in the source SSA. A decoded recurrence or named hash/cipher is not assigned. [WS2,WS3,WS5]

The outgoing first traversal supplies the second seed W5=`0x6341b114`,W6=`0xfaff40f3`,W7=`0x0a2afbd8`,W19=`0x54734960`,as well as X9=F+0x768,W10=`0x9c46cba1`,W13=0x9d34,W16=0x5d5 and W3=`0x7203c9fe`. These seed/control constants are proved independent of the arbitrary first state,word and valid loop index. Other first-state survivors are allowed arbitrary values in the second-loop model. [WS2,WS3]

The 401-instruction second continuation starts at `0x100d9c40c`. At `0x100d9c42c` it reads

```text
W3 = u32(0x7203c9fe+j)
word_address = F+0x768+4*j, 0 <= j < 74
```

Its obfuscated comparison network is proved to select slot0x9d34 -> `0x100cc80a8` for j<73,or0x9d55 -> `0x100b57924` for j=73. The final BRAA at `0x100d9ca4c` uses modifier0x8125. It performs no stores and preserves W0,W1,W14,W22,W24,workspace root X9 and the required loop constants. W23 becomes0x40d0. [WS2,WS3]

The 16-instruction adapter at `0x100cc80a8` increments W3,restores W13=0x9d34 and updates W5 as

```text
W5_next = u32(W19_after_second + W20_after_second + (0x9d34 XOR0xe709472f))
```

W2=0x34a3 selects the second continuation again,with modifier0xbdfd at `0x100cc80e4`. The adapter has no stores. Thus these are separate full traversals,with an explicit adapter in the second loop. They are not an alternating two-block update for each workspace word. [WS2,WS3]

Conditional on the inherited entry and successful recorded dispatches,the path contains `74*392 +74*401 +73*16 +4870 =64720` instructions including BRAA sites. This is a static path count,not a native timing measurement. Both traversals preserve all296 workspace bytes. [WS1-WS4]

## Initializer reads and coherent forwarding

The next complete range is `0x100b57924` through the BRAA at `0x100b5c538` (4,870 instructions). Its frame entry inputs are exactly the74 u32 workspace words and the two current u32 auxiliaries at F+0x728/F+0x730,under the saved TABLE and F+0x758 root premises. Its live scalar inputs are W7,W6,W20,W22,W19,W24 and the proved W23=0x40d0. It loads no bytes from the preceding private tables. [WS2-WS5]

Three computed accesses are first proved against the unmodified source and then normalized for little-endian byte forwarding:

| Site | Access | Exact private address |
| --- | --- | --- |
| `0x100b5ac6c` | u32 workspace load | F+0x824,workspace index47 |
| `0x100b5a518` | u8 plane store | F+0x961 |
| `0x100b5ad64` | u8 plane store | F+0x9f4 |

The coherent model separately proves the original normalized expressions again and every resulting frame read/store address. No source value is replaced by a guessed cipher operation. The other126 byte destinations are literal SP offsets. Two fully specified abstract component valuations,all entry words zero versus repeated0x01010101,produce different values in all128 destination bytes with register inputs otherwise fixed to zero. These examples prove input dependence in the component model; their native reachability and correspondence to external requests are unknown. Declared-input dependency sets are upper bounds,not proofs that every listed input influences every output. [WS3-WS5]

## Table lifetimes and new planes

Retain the preceding physical coordinate:

```text
C(label) = F+0x8b0+((799*label)mod962)
plane0[j] = byte[C(j)]       ,0<=j<64
plane1[j] = byte[C(593+j)]   ,0<=j<64
```

All128 byte stores target distinct cells. Q had occupied C(0..15),and I=inverse(P) had occupied C(593..608). Both are completely replaced. This statement concerns storage and epoch; it does not claim that every new value differs from every old value for every input. [WS3-WS5]

| Prior interface | Labels | Cell count | After initializer |
| --- | --- | --- | --- |
| Q |0..15 |16 | Repurposed by plane0 |
| SUM |72..327 |256 | Preserved |
| XOR |333..588 |256 | Preserved |
| I |593..608 |16 | Repurposed by plane1 |
| Numeric decoder |659..674 |16 | Preserved |
| CARRY |677..932 |256 | Preserved |
| Numeric encoder |936..951 |16 | Preserved |

Therefore `832-32+128=928` cells have established initialization in this962-byte domain;34 remain unclaimed by these contracts. The128 plane cells and800 retained arithmetic/codec cells are disjoint. Existing SUM/CARRY/XOR and role-specific numeric-map contracts persist by address disjointness. Q and I can no longer be read from their old cells as unchanged permutations. A later lookup into either region must use the new plane epoch. P and Q's abstract encodings need not cease to describe already-built tables merely because the generating permutations' storage is reused. [WS3-WS5]

## Saved-slot epochs and outgoing interface

The initializer's 398 stores write1,228 B in total but only668 distinct bytes because private scalar slots are reused. These totals are `128*1 +265*4 +5*8 =1228 B`. All destinations are below F+0x768 or in the proved128-byte planes. The workspace is preserved. [WS3,WS4]

| Saved region | First overwrite | Effect |
| --- | --- | --- |
| F+0x2b8,saved NODE | `0x100b5c434` | u32 store; old full64-bit representation no longer preserved |
| F+0x2c0,saved cookie | `0x100b5c3d4` | u32 store; old full64-bit representation no longer preserved |
| F+0x568,earlier image root | `0x100b588fc` | First of four u32 overwrites |
| F+0x588,earlier image root | `0x100b586a0` | First of four u32 overwrites |
| F+0x350 | `0x100b5c518` | u64 numeric word0x2c238c16ca76f3a8 |
| F+0x360 | `0x100b5c52c` | u64 numeric word0x0ff0ed06a1ef8a89 |

The high halves of the four partially overwritten64-bit slots retain prior bytes; that does not preserve the original complete pointer/cookie identity. Actual equality for a particular input is not excluded. Their replacement values are not established pointers. F+0x350 and F+0x360 likewise hold numeric bias words; no frame-view or object owner is inferred from those constants. [WS3,WS4,WS6]

F+0x358 (saved LOCAL+bias),F+0x368/F+0x370 (saved frame views),F+0x388 (request R),F+0x580,F+0x740 (TABLE),F+0x750,F+0x758 (private root) and F+0x1210 have no intersecting store. F+0x358 and F+0x750 are still unconsumed here. The source reads the auxiliary words at F+0x730/F+0x728 twice each; their late loads at `0x100b5c32c`/`0x100b5c338` feed scalar copies at F+0x2dc/F+0x2d8. Thus the first traversal's frame outputs remain part of the initializer's state interface. [WS3,WS4,WS6]

W23=0x40d0 is saved at F+0x710. The final indirect load at `0x100b5c504` selects slot0x40d0 -> `0x100b6fe00`,modifier0x465a; X14 is the loaded continuation and X11=1 at BRAA. The next continuation's semantics remain unknown in this increment. Zero Mach-port emissions occur in these four selected source ranges: their sole control transfers are the recorded private BRAA edges,with no call or system-call instructions. This does not exclude IPC in other paths or later continuations. [WS2-WS4,WS7]

## Assumption register and bounded continuation

| Assumption | Dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WS1 | Pinned image and prior evidence identify this build | Rehash image,recapture all source/pointer bytes; reject image/source/lineage alterations |
| WS2 | Entry follows the recorded encoder,with coherent continuation/root state | Replay encoder ABI proof; independently prove generic loop constants and all index transitions |
| WS3 | Bit-vector instruction models match the selected integer source | Decode bitfield and register-shift fields; cover every nonbranch site; reject width/shift alterations and every unexpected solver result |
| WS4 | Valid nonwrapping coherent frame/table mappings; no external mutation or alias into private state | Prove all effect addresses and disjoint sets; reject wrong computed destinations; native alias/mapping validity remains unknown |
| WS5 | Arbitrary workspace/register inputs overapproximate the component interface | Preserve all74 word inputs and auxiliary/state symbols; retain complete SSA; compare two explicit abstract valuations; native reachability remains unknown |
| WS6 | Saved-slot identities have phase-specific lifetimes | Intersect exact store byte ranges with each saved64-bit slot; retain partial-overwrite sites and widths |
| WS7 | Authenticated fixup records support static targets,not observed PAC success or IPC | Compare original records,modifiers and selected slots; reject target changes and invented execution flags |
| WS8 | This is a bounded increment of the continuing cross-layer investigation | Retain unresolved consumer,recurrence,native ownership/output and daemon/kext questions; keep goal active |

High impact: follow `0x100b6fe00` using the new128-byte plane epoch and preserved800-cell suite; establish how four-bit operations compose into larger state transformations. High impact: decode the two workspace recurrences while preserving the first-state survivors and F+0x728/F+0x730 data flow. Medium impact: connect the retained LOCAL/request interface to later object accesses without reusing overwritten NODE/cookie/image-root identities. Medium impact: compare this962-byte/799-coordinate layout with the earlier961-byte/866-coordinate family as separate contracts; similar structure alone does not establish algorithm equality. Low impact: characterize the34 unclaimed domain cells only when a source consumer addresses them. These are analysis opportunities; no new native IPC edge is established. [WS5-WS8]

Capture/hash work is O(B+I+D) for image bytes B,instructions I and dependency bytes D. Each traversal has O(n) word-read work and fixed-size rolling register state for n=74; the initializer has fixed4,870-instruction size in this build. SMT bit-vector solving has no claimed linear runtime bound. Stored SSA and exact queries make the bounded claims reproducible.

QG1: No normative judgment is required. QG2: WS1-WS8 list premises,dependent results and falsification probes. QG3: Source identities,data/control interfaces,private layout,external-control limits,environment and IPC scope are reported for this increment; the continuing objective is unfinished. QG4: Widths,byte extents,iteration and effect counts are mechanically checked. QG5: Separate passes,computed accesses,partial overwrites,abstract samples and permutation-storage reuse are explicitly distinguished. QG6: Claims are pinned to original executable/fixup bytes,recaptured dependencies and accepted solver certificates. QG7: Impact-ranked continuation opportunities and unresolved boundaries are bounded above. All gates apply to this increment; native success and the full cross-layer objective remain unproved.

## Parity-state adapter follow-up

The successor parity dispatcher restores different LOCAL/frame-view representations before a shared setup. A following conditional XOR80 update can address any962-domain cell in the independent-word component model. The800-cell retention guarantee established here ends before that update;actual producer correlations remain to be proved. See [parity-state adapters](daemon_mode_one_parity_state_adapters_report.md).
