# Daemon selector21 constructor: byte emitter and frame return

Subsequent enclosing-root evidence: the [versioned-root report](daemon_versioned_root_report.md) derives FP=F+0x970, inner record=F+0x8d8 and offset16 B from the original prologue/setup. Ten allocation-success paths compose the constructor with capability routes and pair retirement, within16 total cases and32 independent A64 replays. These paths return before the IOKit call; native caller admission, complete552 B definitions and the API-buffer join remain unknown. The earlier constructor-only fixtures and counts below retain their original scope.

The private call in the daemon's552 B selector21 constructor is the previously recovered byte emitter `0x100add594 -> 0x100acd9c4`. The caller supplies an address-coded record requesting4 B at `F+0x2d4`, with decoded control `0xb399`. Original-byte execution from two retained state epochs and three private layouts returns a zero frame adjustment in all six cases. The following source block converts the emitted bytes into `u32[F+0x3b4] = BE32(bytes) XOR 0x8b3dc651`.

The record-key identity has an exact condition: `R & 5 == 0`. Eight-byte alignment is sufficient; four-byte alignment alone is insufficient. This differs from the alignment premise of the earlier startup caller. The zero adjustment is established for the six complete private paths and conditionally from the temporary-word contract; it is not asserted for every possible emitter state. The constructor's actual native parent frame, its final IOConnect buffer identity and native daemon/kext pairing remain unknown. The full investigation remains active.

Primary evidence: [producer](triage_evidence/recover_daemon_versioned_header.py), [source, queries and full journals](triage_evidence/daemon_versioned_header_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_versioned_header.py), [A64 replays and interface joins](triage_evidence/daemon_versioned_header_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_versioned_header_publication.py). Parent evidence: [selector21 ABI](versioned_request_abi_report.md), [callback emitter](daemon_callback_revisit_report.md), [state generator](daemon_prng_output_report.md), [Mach port index](mach_ports_report.md). Fairplayd thin arm64e SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

Addresses use the preferred image base `0x100000000`. B denotes bytes. Hexadecimal arithmetic constants carry `0x`; other numerical extents/counts are decimal. U16/u32/u64 arithmetic wraps at its stated width. `F` is the declared constructor SP, `R=FP-0x98`, `O` is incoming X20, and `C` is the selected u64 seed.

| Assumption | Dependent results | Stress test or falsification probe |
|---|---|---|
| VH1 | Original thin image and eight parent receipt hashes identify the source and retained state. All address/source claims depend on them. | Rehash the image, parent artifacts, ten source dependencies, three retained regions and every original opcode visited. |
| VH2 | Two old emitter-entry epochs are restored from the sealed snapshot plus121357 or145961 journal visits. They are input fixtures for this new caller. Native reachability from the constructor's real parent is unknown. | Verify prefix bytes/read consistency and retained snapshot hashes; independently restore the same epochs for A64 replay. A compatible native capture or composed parent trace would test reachability. Prefix visits are not counted as newly executed. |
| VH3 | Six private frames use three layouts and declared table/root/phase registers. Original bank roots come from the pinned image. Actual native FP/SP relationship is unknown. | Vary frame, record, buffer offset and physical unknown backing; retain every initial CPU value and declared RAM overlay. The constructor resolves its own seed and helper target through source loads. |
| VH4 | The record key is decoded with the unrestricted emitter key; agreement with this caller requires exactly `R & 5 == 0`. The selected paths use eight-byte-aligned R. | Fresh arbitrary-u64 equivalence proof; SAT four-byte-aligned counterexample; eight original-byte packing controls covering all residues modulo8. |
| VH5 | PAC instructions denote logical transfers with recorded targets/modifiers and return tokens. Native signing/authentication is unknown. | Independently check each original opcode, modifier and X30 using A64 replay. Hardware acceptance requires a separate compatible native observation. |
| VH6 | The helper's private temporary stays disjoint from unrelated writes until its return load. The six zero-adjustment results depend on this checked lifetime. | Enumerate every overlapping write: only outer bias store and inner cancellation store. Retain the general nonzero-delta formula and a SAT displaced-frame control. |
| VH7 | Phase W21 is `0x871a`; source/data backing comes from the declared sealed epoch and overlays. The compact output-word identity depends on the phase; full emitter termination is finite evidence. | Prove the post-byte identity for arbitrary32-bit byte words at this phase; replay all six full paths. Unknown-dependent arithmetic/control is rejected. Other phases and initializations remain separate domains. |
| VH8 | No IPC/emission finding covers only the new paths through the pre-capability-read boundary. | Enumerate all four calls and stop before `0x100552fa0`. No Mach/IOKit API, native pointer authentication or live IDB mutation executes. |

The former daemon IDA target could not be resolved by the current MCP connection. The default database did not contain these daemon addresses. This increment makes no matching live-IDB claim; original bytes and retained receipts provide its provenance.

```text
sealed old emitter epoch -- declared private constructor frame
                                     |
0x100552dac: save B, B+16, B+32; capacity552 B
0x100552ddc: pack R -> output F+0x2d4, length4, control0xb399
0x100552e9c: load C from image+0x10b8d78
0x100552ef8: call 0x100add594, X1=&(F+0x5e0)
                                     |
              update global seed; private temp=C-0xb0
              0x100add7d4 -> 0x100acd9c4
              temp+=0xb0; emit four descending bytes
              delta=(low16(temp-C)<<4) -> caller cell
                                     |
0x100552efc: SP=F+delta
0x100552f9c: store BE32(bytes) XOR 0x8b3dc651
0x100552fa0: STOP before saved-state-pointer load
                                     |
                capability gates and API buffer join: unresolved
```

| Source interface / site | Exact recovered contract | Evidence boundary |
|---|---|---|
| `0x100552dac..0x100552dd8` | `B=F+0x5f0+O`; u64 cells at `F+0x3f8`, `F+0x480`, `F+0x488` receive B, B+16, B+32. U64 capacity at `F+0x3f0` receives552. | Original source projection; native parent/extent admission unknown. |
| Record stores `0x100552e1c`, `0x100552e24`, `0x100552e34` | R+8: u64 output pointer F+0x2d4; R+0x10: encoded u16 length; R+0x14: encoded u32 control. Bytes at R and R+0x12 are not assigned semantic roles here. | Exact agreement domain below; no native public record ABI asserted. |
| Seed load/store `0x100552e9c/0x100552ea0` | Source resolves u64 image address `0x1010b8d78`, loads C and stores C at F+0x5e0. | No injected post-selection seed; six complete source paths. |
| `0x100552ef8 -> 0x100add594` | Original slot `0x10109fe90`, IA modifier `0x22a0`; X0=R, X1=F+0x5e0. | Source slot proof retained in parent ABI receipt; actual target/modifier independently replayed. |
| `0x100add728` | Global seed becomes `u64(C*0x2ec5+1)`. | Existing source contract plus six new observed source stores. |
| `0x100add74c` | After64 B fixed and16..256 B dynamic reserve, temp receives `u64(C-0xb0)`. | Dynamic reserve is `16*((new_seed>>60)+1)` B. |
| `0x100add7d4 -> 0x100acd9c4` | X0 retains R; X1=temp; IA modifier `0x7c25`. Inner store at `0x100acdb1c` adds `0xb0` to temp. | Exact bias cancellation for arbitrary u64 C; six checked temporary lifetimes. |
| Byte store `0x100a0ca74` | Writes one byte each to F+0x2d7, F+0x2d6, F+0x2d5, F+0x2d4, in this order. | Four writes in every selected complete path; not a universal termination result. |
| `0x100add7d8..0x100add7e4` | `delta=u64(low16(u32(temp)-u32(C)))<<4`; store u64 delta to F+0x5e0. | Source projection; zero iff low16(temp)=low16(C). Range0..1048560 B, multiple16 B. |
| `0x100552efc..0x100552f08` | Set SP=F+delta. The following saved-state cell address is F+delta+0x80. | Same address as the original cell iff delta=0, modulo u64 arithmetic. No native stack-validity conclusion. |
| `0x100552f0c..0x100552f9c` | At phase0x871a, read four bytes at adjusted SP+0x2d4 and store BE32 XOR0x8b3dc651 at adjusted SP+0x3b4. | Arbitrary-byte source proof and independent full-path replay. |

The other two authenticated calls are `0x100b33030 -> 0x10041a5e0` and `0x100a3c13c -> 0x100427514`. They remain internal source helpers. Every new complete path has four authenticated calls and648 logical PAC/control transfers. No additional Mach name, right transfer, incoming port or outgoing IPC emission is established.

Let `K(R)=u32((low32(R) XOR 0xeaae0ac9)*0x7398180b)`. The constructor computes:

```text
A(R) = u32((u32(low32(R) - 2*(low32(R)&0x79c74e30)
                  +0x79c74e35) XOR 0x936944fc)*0x7398180b)
raw_length  = low16(A(R)+0x153f)
raw_control = u32(phase+0x2c7f-A(R))

A(R)==K(R)  iff  (R&5)==0
decoded_length = u16(raw_length-low16(K)-0x153b) = 4
decoded_control = u32(raw_control+K) = phase+0x2c7f
```

The last two equalities require key agreement. At phase0x871a, control is0xb399. The independent packing controls execute23 original instructions each without invoking the helper. R=`0x6400004f68` decodes length4/control0xb399; the four-byte-aligned R=`0x6400004f6c` decodes length16300/control0x9cc173f1. This is an algebra/fixture counterexample, not evidence that the native caller admits a misaligned record or emits that request. Residue2 also agrees in the finite controls; the exact theorem accounts for it.

The temporary-word lifetime explains the observed frame continuity. Outer initialization writes C-0xb0, inner initialization restores C, and the complete journals contain no other overlapping write before the outer return load. Thus the selected paths store delta0. The general return contract still permits nonzero16 B multiples if the low16 temporary changes; no universal state-independent zero-return theorem is asserted.

| Retained epoch | Private layout | F | R | O | Dynamic reserve B | Emitted bytes in address order | Stored u32 |
|---|---|---|---|---|---|---|---|
| 0 | 0 | 0x6400004000 | 0x6400004f68 | 0 | 112 | f683d2fa | 0x7dbe14ab |
| 0 | 1 | 0x6400005000 | 0x6400005868 | 0x20 | 112 | bbed7715 | 0x30d0b144 |
| 0 | 2 | 0x6400006000 | 0x6400007068 | 0x30 | 112 | 8173aaca | 0x0a4e6c9b |
| 1 | 0 | 0x6400004000 | 0x6400004f68 | 0 | 64 | 7f9372ff | 0xf4aeb4ae |
| 1 | 1 | 0x6400005000 | 0x6400005868 | 0x20 | 64 | 32fdd710 | 0xb9c01141 |
| 1 | 2 | 0x6400006000 | 0x6400007068 | 0x30 | 64 | 08630acf | 0x835ecc9e |

Epoch0 starts with C=`0xbab0c03dc992aab9`, advancing to `0x6c8f09c4788a9e5e`. Epoch1 starts with the latter and advances to `0x3dd3d1d9ab20c257`. The layouts vary F, R and O together; the output differences establish layout sensitivity under these fixtures, not independent causal attribution to one address channel. They are not stable native wire constants.

Each complete path newly executes14003 original visits and1272 distinct instructions, with2748 read events/13856 B and753 write events/3286 B. The six producer paths total84018 visits; twelve independent A64 replays total168036 visits,144000 checked register effects,166272 read B and39432 written B. Zero unspecified bytes participate in the new path. Two physical backing patterns are replay controls, not two independent native samples. The source archive additionally retains295 instructions/1180 B across the125-instruction constructor,154-instruction outer adapter and16-instruction inner bias/key region. The total7632 per-case distinct-instruction sum is not a union count.

Eleven fresh negated source/algebra obligations are UNSAT, including exact key domain, constructor buffer views, source record fields, bias cancellation, delta projection/range, SP continuity and arbitrary-byte XOR projection. Three SAT probes retain a four-byte-alignment falsifier, nonzero-delta address displacement and a nonempty aligned domain. Eight isolated original-byte packing controls contribute184 additional visits. Prefix receipt restoration is excluded from both execution totals.

All six paths preserve the saved state-pointer cell F+0x80, capacity552 at F+0x3f0 and the three saved buffer views. There are zero writes into the552 B construction view B during this inspected region. The emitted4 B and derived u32 are scratch-frame products; this report does not identify them as a selector21 wire header. The previous API evidence at `0x100478a04` supplies selector21,552 B and in-place user addresses separately. The missing join between construction B and the later API's current-base+0x10 remains missing.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Recover the constructor's real parent and frame-root lifetime. | High | Derive FP, SP, O, phase and bank roots from upstream source without a declared constructor overlay; preserve matching branch/epoch evidence. |
| Continue the constructor through capability-selected preparation to the API frame. | High | Establish B versus current-base+0x10 and all552 B definitions, including count/status cells, on one coherent path before claiming a wire packet. |
| Separate address channels in the private emitter. | Medium | Hold epoch and two of F/R/O fixed while varying the third; compare exact source read/write and self-text selection dependencies. Current coupled layouts do not isolate the cause. |
| Establish a compatible native daemon/kext pairing. | High | Match source image identities, selector/capacity and observed connection/message events; static numeric agreement is insufficient. |
| Resolve a matching daemon IDB for annotation readback. | Low | Confirm backing SHA and preferred addresses before assigning the new source-local names or storing IDB knowledge. |

Quality gates apply to this bounded report:

- **QG1**: No normative premise is needed; source and fixture results are stated separately.
- **QG2**: VH1-VH8 identify assumptions and falsification probes. Exact alignment and the finite zero-delta domain are explicit.
- **QG3**: Obfuscated helper role, incoming/outgoing local ABI, memory/data/control flow, source environment and IPC limits are reported. The full cross-layer goal remains active.
- **QG4**: Widths, byte extents, modular arithmetic and execution counts are reproducible from retained journals, queries and independent replay. Producer/auditor cost is O(snapshot+prefix+cases*(visits+byte effects)) time/space; each solver query has a30 s limit.
- **QG5**: Eight-byte alignment is sufficient rather than necessary; the exact R&5 domain, four-byte counterexample, general nonzero delta, changed outputs and absent buffer join are retained.
- **QG6**: Source image, parent receipts, dependencies, opcodes and initial/final CPU/RAM effects are verified. Native PAC, API execution and matching live-IDB evidence are unknown.
- **QG7**: The bounded continuation table ranks parent-frame, buffer-join, address-sensitivity, native-pairing and IDB opportunities by impact without treating them as completed.
