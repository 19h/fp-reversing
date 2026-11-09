# Internal spill/restore protocol and an arena-descriptor reader

The word at `[SP+0x2E8]` is an internal saved-register operand, with a matching source store of X24 and subsequent restoration of X24. Its interpretation as a pointer is unproved. A byte-symbolic successor keeps 104 unavailable frame bytes unconstrained, follows 240 original instructions and seven logical authenticated edges, and reaches `0x1004A0620` before reading the pointer-bearing descriptor cell `0x1010B5F38`. That is descriptor `0x1010B5EF0+72`, initialized to the allocated arena pointer by the earlier source publication at `0x10032A56C`. Its current runtime value remains unknown. [SP1-SP11]

This refines the terminology in the [certificate-field report](daemon_record720_fields_report.md). Its original private replays still stop at `0x100633F04`; no unavailable byte is added to those contexts. The new successor is symbolic source analysis with separate finite witness executions, not a newly completed native invocation. The [arena-publication report](daemon_arena_storage_report.md) supplies the earlier pointer/link producer and its independent evidence. Registry publication and a new daemon/kext transaction remain unresolved.

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [source, checkpoint, census and current IDB](triage_evidence/daemon_record720_spill_source.json), [symbolic instruction/effect journal](triage_evidence/daemon_record720_spill_symbolic.json), [source proofs and exact field map](triage_evidence/daemon_record720_spill_proofs.json), [independent checks and witness patterns](triage_evidence/daemon_record720_spill_checks.json), [preservation](triage_evidence/daemon_record720_spill_delivery.json), [quality gates](triage_evidence/daemon_record720_spill_quality_gates.json).

## The saved-word interpretation

Let S denote the SP at the stopped `LDR X24,[SP,#0x2E8]`. The save fragment at `0x100638710..0x10063875C` writes fourteen eight-byte fields. The restore data instructions at `0x100633F04..0x100633F5C` recover register and frame values from those fields. Source proofs quantify arbitrary u64 input words under the fixed disjoint frame layout. They establish a component contract; the save block is absent from the retained allocation-prefix execution. [SP2-SP4]

| S-relative spill offset | Saved source value | Restoration destination |
| --- | --- | --- |
| +0x2E8 | X24 | X24 |
| +0x338 | X26 | X26 |
| +0x220 | Original `[S+0xE0]` | `[S+0xE0]` |
| +0x238 | Original `[S+0xF8]` | `[S+0xF8]` |
| +0x178 | X22 | X22 |
| +0x2F8 | X19 | X19 |
| +0x2D8 | Original `[S+0xF0]` | `[S+0xF0]` |
| +0x160 | Original `[S+0xE8]` | `[S+0xE8]` |
| +0x358 | Original `[S+0xD8]` | `[S+0xD8]` |
| +0x1E8 | X4 | X4 |
| +0x288 | X8 | X8 |
| +0x2D0 | Original `[S+0x148]` | `[S+0x148]` |
| +0x1C8 | X9 | X9 |
| +0x1D0 | Original `[S+0x138]` | `[S+0x138]` |

The save fragment also loads X25 from `[S+0xD0]`; this report does not claim a complete register-context round trip. The proved data round trip covers seven registers and seven original stack words. The fourteen spill fields contain 112 bytes spread through the frame; they are not a contiguous 112-byte native structure. The highest field ends at S+0x360. [SP3,SP4]

In the retained checkpoint, thirteen spill words have no definition and one word at S+0x288 already has a source-defined value. The new analysis introduces one independent eight-bit variable for each of the 104 unavailable bytes: 832 unconstrained bits. These are symbolic machine values, not zeros, pointers or source-initialized bytes. The first missing word is loaded into X24; no use of that value as an effective address or control target is established in the inspected suffix. [SP2,SP5]

## Symbolic successor and actual interfaces

```text
retained declared allocation/certificate prefix
  -> readiness=1, concrete replay stops before 0x100633F04
       |
       `-- symbolic successor, unavailable bytes remain variables
             restore data from fourteen spill slots
             -> 0x1004CD280, selected original dispatch
             -> 0x100540A00, four byte emissions to S+0x1E4..0x1E7
             -> 0x1004A95DC, local selection arithmetic
             -> 0x1004A0604
             -> stop before 0x1004A0620: LDR X15,[X6,#0x48]
                  X6 = 0x1010B5EF0
                  next read = descriptor+72, eight bytes
                  current value unavailable

earlier arena-publication source component
  X0=H, X9=D+48, X15=D
  -> 0x10032A568: store H at D+80
  -> 0x10032A56C: store H at D+72
```

All seven branch targets and all effective addresses in the symbolic suffix simplify to constants independent of the unavailable bytes, under the retained known state. Original authenticated pointer words, IA key/diversity, address-diversity zero and source modifiers are checked. No missing byte is concretized to obtain those branches. The old concrete prefix is unchanged. [SP2,SP5-SP7]

The symbolic suffix performs 39 memory effects: 27 reads and 12 writes. Fifty-six written bytes are exact copies of unavailable input bytes. They retain their byte identities through stack copies; they are not promoted to known values. Other output bytes derive from the retained source-defined state. Six registers still contain opaque words at the new boundary. Their lack of influence over this suffix is a bounded result, not proof that they are dead for the remainder of the routine. [SP5,SP6]

The four byte emissions at S+0x1E4..0x1E7 feed local selection arithmetic. Their complete higher-level purpose remains unknown. No cryptographic primitive, external operation number, Mach message ID or IOKit selector is assigned to these bytes from their numeric values. [SP6,SP11]

## Descriptor and arena publication join

| Interface | Source site | Established contract | Limit |
| --- | --- | --- | --- |
| Publish descriptor link | `0x10032A56C` | X0=H stored at `(D+48)+24 = D+72` | Earlier declared arena-return component |
| Publish paired descriptor link | `0x10032A568` | X0=H stored at D+80 | Same source phase |
| New descriptor reader | `0x1004A0620` | Load u64 from X6+0x48, with X6=D | Current field contents unavailable |
| Component equation | Original publications plus original reader | If the reader observes that publication epoch, X15=H | No live epoch continuity or synchronization assumed |

D is `0x1010B5EF0`. The previous arena report establishes reciprocal links between H and D+48, and the exact 90,000-byte allocation request. The new source reader therefore consumes a cell with an established pointer-publication role. This does not prove that its current value is the original arena base: intervening list/allocator mutations and the relevant runtime epoch remain unknown. No heap owner is mapped at an invented value to continue past the read. [SP7,SP8]

This joins the allocation/certificate continuation to a concrete arena-descriptor interface. It does not join the 720-byte object to a registry value or show a native daemon/kext request. [SP8,SP11]

## Producer census and evidence boundaries

A complete aligned scan of this image's `__text` finds 169 immediate SP-store encodings whose written span overlaps `[SP+0x2E8,SP+0x2F0)`: 168 single stores and one pair store. Forty-eight are exact `STR Xn,[SP,#0x2E8]` encodings. All candidates retain original words, decoded instructions, offsets and widths. [SP1,SP9]

This is an encoding census, not a census of native producers for one frame instance. It covers unsigned-immediate single stores and immediate pair stores. Register-offset stores, SP aliases, preceding SP movement and semantic frame equivalence are excluded. The matching X24 save/restore pair provides stronger data-mapping evidence than the literal offset alone; it still does not establish that the selected prefix executes that save. The retained prefix contains neither `0x100638710`, `0x100638874` nor `0x1008010BC`. [SP4,SP9]

Seven fresh read-only IDB windows, 3584 bytes, match the backing image without normalization. Checkpoint reconstruction checks all 339,218 retained parent opcodes, reconstructs 4294 known bytes from declared inputs and original writes, and leaves absent bytes absent. No native stack or allocator state is inferred from the private backing pattern. [SP1,SP2]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| SP1 | Preferred addresses and opcodes refer to the identified thin source and corresponding IDB slice. | Rehash source/original inputs and compare the seven current IDB windows and full census words. |
| SP2 | The retained readiness-one declared case supplies the checkpoint, not a native process snapshot. | Reconstruct known registers/bytes from all parent visits and effects; preserve the original stopped case and recover native caller continuity separately. |
| SP3 | The save/restore equations use the fixed disjoint frame layout and u64 machine words. | Independently quantify arbitrary input words; check offsets, widths and intervening writes; do not infer arbitrary aliasing or native types. |
| SP4 | Matched data mappings establish an internal spill protocol, not complete function/ABI ownership. | Prove the seven-register/seven-stack-word round trip; identify the actual entering caller and save epoch before composing native restoration. |
| SP5 | Unavailable frame bytes are independent symbolic eight-bit machine values. | Keep all 104 variables unassigned; prove control/address independence under a second independent assignment; inspect exact copied-byte identities. |
| SP6 | The noninterference result ends after the 240-instruction suffix. | Preserve every original instruction/effect/edge; stop before the next unavailable runtime read; do not extend deadness beyond that boundary. |
| SP7 | Pointer authentication is interpreted as logical source transfer with original slot/modifier checks. | Recheck original pointer words and target provenance; native PAC success and runtime relocation require separate observation. |
| SP8 | The descriptor publication and consumer share a field address, with conditional epoch continuity. | Prove both original component equations; recover intervening writers, synchronization and current link value before assigning an owner. |
| SP9 | The immediate-store census covers its stated encoding classes only. | Re-scan all aligned text words; expand register-offset, alias and frame-instance analysis before claiming all possible producers. |
| SP10 | The 16 Unicorn runs materialize abstract variables as finite witnesses, without adding source definitions. | Retain zero/ones/A5/5A/ramp/random patterns and compare actual addresses, effects, GPRs and frontier to the symbolic model. |
| SP11 | No new Mach/IOKit emission or native transaction is established. | Continue actual source successors only with provenance for the descriptor value, then match destination/right/descriptor evidence at transport boundaries. |

## Verification and bounded next evidence

Six source obligations and twelve exact SMT artifacts pass: fourteen save fields, partial register round trip, seven stack-word round trip, 832-bit control/address independence, 448-bit opaque-copy preservation, and the all-u64 descriptor publication/reader component. Sixteen independent finite materializations execute 3728 ordinary A64 instructions and 112 logical authenticated edges. They check 432 reads, 192 writes and all final modeled GPRs, reaching the same descriptor-read frontier. No source instruction is rewritten and no native target runs.

| Impact | Next evidence target | Question resolved |
| --- | --- | --- |
| High | Current value and writer epoch of descriptor D+72 | Which arena/list node is actually consumed next? |
| High | Original caller/save path for the fourteen spill fields | Which predecessor establishes this frame protocol for a native invocation? |
| Medium | Consumers after the descriptor read | How do opaque restored registers and the 720-byte owner participate in later policy/cache interfaces? |
| Low | Register-offset and SP-alias producer analysis | Which additional candidates can be excluded or joined to this frame instance? |

Reproduction from the extracted directory:

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_record720_spill.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/daemon_record720_spill_symbolic.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_record720_spill.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_record720_spill.py
python3 triage_evidence/seal_daemon_record720_spill.py
```

Complexity is O(text words + parent visits/effects + symbolic DAGs + witness steps + solver resources) time and O(parent case + known-byte map + symbolic DAGs + one witness map) space. All extents/offsets are bytes; scalar and symbolic widths are explicit. The full interface investigation remains active.

QG1: Factual source analysis. QG2: SP1-SP11 identify premises and falsification probes. QG3: This increment covers spill roles, symbolic successors, source-address census and the descriptor reader; full goal incomplete. QG4: u8/u64, byte extents, modulo arithmetic and complexity explicit. QG5: Pointer interpretation, native caller continuity, symbolic values, finite witnesses and descriptor epochs remain distinct. QG6: Original source/IDB, exact parent checkpoint, source lifts, original fixups and independent instruction witnesses provide provenance. QG7: Impact-ranked next evidence is bounded above.
