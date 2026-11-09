# Allocator consumers, issuer literal and shared readiness/flag gate

The first arena result is preserved at SP+0x1A8, a second arena allocation returns through `0x1004818F8` and is preserved at SP+0x1B0, and the same path constructs and compares an encoded issuer-name literal. It then reacquires the shared gate and reaches a read of u32 `0x1010B6CB8`, already encountered in startup and arena initialization. That runtime word remains unknown. A source-local proof recovers the exact readiness/flag dispatch without assigning it a value. No new Mach/IOKit emission or registry publication is established. [AC1-AC12]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [reconstructed checkpoints](triage_evidence/daemon_arena_consumer_source.json), [new source journals](triage_evidence/daemon_arena_consumer_symbolic.json), [six caller/ISA obligations](triage_evidence/daemon_arena_consumer_proofs.json), [continuous independent CPU checks](triage_evidence/daemon_arena_consumer_checks.json), [issuer, gate, six further obligations and original IDB bytes](triage_evidence/daemon_arena_consumer_gate_contracts.json), [preservation](triage_evidence/daemon_arena_consumer_delivery.json), [scoped gates](triage_evidence/daemon_arena_consumer_quality_gates.json).

## Exact continuation and data flow

```text
verified first arena split
  -> 0x10031F248: preserve P1 at SP+0x1A8, test P1==0
  -> change saved continuation at SP+0x258
  -> CASAL at 0x100503D18: gate 0x5D96 -> 0xA94EF
  -> second split of the existing remaining span
  -> restore gate 0x5D96; authenticated continuation 0x1004818F8
  -> preserve P2 at SP+0x1B0, test P2==0
  -> copy 98 encoded literal bytes to SP+0x9FE
  -> compare issuer workspace bytes at SP+0x3B0
  -> CASAL at 0x1005F437C: gate 0x5D96 -> 0xA94EF
  -> readiness test against 1 at 0x10062B2CC
  -> stop before 0x10062B32C: load runtime flag 0x1010B6CB8
```

Both initial arena bases follow 66,132 new source visits, 7,377 memory effects and 1,866 logical authenticated edges. The preceding allocator journal contributes 64,295 visits per case, making 130,427 visits in each continuous composition. These paths retain the original declared initializer handover and certificate fixture; they do not establish native caller or initialization epochs. [AC2,AC3]

The checkpoint reconstructs 6,206 known bytes, 96 symbolic memory bytes, concrete GPRs and one symbolic GPR. The 96 memory bytes are stored expressions over the original 104 unavailable frame-byte variables; they are not 96 new independent inputs. All 104 original variables remain unconstrained. Source stores may overwrite their original spill addresses; those later memory definitions do not assign values to the original variables. Pointer origins are reconstructed instruction by instruction, including stack spills and all 1,742 parent authenticated edges. Eight continuous Unicorn witnesses execute the original parent and new suffix in the same private CPU state, checking every checkpoint byte and GPR at the join. [AC2,AC4]

| Source interface | Contract | Bound |
| --- | --- | --- |
| `0x10031F248..0x10031F264` | Store P1=X23 at SP+0x1A8; index `I XOR (P1==0 ? 0x2E : 0)` | I is u32 at SP+0x9C |
| `0x100637E04` | Replace SP+0x258 with continuation `0x1004818F8` | Original pointer provenance retained |
| `0x1004818F8..0x100481920` | Store P2=X23 at SP+0x1B0; index `(F+0x9D7) XOR (P2==0 ? A+B-0xB2DC : 0)` | F,A,B are explicit u32 phase/frame inputs |
| `0x100607350`, `0x100607358` | Signed byte loads into W13/W14; W writes clear upper X bits | Eight-bit sign extension precedes byte-mask comparison |
| `0x100503D18`, `0x1005F437C` | CASAL requests `0x5D96 -> 0xA94EF` on the shared gate | Selected single-thread component outcomes; no general native ordering claim |

The parameterized caller proofs cover all u64 payload words and all u32 phase/frame inputs under the fixed component-cell layout. They do not establish a native allocation-failure return or an ordinary C return-in-X0 convention. [AC5,AC6]

## Second allocation and the two payloads

Let H be the declared 90,000-byte arena base, M=`0x5E878C613B8123EA`, D=`0x1010B5EF0`. The first split left a free-span value of 88,300 bytes. The second observed debit is again 1,676 bytes:

```text
R2 = 88,300 bytes - 1,676 bytes = 86,624 bytes = 0x15260 bytes
B2 = H + R2
P2 = B2 + 24 bytes = H + 0x15278 bytes
P1 = H + 0x15904 bytes
P1 - P2 = 1,676 bytes
cumulative account increment = 2 * 1,676 bytes = 3,352 bytes
```

| Arena base H | First boundary B1 | First payload P1 | Second boundary B2 | Second payload P2 |
| --- | --- | --- | --- | --- |
| `0x6500000000` | `0x65000158EC` | `0x6500015904` | `0x6500015260` | `0x6500015278` |
| `0x6500100000` | `0x65001158EC` | `0x6500115904` | `0x6500115260` | `0x6500115278` |

The second fill writes 1,724 descending bytes over `[H+0x15230,H+0x158EC)`. Its late metadata patches include H+8=M+R2, B2=M+R2, B2+8=M-1,676, and D+40=`0x1AA4071F08018373`. Writer `0x1005883CC` stores M at B1, the preceding first boundary word. Thus the first payload remains untouched, while its boundary metadata changes. [AC7]

Within this new suffix, P1's 1,652-byte geometric payload interval receives no read or write. The second interval receives its allocator fill and no later payload access. Both pointer results are parked on the frame. Their later application-level contents, registry ownership and eventual transport use remain unknown. These extents are measured for the selected cases, not universal capacities. [AC7,AC12]

## Issuer-name representation and comparison

The source copy at `0x100406A48` reads exactly 98 original bytes from `0x100F266A4..0x100F26706` and writes them at SP+0x9FE. Each stored byte equals its corresponding read-only source byte. XOR 0x81 decoding yields the following ASCII string plus one NUL byte:

```text
/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Key Services Certification Authority
```

The full copy precedes the observed comparisons. The input address SP+0x3B0 is the issuer text workspace identified in the [certificate-field report](daemon_record720_fields_report.md). Its selected fixture contains `/CN=Fixture`. At `0x100607350/0x100607358`, the first three input/literal byte pairs are `(2F,AE)`, `(43,C2)`, `(4E,BC)`. The XOR-decoded literal prefix is `/C=`, giving two matching bytes and then a difference. The new gate artifact retains exact source addresses, write/read event ordering and all 98 raw bytes. [AC8,AC9]

The complete local comparison fragment is parameterized by its u32 phase K. It tests byte XOR against the low byte of `((((K+0x7FEF6F30)&0xDFFDFEDF)+0xA012C0BD)^0x1B)` and changes its dispatch index by XOR 0x22 on equality. This source theorem preserves the phase prerequisite. The decoded literal and this fixture do not prove complete issuer policy, signature validation, trust-chain acceptance, all name encodings or native certificate reachability. [AC8,AC9]

## Readiness, runtime flag and two conditional branches

The flag address is reconstructed from an original ordinary rebase at `0x1010A4528`: decoded scalar `0x1088E003F`, then source bias `-0x07829387`, giving `0x1010B6CB8`. The raw chained word is not the final runtime pointer. This is a process-local u32 control input, not a Mach port. [AC10]

For the recovered phase W9=`0xA220`, the marker comparison is readiness==1. The subsequent `CCMP W11,#0,#4,EQ` and source bit operations establish:

| Readiness byte | Runtime flag u32 | Table index | Original slot | Target |
| --- | --- | --- | --- | --- |
| 1 | Nonzero | `0xA232` | `0x10108B080` | `0x10061B524` |
| 1 | Zero | `0xA220` | `0x10108AFF0` | `0x10047BE18` |
| Not 1 | Any | `0xA220` | `0x10108AFF0` | `0x10047BE18` |

Both original slots use IA diversity 0x26A0, address diversity zero. A proof covers all 256 readiness values and all 2^32 flag values. Independent source-component CPU execution checks all readiness values against flag samples 0,1,2,0xFFFFFFFF: 1,024 cases and 18,432 A64 instructions. These flag samples are component inputs and are never installed in the continuous daemon suffix. Its original read frontier remains unchanged. [AC10,AC11]

At `0x10047BE18`, source restores gate=0x5D96, sets W9=0x74C29D85 and transfers through the saved SP+0x200 continuation with modifier 0x50CC. At `0x10061B524`, source computes P1-24 and stores it at SP+0x240, then tests P1 for nonzero. This establishes a boundary-address consumer; deallocation or coalescing is not yet proved. Both branch contracts have separate all-u64 source obligations. [AC11]

Earlier [startup](daemon_frame_entry_report.md) and [arena](daemon_arena_storage_report.md) reports use this same u32 cell, with distinct predicates. Those earlier flag=1 fixtures are not a native publisher for the current read. The present IDB exposes seven indexed pointer-pool references; this is not an exhaustive writer census. One reference prepares and spills the decoded flag address at `0x1002900A0`. The runtime writer, reset policy and full flag semantics remain unknown. [AC10-AC12]

## Validation, assumptions and limits

Twelve rebuilt source obligations have 24 original/simplified SMT-LIB files, all UNSAT. The continuous checks cover eight witnesses, 1,014,552 A64 instructions, 58,360 reads, 56,648 writes, 28,864 logical authenticated edges and eight exact checkpoint joins. Separate CPU tests check all 256 signed-byte values and 256 conditional-selection flag/operand cases. Eleven fresh IDB ranges match 2,624 original bytes. PAC transfers are checked logically; no hardware authentication, imported target API or native daemon/kext transaction executes.

| ID | Assumption or component premise | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| AC1 | Thin image is the analyzed source | All addresses and instructions | Rehash image; verify eleven raw IDB ranges |
| AC2 | Parent journal and retained handover define the starting state | New consumer path | Reconstruct all writes and origins; compare continuous CPU state at the join |
| AC3 | Declared initializer/certificate fixtures are component inputs | Both arena-base compositions | Preserve native-epoch uncertainty; require original caller evidence for native claims |
| AC4 | Original 104 unknown frame bytes retain their identities | Opaque data flow | Four materializations per base; no added source-defined bytes |
| AC5 | Fixed disjoint caller cells and u32/u64 widths | Caller store/dispatch formulas | Rebuild quantified source obligations |
| AC6 | Local single-thread CASAL value semantics | Gate transitions | Original-instruction replay; no multi-thread or memory-order theorem |
| AC7 | Selected arena geometry and access intervals | Second split and parked payloads | Audit every fill/metadata write at both bases; include changed B1 word |
| AC8 | Exact source literal bytes and event ordering | Name representation | Compare all 98 source/read/write bytes; verify copy completes before comparison |
| AC9 | Comparison phase K remains explicit | Byte comparison contract | Quantify K and both bytes; do not promote to complete issuer policy |
| AC10 | Readiness source value and decoded flag address are phase-specific | Shared-state join | Check original rebase/bias, earlier consumers and unknown runtime value |
| AC11 | Flag samples are isolated component inputs | Two branch contracts | Exhaust readiness and prove all u32 flags; preserve continuous read stop |
| AC12 | Native writers, ownership and transport join are unproved | Scope and continuation priorities | Require writer/reset and original caller/IPC evidence |

Time complexity is O(parent reconstruction visits + new visits + witness visits + solver resources); space is O(one journal, private map and expression DAGs). Byte extents are exact; machine arithmetic is little-endian u32/u64 with modular overflow and explicitly signed byte loads.

Reproduce using the retained interpreter and Z3 environment from the preceding [arena report](daemon_arena_list_report.md): run `capture_daemon_arena_consumer.py`, `daemon_arena_consumer_symbolic.py`, `prove_daemon_arena_consumer.py`, `validate_daemon_arena_consumer.py`, then `recover_daemon_arena_consumer_gate.py --check`, all under `triage_evidence/`. The last command verifies the retained supplemental contracts and proofs without overwriting them.

| Impact | Bounded continuation target | Uncertainty resolved |
| --- | --- | --- |
| High | Find original writes/reset to `0x1010B6CB8` and join its native epoch | External or environmental control of the post-name decision |
| High | Follow both gate branches and P1-24 consumer | Actual allocator release/coalescing and pointer lifetime |
| High | Continue both parked payloads toward registry publication and IPC | Application data and daemon/kext join |
| Medium | Recover remaining name comparisons and successful certificate cases | Full name policy and representation prerequisites |

- QG1: Pass for factual technical analysis.
- QG2: Pass; AC1-AC12 state dependencies and falsification probes.
- QG3: Pass for this increment; the full interface goal remains active and incomplete.
- QG4: Pass; bytes, signed loads, widths, endian order and complexity are explicit.
- QG5: Pass within scope; continuous execution, component flag cases and native unknowns are distinct.
- QG6: Pass; original image, fixups, IDB ranges, source proofs and independent CPU witnesses supply provenance.
- QG7: Pass; bounded continuation targets carry impact labels.
