# Constructor descriptor and feedback phase contracts

The initializer's SP+0x2b0 field points to `0x1010b7cc0` in all twelve retained profiles. A separate descriptor at SP+0x9e0 encodes the initializer input counter relative to its frame address. These are source producer candidates for the unresolved success path; a continuous initializer-to-current-caller epoch remains unknown. This increment supplies no new guest bytes and executes no new guest interval. [CD1-CD4; CD-A1-CD-A3]

The source consumer reverses the descriptor arithmetic. A nearby wrapper computes `new=u64(old*0x2ecd+1)`, reserves 16-256 B of additional stack from its high nibble, and quantizes a returned difference into a multiple of 16. These phase contracts identify dataflow and stack effects. The feedback store's destination and the wrapper's complete operation remain unknown. [CD1-CD3; CD-A3-CD-A5]

```text
separate initializer profiles
  record[0] XOR 1c0b9f7ce10f2255 -> counter c
  b = frame SP + 9e0; aligned frame
    [b+0] / 4 B = low32(b+c) + b5caf0c6
    [b+4] / 4 B = no retained writer
    [b+8] / 8 B = b+c
  [SP+2b0] / 8 B = 1010b7cc0
                         |
                current epoch join UNKNOWN
                         |
current success frontier 1008a2704
  SP+2b0 and SP+9e0..9ef remain undefined

compatible source phases, without claiming continuous execution:
  root -> cell value -> private SP+bdc8 copy
  descriptor -> fixed word bias; q-b -> original counter
  wrapper old -> old*2ecd+1 -> 16..256 B stack reservation
  nested cell old-d0 -> restoration by +d0
  returned low16 difference -> multiply by 16 -> caller cell
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CD1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_constructor_descriptor.py) retains eight original source regions and the original chained-fixup word. |
| CD2 | Twelve initializer profiles in [bank-origin checks](triage_evidence/daemon_return_bank_origins_checks.json.zst), and 304 frozen exports from the [constructor-buffer report](daemon_constructor_buffer_report.md). |
| CD3 | [Contract checks](triage_evidence/daemon_constructor_descriptor_checks.json.zst): 36 source writers, 24 source reads, four distinct frame/counter pairs, eight nonvacuous source equations, one alignment counterexample and all 304 frontier definedness checks. |
| CD4 | [Publication verifier](triage_evidence/verify_daemon_constructor_descriptor_publication.py): fresh source/profile/equation reconstruction, source hash/fixup verification, exact manifest delta, input preservation and decoded path checks. |

## Root pointer and descriptor producer

The original 8 B pool word at `0x1010a3eb0` is `02 94 4b 7b 00 00 08 00`. It is a chained rebase, not an already relocated address. Independent pointer-format-12 decoding yields `0x17b4b9402`. Instructions `0x1004c3560..0x1004c3568` add the sign-preserving 64-bit bias `0xffffffff85bfe8be`, yielding `0x1010b7cc0`. `STR X11,[SP,#0x2b0]` at `0x1004c356c` stores that result once per retained profile. The target's original eight bytes are `17 1b 0a 35 19 a1 f6 d3`; current native contents are unknown. [CD1-CD4; CD-A1-CD-A3]

At the success frontier, source `0x1008a2704` loads SP+0x2b0; `0x1008a2708` dereferences the resulting pointer; `0x1008a2710` stores the loaded value at outer SP+0xbdc8. This establishes the local pointer-to-cell-to-private-copy shape. No execution through this frontier is added here. [CD1, CD3-CD4; CD-A3]

Let c be the u64 obtained by XORing the input record's first u64 with `0x1c0b9f7ce10f2255`, and let b=`u64(SP+0x9e0)`. Lifting all instructions `0x10061a464..0x10061a4b8` gives:

```text
q = u64(b + c + 2*(b & c & 2) - (b & 2))
[SP+9e8] / u64 = q
[SP+9e0] / u32 = u32(q + b5caf0c6)
```

For SP divisible by 16, b&2=0, so q=`u64(b+c)`. The 16-byte alignment premise is sufficient; the proof does not claim it is necessary. The unrestricted simplification is false: SP=2 and c=0 produce q=`0x9e0`, while b+c=`0x9e2`. This is an arithmetic counterexample to the simplified equation, not a native execution observation. [CD1-CD4; CD-A2-CD-A3]

| Frame SP | Declared c | Stored q at SP+0x9e8 | Stored u32 at SP+0x9e0 |
| --- | --- | --- | --- |
| `0x680004f230` | `0` | `0x680004fc10` | `0xb5cfecd6` |
| `0x680004f330` | `0x123456789abcdef0` | `0x123456e09ac1dc00` | `0x508cccc6` |
| `0x680004f430` | `0xffffffffffffffff` | `0x680004fe0f` | `0xb5cfeed5` |
| `0x680004f530` | `1` | `0x680004ff11` | `0xb5cfefd7` |

Each row occurs in three retained RPC variants. The pointer and word writers are `0x10061a4a8` and `0x10061a4b8`. No retained initializer writer overlaps the intervening four bytes SP+0x9e4..+0x9e7. Absence of a writer in this retained execution is narrower than absence of all possible producers. [CD2-CD4; CD-A2]

## Consumer and wrapper phase interfaces

| Original source phase | Input domain / premises | Established effect |
| --- | --- | --- |
| `0x100a5eac8..0x100a5ead0` | Compatible pair: word=`u32(q+b5caf0c6)`, u64=q | W15 becomes `0xb5caf0c6` at the subtraction. Later instructions overwrite W15. |
| `0x100a5eaec` | X14=b, X17=`u64(b+c)`; intervening source preserves these registers | X14 becomes c by u64 subtraction. |
| `0x100b2120c`, `0x100b21308..0x100b21314` | X19 is the saved X1 pointer; readable u64 old | X21=old; X2=`u64(old*0x2ecd+1)`. |
| `0x100b21374` | Controller/table phase completes; its source preserves X2 | Stores the computed X2 through `[X4,X5]`; destination identity remains unresolved. |
| `0x100b21378..0x100b21398` | X2=new; current local SP=l | n=`new>>60`; extent=`16*(n+1)` B; SP=X20=`u64(l-extent)`; stores `u64(old-0xd0)` at X20. |
| `0x100b0051c..0x100b00524` | X1 points to the compatible `old-0xd0` cell | Adds 0xd0 and stores old back into that cell. Source-phase compatibility is proven; call continuity is unknown here. |
| `0x100b2143c..0x100b21448` | X20 points to returned u32 t; X21 retains old; X19 points to caller cell | Stores u64 `16*u16(t-low32(old))` into the caller cell, range 0..1048560 in multiples of 16. Semantic unit beyond the arithmetic scale is unknown. |

The additional reservation is exactly one of 16,32,...,256 B; it preserves SP modulo 16. The prologue has already reserved 0x40 B before this phase. The reservation equation concerns that additional dynamic part, not the complete nested call's stack footprint. The returned quantity is a scaled integer; its interpretation as a length, alignment token or protocol field is unknown. The modulo-2^64 recurrence alone does not establish randomness, cryptographic purpose or native global ownership. [CD1-CD4; CD-A3-CD-A5]

## Verification and present boundaries

All twelve profiles match the input-counter read, relocated pool read and three exact writer events, including original source words and visit indices: `12*2=24` reads and `12*3=36` writers. Eight SMT obligations have satisfiable premises and unsatisfiable negated conclusions, using original source lifts with u32/u64 modular arithmetic and a 30 s timeout per query. Two skipped source spans receive explicit register-preservation checks; no skipped span is treated as executed. The aligned simplification has an explicit falsification control outside its premise. [CD1-CD4]

All 152 successful exports retain an undefined SP+0x2b0/8 B and an undefined SP+0x9e0/16 B. All 152 NULL exports retain undefined S+0x30/8 B. These are inherited model definedness boundaries. Neither native invalid access nor a native vulnerability is established. The descriptor's declared counter is not identified with a later caller cursor. Existing 96 B of conditional root premises remain unchanged; this increment adds zero definition bytes. [CD2-CD4; CD-A2-CD-A3]

Time is O(source words + profile events + terminal bytes + solver query DAG), excluding solver search complexity; storage is O(largest input receipt + one terminal byte map + query DAG). The solver timeout is a limit, not a complexity bound. All offsets, addresses and allocation/reservation extents are bytes; u32 and u64 arithmetic wraps at 2^32 and 2^64. No target API, IPC, allocation, free, filesystem operation, hardware PAC or IDB mutation executes. Retained primary data suffices; IDA is not accessed. [CD1-CD4]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CD-A1: Pinned source image, fixups and retained receipts apply | Source locations, pointer decoding and equations | Check original SHA, every retained instruction word, original format-12 slot and decoded target, and frozen parent digests. |
| CD-A2: Retained profiles and exports have their published conditional scope | Twelve producer examples and 304 definedness checks | Verify exact writer/read widths, addresses, values and visit indices; retain padding and frontier unknowns; do not infer exhaustive native profiles. |
| CD-A3: Compatible source phases do not establish a continuous epoch | Descriptor consumer and downstream architectural interpretation | Keep actual counter and current initializer/caller join unknown; preserve the unaligned counterexample and satisfiable aligned premise. |
| CD-A4: Sequential integer phase semantics apply | Modular equations and stack reservation | Lift original instructions; check u32 zero extension and skipped-register preservation; native concurrent mutation and PAC remain unknown. |
| CD-A5: Destination and operation identity require independent joins | Feedback and transport interpretation | Do not assign the store at 0x100b21374 to the root cell without effective-address provenance; require actual call and buffer custody for cross-layer claims. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Join initializer frame/counter to the current success caller | Matching producers do not establish the current epoch or justify supplying c=0. |
| High | Resolve the effective address at feedback store 0x100b21374 | The recurrence value is proven; destination/global-cell identity remains unknown. |
| High | Establish S+0x30 producer and lifetime | The NULL frontier still demands eight undefined model bytes. |
| High | Join S/U/F and descriptor identities to native Mach/IOKit buffers | This increment establishes no new port, right transfer or external emission. |
| Medium | Recover the full counter-dependent consumer partition | Arithmetic counter recovery is proven; complete downstream dispatch and operation semantics remain unknown. |

**QG1**: factual source and ABI analysis. **QG2**: CD-A1-CD-A5 identify dependencies and falsification probes. **QG3**: this source-contract increment is covered; the full interface goal remains active. **QG4**: widths, modular equations, byte extents, counts and complexity are explicit. **QG5**: alignment, overwritten registers, padding and phase/epoch boundaries are separated. **QG6**: fresh source/profile/fixup/solver and publication verification qualify the pinned primary artifacts. **QG7**: impact-labeled adjacent opportunities and unresolved joins are explicit.

Follow-up: The [feedback-root report](daemon_feedback_roots_report.md) resolves all three source selector destinations over complete u32 domains: controller cells 0x1010b6590/0x1010c4670 and feedback cell 0x1010b7cc0. The last matches the initializer SP+0x2b0 root. It recovers both controller update equations and the feedback destination through 768 partitions with symbolic upper bits and four source proofs. Current caller epoch, contemporaneous-global equality and native Mach/IOKit pairing remain unknown.
