# Arena release/coalescing, private result channels and ordinary-owner cleanup

The retained issuer-name path now reaches the previously recovered 720-byte cleanup request through both exhaustive stable-flag classes. With flag `0x1010B6CB8 != 0`, it releases the two arena suballocations and restores all 80 source-defined descriptor bytes and all 48 source-defined initializer heap bytes. With flag zero, this interval performs no arena writes. Both classes produce the same private record result and zero cursor adjustment, then reach `_free(0x6800070000)` at `0x1001C6100`. The native flag value/writer and allocator effects remain unknown. [L1-L10]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [exact checkpoints and source call/return provenance](triage_evidence/daemon_arena_lifetime_source.json), [four symbolic flag-class journals](triage_evidence/daemon_arena_lifetime_symbolic.json), [eight source obligations](triage_evidence/daemon_arena_lifetime_proofs.json), [continuous CPU, metadata and output checks](triage_evidence/daemon_arena_lifetime_checks.json), [bounded writer-candidate census](triage_evidence/daemon_arena_lifetime_refs.json), [preservation](triage_evidence/daemon_arena_lifetime_delivery.json), [scoped gates](triage_evidence/daemon_arena_lifetime_quality_gates.json).

## Ownership and control closure

```text
issuer/name component, readiness=1, current flag unknown
  -> declare one symbolic u32 flag; preserve original frame variables
       |
       +-- flag==0: restore gate, skip arena-release sequence
       |
       `-- flag!=0: release P1, then P2; coalesce free spans
                    restore initialized descriptor/boundary/link state
       |
       -> write private result at R+0x1C
       -> logical RETAB to 0x100537104
       -> write cursor adjustment
       -> logical RETAB to 0x100B0B964
       -> caller reads R+0x1C; overwrites X0 without reading it
       -> reuse R for private cleanup control 0xBBB3
       -> BLRAA 0x100BE0C50 -> 0x100435B9C
       -> stop before _free(P720) at 0x1001C6100
```

The new checkpoint is reconstructed from the [allocator-consumer journal](daemon_arena_consumer_report.md): 8,016 known bytes, 88 symbolic memory bytes, concrete GPRs and source-derived NZCV=0x60000000. The original 104 unavailable frame-byte variables remain unconstrained; original spill addresses may have been overwritten by later source stores. The runtime flag adds one independent 32-bit variable. No flag value is installed in the symbolic source execution. [L2,L3]

The two path predicates are `flag==0` and `flag!=0`. The suffix assumes no external writes to modeled globals: repeated flag reads observe the same symbolic word. Flag transitions and concurrent interleavings are outside these two source paths. Whenever a flag-dependent expression supplies an address, the engine proves that it has one unique value under the predicate; otherwise it stops. Retained SMT obligations establish the two original table-slot addresses for every value in their respective classes. Finite CPU witnesses instantiate flag values 0,1,0xFFFFFFFF separately from those source proofs. The original pre-flag-read journal is preserved unchanged. [L3]

| Flag class | New source visits per arena base | Arena account at cleanup entry | Common native-API frontier |
| --- | ---: | --- | --- |
| Zero | 408 | A+3,352 bytes | Before `_free(P720)` |
| Nonzero | 30,782 | A, after two 1,676-byte debits | Before `_free(P720)` |

A=`0x1AA4071F0801765B` is the encoded account baseline at descriptor D=`0x1010B5EF0`. These are source-component paths over the retained initialized arena and certificate fixture. Native initialization/caller/flag epochs are unproved; the zero class does not establish a native leak or an entry-reachable allocation policy. [L3,L7]

## Release, coalescing and byte extents

P1 and P2 are suballocations inside a declared 90,000-byte arena H. Their payload addresses are H+0x15904 and H+0x15278, respectively. Their boundary records begin 24 bytes earlier. The source release sequence checks and changes encoded boundary words, inserts a free block into the doubly linked structure, merges adjacent free spans, and decrements descriptor+40 at `0x10061D6D0`. [L7]

```text
account after two allocations: A + 3,352 bytes
first release:                A + 1,676 bytes
second release:               A
restored free-span value:     89,976 bytes = 90,000 bytes - 24 bytes
```

| Source site | Established operation |
| --- | --- |
| `0x10061B538` | Form boundary candidate P-24 |
| `0x10061D6B4..0x10061D6D4` | Account := account-debit, modulo 2^64, when incoming encoded size is M-debit |
| `0x10062ABB4..0x10062ABC8` | Update new free-node links, descriptor tail and previous tail's forward link |
| `0x100607BD8`, `0x1005AA478..0x1005AA4A8` | Update merged-span word and unlink merged node |
| `0x100552190` | 500 byte-store visits across the two releases |
| `0x100607DE8` | 364 further byte-store visits in the selected coalescing path |

M=`0x5E878C613B8123EA`. The final comparison uses the initializer's actual defined-byte masks: 80 of 88 descriptor bytes and 48 of 90,000 heap bytes. All those defined bytes match the original initializer at both arena bases (`0x6500000000`, `0x6500100000`). Other heap bytes acquire source writes; the whole arena is not restored or cleared. The byte stores do not establish secure erasure. General free-list invariants, all-size behavior and allocator-library identity remain unknown. [L7]

## Output channels, stack frames and record epochs

| Interface | Observed output in both flag classes | Source site |
| --- | --- | --- |
| Private 32-byte record R | u32 R+0x1C=`0x74C29D8A` | `0x10061AABC` |
| Adapter cursor-output cell | u64 `0x6800023988=0` bytes | `0x100537110` |
| Ordinary-owner cleanup argument | P720=`0x6800070000` | `0x100BE0BE8`, `0x1001C6100` |

The dispatcher returns with different X0 bit patterns in the two classes. The inspected caller sequence has no read of X0/W0 before its overwrite at `0x100BE0C48`; it reads the record word instead. No success/failure meaning is assigned to the raw register patterns or record word. The all-u32 cursor contract is `u64((current32-saved32)&0xFFFF)<<4`; this fixture yields zero. [L4]

| Original call | Callee entry | Return site/target | Return SP in the fixture |
| --- | --- | --- | --- |
| `0x100537100`, IA diversity 0x8489 | `0x100523894` | `0x10061AAF4 -> 0x100537104` | `0x680001FFB0` |
| `0x100B0B960`, IA diversity 0x566A | `0x100536E98` | `0x100537124 -> 0x100B0B964` | `0x6800020000` |

The dispatcher restores 12 saved GPRs and advances SP by 0xD60=3,424 bytes. The adapter resets its dynamic reservation from FP, restores six GPRs and its caller SP. Both source prologues use PACIBSP and both returns use RETAB. Call-site bytes, original authenticated target slots, actual saved-link stores and matching signing/return SP establish logical return provenance. Hardware PAC signing/authentication is not executed. Post-indexed LDP updates are included and independently checked. [L5,L6]

The cleanup prologue reuses stack addresses after those returns; saved-link immutability is checked only until each link is consumed. The record R=`0x680002DE90` is also reused: its earlier 32-byte control-0x7A3A epoch becomes the known 20-byte cleanup interface, with owner at +8 and encoded control at +0x10. The address-derived cleanup key decodes that control to 0xBBB3. Old upper bytes of the former pointer field are not interpreted as a new pointer. See the prior [handoff](daemon_record720_handoff_report.md) and [release](daemon_record720_release_report.md) contracts. [L4,L5]

P720 is the owner returned by the retained declared `_malloc(720)` model at `0x100BAE048`; its initializer-defined subordinate pointer at +0x2C0 is zero. The new path therefore reaches the existing owner-free site, rather than a subordinate free. Original slot `0x10109FF30` binds libSystem `_free`, IA diversity 0x46A2, address diversity zero and total addend zero. The call is not executed: native retirement, normal return, allocator internals and any deeper VM activity remain unobserved. No new Mach/IOKit port emission is established. [L8]

## Flag-writer search and evidence boundary

A raw aligned-instruction census covers literal unsigned-immediate LDR64 loads from two relevant SP offsets. A subsequent 16-instruction straight-line scan retains direct stores through the loaded pointer, including simple X-register moves and terminating at control transfer or pointer-register overwrite.

| SP offset | Literal LDR64 sites | Direct-store candidate sites |
| --- | ---: | --- |
| +0x998 | 152 | `0x1006B27AC`, `0x10091007C` |
| +0x1C8 | 75 | `0x100A1BE7C`, `0x100E1A1AC`, `0x100E27374` |

These five stores are conditional candidates: their slots must contain the flag address in the same frame epoch. That equivalence is unproved. The indexed pointer-preparation reference at `0x1002900A0` stores an address into SP+0x998; it does not store the global u32 value. Its flag-address interpretation depends on the expected encoded pool word being selected. SP aliases, pair loads, arithmetic aliases, intervening branches and interprocedural propagation are outside this census. The native writer/reset and external control of the flag remain unknown. [L9]

## Validation and reproducibility

Eight rebuilt source obligations have 16 original/simplified SMT files, all UNSAT. They cover modular account decrement, record output, cursor formula, both epilogues, checkpoint flags and universal flag-class address resolution. Fixed valid component cells and the source-derived phase are explicit premises; these do not prove all-size allocator correctness.

Eight continuous CPU witnesses execute the two retained ancestor journals and each new suffix in one private CPU state. They check 1,135,556 A64 instructions, 66,372 reads, 63,836 writes, 32,596 logical authenticated edges, 16 logical returns and eight logical PAC-sign operations. At each join they compare all 8,016 known bytes, 88 symbolic bytes, 31 register values (including SP) and NZCV. The source prologue/call/return tokens are checked separately from hardware authentication.

Independent instruction cases include 512 UDIV, 512 SDIV, 256 CSINC and 128 pre/post-index writeback cases. They include zero divisors, signed minimum divided by -1, all NZCV combinations for CSINC and relocated stack cells. Fifteen fresh IDB ranges match 2,304 original bytes. Full goal completion, a native flag assignment and execution of host `_free` remain false in the retained checks.

With the interpreter/Z3 environment from the [preceding report](daemon_arena_list_report.md), reproduce the owned files in order:

```sh
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_arena_lifetime.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/daemon_arena_lifetime_symbolic.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_arena_lifetime_refs.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_arena_lifetime.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_arena_lifetime.py
```

Time is O(parent reconstruction visits + new visits + witness visits + text words + solver resources); space is O(one case, private map, census and expression DAGs). Machine quantities are little-endian u32/u64, modular where marked. Byte extents and counters are exact integers. The selected flag classes make progress to the stated API frontier before the 100,000-visit suffix limit.

## Assumption register

| ID | Premise or bounded assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- | --- |
| L1 | Pinned thin image supplies the code and data | Source addresses and contracts | Rehash image; compare fifteen raw IDB ranges |
| L2 | Verified ancestors define the exact checkpoint | New paths and saved links | Rebuild all writes/origins; compare continuous CPU bytes, GPRs and NZCV |
| L3 | Modeled globals are stable during the single-thread suffix; flag classes are predicates over a symbolic word | Conditional control and lifetime | Prove uniqueness under each predicate; establish writer synchronization and read epochs before interleaving claims |
| L4 | Private output and record epochs follow source accesses | Result/cursor and cleanup framing | Audit R+0x1C, X0 read-before-kill, cursor store and 32-byte to 20-byte reuse |
| L5 | Saved-link/prologue/call provenance authorizes logical returns | Two caller continuations | Match original slots, stores, PAC keys and SP; reject overwrite before consumption; allow later frame reuse |
| L6 | Instruction semantics include division edge cases and writeback | Free metadata and stack restoration | Original-opcode CPU cases and all-word epilogue proofs |
| L7 | Retained arena geometry and initializer masks apply | Two releases and coalescing | Audit account sequence and all 80+48 defined bytes at both arena bases |
| L8 | P720 is the retained declared 720-byte allocation | Final ownership request | Match original malloc model and cleanup record; stop before native free |
| L9 | Literal SP loads do not imply frame equivalence | Writer-candidate census | Establish matching frame/slot epochs and pointer propagation before promotion |
| L10 | Native caller/flag state and deeper IPC remain unproved | Overall scope | Require native provenance and actual Mach/IOKit emission before transport claims |

## Bounded continuation targets

| Impact | Next evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Establish pointer/frame provenance for the five writer candidates | Actual flag writers, reset and external control |
| High | Continue after a separately declared normal `_free` return | Cleanup result, caller continuation and later publication |
| High | Recover native caller/initialization epochs and broader certificate inputs | Which conditional paths occur natively and complete name policy |
| High | Establish flag-writer synchronization and transitions between reads | Lifetime behavior under interleavings |
| Medium | Extend release contracts across sizes, node positions and failure states | General allocator invariants beyond the selected round trip |
| Medium | Follow retained data/ownership into original transport calls | Daemon/kext/deeper joins and message/port ownership |

- QG1: Pass for factual technical analysis.
- QG2: Pass; L1-L10 identify dependencies and falsification probes.
- QG3: Pass for this increment; the full interface objective remains active and incomplete.
- QG4: Pass; widths, byte extents, signed arithmetic, endian order and complexity are explicit.
- QG5: Pass within scope; conditional paths, frame epochs, logical PAC and unexecuted native effects are distinct.
- QG6: Pass; source bytes, original fixups/journals, IDB matches, SMT files and independent CPU execution provide provenance.
- QG7: Pass; bounded continuation opportunities are impact-labeled.
