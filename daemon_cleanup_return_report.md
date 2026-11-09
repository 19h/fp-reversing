# Normal cleanup return and the outer result-object boundary

Under a separately declared normal `_free` return, all four retained arena/flag cases reach `0x10095F074: STR W23,[X0,#0x10]` after 133 source visits. W23 is `0x74C29F37`. X0 comes from eight unavailable bytes at F+0x24F8; the source execution stops before the store without assigning that word a pointer value. This establishes a prospective u32 result field at offset 16 bytes and a minimum nonwrapping accessed extent of 20 bytes. Native pointer provenance, caller reachability and any connection to Mach/IOKit remain unknown. [CR1-CR10]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [checkpoint reconstruction](triage_evidence/daemon_cleanup_return_source.json), [four symbolic continuations](triage_evidence/daemon_cleanup_return_symbolic.json), [original contracts and candidate census](triage_evidence/daemon_cleanup_return_contracts.json), [seven source obligations](triage_evidence/daemon_cleanup_return_proofs.json), [independent validation](triage_evidence/daemon_cleanup_return_checks.json), [preservation](triage_evidence/daemon_cleanup_return_delivery.json), [scoped quality gates](triage_evidence/daemon_cleanup_return_quality_gates.json).

## Source continuity and output channels

```text
retained lifetime paths: flag==0 / flag!=0, two arena bases
  -> before original _free(P720), PC=0x1001C6100
  -> assume normal API return; forget scalar volatile state
     retire P720; forget modeled stack bytes below API-entry SP
  -> form cleanup raw word 0x364C5349
  -> write u32 R+0 at 0x100270AC4
  -> restore ten saved GPRs; SP += 96 bytes
  -> logical RETAB -> 0x100BE0C54
  -> form outer raw word 0x74C29F37
  -> spill/reload u32 F+0x393C -> W23
  -> load opaque u64 F+0x24F8 -> X0
  -> authenticated logical edge -> 0x10095F074
  -> STOP before STR W23,[X0,#16]: address is nonunique
```

F=`0x6800020000`, R=`0x680002DE90`, P720=`0x6800070000` are retained component addresses. P720 originated in the earlier declared `_malloc(720)` return; these addresses are not native observations. The [preceding lifetime report](daemon_arena_lifetime_report.md) closes the two arena releases and reaches the pre-free checkpoint. This increment reconstructs its actual writes, saved-link provenance, original authenticated slots, GPRs and NZCV. It does not replace that checkpoint with a fresh function-entry fixture. [CR1,CR2]

| Interface or source site | Established effect | Evidence boundary |
| --- | --- | --- |
| `0x1001C6100`, slot `0x10109FF30` | libSystem `_free(P720)`, IA diversity 0x46A2, address diversity 0, addend 0 | Normal return declared; native API unexecuted |
| `0x1001C6108..0x1001C610C` | Construct W8=`0x364C5349` | Raw cleanup word; no semantic status name |
| `0x100270AC4` | Store u32 `0x364C5349` at R+0 | Cleanup-record epoch; distinct from earlier R+0x1C output |
| `0x100270AC8..0x100270ADC` | Restore X19-X26, X29, X30; SP += 0x60 | Ten original saved GPRs; arbitrary saved u64 proof |
| `0x100270AE0` | Logical RETAB to `0x100BE0C54`, SP=F | Original call `0x100BE0C50`, entry `0x100435B9C`, PACIBSP key IB |
| `0x100952AA8..0x100952AAC` | Construct W19=`0x74C29F37` | Outer result domain; consumer unknown |
| `0x10095129C`, `0x100B90EC8` | Write/read u32 F+0x393C; zero-extend into X23 | Source-defined spill and reload |
| `0x100B90EF4` | Load u64 F+0x24F8 into X0 | All eight bytes unavailable; no pointer concretization |
| `0x10095F074` | Prospective u32 store to X0+16 | Not executed in the continued source paths |

The cleanup epilogue's return target, SP and IB-signing provenance match the retained call/prologue. This is logical pointer-authentication bookkeeping; hardware signing or authentication is unobserved. The source returns through the stack-saved caller link, so no `_free` return value or surviving volatile LR is required. [CR4,CR5]

For comparison only, applying the previously recovered [XOR status representation](daemon_iokit_callers_report.md) gives `0x74C29F37 XOR 0x8B3DC651 = 0xFFFF5966`; signed32 conversion gives `4,294,924,646 - 4,294,967,296 = -42,650`. The consumer of this output object is unresolved. Arithmetic compatibility does not establish that consumer's decoder, semantic error identity, or a transport join. [CR8]

## API-return projection and forgotten memory

The model introduces 19 arbitrary 64-bit scalar values for X0-X17 and X30, plus four arbitrary NZCV bits: `19*64+4 = 1,220` bits. X19-X29 and SP are retained. The consulted AAPCS64 specifies these callee-saved registers and undefined condition flags across public interfaces; LR is conservatively forgotten. SIMD/FP state is outside the scalar projection and is not consumed by the explored interval. The consulted revision is 2026Q3; it is not a build-version attribution for this image. [AAPCS64, sections 6.1 and 6.4](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst). [CR3]

The API is `void free(void *)`; its documented operation deallocates the supplied allocation. Here that behavior is a model premise, not an observed allocator effect. The model removes all 161 previously defined bytes from the 720-byte owner and rejects subsequent accesses to the retired range. It also forgets defined bytes in `[0x680001C000,0x680001FFA0)`, below API-entry SP: 3,642 bytes in each zero-flag case and 3,686 bytes in each nonzero-flag case. Forgetting represents loss of usable knowledge; it does not assert clearing, zeroization or the API's actual write set. [Apple malloc/free manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/malloc.3.html). [CR3,CR6]

The new 133-visit interval reads neither forgotten region. It also has no read of a modeled caller-saved register or NZCV before a source definition. Self-composition with independently renamed ABI variables proves independence of the accepted memory effects, observed branch/access addresses, frontier address and W23. Unused final volatile registers may remain arbitrary. This is a source-component result under the normal-return and preserved-memory premises. [CR3,CR6]

There are 112 unconstrained frame-byte variables: 104 inherited variables plus the eight newly encountered F+0x24F8 bytes. The separate u32 runtime flag remains symbolic under exhaustive stable zero/nonzero predicates. No source definition is supplied by the finite CPU witness values. [CR2,CR7]

## Output-base producer census

An aligned scan of the original text selects exactly the unsigned-immediate `STR Xn,[SP,#0x24F8]` encoding. It finds seven candidates, five using X0.

| Original store PC | Spilled register | Same frame/epoch as the consumer |
| --- | --- | --- |
| `0x10027147C` | X8 | Unknown |
| `0x10064CEA8` | X0 | Unknown |
| `0x10075E378` | X12 | Unknown |
| `0x10097C778` | X0 | Unknown |
| `0x100A2E3A0` | X0 | Unknown |
| `0x100B2CF64` | X0 | Unknown |
| `0x100B74138` | X0 | Unknown |

The all-u64 spill/reload proof uses `0x10064CEA8` and the observed consumer as isolated components with a shared valid frame cell. That theorem proves their transfer semantics under its premise; it does not prove they execute in one frame epoch. Pair stores, SP aliases, register-offset stores, intervening SP movement and interprocedural flow are outside the literal census. The actual producer is unknown. [CR9]

The new sink is adjacent to a stack-canary check and a larger epilogue in the raw IDA range. Those unexecuted instructions are a structural lead toward the outer caller, not established normal-return behavior. The next store is retained as a boundary because its destination lacks a source definition. [CR9,CR10]

## Validation and reproducibility

Seven rebuilt obligations produce 14 original/simplified SMT files, all UNSAT. They cover the raw cleanup word, ten-register/96-byte epilogue, outer word-to-W23 transfer, generic spill/reload, output-field width and surrounding bytes, opaque address formula and scalar ABI noninterference. Fixed valid cells and nonwrapping object extent are explicit component premises. [CR4,CR5,CR8]

Eight independent Unicorn witnesses replay each retained lifetime suffix and the new continuation in one private CPU state. They check 121,980 A64 instructions, 8,188 reads, 7,204 writes, 3,804 logical authenticated edges, 24 logical returns, eight logical signs and eight declared API returns. Each API-entry join checks every known byte (8,044 or 8,270), all 92 symbolic memory bytes, 31 GPR values including SP, and NZCV. The initial checkpoint's symbolic expressions are materialized directly; original variable-origin addresses are not overwritten indiscriminately. These witnesses begin at the frozen pre-lifetime checkpoint; earlier ancestors retain their preceding validation coverage.

The private CPU poisons the retired owner and mapped stack bytes below API-entry SP and varies the 1,220 ABI bits across witnesses. Newly discovered frame bytes receive finite values only in that independent validation. The continued path still stops before the opaque store. Sixteen separately owned output objects exercise the original store opcode at relocated valid bases and varying u32 words, confirming that only bytes +16 through +19 change. Those isolated objects do not resolve the original output pointer. Five fresh read-only IDA ranges match 960 original bytes. [CR1,CR2,CR6,CR8]

Reproduce with the pinned interpreter and Z3 runtime used by the preceding reports:

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_cleanup_return.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/daemon_cleanup_return_symbolic.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_cleanup_return.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_cleanup_return.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_cleanup_return.py
```

The IDA JSON is a retained read-only capture, not generated by the offline commands. Capture/replay time is O(parent visits + effects + expression DAGs); census time is O(text words); solver resources are additional. Space is O(one case, private CPU map and expression DAGs). Values use little-endian u32/u64; address arithmetic in source expressions is modulo 2^64. Byte counts and observed visit counts are exact integers. General pointer validity and canonicality are not proved.

## Assumption register

| ID | Premise or bounded assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- | --- |
| CR1 | Pinned thin image and retained original fixups are authoritative | All source PCs, opcodes and bindings | Rehash image and all dependencies; compare five raw IDA ranges |
| CR2 | Frozen lifetime journals define the current API-entry checkpoint | New source continuity and owner identity | Reconstruct writes/origins; continuous CPU comparison of all bytes, GPRs and NZCV |
| CR3 | `_free` returns normally under the scalar ABI; relevant caller-frame and immutable source bytes remain valid | Post-API continuation and ABI independence | Vary volatile GPR/NZCV; inspect native return and relevant memory before native claims |
| CR4 | Original saved-link/prologue/call provenance authorizes logical RETAB | Return to 0x100BE0C54 | Verify IB key, saved target, original slot and matching SP; hardware PAC remains unknown |
| CR5 | Original scalar/load/store semantics apply to fixed valid component cells | Epilogue, spills and output-field contracts | Rebuild SMT obligations and independent original-opcode CPU checks |
| CR6 | The full declared 720-byte owner is retired and lower stack knowledge is forgotten | Absence of dependence on deallocated/inactive storage | Reject source accesses to retired bytes; poison private CPU regions and audit all new effects |
| CR7 | Runtime flag/global epochs remain stable during the single-thread source suffix | Two exhaustive flag-class paths | Establish actual flag writer synchronization and transitions before interleaving claims |
| CR8 | Output base is arbitrary; valid writable nonwrapping cell is only an isolated component premise | Prospective u32 field at +16, minimum extent 20 | Keep all eight source bytes symbolic; test isolated relocations; obtain real producer and consumer |
| CR9 | Equal SP immediates do not establish frame/epoch equivalence | Seven candidate spill sites and structural caller lead | Recover SP deltas, frame roots and source control paths from each candidate to the load |
| CR10 | Native outer caller, output decoder and Mach/IOKit join are unknown | Overall scope and port classification | Require original call/record/transport continuity and actual right/emission evidence |

## Bounded continuation targets

| Impact | Next evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Recover frame and control provenance for the seven F+0x24F8 candidate stores | Actual output base, its owner and external caller |
| High | Follow the output object through its consumer and original transport adapter | Whether this result reaches Mach/IOKit or stays private |
| High | Establish native allocation, normal free return and runtime-flag epochs | Native occurrence of the retained component paths |
| Medium | Recover the adjacent canary/outer epilogue and saved caller-link provenance | Outer function boundary and return contract |
| Medium | Match the output word's actual consumer decoder | Status-domain equivalence beyond arithmetic compatibility |

- QG1: Pass for factual technical analysis.
- QG2: Pass; CR1-CR10 name premises, dependencies and falsification probes.
- QG3: Pass for this increment; the broad interface objective remains active and incomplete.
- QG4: Pass; byte extents, integer widths, endian order, modular arithmetic and complexity are explicit.
- QG5: Pass within scope; declared API return, arbitrary pointer, finite witnesses, candidate frame joins and native effects are distinguished.
- QG6: Pass; original bytes/fixups, retained journals, IDA readback, SMT, independent CPU execution and primary ABI/API sources provide provenance.
- QG7: Pass; continuation opportunities and unresolved architectural joins are impact-labeled.
