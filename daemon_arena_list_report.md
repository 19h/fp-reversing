# Arena-list selection, block splitting and internal allocation return

The consumer of descriptor `0x1010B5EF0+72` compares its head with the sentinel `D+48`. A retained initializer handover reaches a block split, boundary-word updates, descriptor accounting, shared-gate restoration and an authenticated continuation. This supports a linked-block allocator interpretation. Its payload result is X23; X0 retains the boundary-record address. An explicitly declared empty-list fixture instead reaches `_malloc(5000)` at `0x100477840`. Native descriptor state and the daemon-to-driver join remain unknown. [AL1-AL11]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Nine fresh read-only IDB windows match 2,304 bytes of this image. Automatic IDA analysis annotations are not used as evidence of completed execution. Evidence: [original source, defined-byte handovers and IDB matches](triage_evidence/daemon_arena_list_source.json), [symbolic instruction/effect journals](triage_evidence/daemon_arena_list_symbolic.json), [eight source obligations](triage_evidence/daemon_arena_list_proofs.json), [independent replay and geometry audit](triage_evidence/daemon_arena_list_checks.json), [preservation](triage_evidence/daemon_arena_list_delivery.json), [scoped quality gates](triage_evidence/daemon_arena_list_quality_gates.json).

## Evidence boundary and composition

Each case starts at the unchanged [spill checkpoint](daemon_record720_spill_report.md), before `0x100633F04`. The prior 240-instruction, 39-effect prefix is retained exactly. Its 104 unavailable frame bytes remain independent eight-bit variables, giving 832 unconstrained bits per case. Source execution does not assign values to them. Four materializations per case are separately labeled finite CPU witnesses. [AL2,AL3]

| Component case | Extra defined bytes | Arena ownership declaration | Natural endpoint |
| --- | ---: | --- | --- |
| `sentinel_equal` | 80 descriptor bytes | None; D+72 and D+80 explicitly set to D+48 | Before `_malloc(5000)` at `0x100477840` |
| `initial_arena0` | 80 descriptor + 48 heap bytes | H=`0x6500000000`, extent 90,000 bytes | Before continuation `0x10031F248` |
| `initial_arena1` | 80 descriptor + 48 heap bytes | H=`0x6500100000`, extent 90,000 bytes | Before continuation `0x10031F248` |

The nonempty cases transfer only bytes marked source-written in two retained [arena initializer profiles](triage_evidence/daemon_arena_storage_profiles.json). The other 89,952 arena bytes remain undefined. Reads from undefined arena bytes stop analysis; declared ownership does not initialize storage. The untouched eight-byte descriptor field at +24 is not handed over. The empty self-link state is a structural fixture; no native empty-state producer is established. These compositions do not prove that initialization and consumption occur in the same native epoch. [AL3,AL4]

## Source interfaces and control

```text
retained spill/certificate component
  -> 0x1004A0620: head = [D+72]
       |
       +-- head == D+48 -> 0x100636CF0 -> ...
       |     -> original slot 0x10109FF58: libSystem/_malloc
       |     -> W0=5000, X17=0x6AA4
       |     -> stop before BLRAA at 0x100477840
       |
       `-- head != D+48 -> 0x10063106C -> ...
             -> signed conditional comparison at 0x100552D04
             -> descending byte fill, 1,724 stores
             -> split metadata and descriptor accounting
             -> 0x100634280: restore gate word 0x5D96
             -> reload saved continuation from [SP+0x258]
             -> BRAA at 0x10063428C, modifier 0x7315
             -> stop before 0x10031F248, payload in X23
```

| Source site | Recovered role or contract | Evidence limit |
| --- | --- | --- |
| `0x1004A0624..0x1004A063C` | Equality with sentinel selects table index `0x7164`; inequality selects `0x71DB` | Not a null-pointer test |
| `0x100552D00..0x100552D0C` | `CMP X2,X17; CCMP X2,X16,#0,GT; CSET W17,GE` | Signed 64-bit compare; no universal capacity theorem |
| `0x1006081F8` | Writes one byte per descending loop iteration | Nonconstant fill; primitive identity unknown |
| `0x10058833C..0x1005883E0` | Patches boundary words, auxiliary word and account; sets X23=X0+24 | Component-cell layout and phase inputs are explicit premises |
| `0x100477838` | Zero-extends W0=5,000 bytes into X0 | Stops before API call; allocation outcome unknown |
| `0x100637E00`, `0x100637E04` | Loads original continuation slot and spills it to SP+0x258 | Retained parent journal verifies exact read/store |
| `0x100634284..0x10063428C` | Reloads continuation and logically branches with IA diversity `0x7315` | No hardware PAC execution |
| `0x10031F248` | First instruction stores X23 at SP+0x1A8; next compares X23 with zero | Static consumer evidence; continuation body not executed here |

For arbitrary u64 operands A=X2, B=X17 and C=X16, the comparison fragment yields `W17 = (A <=signed B || A >=signed C) ? 1 : 0`. The fallback immediate NZCV=0 makes GE true when GT is false. A source proof and 512 independent CCMP flag cases, including all 16 incoming NZCV combinations, check this distinction. Its higher-level fit/rejection meaning remains bounded by the observed path. [AL5]

The fallback pointer is an original authenticated bind: slot `0x10109FF58`, raw word `0xC0086AA40000008C`, libSystem `_malloc`, IA diversity `0x6AA4`, address diversity zero, total addend zero. The continuation is an original authenticated rebase from slot `0x10103B7C0` to `0x10031F248`, IA diversity `0x7315`, address diversity zero. Source provenance is preserved through the spill; a numerical code address alone is not treated as sufficient pointer provenance. [AL6,AL7]

## Measured block geometry and writes

Let H be the declared arena base, N=90,000 bytes, M=`0x5E878C613B8123EA`, and D=`0x1010B5EF0`. The two nonempty cases agree on these byte extents:

```text
T = N - 24 bytes            = 89,976 bytes = 0x15F78 bytes
 d = observed account debit =  1,676 bytes =   0x68C bytes
R = T - d                  = 88,300 bytes = 0x158EC bytes
B = H + R                  boundary-record address
P = B + 24 bytes           = H + 0x15904 bytes; returned in X23
T - (R + 24 bytes)         =  1,652 bytes
```

These are exact integer calculations for the two retained initializer cases. The 1,652-byte geometric gap is not asserted to be the general allocator capacity or a requested 720-byte record size. X0=B at the boundary. No ordinary C return-in-X0 convention is inferred for this internal flattened-control interface. [AL8]

| Source writer | Address | Stored value, modulo 2^64 unless u32 |
| --- | --- | --- |
| `0x1006081F8` | Descending `[H+R-48, H+T)` | 1,724 nonconstant bytes, before metadata patches |
| `0x10058835C` | H+8 | M+R = `0x5E878C613B827CD6` |
| `0x100588378` | B | M+R |
| `0x100588378` | B+8 | M-d = `0x5E878C613B811D5E` |
| `0x1005883B4` | B+16 | Auxiliary word; exact per-case expression in audit |
| `0x1005883CC` | H+T | M |
| `0x1005883D8` | D+40 | `0x1AA4071F0801765B` + d = `0x1AA4071F08017CE7` |
| `0x100634280` | `0x1010B5DE0` | u32 `0x5D96` |

The fill interval is 1,724 bytes because `(T - (R-48)) = d+48`. Metadata writes overlap part of that fill. Its journal is not a final all-payload layout. The auxiliary word depends on an eight-bit frame value and u32 phase arithmetic; the source-local proof retains both inputs. Its semantic name and any allocator library/version identity are unknown. [AL8,AL9]

The gate restoration is a plain four-byte STR. Prior evidence identifies acquisition through CASAL; this increment does not infer atomic release semantics for every architecture or prove native concurrent exclusion. No source call to Mach, IOKit or the kext is reached. New incoming/outgoing port rights, port creation, message IDs and new emission sites are therefore unestablished in this increment. [AL10]

## Verification and reproducibility

Eight source obligations have retained original and simplified SMT-LIB files, all independently rebuilt and checked UNSAT. They cover arbitrary-u64 head equality, the signed conditional compare, fallback size/modifier, arbitrary-u64 continuation spill/reload, modular boundary/account words, arbitrary-u32/u8 auxiliary word, X23/X0 distinction and gate store. The metadata theorem uses fixed, disjoint component cells; it does not prove arbitrary pointer aliasing, arena ownership, all input sizes or linked-list invariants. [AL5-AL9]

The three source journals contain 296, 64,295 and 64,295 executed instruction visits. The two nonempty paths stop before executing the continuation; the empty case stops before its call. Independent Unicorn replay checks original instruction bytes, computed addresses, read values, write values, final GPR expressions and logical authenticated edges for four opaque-byte materializations per case. The twelve witnesses check 501,568 A64 instructions, 28,260 reads, 27,944 writes and 13,976 logical authenticated edges. Materializations do not change the symbolic source-defined-byte masks. PAC instructions are handled as checked logical transfers, not CPU authentication. [AL2,AL6,AL7]

Reproduce from this directory using the retained local environment:

```sh
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/capture_daemon_arena_list.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/daemon_arena_list_symbolic.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_arena_list.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_arena_list.py
```

The capture validates retained IDB bytes against the original image; obtaining fresh windows requires the connected IDA database. Time is O(retained handover bytes + executed instruction visits + witness visits + solver resources); space is O(one source case, expression DAGs, mapped pages and retained journals). Loops are bounded by a 100,000-visit analysis limit; accepted cases reach their stated natural frontier before that limit. Exact checks and witness totals are recorded in the linked JSON. All amounts above are bytes, addresses are virtual addresses, and machine arithmetic is little-endian u32/u64 with modular overflow. Signed comparisons are marked explicitly.

## Assumption register and falsification probes

| ID | Assumption or bounded premise | Dependent results | Stress test or falsification probe |
| --- | --- | --- | --- |
| AL1 | Retained thin image matches relevant IDB source | Source sites and decoded contracts | Rehash image; compare all nine raw windows |
| AL2 | Parent checkpoint contains only its 4,294 defined bytes and original GPRs | All three symbolic successors | Rebuild capture; compare 240 steps and 39 effects exactly; keep 104 variables |
| AL3 | Initializer source-written bytes may be handed over as a component input | Nonempty allocation cases | Verify masks, omit D+24 and unknown heap bytes; relocate H by 0x100000 |
| AL4 | Empty sentinel self-links are explicitly declared | Fallback reachability | Treat as fixture only; locate actual empty-state producer before native claim |
| AL5 | Full NZCV semantics include signed GT and GE | Guard selection | Rebuild symbolic theorem; replay actual CCMP for all 16 flag inputs and corner/random words |
| AL6 | Imported pointer provenance follows original bind slot | `_malloc(5000)` frontier | Decode raw word, library, addends and modifier; stop before call |
| AL7 | Continuation originates in original rebase and survives stack spill | Logical tail continuation | Verify parent read/store bytes and slot; prove generic spill/reload; check raw diversity |
| AL8 | Selected 90,000-byte fixtures define the measured geometry | Split/accounting result | Independently replay both bases, audit all fill addresses and late writes |
| AL9 | Metadata proof cells are fixed, disjoint and phase inputs explicit | Parameterized header/auxiliary formula | Rebuild local source lift; no arbitrary-alias or all-size inference |
| AL10 | Gate store and private arena execution do not establish transport | IPC and concurrency limits | Trace continuation and native callers; require original transport emission before claiming a new port |
| AL11 | Component composition is distinct from native continuity | Allocator interpretation and scope | Establish runtime D epoch, actual caller and successful return-to-consumer chain |

## Bounded continuation opportunities

| Impact | Observation or next evidence target | Specific uncertainty resolved |
| --- | --- | --- |
| High | Continue at `0x10031F248` with X23 as the output operand | Actual allocated-object consumer and eventual registry/driver join |
| High | Establish a native producer/epoch for current D+72, D+80 and gate state | Whether selected initializer-to-consumer composition occurs natively |
| Medium | Trace undersized-block, next-node and empty-fallback return paths | Full traversal, coalescing/reuse and allocation-failure semantics |
| Medium | Recover byte-fill seed/recurrence consumers and auxiliary-word checks | Whether metadata protects allocator state and how fill is subsequently used |
| Low | Compare a second source image using the recovered structural contracts | Cross-version applicability without assigning an unsupported library name |

## Quality gates

- QG1: Pass for this factual technical increment.
- QG2: Pass; AL1-AL11 state premises, dependent results and falsification probes.
- QG3: Pass for this increment; routine roles, internal ABI, data/control flow and port-evidence limits are reported. The full cross-layer goal remains incomplete.
- QG4: Pass; byte extents, modular widths, signed comparisons, endian order and complexity are explicit and reproducible.
- QG5: Pass within stated scope; empty fixture, retained initializer handover, symbolic unknowns, finite witnesses and native state are distinct. Unresolved native behavior is recorded as unknown.
- QG6: Pass; original binary, authenticated fixups, source-byte IDB matches, source proofs and independent A64 replay provide provenance.
- QG7: Pass; continuation opportunities are bounded and impact-labeled.
