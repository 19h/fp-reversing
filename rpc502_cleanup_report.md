# RPC502 mapping cleanup: argument codec, mode and descriptor invalidation

The different mapping lifetimes now have a source-level explanation. Both selected callers invoke helper `0x100444704`, using a reused 24-byte argument prefix. The supplemental-file caller stores mode byte0 and selects close-only cleanup. The primary-file caller stores mode byte1 and selects unmap-then-close. The helper subsequently writes FD=-1 regardless of the modeled close result. Native resource retirement and complete mapping ownership after return remain unknown.

This extends the [resource ledger](rpc502_ownership_report.md) from observed API sequences to their original constructors and dispatch fields. It adds five local scalar proofs, an alignment counterexample, four source-built caller observations and 24 original helper fixtures with 24 distinct fresh replays. It adds no complete worker execution or native API execution.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| C1 | The supplied daemon slice is the intended implementation | Addresses, source instructions, tables and codecs | Rehash original thin/universal bytes and UUID; attest the live slice and IDB independently |
| C2 | Frozen complete worker journals preserve the declared API/PAC/heap/serial-lock execution | Four original caller records and selected targets | Compare retained/fresh canonical results and current-source journal hashes; native predecessors remain separate |
| C3 | The cleanup argument address is aligned to8 bytes | Primary constructor/consumer codec equivalence and plain mode-bit interpretation | Prove the aligned domain, check actual `SP+0x10cb8`, retain a 4-byte-aligned algebraic counterexample |
| C4 | The decoded base dispatch index is `0x6922` in these callers | Close-only versus unmap-then-close target mapping | Recompute caller state/addends, compare helper W27 and original table entries; other base indices remain unknown |
| C5 | The 24-/32-byte analytical prefixes are readable and nonaliasing in the declared helper fixtures | Reads, writes and API arguments | Guard fixture extents and compare all before/after bytes; complete native allocation/type provenance remains separate |
| C6 | Explicit close/munmap results and PAC bypass apply to the isolated helper fixtures | Failure controls and descriptor invalidation | Reexecute all original helper instructions, reject other imports and compare exact requests; no native effects are inferred |
| C7 | Contiguous source constructor execution connects its fixed stores to the immediately following helper call | Mode0/1 and argument-pointer provenance | Require every original instruction from constructor entry through call in sequence; compare passed pointer, SP, live decoded index and target |
| C8 | Finite fixtures and local proofs have their stated domains | Size forwarding, status handling and lifetime interpretation | Review other callers, statuses, aliases and native resource histories; do not infer a whole-program destructor or leak from this helper |

[Contracts](triage_evidence/rpc502_cleanup_contracts.json) retain five original spans, 11 pointer/import records, original dispatch targets, five SMT obligations and the alignment counterexample. [Independent checks](triage_evidence/rpc502_cleanup_checks.json) retain original caller summaries, current-source journal hashes and replay counts. [Helper profiles](triage_evidence/rpc502_cleanup_profiles.json) and [distinct fresh replays](triage_evidence/rpc502_cleanup_replays.json) contain exact API requests, source stores and before/after records. [C1-C8]

## Partial cleanup argument ABI

Let P be the argument pointer and p=`low32(P)`. All key arithmetic below is modulo `2^32`. The helper reads only the listed fields; the first8 bytes are not initialized by these cleanup constructors and are not assigned a cleanup meaning. The observed prefix occupies24 bytes including alignment padding. This is not a complete public C prototype. [C3-C5,C7]

| Argument offset | Extent, bytes | Source reader | Established role |
| --- | ---: | --- | --- |
| 0..7 | 8 | No read by the recovered cleanup helper | Reused storage; cleanup meaning unknown |
| +8 | 8 | `0x100444880` | Pointer to a mapping-result record |
| +16 | 4 | `0x100444870` | Address-keyed base dispatch index |
| +20 | 1 | `0x100444878` | Byte whose decoded low bit selects the cleanup mode |
| +21..23 | 3 | No read by the recovered cleanup helper | Padding/other role unknown |

The consumer key is:

```text
H(p) = ((((0x3c642ede OR (p << 1)) - p + 0xe1cde891)
          XOR 0x885c4f7d) * 0x592e2f77) mod 2^32

base  = stored_u32_at_16 XOR H(p)
mode  = (stored_byte_at_20 XOR H(p)) AND 1
index = base XOR (mode * 0xd323)
```

Original instructions establish these operations; the source-pinned scalar lift proves `H(p) AND 1 = p AND 1` for every32-bit p. For an aligned argument, mode is therefore the stored byte's low bit. The other seven byte bits do not affect this selected mode. [C3,C4]

| Actual caller | Original argument stores | Observed stored byte | Decoded base | Selected index | Original target |
| --- | --- | ---: | --- | --- | --- |
| Supplemental-file cleanup, call `0x1007484d4` | Pointer `0x100748454`; index `0x100748460`; byte `0x100748450` | 0 | `0x6922` | `0x6922` | `0x1001f1988`, close-only |
| Primary-file cleanup, call `0x100723bbc` | Pointer `0x100723b40`; index `0x100723b54`; byte `0x100723b48` | 1 | `0x6922` | `0xba01` | `0x1003aae74`, unmap then close |

Both callers pass `SP+0x10cb8`; their observed address is `0x70077cd8`, hence it is8-byte aligned and has residue8 modulo16. The same address held other protected records earlier. Its earlier fields must not be assigned this later cleanup layout. The helper receives distinct mapping-result pointers for the two file epochs. [C2,C3,C7]

The original pointer-table base is `0x101039ef0`. Index `0x6922` uses slot `0x10106e800`; index `0xba01` uses slot `0x101096ef8`. Their original chained targets are the two cleanup continuations above. Hardware authentication of those pointers is not tested. [C1,C4,C6]

## Constructor equivalence and alignment boundary

The supplemental constructor uses a different-looking expression:

```text
S(p) = ((((0x0edb92fa OR (p << 1)) - p + 0xf8923683)
          XOR 0x9103916f) * 0x592e2f77) mod 2^32
```

The primary constructor uses:

```text
R(p) = (((p - 2*(p AND 0x141fcb58) + 0x941fcb5c)
          XOR 0x0271934e) * 0x592e2f77) mod 2^32
```

Source-pinned SMT checks prove `S(p)=H(p)` for every32-bit p, and `R(p)=H(p)` when `p AND 7=0`. The primary identity is not valid for arbitrary addresses: p=4 gives H=`0xa96afc3a` and R=`0x05bf6f62`. This is an algebraic falsification of an overbroad codec claim, not an observed native caller. Actual constructor addresses satisfy the proven alignment domain. [C3]

Each caller XORs its constructor key with a state-derived base index. Independent live branch snapshots give the same decoded value `0x6922` in all four observed cleanup calls. The fifth proof establishes the selected dispatch expression for all aligned32-bit p and all256 mode-byte values, under that base-index condition. It does not classify arbitrary encoded records or other helper callers. [C2-C4,C7]

## Mapping record, API requests and postconditions

The pointer at argument+8 refers to the earlier mapping-result prefix. The unmap continuation loads the raw mapping and encoded extent together at `0x1003aae74`, then decodes the extent by XOR with `0xb3800b93c8bcf32b`. The operands and XOR are64-bit. It requests `_munmap(mapping, extent)` at `0x1003aaef4`, then joins close-only continuation `0x1001f1988`. [C1,C5,C6]

| Mapping-result field | Offset | Extent, bytes | Cleanup use / postcondition |
| --- | ---: | ---: | --- |
| Descriptor | 0 | 4 | Loaded into W0 at `0x1001f19ac`; set to `0xffffffff` after close |
| Padding | 4 | 4 | Unchanged in all24 fixtures |
| Raw mapping pointer | 8 | 8 | Supplied as unmap X0 only in selected mode1; field remains unchanged |
| Encoded extent | 16 | 8 | Decoded into unmap X1 only in selected mode1; field remains unchanged |
| Auxiliary qword | 24 | 8 | Unchanged in all24 fixtures; cleanup meaning unknown |

```text
cleanup argument -> decode base/index and low mode bit
                     |
                     +-- mode0 ----------------------+
                     |                               |
                     +-- mode1 -> munmap request ----+-> close request
                                                        -> descriptor = -1
                                                        -> return
```

Close is requested at `0x1001f19c4`. The following two instructions load constant-1 and store it at mapping-record+0 (`0x1001f19c8`/`0x1001f19cc`). They do not test the close result. Similarly, the unmap continuation reaches close without a result-dependent local branch. These statements concern requested control flow and record mutation, not successful resource retirement. [C1,C6]

The24 isolated fixtures cover two aligned argument addresses, extents64 and `0x100000009` bytes, eight mode-byte values, and eight controls with modeled failed close and/or unmap. The larger extent is a scalar ABI input; no mapping of that size is created. All24 fixtures request close and invalidate the descriptor. Fourteen request unmap first. Both argument records and mapping fields other than the four descriptor bytes remain byte-identical after return, including failure controls. [C5,C6,C8]

Consequently the supplemental mapping's absence from the worker's unmap ledger follows from an original close-only selection. This establishes the local mechanism, while retention, transfer, encoded aliases, enclosing cleanup and native lifetime remain unknown. The helper's retained pointer fields do not alone prove later use or invalid reuse. Its return register is not assigned a public status meaning. [C2,C7,C8]

## Validation and continuation

The verifier freshly reruns five SMT queries, reads five original spans and11 pointer/import records, and independently executes all24 helper fixtures again. The fresh helper corpus contains4104 original-source visits and186 distinct instructions. It also rechecks the two frozen complete retained/fresh worker pairs,29969824 source visits in each corpus, four contiguous caller constructors and four selected helper targets. No new complete worker execution is claimed.

Reproduction:

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_cleanup.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_cleanup.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_cleanup.py
```

The helper has O(1) local instruction work and space, excluding modeled/external API costs. Journal verification is O(V+E+B+F) for visits, events, source bytes and fixups, with space bounded by the largest case/journal. Each solver has a60000 ms timeout. Record extents are bytes, codecs are modulo `2^32`, mapping-length forwarding is64-bit, and descriptor invalidation is32-bit. No native API, target process or IDB is executed or changed.

[Preservation](triage_evidence/rpc502_cleanup_preservation.json) checks1147 prior artifacts, permitting only the six reporting/index/aggregator updates. [Scoped quality gates](triage_evidence/rpc502_cleanup_quality_gates.json) include fresh source identity, producer/dependency pins, packet-independent helper checks and local report links. Other published analytical files remain frozen.

| Impact | Remaining requirement | Further evidence |
| --- | --- | --- |
| High | Owner of the close-only supplemental mapping after return | Complete encoded references, wider caller/global state, teardown and native VM lifetime |
| High | Accepted worker output and actual transport pairing | Native daemon/kext/provider/port identity, accepted processing and request/reply/resource observation |
| Medium | Other callers/base indices of the cleanup helper | All incoming edges, constructor states and caller-specific readable/alias/alignment preconditions |
| Medium | Failure-lifetime policy outside this local helper | Native API results, descriptor reuse, outer retry/cleanup and concurrent state |

QG1: factual analysis. QG2: C1-C8 assumptions and falsification probes. QG3: cleanup-ABI increment covered; the broad interface goal remains active. QG4: byte/u32/u64 domains, alignment, formulas and complexity explicit. QG5: close-only versus unmap/close, local invalidation versus retirement, and isolated helper versus complete worker/native evidence distinguished. QG6: original source/fixups, source-built caller state, exact record writes, fresh helper replay and fresh bounded proofs. QG7: impact-bounded continuation table above.
