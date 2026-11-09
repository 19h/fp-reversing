# RPC502 supplemental files: cursors, protected argument records and fallback

This increment extends the [sidecar parser](rpc502_parser_report.md) through its source-built `.v5.supf` open. Original daemon instructions establish two variable-offset file layouts, a shared address-keyed argument interface, a `.v4.supp` fallback, and bounded cleanup behavior. The 348 retained whole-worker cases include every possible first-byte value in one fixed environment. Fifty-three cases call the original protected carrier and return its encoded rejection. Successful protected processing, a subsequent daemon/kext transaction, and native resource behavior remain **unknown**. The broader interface investigation remains active.

The complete source contracts are in [contracts](triage_evidence/rpc502_supp_contracts.json); original instruction visits, API declarations, file reads, source stores and call records are in [profiles](triage_evidence/rpc502_supp_profiles.json). [Independent verification](triage_evidence/rpc502_supp_checks.json) includes a complete fresh worker replay of every case. Published earlier producers and evidence remain frozen; [preservation](triage_evidence/rpc502_supp_preservation.json) checks the preceding 953-artifact snapshot, with only six permitted reporting/aggregator changes.

## Assumption register and falsification probes

| ID | Assumption / explicit limitation | Dependent findings | Stress test or falsification probe |
| --- | --- | --- | --- |
| S1 | The selected source is the supplied arm64e slice, not an attestation of a running process or current IDB. | Every address and source-derived result below. | Rehash the thin image and universal image; compare the complete selected slice; independently decode each retained opcode/fixup and metadata range. |
| S2 | Original worker entry `0x100422d48` runs with the frozen inherited RPC502 filename, PID, QoS, CSR, BootPolicy, VMM, CoreKE and stack-seed fixtures. The first `.sinf` contains BE32 header 1 and selector 1, with 64 declared bytes. | Reachability, filename construction, header classifier and all finite outcomes. | Change those actual upstream inputs and repeat without overriding parser PC, stack, branch gates or register state. |
| S3 | File descriptors, metadata, mappings, allocation, errno, serial once/locks and cleanup results are explicitly modeled. No target API executes natively. | File bytes, API continuations, ownership journals and failures. | Replace one declared API result/output at its actual boundary; compare source reads and cleanup. Verify with actual OS facilities before asserting native acceptance or resource loss. |
| S4 | PAC operations are explicitly bypassed by the inherited private execution engine. | Indirect-call reachability under the private model. | Hardware authentication and a native end-to-end call can falsify feasibility. Exact original branch bytes/targets remain independently inspectable. |
| S5 | Exhaustive first-byte coverage means all 256 values with a 256-byte zero-filled remainder in this inherited environment. | The five accepted parser classes and their fixed-context rejection results. | Vary remaining bytes, environment and predecessor state; the sweep does not quantify those domains. |
| S6 | Compact cursor equations describe the observed source paths; the extent proof uses unsigned modulo-2^32 arithmetic and stated frame predicates. | File layout, bounds and record formulas. | Test wraparound counts, independent size64/count32 axes, all predecessor guards and complete logical extents. Do not substitute an unbounded integer sum. |
| S7 | Observed record accesses cover offsets 0 through 43. They do not establish total object size, all fields, or the semantic role of field +28. | The partial internal ABI and candidate routine roles. | Trace additional consumers, especially +28, valid body records, successful returns and actual upstream constructors. |
| S8 | A source-path mapping/FD left live in a private fixture is an ownership observation, not a native leak demonstration. | Cleanup findings. | Resolve every transfer, global cache, alternate exit and native lifetime; compare successful processing and failure histories. |
| S9 | Prior analysis memories supplied source-pinning and parser-state preservation guidance. New target claims are verified against current original files. | Method only. | Re-read original source rather than importing semantic labels from older method-26 analysis. |

## Source identity and control-flow boundary

The thin image `/Users/___/Downloads/zut/fairplayd.arm64e` is 17668912 bytes, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. It equals the entire arm64e slice at file offset 3407872 of `/Users/___/Downloads/fpx/fairplayd`, SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`. The verifier rechecks those byte identities. The [prior current-file identity record](triage_evidence/rpc502_parser_source_identity.json) and [IDA context](triage_evidence/rpc502_parser_ida_context.json) remain unchanged. Live IDA bytes are unverified because the bridge was unavailable; the file evidence is sufficient for this increment. [S1]

Every original guest opcode is compared with original file bytes at each visit. Retained visit streams are independently hashed and decoded. No parser entry, branch predicate, stack field, instruction, register or file byte is changed after entry to force a desired path. Model outputs are recorded at the actual external API boundary. Original compiler metadata assigns the 28 bounded source spans to 17 physical compiler ranges; this is not proof that each large physical range is one semantic routine or a conventional call graph. [S1-S4]

```text
original RPC502 worker
  -> .sinf mapping/copy/parser -> retire 56-byte parsed record
  -> source filename .v5.supf -> open/stat/mmap
       | open fails, errno=2 -> source filename .v4.supp -> next open boundary
       | other tested errno -> worker error
       ` mapped file -> first byte -> one of two cursor layouts
            -> construct partial internal argument record
            -> 0x1009d53cc wrapper -> 0x10099ab1c protected carrier
            -> direct mapped-body byte reads -> encoded error at record+32
  -> second FD close -> first copy free -> first map unmap -> first FD close
  -> QoS restoration -> worker return
```

## File layout and exact reads

`BE32(o)` denotes four big-endian bytes at file offset `o`. `N` is the low 32-bit extent used by the local parser comparison. `A`, `B`, `C` are recovered scalar values; `D` is the direct mapped-body offset. Offset equations below are the compact ordinary-sized forms; relevant source operations use 32-bit arithmetic. [S2-S6]

| First byte | First field | Second field | Third field | Body pointer / length | Carrier field +28, decoded |
| --- | --- | --- | --- | --- | --- |
| 1 | `A=BE32(24)` | `B=BE32(28+32*A)` | No third wire read on this path | `mapping + D`, `D=32+32*A`, length `B` | 128 |
| 4 | `A=BE32(4)` | `B=BE32(8+32*A)` | No third wire read on this path | `mapping + D`, `D=12+32*A`, length `B` | 128 |
| 2, 3, 5 | `A=BE32(4)` | `B=BE32(8+A)` | `C=BE32(12+A+B)` | `mapping + D`, `D=12+A`, length `B` | `C` |
| Other 251 values | Only first-byte read in the sweep | None | None | No protected carrier call in the sweep | No record constructed |

Thus `A` is not a fixed-offset selector. In the first family it determines a 32-byte-stride skip; in the second it determines a byte skip. `B` is the body length actually passed into the protected carrier. Field +28 is an encoded parameter whose role remains unknown. Its constant value 128 in one family does **not** establish an operation number, signature width, algorithm, or IOKit selector. [S5-S7]

| Source read site(s) | Meaning established by actual addresses/bytes |
| --- | --- |
| `0x100895d78` | First mapped byte, offset 0 |
| `0x1005b94fc`, `0x1005b9508`, `0x1005b9514`, `0x1005b952c` | Four consecutive bytes at the two variable word positions for byte 1/4 |
| `0x100118ed0`, `0x100118ed8`, `0x100118ee0`, `0x100118f04` | BE32 at offset 4 for byte 2/3/5 |
| `0x1000810b8`, `0x1000810cc`, `0x1000810e0`, `0x100081110` | BE32 at offset `8+A` |
| `0x10010e35c`, `0x10010e370`, `0x10010e384`, `0x10010e3b4` | BE32 at offset `12+A+B` |
| `0x100315ae8`, `0x10022cb78` | First and conditional second body byte at `mapping+D` and `mapping+D+1` in tested nonzero-body cases |

The byte-1/4 word reader computes `word XOR 0x8b3dc651`; the new source-pinned SMT obligation proves the complete 32-bit word identity under its retained parameter registers. Every mapping read is checked against both declared logical extent and supplied known bytes. The supplemental file is parsed directly from its mapping; no supplemental copy allocation occurs in this corpus. A separate control supplies only32 known bytes while declaring a256-byte logical extent:with B=0,the source reads no unknown tail bytes and still reaches the carrier rejection. The frame oracle uses the declared logical extent,not the length of supplied known bytes. [S2-S6]

Five additional body candidates are retained separately in [candidate profiles](triage_evidence/rpc502_supp_bodies_profiles.json) and [fresh candidate checks](triage_evidence/rpc502_supp_bodies_checks.json). Each uses byte2,`A=0`,body length equal to the supplied candidate,`C=128`,and512 declared bytes. These are grammar probes,not externally sourced valid FairPlay records. [S2-S7]

| Body bytes | Original-worker steps | Supplemental mapping reads | Carrier result |
| --- | --- | --- | --- |
| `30 00` | 68072 | 17 | `0xffff5bde` |
| `31 00` | 44867 | 15 | `0xffff5bde` |
| `04 00` | 44867 | 15 | `0xffff5bde` |
| `02 00` | 44867 | 15 | `0xffff5bde` |
| `30 03 02 01 00` | 68536 | 22 | `0xffff5bde` |

The `30` candidates traverse substantially more source code. All five still consume only record offsets0/4/16/24/36 and reject before any read of+28. This differential is a reproducible lead for body grammar recovery;it does not identify an encoding standard,prove accepted parsing,or reach a driver transaction.

## Bounds and failure partition

At `0x1008b5170..0x1008b5200`, the obfuscated low-32 size calculation reduces exactly to `N`, followed by unsigned comparison with 4. Extents 0 through 3 return `0xffff5bd9` without reading a mapped byte. A successful zero-length mapping here is a declared fixture outcome, not evidence that native mmap accepts length zero. [S3,S6]

At `0x10049bc34..0x10049bd4c`, for the byte-1/4 path, the frame conditions `AD80=D`, `AD6C=N+0x4b224d13`, and reader output `B XOR 0x8b3dc651` reduce the local rejection predicate to:

```text
reject = UGT32((D + B + 128) mod 2^32, N)
```

The proof covers all 32-bit inputs under those local frame conditions. It does not prove prior cursor construction is overflow-free or establish an end-to-end memory-safety result. Values `0x7fffffff`, `0x80000000`, and `0xffffffff` in `A` are included for bytes 1, 2 and 4. All nine fixtures reject; some still perform variable reads after arithmetic wraps. [S6]

| Fixture | Last pre-carrier extent / result | First carrier-reaching extent / result |
| --- | --- | --- |
| Byte 1, `A=B=0` | 159 bytes -> `0xffff5bd9` | 160 bytes -> carrier -> `0xffff5bde` |
| Byte 4, `A=B=0` | 139 bytes -> `0xffff5bd9` | 140 bytes -> carrier -> `0xffff5bde` |
| Byte 1, `A=1,B=0` | 191 bytes -> `0xffff5bd9` | 192 bytes -> carrier -> `0xffff5bde` |
| Byte 4, `A=1,B=0` | 171 bytes -> `0xffff5bd9` | 172 bytes -> carrier -> `0xffff5bde` |
| Byte 2, `A=B=C=0` | 15 bytes -> `0xffff5bd9` | 16 bytes -> carrier -> `0xffff5bde` |

The byte-2/3/5 path has its own staged bounds; the byte-1/4 `+128` predicate must not be applied universally. The source visits, raw reads and finite whole-worker results establish the listed cases; a compact universal formula for every byte-2/3/5 guard remains unknown. [S6]

## Partial internal argument ABI and obfuscated routine roles

For argument pointer `P`, the caller at `0x100500b58..0x100500b8c` and carrier entry at `0x10099ac90..0x10099ace0` independently reduce to the same low-32 address key:

```text
Kp = ((low32(P) XOR 0xc6d66014) * 0x6b86592f) mod 2^32
K  = 0x8b3dc651
```

Separate SMT obligations prove the caller's 32-bit expression and the low-32 portion of the carrier's original 64-bit expression. The observed stack addresses differ between the two layout callers, so a single sampled literal key is insufficient. [S1,S6,S7]

| Offset / width in bytes | Representation / actual consumer | Established role |
| --- | --- | --- |
| +0 / 4 | `stored XOR Kp`; carrier LDP at `0x10099ace0` | `0x38411d06` for bytes 1/2/3; `0x38411d07` for bytes 4/5. Both satisfy the observed high-bit tag comparison. Public operation meaning unknown. |
| +4 / 4 | Same LDP | Encoded carrier dispatch/control field; full semantics unknown. |
| +8 / 4 | Caller writes; no carrier read observed here | Encoded scalar; full semantics unknown. |
| +12 / 4 | Not written by the current record builder | Prior stack epoch; not an established input field. |
| +16 / 8 | Raw mapped pointer; LDR at `0x100a4fd3c` | Supplemental mapping base. |
| +24 / 4 | `(stored XOR Kp)+0xc898a600`, modulo 2^32; LDR at `0x100a4fd24` | Offset `D`; source ADD at `0x100a4fd58` constructs mapped body pointer. |
| +28 / 4 | `((stored+Kp) mod 2^32) XOR K` | Parameter 128 or wire value `C`; no consumer observed in these 53 calls. |
| +32 / 4 | STR at `0x10065f11c` | Carrier output status `0x74c29d8f`, decoding with XOR K to `0xffff5bde` in every observed carrier call. |
| +36 / 4 | `((stored-Kp) mod 2^32) XOR K`; LDR/sub at `0x100a4fd14..fd1c` | Body length `B`, retained in encoded form inside the carrier. |
| +40 / 4 | Caller writes; no carrier read observed here | Encoded scalar; full semantics unknown. |

The accessed extent is 44 bytes, not a proven complete 44-byte C object. The [compile-only SDK view](triage_evidence/rpc502_supp_layouts.c) places these members at the observed offsets and has a 48-byte padded C size. Neither that padding nor the captured 128-byte stack prefix proves the target object's total size. Earlier stack writes at +12/+32 remain separate byte epochs. [S7]

| Exact source site / range | Source-supported analytical role | Limit |
| --- | --- | --- |
| `0x100500ad4..0x100500cd4` | Byte-1/4 protected argument builder and call | `0x100500cd0` calls wrapper `0x1009d53cc`; not a kext method number. |
| `0x10000b1a0..0x10000b380` | Byte-2/3/5 protected argument builder | Separate stack record, same carrier ABI; original call to wrapper at `0x10000b3d0`, retained in the instruction pool and call-edge journal. |
| `0x1009d53cc..0x1009d562c` | Stateful wrapper to original protected carrier | `0x1009d5624` calls `0x10099ab1c`; source state updates are executed, not bypassed. |
| `0x10099ab1c`, `0x10099ace0` | Carrier entry and record tag/control load | Physical compiler carrier also contains many flattened blocks; no whole-function semantic rename is claimed. |
| `0x100a4fd10..0x100a4fd68` | Record body-length/cursor/mapping decoder | Exact consumed bytes and resulting pointer established. |
| `0x100315a80..0x100315b30`, `0x10022cb54..0x10022cbc4` | Conditional mapped-body byte parsing | Full body grammar and successful processing unknown. |
| `0x10065f11c` | Carrier status output store at argument+32 | The output is not a Mach reply or driver status by itself. |

These are reporting aliases. Original files, names and IDBs are unchanged. [S1-S4,S7]

## External APIs, fallback and ownership

All opens use flags 0 and the shared source emission site `0x100d94494`. The fixture's source-built paths are `/synt/SC_Info/etic/fixture.bin.sinf`, `/synt/SC_Info/etic/fixture.bin.v5.supf`, then conditionally `/synt/SC_Info/etic/fixture.bin.v4.supp`. The synthetic split path is not an assertion about an installed filesystem. Path bytes, including NUL terminators, are independently reconstructed from source store epochs. [S2,S3]

The failed-open path calls `___error` at `0x100c211dc`, reads its declared errno word at `0x100c211e0`, and selects an encoded status at `0x100c21200`. The retained source state W23=`0x27ae` makes the comparison value `W23 XOR0x27ac` equal2. Errno2 selects encoded `0x74c29dd1` (XOR K -> `0xffff5b80`) before the third filename/open;errno1,4 and13 select `0x74c29dd3` (XOR K -> `0xffff5b82`) and the worker returns that error. The third open is recorded before any API result is supplied and remains a continuation boundary. No `.v4.supp` file acceptance has been established. [S3]

| Source/API boundary | Observed result / ownership effect |
| --- | --- |
| Second fstat fails, no output seeded | Guarded unknown read of 8 bytes at stat+96, PC `0x100cc083c`; fixture stops, status correctly remains -1. |
| Second fstat fails, explicit st_size additionally seeded | Worker returns `0xffff5b82`; no second FD close request. This distinct counterfactual model does not invent successful native fstat output. |
| Second mmap returns MAP_FAILED | Worker returns `0xffff5bd4`; no second FD close request. |
| Second mapping succeeds | Parsing uses this mapping directly; no second copy allocation. No second mapping unmap request occurs in any retained case. |
| Close at `0x1001f19c4` | Second FD8 closes on ordinary parsed/rejected paths; first FD7 closes later. Injected second-close failure leaves FD8 live in the declared model and preserves the tested worker error. |
| Free at `0x1008ec710` | First file's private copy retires with exact reconstructed bytes. |
| Unmap at `0x1003aaef4` | First mapping retires on success; injected first-unmap failure leaves it live in the declared model. |
| First-close failure | First FD7 remains live in the declared model; the tested carrier error remains unchanged. |

A close request does not retire its mapping. Conversely, `file_epoch=2` on a model event identifies the current phase; cleanup arguments still identify the first mapping/FD when those are retired. The verifier matches requests to owner identity rather than interpreting the phase tag as ownership. No native resource-loss conclusion is made. [S3,S8]

No new incoming or outgoing Mach port is established by this corpus. It reaches neither native transport nor a new protected IOKit emission. Record +28, the private file descriptor, and synthetic pointer values must not be converted into Mach names or public selectors. Existing [Mach-port evidence](mach_ports_report.md) and [cross-layer ABI evidence](interface_abi_report.md) retain their earlier scopes. [S3,S4,S7]

## Verification, reproducibility and quality gates

All **13,436,642 main-corpus assertions** pass,including348 complete fresh original-worker runs and13,217,516 retained source visits plus the same number freshly replayed. The five separately verified body candidates add289,610 assertions and270,999 retained/fresh visits each. Combined: **353 fresh worker runs,13,726,252 assertions and13,488,515 visits in each retained/fresh set**,covering19476 distinct original instructions across the two pools.

| Main-corpus check | Verified count |
| --- | --- |
| Fixed-context first-byte domain | 256 |
| Bounded source spans / physical compiler ranges | 28 / 17 |
| Original pointer/fixup records / local unsatisfiable formulas | 539 / 5 |
| Source supplemental mapping reads | 1067 |
| Original carrier entries / field reads / status stores | 53 / 265 / 53 |
| Source predecessor stores checked for record entry | 1646 |
| Source owner stores / written bytes / final snapshots | 187572 / 194880 / 1392 |
| Source pathname snapshots / byte applications | 697 / 41883 |
| Complete worker returns / third-file boundaries / failed-stat unknown-read stops | 346 / 1 / 1 |

The [scoped quality gates](triage_evidence/rpc502_supp_quality_gates.json) and [prior-artifact preservation record](triage_evidence/rpc502_supp_preservation.json) pass. Of953 prior artifacts,947 are unchanged;the six differences are the four reporting indexes,the active-status file,and the delivery aggregator. The three original supplied inputs are unchanged.

Primary evidence is original Mach-O code, original chained-fixup/import records, LC_FUNCTION_STARTS, supplied file bytes and source-emitted reads/stores/calls. SMT results prove only their stated local formulas. SDK compilation proves the analytical member layout for arm64e; no compiled target code executes. Complete fresh private replay proves determinism under the declared fixture, not native scheduling, PAC, credentials, filesystem behavior, valid FairPlay records or a hardware transaction.

From `/Users/___/dev/dylex/extracted`, the finite producer and independent verifier are reproducible as follows. The contract recovery additionally uses the already-installed Z3 Python binding/runtime locations recorded in the preceding parser workflow; no installation or global configuration change is required.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_supp_cases.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc502_supp.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_supp.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rpc502_supp_bodies.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_supp_bodies.py
```

Those producer commands recreate this new evidence set; they do not mutate the frozen prior evidence. Extraction and independent checking are O(C*(B+V+E+S)) for bounded cases C, source bytes B, visits V, events E and snapshots S; compiler partitioning additionally uses O(R log F) lookups. Solver cost is separate, with30000 ms per producer obligation and120000 ms per independent verification obligation;the independent query changes only the timeout option. Byte counts, signed32 API results, unsigned32 predicates, size64 metadata and low32 address keys are explicitly distinguished.

| Gate | Scoped result / evidence |
| --- | --- |
| QG1 | Pass: descriptive technical findings; no normative premise required. |
| QG2 | Pass: S1-S9 state dependencies and falsification probes. |
| QG3 | Pass for this increment: supplemental layouts, internal ABI, fallback and ownership; broader goal remains active. |
| QG4 | Pass: explicit byte extents, integer widths, modulo arithmetic, compile-only layout and bounded complexity. |
| QG5 | Pass: fixed-context exhaustiveness, local formulas, partial record extent, prior stack epochs, failed-stat output and native unknowns are separated. |
| QG6 | Pass: original bytes/fixups/compiler metadata, fresh replays, independent byte journals, SMT and SDK evidence; no unsupported IDB attestation. |
| QG7 | Pass: bounded continuation opportunities below. |

## Bounded continuation opportunities

| Impact | Next source evidence | What it resolves |
| --- | --- | --- |
| High | Decode a valid body through the actual `mapping+D,B` consumers and follow the first read of record+28. | Parameter meaning, successful carrier output, and whether this path reaches a real protected provider/IOKit/Mach call. |
| High | Continue the already source-built `.v4.supp` third-file boundary with distinct FD/stat/map owners. | Fallback grammar, version compatibility and additional constructor/cleanup contracts. |
| High | Recover all byte-2/3/5 staged size guards and widened size/count invariants; preserve source wrapping. | Complete extent contract beyond finite cases and the byte-1/4 local proof. |
| Medium | Trace second mapping/FD publication, transfer and all exits, then compare native accepted files. | Whether observed live owners are retained, transferred, or lost; successful versus rejected lifetime differences. |
| Medium | Recover +4/+8/+40 and prior +12/+32 epochs from every builder and consumer. | Complete internal record schema, dispatch control and actual object extent. |
| Medium | Resolve carrier body grammar and its tag/length branches from source rather than assigning a familiar encoding name from two bytes. | Parser semantics and meaningful accepted-record generators. |
| Low | Restore live IDA read access and compare the retained spans with the loaded database. | Current IDB-byte/context correspondence; original file-backed results are already reproducible. |
