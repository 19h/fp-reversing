# RPC502 policy-state dataflow and sidecar-file ABI

The subsequent [mapping and parser-boundary report](rpc502_mapping_report.md) extends this report's stopping points through size/status consumers, mmap/malloc, mapping-result publication, native copy and selected cleanup/QoS exits. The fixture counts below retain this increment's original scope.

The daemon's BootPolicy/CSR result feeds a mutable u32 global at `0x1010b9630`. A later block converts that global into the starting byte index of the filename scan. This establishes a concrete policy-to-dataflow connection below RPC502. The previously unexplained five `0x98` bytes are now traced to skipped, unwritten prefix-buffer bytes in the bounded fixture. A separate right shift changes the pathname split even with an application-shaped input. Valid native pathname framing remains unknown.

The next file interface is also recovered: `open` with flags zero branches on its signed 32-bit result; nonnegative results reach `fstat`, including descriptor zero, while a negative result reaches `__error` and an errno dereference. After fstat, the selected continuation reads its eight-byte size field even for a modeled negative result, with a changed status marker. Original arithmetic encodes the size into X23. No target host file, IPC, synchronization, loader, sysctl or CoreKE operation was executed. Original target instructions ran only in private Unicorn memory with explicit imported-API models.

## Provenance and assumption register

Analysis date: 2026-11-01. Original daemon arm64e SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The live daemon IDB, short hash `6b117c693e3b`, reports backing path `/Users/___/Downloads/fairplayd` and universal-file SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`. Four current 48-byte IDB readbacks match the extracted slice exactly; no IDB mutation occurred. [Readback](triage_evidence/rpc502_sidecar_ida_readback.json) retains actual tool output, excluding automated host suggestions. Exact current IDA knowledge-store queries for `CoreKE` and `SC_Info` returned no facts/notes; that result is limited to those queries.

[Contracts](triage_evidence/rpc502_sidecar_contracts.json) retain 14 original bounded instruction ranges, four SMT queries, a 256-input byte-encoder check, two exhaustive 256-input import-selector checks, original fixups/import bindings, 15 path/state fixtures, three open-result continuations and two fstat-result continuations stopping at unknown metadata. These are complementary evidence classes; neither the solver nor a finite fixture proves native whole-program reachability.

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| S1: this original daemon slice is the intended target | All static addresses and interpretations | Recheck original hash, universal slice and live IDB bytes. Attest actual runtime executable/slice separately. |
| S2: the selected protected predecessor establishes W24=`0x6cf4`, the global alias and recovered control-register states | Compact policy/global formula, decoder roles and dispatch interpretation | Capture another predecessor and compare encoded frame, table/bank, register and alias values. Formula preconditions are explicit in the contracts. |
| S3: the existing private PID-zero, CPU/origin, QoS, CSR/BootPolicy, PAC-bypass, serial-once/lock and private-heap models are adequate for these bounded continuations | Every fixture observation | Match native state/API behavior independently; stop on unknown imports/opaque reads. Fixtures do not attest PAC, startup, concurrency or native memory permissions. |
| S4: VMM query status zero and u32 value one select the inspected diagnostic/skip-CoreKE continuation | All sidecar fixtures and file-boundary observations | Inspect the CoreKE-loading branch and its result effects. No CoreKE code is executed here; those effects may be necessary for a different valid native path. |
| S5: chosen byte strings and counts are useful synthetic input probes | Concrete output paths, origin and CPU comparisons | Recover actual kext-produced pathname/record examples and upstream invariants. Application-shaped input is not proof of valid native framing. |
| S6: original initial global and zero-filled fixture stack represent only the specified test state | Default starting index and `0x98` prefix | Seed global+6 and prefix bytes `0xa5` independently; both perturbations are retained. Establish native initialization and lifetime before any memory-defect claim. |
| S7: installed SDK declarations describe the relevant API ABI | `struct stat` extent/offsets and API-level terminology | Compile for arm64e with explicit sysroot; match the loaded runtime/library separately. Native register widths/import identities are independent evidence. |

## Policy result becomes a filename index

The inspected local dataflow is:

```text
BootPolicy result -> marker M -----+
                                  +-> global G (u32) -> scan start (u64)
CSR result -------> indicator I ---+                         |
                                                            v
RPC502 filename bytes -> encoded prefix and last slash -> split
                                                            |
                                                            v
                          prefix + /SC_Info/ + tail + .sinf
                                                            |
                                                            v
                                                   open -> fstat / errno
```

At `0x1005bbb20`, W24=`0x6cf4` yields W19=`(0x6cf4 + 0x77c) | 0x885 = 0x7cf5`. Original instructions read G through SP+`0x358`, add the marker in W9 and CSR indicator in W23, and write G at `0x1005bbb68`. The constants satisfy:

```text
(0x7cf5 XOR 0x6258e701) + 0x346a14aa = 0x96c2b09e mod 2^32
0x96c2b09e = -0x693d4f62 mod 2^32
G_after = G_before + (M - 0x693d4f62) + I mod 2^32
```

This equality is SMT-proved for all 32-bit G, M and I under S2. It does not require G to equal its file value. At `0x1005d1354`..`0x1005d136c`, another native block reads G, adds `0xe315e976` in W8 and stores X8 as the scan counter. A W-register write zero-extends into X8:

```text
scan_start = zero_extend_u64((G_after + 0xe315e976) mod 2^32)
file G0 = 0x1cea168a
G0 + 0xe315e976 = 0 mod 2^32
```

Consequently, with the original G0, the initial index equals the marker delta plus CSR indicator, modulo 2^32. It is a byte index, not a mode enumeration or a boolean. The [earlier environment](rpc502_environment_report.md) and [BootPolicy backend](bootpolicy_backend_report.md) reports establish the upstream marker partition; actual security-mode enum names remain unknown.

| Mode/status seed | CSR seed/status | Marker delta | Indicator | Starting byte index |
| --- | --- | --- | --- | --- |
| mode 1 or 2, status 0 | config 0, status 0 | 0 | 0 | 0 |
| mode 3, status 0 | config 0, status 0 | 3 | 0 | 3 |
| mode 0, status 0 | config 0, status 0 | 6 | 0 | 6 |
| status 5 | config 0, status 0 | 6 | 0 | 6 |
| mode 1, status 0 | config 1, status 0 | 0 | 1 | 1 |
| mode 1, status 0 | config `0x10`, status 0 | 0 | 0 | 0 |
| mode 1, status 0 | CSR status 5 | 0 | 2 | 2 |

The recovered CSR indicator is 2 on getter failure; otherwise it is `(config & 0xffffffef) != 0`. These are local computed effects, not complete accept/reject rules. Each of the 15 fixtures observes exactly one four-byte write to G, at the same native PC. A privately seeded G0+6 with mode1/CSR0 retains G0+6 and produces index6, demonstrating the formula's dependence on incoming state.

If successive invocations visit this update without another write/reset, the algebra gives `G_n = G_initial + sum(marker_delta + I) mod 2^32`. Whether a native request sequence satisfies that condition is **unknown**. Complete writers, initialization/reset paths, synchronization and cross-request persistence have not been recovered. No native repeated-request or race behavior is asserted.

## Byte construction and the skipped-prefix explanation

| Native range / site | Recovered local role | Evidence boundary |
| --- | --- | --- |
| `0x1007f0d70`..`0x1007f0dc4` | Compare u64 scan counter with derived limit1024 | Limit/register state verified in all sidecar-reaching fixtures; earlier RPC502 NUL scan is a separate, earlier operation |
| `0x1005c6780` / `0x1005c6784` | Load source pointer from SP+`0x5650` and one byte at counter | Native byte load, then NUL-dependent routing |
| `0x10074cbc8`..`0x10074cc18` | Encode byte into buffer from SP+`0x6b48`, remember slash index, increment counter | Selected W14=`0x6be`; 256-byte exhaustive encoder equivalence |
| `0x100787f48` / `0x100787f4c` | Two variable logical right shifts of remembered slash index | Selected X13=0 and X11=1, hence split=`last_slash >> 1`; universal predecessor interpretation unknown |
| `0x1004f59a0` | Write encoded NUL `0x98` at split | Selected W13 low byte=`0x98`; tail pointer becomes original filename+split+1 |
| `0x10078e168`..`0x10078e1ac` | Decode/copy prefix with XOR `0x98`, including decoded NUL | Stop compares encoded byte with `0x98` under selected control state |
| `0x1009ab630`..`0x1009ab664` | Decode and append `/SC_Info/` and later `.sinf` from separate encoded sources | Byte transform subtracts `0x11` modulo256; current literals/terminators observed |
| `0x10083ec3c`..`0x10083ec74` | Copy selected original filename tail, including NUL | Current source/destination and termination observed; complete generic helper semantics remain open |

The native encoder computes, for byte b and observed shift one:

```text
encoded = b - ((b << 1) & 0x30) - 0x68 mod 256
encoded = b XOR 0x98
```

All 256 input values agree. The inverse prefix decoder uses the same XOR constant. The default filename `/synthetic/fixture.bin` has its last slash at byte index10. The paired shifts produce split5; the encoded terminator therefore overwrites buffer byte5. Mode0/CSR0 starts encoding at byte6, leaving bytes0..4 unwritten on this bounded path. The decoder nevertheless reads those five bytes before the terminator.

With the fixture's initial zero bytes, decoding yields five `0x98` bytes. Seeding those same prefix-buffer bytes with `0xa5` before the first target instruction yields five `0x3d` bytes (`=`), because `0xa5 XOR 0x98 = 0x3d`. The two fixtures otherwise reach the same construction sites and file boundary. [Byte trace](triage_evidence/rpc502_sidecar_byte_trace.json), [prefix writers](triage_evidence/rpc502_sidecar_prefix_writers.json), [counter trace](triage_evidence/rpc502_sidecar_counter_trace.json) and the reproducible [15-case matrix](triage_evidence/rpc502_sidecar_profiles.json) retain distinct observations. The earlier one-off traces are supplementary snapshots; the current matrix and its generator hashes define the validated case set.

Thus the five bytes are explained within S2-S6. Native stack initialization, valid path protocol and upstream effects remain unknown. This evidence does not establish a native uninitialized-memory disclosure, successful file access or exploitable condition.

## Input, CPU and origin variation

| Synthetic case | Observed result |
| --- | --- |
| `/synthetic/fixture.bin`, mode1/CSR0 | `/synt/SC_Info/etic/fixture.bin.sinf` |
| Same name, mode0/CSR0 | five bytes `0x98`, then `/SC_Info/etic/fixture.bin.sinf` |
| Same name, mode3/CSR0 | three bytes `0x98`, then `nt/SC_Info/etic/fixture.bin.sinf` |
| Same name, mode1/CSR1 | one byte `0x98`, then `synt/SC_Info/etic/fixture.bin.sinf` |
| `/tmp/app`, mode1/CSR0 | `/t/SC_Info/p/app.sinf` |
| `/Applications/Test.app/Contents/MacOS/Test`, mode1/CSR0, origin0/1/2 separately | `/Applications/Test/SC_Info/app/Contents/MacOS/Test.sinf` in all three cases |
| Application-shaped name, CPU `0xabcd` | Returns low32=`0xffff5869` before sidecar open; complete status meaning/CPU-sentinel route remains unknown |

Ordinary CPU seed is `0x0100000c`; declared counts include one NUL byte. No target instruction changes the original filename in these cases. The application-shaped input has last slash37 and split18. This rules out the short synthetic filename alone as the explanation for the observed halving; it does not validate S5 or establish a native pathname bug. The count and framing contracts of the kext, MIG server and private application record remain distinct from this local scan.

The selected filename encoder scans at most1024 byte positions, with an unsigned counter comparison. This later limit does not retroactively bound the earlier wrapper's filename-NUL scan documented in [RPC502 application ABI](daemon_rpc502_report.md). For these fixtures, local scan/copy work is O(L) time and O(L) temporary storage, L bounded by inspected scan extent. Complete output-capacity/error guarantees and malformed/boundary-length cases remain unknown.

## File descriptor and metadata ABI

The original `_open` emission is `0x100d94494`; W1 is explicitly zero. Current SDK constants identify zero as `O_RDONLY`. No `O_CREAT` flag is present; a residual X2 register is not evidence of a meaningful mode argument. The returned descriptor/result is tested with `cmp w0,#0` and a signed-negative predicate. Under the observed protected control state, an SMT proof covers all 32-bit results:

| Signed W0 result | Table index / original target | Next bounded imported boundary |
| --- | --- | --- |
| Negative | `0x9ac0` -> `0x100c2119c` | `___error` at `0x100c211dc`; return PC `0x100c211e0` |
| Zero or positive | `0x9af2` -> `0x100dbedac` | `_fstat` at `0x100aaf954`; return PC `0x100aaf958` |

Original table fixups independently retain both dispatch targets. `_fstat` and `___error` bind to `/usr/lib/libSystem.B.dylib`, with original slots `0x1010a09f0` and `0x1010a0100`, authenticated IA discriminators `0x5e4e` and `0x6e96`, respectively. Exhaustive selector-bank checks cover all 256 selector-byte inputs for each binding. This establishes static binding provenance, not runtime authentication.

At the fstat call, X0 forwards the descriptor, and X1 is SP+`0x30`; the observed private buffer is `0x70066e30`. Native instructions preserve the descriptor in X24. The negative-open continuation calls `__error(void)` and immediately loads a u32 through returned X0 at `0x100c211e0`, establishing errno-output use independently of any errno value. Residual argument registers at this zero-argument call are not assigned API semantics.

Three separate [private open-result fixtures](triage_evidence/rpc502_sidecar_io_index.json) inject -1, 0 and7 only at the established open boundary. Results0 and7 both reach fstat with the same descriptor value; -1 reaches the errno accessor. Each stops before that next API executes. No `struct stat` contents, file data or errno value is synthesized; no actual descriptor is created.

The [compile-only SDK probe](triage_evidence/rpc502_sidecar_layouts.c) checks int/result width4 bytes, `sizeof(struct stat)=144` bytes, st_mode offset4, st_size offset96 and st_size width8. Those offsets describe the installed arm64e SDK ABI; matching runtime version remains unverified.

## First metadata consumption and size encoding

Two additional [metadata continuations](triage_evidence/rpc502_sidecar_metadata_index.json) return private descriptor7 from open and inject fstat result0 or-1. The complete 144-byte metadata output is marked unknown; no metadata value is supplied. Both stop at `0x100cc083c`, `ldr x8,[sp,#0x90]`, before subsequent execution is interpreted. Fstat's buffer was SP+0x30, so the read is at buffer+0x60, eight bytes wide: the compiled SDK st_size field. There are no intervening native writes to that output buffer in either fixture.

After fstat, `cmp w0,#0` and `csel w28,...,lt` preserve W28=`0x8b3dc651` for result0 or select `0x74c29dd3` for result-1. Under selected W23=0 and W20=`0x6c4a`, the dispatch calculation at `0x100aaf96c`..`0x100aaf988` selects table index0x6c4a independently of that result. The original fixup resolves to `0x100cc082c`, which reaches the size load. This establishes local load ordering and status-marker separation; it does not establish a native disclosure, API output contents, final status or caller-visible effect on failure.

Original instructions after the load derive W25=`(0x699b - 0x6426) | 0xc080 = 0xc5f5` from selected W21. They then compute:

```text
mask = zero_extend_u64(W25) + 0x6700172791792061
     = 0x670017279179e656
X23 = size_bits - ((size_bits << 1) & mask) + 0xb3800b93c8bcf32b mod 2^64
X23 = size_bits XOR 0xb3800b93c8bcf32b
```

The last equality is SMT-proved for every 64-bit size bit pattern under that register precondition. The XOR key is an encoding constant; it is not identified as a cryptographic key. These static instructions have not executed in the unknown-metadata fixtures, which stop at the preceding load. Subsequent size validation, allocation/read extents, mode-field use, cleanup and successful output remain unknown. Both the original encoded arithmetic and the SDK's signed off_t interpretation must be retained when following consumers of X23.

## Reproduction and bounded continuation

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/run_rpc502_sidecar_profiles.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_rpc502_sidecar_io.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_rpc502_sidecar_metadata.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_rpc502_sidecar.py
```

The verifier checks the 15 current generator-bound cases, three open-result and two unknown-metadata profiles, four live-IDB byte ranges, exact original imports/fixups, four UNSAT arithmetic queries, 256 encoder inputs and two 256-input selector banks, then recompiles the SDK assertions. Source hashes and explicit seeds are retained. Original input files and IDBs remain unchanged. Extraction/validation is O(B+C*L) time and O(B+E) retained space, with solver-dependent proof cost, as specified by the [verifier](triage_evidence/recover_rpc502_sidecar.py).

| Impact | Further foundational finding / exact next evidence |
| --- | --- |
| High | The policy-to-global-to-index connection changes actual path bytes. Recover every writer/reset and protected predecessor before interpreting state persistence or native environmental effects. |
| High | Split-halving remains independent of tested origin values and persists for the application-shaped input. Recover the control-word derivation in `0x100787b9c` and actual upstream pathname/record conventions. |
| High | The CoreKE-loading branch and VMM-positive sidecar branch have different unexecuted dependencies. Recover CoreKE's output/status and full record contract before generalizing path observations across branches. |
| Medium | The nonnegative-open path exposes an exact descriptor/metadata interface. A size load is reached after both modeled fstat results with different status markers, and the original next block XOR-encodes that size. Follow X23 and the status marker jointly; establish validation, allocation/read extents, mode checks, close/free and successful result ownership with explicit initialized metadata. |
| Medium | Later1024-byte scanning and the earlier unbounded NUL scan are different boundaries. Recover capacity, no-slash, embedded-NUL and extent-error behavior without conflating local bounds with incoming MIG safety. |
| Low | Current targeted IDA memories add no sidecar/CoreKE facts. Original byte matches allow reproducible investigation despite missing annotations; empty search results do not exclude other stored analyses. |

QG1: factual technical analysis. QG2: S1-S7 and falsification probes are explicit. QG3: this increment covers policy-state/path dataflow, byte construction and the next file ABI; the broad interface investigation remains active and incomplete. QG4: byte units, u32 modulo arithmetic, zero extension, signed descriptor checks, compiled layouts and complexity are explicit. QG5: skipped-stack bytes versus split-halving, initial versus repeated state, VMM versus CoreKE routes, descriptor zero and native versus synthetic evidence are distinguished. QG6: original bytes/fixups, current live-IDB byte matches, SDK hashes, arithmetic proofs and finite cases have separate provenance. QG7: impact-labeled scope extensions and continuation probes are bounded above. [Machine-readable checks](triage_evidence/rpc502_sidecar_quality_gates.json) record the verified increment.
