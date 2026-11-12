# Selector-21 inner entry, environmental flag and bounded error return

The selected adapter now has a source continuation through its original probe, inner prologue, record decoding and two bounds calls. A strict prefix stops before an undefined auxiliary qword at A+`0x270`. Separate continuations preserve that arbitrary qword and declare stable values 0 or 1 for a byte at `0xfffffe000ccca078`. Value 0 reaches a pending 104 B `site.FPAESParameters` allocation. Value 1 reaches an insufficient-extent stream error, returns through the inner routine and adapter with an exported zero stack delta, then stops before freeing the output-stream object. No allocation/free API, native transaction or output-B write executes. [IE1-IE7]

```text
unchanged pending adapter call
  -> original small stack-probe path (readability assumed)
  -> inner frame / record decode / two unsigned bounds calls
  -> STRICT STOP before A+0x270 read
       |
       + separate arbitrary-qword continuations; no concrete fill
       |
       + flag fixture 0 -> pending 104 B FPAESParameters allocation
       |
       + flag fixture 1 -> relative-table entry 0
                           -> 8 B remaining-extent test fails
                           -> encoded status 0xce515b53
                           -> inner return -> adapter delta 0
                           -> pending output-stream free
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IE-A1 | Pinned original KC, normalized kext and preceding receipts identify the source build/epochs. All joins depend on it. | Rehash dependencies, reproduce the preceding output-stream cases, compare original instruction bytes and original chained pointers. Native build pairing remains unknown. |
| IE-A2 | The preceding successful, distinct 32 B stream returns and their ordinary call ABI remain premises. New source paths depend on them. | Reproduce each preceding case exactly. Supply no new allocator result and stop before allocation/free APIs. |
| IE-A3 | The stack guard is an arbitrary coherent u64 across its two reads, and the small probe address is readable. The selected guard/probe path depends on these premises. | Preserve the original import and exact probe source, record the discarded WZR read at its own epoch, retain a symbolic guard and prove the equality test. Native faults or guard mutation are unknown. |
| IE-A4 | The strict undefined A+`0x270` qword can be represented separately by an arbitrary u64, without choosing its value or assuming allocation zeroing. Symbolic continuations depend on it. | Keep the strict frontier unchanged; require every selected control/address/call to be concrete. Only the exact unchanged word may be copied back to the same auxiliary cell. Reject other symbolic non-frame stores. |
| IE-A5 | Stable environmental byte values 0 and 1 are declared fixtures. Finite flag paths depend on those values and stability. | Prove the first gate uses bit 0 for every u32 input; retain the original on-disk byte 0 separately. Writers, runtime value, domain and concurrent changes remain unknown. Other byte values are not complete-path cases. |
| IE-A6 | Frames, record, heap objects, workspace/auxiliary spans and controller globals retain valid disjoint extents and stated reaching definitions. Memory/ABI equations depend on this model. | Two placements/global fixtures, strict byte epochs, extent/nonwrapping checks and source-defined masks. A pointer inequality alone does not establish ownership or native mapping. |
| IE-A7 | A64 widths, signed/unsigned conditions, pre/post-indexing, vector-zero stores, signed relative entries and abstract PAC returns describe the source model. All continuation results depend on these semantics. | Compare every retained instruction word, re-run ten source equations and reconstruct byte epochs/snapshots independently. Actual native authentication and full inner semantics remain unknown. |

## Entry frames, guard and original bounds calls

The [output-stream report](versioned_output_stream_report.md) ends before call `0xfffffe000a5a8508` to adapter `0xfffffe000a69ee38`. This increment lifts the original call and adapter/inner source. The preceding pending-call receipts remain unchanged. Each parent case has one strict prefix and two separate continuations. [IE2-IE4]

The original import at `0xfffffe000847c5f8` points to `___stack_chk_guard`, kernel address `0xfffffe000cacb000`. The original file word is not used as a runtime guard premise: the new source model carries an arbitrary u64 through its frame store and later comparison. The small `__chkstk_darwin` path executes as a source lift, including its discarded byte read into WZR. No byte is chosen for an undefined discarded read, and that read does not initialize memory. Readability and ordinary source-return behavior remain IE-A3 premises. [IE1,IE3-IE5]

For all retained cases, the adapter's derived private reservation is 64 B. With G=caller pre-call SP, its fixed reservation is another 64 B and the private header is H=G-128 B. The inner fixed frame uses `0x660`=1,632 B, so its initial body SP is H-1,632 B. The original header initialization/restoration recovers the captured S=`0x8137bc5b6dfd9a21` in these fixtures. This finite S and reservation are distinct from the preceding report's arbitrary-S 16..256 B domain. [IE2-IE4]

| Inner call site | Arguments recovered from the record | Selected target |
| --- | --- | --- |
| `0xfffffe000a689308` | X0=W+`0x4c0`; X1=W+`0x4000` | `0xfffffe000a687ecc` |
| `0xfffffe000a689378` | X0=A+`0x280`; X1=A+`0x1000` | Same bounds helper |

Both original bank selections resolve through slot `0xfffffe000847a828`, IA diversity `0x4d6a`. The source helper returns for unsigned X0<=X1 and otherwise branches to BRK. Fresh source equations prove the argument fields and returning inequalities under their explicit nonwrapping base bounds. These comparisons establish ordered end addresses, not a complete memory-access or ownership check. [IE3,IE5-IE6]

The inner prefix also carries C+`0x48` (task) to inner-SP+`0x2d8`, C+0 (output stream) to +`0x420`, and C+`0x38` (input stream) to +`0x3e0`. Source-defined workspace/auxiliary stores include an encoded status at W+`0x274`, a qword zero at A+`0x1a0` and a 16 B vector zero at A+`0x210`. None is an output-B write. [IE3-IE5]

## Strict auxiliary frontier and controller epochs

Every strict prefix makes 678 visits and stops before `LDR X28,[X22,#0x270]` at `0xfffffe000a68a080`, where X22=A. All 8 B lack a reaching source definition in the retained epoch. The prior 4,096 B typed allocation of A did not establish zeroing. A missing source definition is not proof of a native uninitialized read; native allocator behavior and other reaching state remain unknown. [IE2-IE4]

The separate continuations name that word `aux270_word64`; they make no assignment to it. On the flag-1 path, source `0xfffffe000a69b228` copies the same word back to A+`0x270`. Its value never becomes a selected branch, address, call target or concrete non-frame result on either retained path. The copy preserves an arbitrary origin; it does not prove native initialization. [IE3-IE4,IE7]

The new source journals retain the adapter's controller writes and the inner controller updates. Five fresh exhaustive bank identities, 1,280 byte inputs, bind the relevant addresses and bounds calls: [IE4,IE6]

| Binding | Effective result |
| --- | --- |
| Inner controller | `0xfffffe000ccc3618` |
| Shared controller, original pool target minus 4 | `0xfffffe000ccc32f8` |
| First bounds call | `0xfffffe000a687ecc` |
| Second bounds call | `0xfffffe000a687ecc` |
| Environmental byte | `0xfffffe000ccca078` |

These mutable cells have ordered source epochs. Original table identities are exhaustive; actual source-path correspondences are separately checked against the retained instructions and pointer reads. No native global-state lifecycle or concurrency property follows. [IE3-IE6]

## Environmental flag and relative state table

The source-selected pool slot `0xfffffe00084727b0` points to byte `0xfffffe000ccca078`; its original file value is 0 and no exact symbol name is supplied. Under the retained phase, the gate at `0xfffffe000a68a0d8..0xfffffe000a68a0f8` normalizes to: [IE3,IE5-IE6]

```text
index = 0x31a if (flag & 1)==0 else 0x359
TABLE[0x31a] -> 0xfffffe000a69d87c
TABLE[0x359] -> 0xfffffe000a69de64
```

This first-gate equation quantifies over arbitrary u32 flag inputs. It does not prove that all later uses ignore the upper seven byte bits, that the byte is a Boolean variable, or that the runtime value equals its original file byte. The complete paths here use only stable fixture values 0 and 1. [IE-A5]

The flag-1 path reaches `LDRSW X16,[X17,X16,LSL #2]` at `0xfffffe000a69decc`, followed by addition to base `0xfffffe000a69ded0` and `BR X16` at `0xfffffe000a69ded8`. The preceding unsigned guard restricts the index to 0..15. The original 64 B table at `0xfffffe000a69ecf8` contains signed little-endian i32 displacements. All sixteen targets are aligned BTI-J entries within the captured inner envelope. [IE3-IE4,IE6]

| Index | Signed offset, B | Target |
| --- | ---: | --- |
| 0 | -11500 | 0xfffffe000a69b1e4 |
| 1 | -1628 | 0xfffffe000a69d874 |
| 2 | -21600 | 0xfffffe000a698a70 |
| 3 | -14924 | 0xfffffe000a69a484 |
| 4 | -36580 | 0xfffffe000a694fec |
| 5 | -29000 | 0xfffffe000a696d88 |
| 6 | -38988 | 0xfffffe000a694684 |
| 7 | -38280 | 0xfffffe000a694948 |
| 8 | -50944 | 0xfffffe000a6917d0 |
| 9 | -47224 | 0xfffffe000a692658 |
| 10 | -58520 | 0xfffffe000a68fa38 |
| 11 | -52612 | 0xfffffe000a69114c |
| 12 | -66424 | 0xfffffe000a68db58 |
| 13 | -61928 | 0xfffffe000a68ece8 |
| 14 | -81344 | 0xfffffe000a68a110 |
| 15 | -67660 | 0xfffffe000a68d684 |

The retained flag-1 cases select index 0, target `0xfffffe000a69b1e4`. The other rows are exact static table mappings, not sixteen established reaching paths. The table begins at the captured inner envelope's end and occupies 64 B before the next catalog entry. Its bytes are explicitly read as data and are not counted as decoded instructions or new execution visits. This provides a concrete reason to distinguish catalog boundaries, code envelopes and embedded relative-table data. [IE1,IE6]

## Eight-byte extent failure and separate return channels

The input stream's encoded cursor and endpoint are unchanged at this stage from the earlier reader: cursor=12 B, endpoint=12 B. The 16 B transformed input still contains its marker/padding bytes, but the scan-derived endpoint excludes them from this read span. The new source test at `0xfffffe000a69b6cc..0xfffffe000a69b730` normalizes to: [IE2-IE5]

```text
enough = unsigned32((cursor + 8) mod 2^32) <= unsigned32(endpoint)
index  = 0x96c XOR (0xbc if enough else 0)
failure index 0x96c -> 0xfffffe000a69b804
success index 0x9d0 -> 0xfffffe000a69b73c
```

The equation holds over arbitrary u32 cursor/endpoint pairs under the selected source phase. Interpreting it as an ordinary 8 B remaining-extent check requires nonwrapping `cursor+8`; that premise holds for the retained 12 B cursor. Here 12+8=20 B exceeds 12 B, so the source takes the error branch before reading additional input-B bytes. This is an 8 B test, not a 4 B test. [IE3,IE5]

Original store `0xfffffe000a69b82c` writes u32 `0xce515b53` to H1+`0x18`. The source then carries that word to W25 and writes it to C+`0x20` at `0xfffffe000a69d834`. A universal result-store equation establishes this cell independently of incidental X0. The inner epilogue checks its saved guard and returns at `0xfffffe000a69d86c`. Source guard equality is conditional on the coherent arbitrary guard premise. No protocol-wide status name or native error event is assigned. [IE3-IE5]

In all eight flag-1 cases, the private header remains exactly the strict prefix's restored S. At `0xfffffe000a69f04c`, the original adapter writes u64 zero to the caller delta cell. Its return at `0xfffffe000a69f060` restores G; the caller's subsequent addition of zero preserves G. This closes the actual source return chain for these eight declared error paths, including arbitrary auxiliary/guard origins. It does not prove final header preservation on the flag-0 allocation path, other operations, changed input or native execution. [IE3-IE5,IE7]

The caller subsequently overwrites all 32 B of H2 in reverse order, then stops before `_IOFreeTypeImpl` at `0xfffffe000a5a92e4`, X0=`0xfffffe000847bba0`, X1=H2. This is the output-stream object in the flag-1 cases; the preceding null-second-allocation controls reached the same free site with H1 instead. No free result, later input-object cleanup, wrapper completion or UserClient copyback is supplied. [IE2-IE4]

## Clear-bit allocation frontier

Each flag-0 continuation adds 65 visits after the strict cut and stops before call `0xfffffe000a69d8f0`. Each flag-1 continuation adds 1,527 visits. The clear-bit call resolves to `_IOMallocTypeImpl`, target `0xfffffe000c4ba154`, modifier `0xd0c8`, with X0=`0xfffffe000847b460`. That original type view has name `site.FPAESParameters`, flags `0x64` and size 104 B. Its other argument registers are incidental to this allocator's established ABI. [IE3-IE4,IE6]

This reaches a typed AES-parameter allocation site from the admitted selector-21 source path and provides a narrower type context for the earlier [104 B packed-carrier/reset analysis](carrier_control_report.md). The allocator remains pending: a returned pointer, its initialization, later preparer/coordinator linkage and successful operation are not established. No new 104 B object is supplied. [IE6-IE7]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| IE1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The recaptured inner envelope contains 22,279 instructions / 89,116 B. |
| IE2 | Parent output-stream receipt SHA256 `be9917579a29d521f1608f69db5ee89823d24bab35006af9e80bcb4f4754ec54` and pinned transitive receipts. Fresh parent equality precedes every new source path. |
| IE3 | [Extractor and source lift](triage_evidence/recover_versioned_inner_entry.py): explicit source-call stack, original probe/bounds bodies, strict unknown reads, arbitrary coherent guard/auxiliary origins, fixed flag-read fixtures, typed writes and ten UNSAT equations / 68 lifted instruction instances. |
| IE4 | [Compressed receipt](triage_evidence/versioned_inner_entry_checks.json.zst): eight strict prefixes and sixteen separate continuations, 18,160 retained visits, 16,288 read bytes, 14,304 write bytes, 496 authenticated transfers, 40 source returns and eight relative-table transfers. Repeated parent/prefix reproduction is excluded from these retained totals. |
| IE5 | Source equations establish bounds arguments and nonwrapping inequalities, small-probe routing, first flag-bit dispatch, modular 8 B extent, encoded stream error, C+`0x20` result store and stable-guard comparison. |
| IE6 | Five exhaustive bank identities / 1,280 inputs, original import/call/type pointers, 104 B type view and sixteen original signed relative entries/targets. Full envelope capture does not imply complete semantic recovery. |
| IE7 | [Publication verifier](triage_evidence/verify_versioned_inner_entry_publication.py): fresh extraction/proof equality, independent byte epochs, branch/return/snapshot checks, exact publication delta, preserved originals and decoded-path hygiene. Original files suffice; no new IDA access, guest or native API executes. |

The independent byte audit checks all 18,160 source words, 16,288 read bytes (352 symbolic), 14,304 write bytes (128 symbolic), eight discarded probe bytes and 3,840 snapshot bytes. The source-defined masks and arbitrary-origin identities remain distinct. Runtime environment fixtures are declared reads; they are not source writes or native observations. [IE4,IE7]

Run the extractor, verify/compress its receipt with zstd level 22, refresh the manifest and run the publication verifier with the pinned project dependencies. Time/space cost is O(receipt bytes+C*V+I+256R), plus solver cost capped at 30 s/query. Each new source interval is bounded at 10,000 steps; parent/prefix reproduction is additional explicit work.

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Continue the pending 104 B allocation through initialization and its next consumer. | Exact return/type premise, original stores, failure branch and reaching pointer identity. |
| High | Establish environmental-byte lifecycle. | Writers of `0xfffffe000ccca078`, initialization order, valid value domain and read epochs; image value 0 is insufficient. |
| High | Establish the native definition/lifecycle of A+`0x270`. | Allocator initialization and reaching stores; unchanged symbolic copies do not prove native definite assignment. |
| High | Finish error cleanup and selector-21 copyback. | Actual remaining source return contracts, preserved status and R+`0x40`/UserClient status gating. |
| High | Establish native daemon/build/task/connection/right pairing. | A matched actual transaction and ownership epoch; private source pointers do not establish it. |
| Medium | Check other metadata boundaries for relative tables. | Actual data reads, signed-offset target validation and code/data metadata. Catalog membership alone is insufficient. |

- **QG1**: Pass. Factual source, ABI, state and control-flow analysis requires no normative content.
- **QG2**: Pass. IE-A1..IE-A7 give premises, dependencies and falsification probes.
- **QG3**: Pass for this increment. Entry/probe/bounds, strict auxiliary frontier, sampled environmental paths, relative table, typed allocation and one complete inner/adapter error return are covered. The full goal remains active.
- **QG4**: Pass. Byte extents, u32 wrap semantics, signed i32 offsets, 16*4=64 B table, 22,279*4=89,116 B envelope and retained/reproduced visit accounting are explicit.
- **QG5**: Pass. Undefined source bytes, symbolic preservation, environment fixtures, file values, private/native execution and path-specific/all-path header preservation remain distinct.
- **QG6**: Pass. Original bytes/chains, pinned receipts, source equations, exhaustive tables and independent epochs provide scoped provenance.
- **QG7**: Pass. Remaining allocation, environmental, state-lifecycle, cleanup, code/data and native-pairing work is bounded and impact-ranked above.
