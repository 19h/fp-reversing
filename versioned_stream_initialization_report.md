# Selector-21 stream initialization, scan control and typed cleanup

The pending 32 B allocation now has a source-only continuation through its null check, backward byte scan, stream-object construction and rejection cleanup. With a declared fresh object, eight retained baseline/generated-word cases skip three `0xcd` bytes, find `0x4d` at input-B offset 12 and initialize 28 B of the object. Four changed-block cases reach pending typed cleanup without initializing the object. Twelve separate null-return controls store encoded dispatcher result `0xce515bb2`. Neither allocator nor free executes. The baseline path stops before another unspecified frame read, at `0xfffffe000a5a731c`. [SI1-SI7]

```text
pending typed allocation -> declared return
  null  -> encoded dispatcher result -> stop before epilogue
  fresh -> backward scan over 0xcd
             +-> other final byte -> pending typed free
             +-> 0x4d marker -> initialize stream -> mode/position guards
                                                   -> copy symbolic W24
                                                   -> STOP before FP-0xe8 read
```

Subsequent continuation: the [stream-word report](versioned_stream_words_report.md) leaves these strict prefixes unchanged and introduces coherent arbitrary frame-byte origins in a separate source model. It resolves three reader words and output-B preparation before the next allocation without selecting missing frame values. Native initialization and complete processing remain unknown.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SI-A1 | The pinned original KC, normalized kext and preceding receipts identify these builds and byte epochs. All joins depend on it. | Fresh source-byte equality and hash checks; changed builds invalidate address/ABI correspondence. |
| SI-A2 | The allocation call returns either a fresh distinct 32 B object or null under an ordinary preserved-register ABI. Each source-only case depends on its labeled return fixture. | Two object placements; overwrite X1-X18 with independent arbitrary symbols and retain W24's unresolved origin. No native success/failure feasibility is asserted. |
| SI-A3 | A successful allocation provides writable storage, initially unspecified in this model. Object construction depends on that storage premise. | No heap-byte seeds, zeroing or allocator memory writes; only original constructor stores define the first 28 B. Tail bytes remain unspecified. |
| SI-A4 | Fixed guest cells, input-B and the declared object retain their stated ownership without unexpected aliases. Memory joins depend on it. | Independent ordered byte-epoch reconstruction, strict private-read checks and two placements. Native input/output buffer aliasing remains unknown. |
| SI-A5 | Source-selected scalar phases are the established mode-2 operation, with input count 16 B. Retained path observations depend on them. | Baseline, block-bit and generated-word-bit profiles from two daemon fixtures; universal equations separately quantify u32 count, position and mode. Conditional equations do not establish other modes' admission. |
| SI-A6 | The unresolved W24 word remains an unconstrained u32; the next frame word is unspecified. Continuation limits depend on these origins. | Copy W24 symbolically into the stack; stop before the first new unspecified read. Do not initialize either original frame location or continue the guest. |
| SI-A7 | Matching type-view fields identify compatible static allocation/free descriptions, conditional on native allocator bookkeeping and valid authentication. Cleanup interpretation depends on it. | Original chains, exact name/size/flags and pointer targets agree; distinct view addresses and unknown runtime pointer fields are retained. |

## Backward scan and constructed object

The source encodes the input count N as `N+0x13496211` in body SP+`0xac`. It loads that word at `0xfffffe000a5a6fd0`. At each scan iteration, the original instructions at `0xfffffe000a5a702c..0xfffffe000a5a7034` compute index i and the decremented encoded position, then read D[i]. The byte comparison is against `0xcd` at `0xfffffe000a5a7038`; the first different byte is compared against `0x4d` at `0xfffffe000a5a7084`. The loop's zero-position guard prevents another backward iteration after i=0. These are source-defined byte tests, without an assigned external format or cryptographic algorithm name. [SI2-SI4]

| Retained input-B after the block helper | Source scan | Declared successful-allocation outcome |
| --- | --- | --- |
| Baseline or generated-word bit change | offsets 15,14,13: `0xcd`; offset 12: `0x4d` | Initialize the stream object; continue through the mode/position guards. |
| Input block bit change | offset 15: `0xda` | Branch to cleanup; no stream-field stores occur. |

Let C be the fresh object, D the input-B pointer, N the input byte count and i the `0x4d` marker position. The constructor at `0xfffffe000a5a708c..0xfffffe000a5a70fc` establishes the following fields. All scalar arithmetic is modulo 2^32. [SI3-SI4]

| Offset / width | Source-defined initial value | Retained baseline value / role |
| --- | --- | --- |
| `+0x00` / u64 | D | Input-B pointer; storage ownership is unchanged. |
| `+0x08` / u32 | `N*0x13509fb7+0x4552bd62` | `0x7a5cb8d2`; reversible encoding of count 16. |
| `+0x0c` / u32 | `i+0x13496211` | `0x1349621d`; encoded marker position 12. |
| `+0x10` / u32 | `0x0c69aa47` | Initial control word; complete meaning unknown. |
| `+0x14` / u32 | `0xbd904c36` | Initial control word; complete meaning unknown. |
| `+0x18` / u32 | `0x31ae0066` | Initial encoded status; not the final provider result. |
| `+0x1c` / 4 B | No source definition in this model | Unspecified; no read of these bytes is credited. |

The count encoding is bijective over u32: `(C[8]-0x4552bd62)*0x472d6e07=N`, modulo 2^32. This is a proved mathematical inverse of the constructor expression; later decoder use is not asserted. Four original instructions, including two STP instructions, perform six scalar stores defining the first 28 B. No assumed allocator zeroing supplies them. [SI3-SI4]

The following original guards remain distinct:

| Original decision | Selected table index / target | Retained mode-2 path |
| --- | --- | --- |
| Unsigned mode > 1, guard ending `0xfffffe000a5a7124` | true `0xe05` -> `0xfffffe000a5a7128`; false `0x783` -> `0xfffffe000a5a80d0` | true |
| Unsigned marker position < 8, guard ending `0xfffffe000a5a7188` | true `0xd54` -> `0xfffffe000a5a718c`; false `0xd36` -> `0xfffffe000a5a72bc` | false, because i=12 |

At `0xfffffe000a5a7318`, the latter path stores the unresolved W24 symbol to SP+`0x134`. It next reaches `LDUR W13,[FP,#-0xe8]` at `0xfffffe000a5a731c`, equivalent to body SP+`0x168`; all four bytes are unspecified. This is the selected path's first new frame frontier. The SP+`0x148` read in another earlier-inspected source block is not the first unknown read on this path. The original guest remains stopped before its earlier SP+`0x130` load throughout this analysis. [SI2-SI4]

## Kernel allocator and cleanup interfaces

Four compiler-bounded kernel functions, 66 instructions / 264 B, expose the next layer of the ABI. They are inspected from original bytes without execution. [SI5]

| Function entry / KC symbol | Original behavior relevant here |
| --- | --- |
| `0xfffffe000c4ba154` / `_IOMallocTypeImpl` | Reads u32 type flags at X0+`0x28`; sets W1 to `0x8004` if bit `0x10` is clear, otherwise 4; tail-calls `_kalloc_type_impl`. |
| `0xfffffe000bcfeb8c` / `_kalloc_type_impl` | Reads two runtime view pointers and thread-local state; masks incoming flags to their low three bits; selects deeper allocation paths. First-pointer state and thread context are native inputs. |
| `0xfffffe000c4ba368` / `_IOFreeTypeImpl` | Tail-calls `_kfree_type_impl`, preserving the view and object arguments. |
| `0xfffffe000bcff010` / `_kfree_type_impl` | Branches on the view's runtime first pointer; otherwise chooses among three global contexts from flags, derives low24 size and transfers to the deeper free path. |

For the stream view, flags `0x64` select raw W1=`0x8004`; the implementation's low-three-bit projection is 4. No version-matched flag-name definition, native allocator success, native zeroing or failure feasibility is claimed. Zone/accounting roles for the first two view pointers are an interpretation of the typed allocator context; their native values and exact structure-field correspondence remain unknown. The original view's zero bookkeeping bytes do not establish its native post-initialization values. The null-return cases are counterfactual return controls for the caller's explicit null branch. [SI3,SI5]

| Cleanup contract | Recovered value |
| --- | --- |
| Pending call | `0xfffffe000a5a7274`, `_IOFreeTypeImpl` at `0xfffffe000c4ba368`, modifier `0x4d6a` |
| X0 / free view | `0xfffffe000847b720` |
| X1 | Same fresh 32 B object pointer returned by the declared allocator fixture |
| Allocation view | `0xfffffe000847b320` |
| Both views' name / flags / size | `site.FPByteArrayStreamInternal` / `0x64` / 32 B |
| Both views' two static pointer targets | Equal, including the name and ASCII `1222` pointers |
| Runtime pointer-field equivalence, release and object lifetime completion | unknown |

Two additional bank identities exhaust 512 byte inputs to recover the cleanup function and free view independently of their obfuscation input byte. Four pending cleanup pointer records and 76 performed source-slice transfers agree with original target/authentication metadata. Nine further static control-slot records qualify the conditional branch equations. Native PAC is not tested. [SI3-SI6]

| Caller result path | Encoded dispatcher word | Conditional wrapper XOR decoding |
| --- | --- | --- |
| Declared null allocation | `0xce515bb2`, actually stored in all twelve null controls | `0xffff5bd4` |
| Changed-block rejection, if the pending free returns normally | `0xce515bbf`, proved from post-call source | `0xffff5bd9` |

The wrapper decoder XORs with `0x31ae0066`. The changed-block free remains unexecuted; its post-return result is conditional. Neither row establishes a completed outer wrapper/UserClient return or output-count update. No output user span, new Mach port, right transfer or emission site is produced by these slices.

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| SI1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. |
| SI2 | Preceding dispatcher-frame receipt SHA256 `f33cd61a5e74dc26f8f62af789a24d0d431b3ec50e23c364373e269efb1e0c80`; preparation receipt `b5a8adb34c380be6daf899d7b481a7a55e7e814b353ee24a39c076f88d781941`. All original private prefixes remain unchanged. |
| SI3 | [Extractor and source interpreter](triage_evidence/recover_versioned_stream_initialization.py); eleven fresh UNSAT obligations / 95 lifted instructions; explicit allocator-register clobbers and arbitrary-word provenance. |
| SI4 | [Compressed receipt](triage_evidence/versioned_stream_initialization_checks.json.zst): 24 cases, 2,124 post-call source instruction visits, 1,556 read bytes and 816 write bytes, including eight symbolic 4 B stack copies. The repeated preceding slices are recorded separately. |
| SI5 | Original compiler-bounded kernel wrappers/implementations, symbols, both 64 B type views and their original chained pointer records, retained in the receipt. |
| SI6 | Two exhaustive cleanup bank identities / 512 inputs, 76 authenticated source-slice transfers, four pending cleanup pointers and nine static guard slots. |
| SI7 | [Publication verifier](triage_evidence/verify_versioned_stream_initialization_publication.py): fresh source-case equality, frozen SMT checks, independent ordered byte epochs and final snapshots, model/unknown controls, compression and decoded-path hygiene. No IDA access was needed because the original sources suffice. |

Run the extractor, compress its receipt with zstd level 22 after verifying round-trip equality, then run the publication verifier with the project's pinned Python dependencies. Cost is O(receipt bytes+C*V+I+256R) time/space plus solver cost, capped at 30 s/query. Each post-call case is limited to 1,000 source instructions. Native calls and new guest execution remain absent.

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Establish FP-`0xe8` provenance and continue the selected stream consumer. | Source-defined predecessor epochs, field consumers and remaining unknowns; no private-fill substitution. |
| High | Recover typed allocator initialization and actual lifetime pairing. | Initialization and exact field correspondence of the view's first two pointers, matching build flags and a recorded allocation/release epoch. |
| High | Establish native daemon/UserClient connection ownership and pairing. | Matching task/connection/right epoch and an actual transaction. |
| Medium | Identify the complete byte-stream format. | Additional field/reader transitions and independent valid-format evidence; delimiter bytes and a type name alone are insufficient. |

- **QG1**: Pass. Factual source/interface analysis requires no normative content.
- **QG2**: Pass. SI-A1..SI-A7 register premises, dependent results and falsification probes.
- **QG3**: Pass for this increment. Stream data/control fields, caller result paths and deeper allocation/free ABI are covered; the full goal remains active.
- **QG4**: Pass. Byte extents, u32 modular arithmetic, unsigned guards, source counts and complexity are explicit.
- **QG5**: Pass. Actual retained prefixes, declared allocation returns, symbolic source writes, pending free and native state remain distinct.
- **QG6**: Pass. Original bytes, compiler metadata, chained pointers, frozen receipts and symbolic models are separately traceable.
- **QG7**: Pass. Additional data/control/environment and native ownership work is bounded and impact-ranked above.
