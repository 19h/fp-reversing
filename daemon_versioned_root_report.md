# Daemon versioned root: admission, frame, allocation and retirement

The source entry at `0x10049f358` encloses the previously inspected constructor at `0x100552dac`. Its prologue establishes the frame and its source setup establishes the phase, bank roots and buffer offset; those values no longer require an interior constructor overlay. Sixteen original-byte paths cover two retained state epochs, null inputs, allocation failure and five capability settings. Every selected path reaches the enclosing return boundary at `0x100309d10`.

The first private helper allocates 32 B and initializes 28 B. The later helper at `0x100439874` checks a pair of pointers, skips the null member, overwrites all 32 B of the allocated member in descending address order and reaches the matching `_free` call. These observations establish local construction and retirement roles under the stated fixtures. They do not establish native admission of the caller record or a daemon/kext transaction: none of the sixteen paths visits the independently recovered IOKit call at `0x100478a04`. The full investigation remains active.

Primary evidence: [producer](triage_evidence/recover_daemon_versioned_root.py), [source, proofs and complete journals](triage_evidence/daemon_versioned_root_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_versioned_root.py), [replay and interface receipts](triage_evidence/daemon_versioned_root_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_versioned_root_publication.py). Parent evidence: [constructor/emitter](daemon_versioned_header_report.md), [versioned request ABI](versioned_request_abi_report.md), [retained callback epochs](daemon_callback_revisit_report.md), [Mach port index](mach_ports_report.md). Original thin daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

Addresses use preferred image base `0x100000000`. B denotes bytes. Arithmetic wraps at the stated u32/u64 width. `F` denotes SP after the enclosing prologue, `R` the incoming caller record, `I=F+0x8d8` the reused inner record, `P=F+0x698` the pointer pair and `A` the modeled allocation. These are private fixture addresses, not recovered native addresses.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| VR1 | The original image, ten parent receipt hashes and fourteen source dependencies identify this analysis. | Rehash all inputs, compare the seven retained source regions, each journal opcode and every used original fixup/import word. |
| VR2 | The two retained epochs are restored from sealed prefixes of 121357 and 145961 visits. They are environment inputs to this new root execution. Native startup and root admission remain unknown. | Check prefix opcode/read consistency, independently restore their effects and vary physical unknown backing. A compatible native entry capture would test admission. Prefix visits are excluded from new execution totals. |
| VR3 | Caller records decode to operation `0x871a` and numeric count 16; nonnull input fixtures contain 256 B of zeros. The fixture label `decoded_count_B` declares a length hypothesis, not a complete public length contract. | Prove numeric key inversion and the source null-pair gate; run separate null-A/null-B controls and retain exact input extents. Other counts, operations, input contents and native producers remain separate domains. |
| VR4 | Fresh private frames contain unspecified bytes until source or declared input overlays define them. The allocation is a disjoint 32 B subrange of the private heap fixture. | Independent replay uses two different physical realizations. Reject unknown-dependent arithmetic/control, reads before definition of allocation bytes and allocation accesses outside the modeled lifetime. |
| VR5 | Native `_malloc` and `_free` are replaced by explicit return/lifetime models. | Check original call opcode, bind, modifier and X0; test null and nonnull allocation returns. Clobber X0-X17, unspecified vector portions and NZCV; preserve SP, X18-X29 and low 64 bits of Q8-Q15. Replay both physical clobber patterns. No native allocator behavior is claimed. |
| VR6 | PAC instructions denote logical source transfers and unchanged return tokens. | Independently check targets, modifiers and X30. Stop before terminal RETAB to the external token; hardware signing/authentication is unknown. |
| VR7 | Source algebra uses fixed symbolic cells with disjoint record, pair and allocation objects. | Fresh negated source obligations are UNSAT; allocation/header projection is conditional on object separation. Concrete fixtures independently check every access address and byte effect. Aliasing callers require a separate analysis. |
| VR8 | The constructor's zero frame adjustment and subsequent capability paths are finite results for the ten allocation-success cases. | Follow original source from the enclosing entry without an interior PC injection; verify SP at constructor return, source-created roots and final restored registers/SP. Retain the earlier general nonzero-adjustment formula. |
| VR9 | No new port/emission finding covers only the new source paths and their two modeled C API sites. | Enumerate all internal authenticated calls and API boundaries; verify absence of `0x100478a04`. Data import reads do not establish port acquisition, right transfer or message emission. |
| VR10 | Returned u32 values and working modes are source results, without assigning public error names. | Retain exact stores and per-case results. A matched caller/consumer and compatible native observation would establish their external interpretation. |

No matching live daemon IDB is asserted in this increment. The original image and retained receipts suffice for the claims below; no IDB annotation or native target execution occurs.

```text
declared R, seed cell, input fixtures + sealed image/state epoch
                            |
0x10049f358: root prologue; decode R; increment seed; check input pair
             | null                         | nonnull
             v                              v
       opaque result                0x1003af998 -> 0x100455c30
                                             |
                                  0x100455e58: modeled malloc(32)
                                     | null       | allocation A
                                     |            v
                                     |      initialize A; pair=(A,0)
                                     |            |
                                     |      source setup -> constructor
                                     |      -> byte emitter -> capability route
                                     |            |
                                     |      0x1004bfb58 -> 0x100439874
                                     |      pair[1]=0: skip
                                     |      pair[0]=A: overwrite 32 B
                                     |      0x1002dc500: modeled free(A)
                                     |            |
                                     +------------+
                                             |
0x100309cd8: store u32 result at R+8; check canary; restore frame
0x100309d10: STOP before RETAB to external return token

IOKit call 0x100478a04: not visited in these cases
```

| Frame / interface location | Source-established meaning | Limit |
|---|---|---|
| Entry `0x10049f358`; prologue through `0x10049f378` | Save area 96 B plus local reserve 2336 B: entry SP=`F+0x980`, FP=`F+0x970`. | Source frame identity; actual native SP value unknown. |
| FP-0x98=`F+0x8d8` | Inner record reused by initializer, emitter caller and retirement caller. | Field meaning changes by call epoch. |
| FP-0x60=`F+0x910` | Saved canary, checked against the original guard import before return. | Logical guard fixture; native stack protection not exercised. |
| X0 / X1 on root entry | X0=R; X1 points to a u64 cell incremented by `0xb0` at `0x10049f4a0..0x10049f4a8`. | Increment is a u64 value, not a byte extent. |
| R+0 / R+4 | Encoded u32 count / encoded u32 operation. | Exact numeric decoder below; full public record ABI unknown. |
| R+0x10 / R+0x18 | Two u64 input pointers, tested for null by `CMP/CCMP` at `0x10049f530..0x10049f534`. | Full pointee semantics/required extents unknown. |
| R+8 at `0x100309cd8` | Returned opaque u32, source carrier W28. | Public status names unknown. |
| `F+0x2a0`, store `0x1003af98c` | Saved scalar operation `0x871a`. | This cell is not a global-root pointer. |
| `F+0x80`, `F+0x3f0` | Source-created state pointer `0x1010b6380` and u64 capacity 552 B. | Capacity declaration does not prove a full transmitted buffer. |
| X20 before `0x100552dac` | Literal offset 16 B from source setup at `0x100634c20`. | This removes the earlier declared-offset premise for these cases. |
| `F+0x3f8`, `F+0x480`, `F+0x488` | Saved construction views B, B+16, B+32, where B=`F+0x600`. | Identity with the later API's current-base+0x10 remains unknown. |
| `F+0x698`, `F+0x6a0` | Source pointer pair `(A,0)`, initialized before the constructor. | These slots lie inside the declared 552 B construction view; a whole-frame write is not automatically a wire field. |

The original record key at `0x10049f4ac..0x10049f508` is:

```text
x   = u64(R XOR 0xadef4a231bdba15d)
K64 = u64((u64(((x<<1) OR 0x3920867a64d1a5ec)
              -x+0xe36fbcc2cd972d0a) XOR 0xde4326985541f84b)
          *0x83918153)
operation = u32(raw_u32[R+4] - low32(K64))
count     = u32(raw_u32[R+0] + low32(K64))
```

The fixture encoder inverts these modular operations. Operation `0x871a` plus two nonnull inputs reaches the initializer. Null-A and null-B paths return without allocating. This is a source-local admission result under VR2-VR4, not proof of a native caller producing this record.

| Boundary | Incoming contract / emitted effect | Original slot and modifier |
|---|---|---|
| `0x1003af998 -> 0x100455c30` | X0=I; I+8=P; address-coded control at I+0x10 decodes to `u32((operation XOR 0xb3e0)+0x8322)`, equal to `0xb81c` in these cases. | `0x1010a03d0`, IA `0xe280`. |
| `0x100455e58 -> _malloc` | X0=32 B. Model returns either zero or A. | `0x10109ff58`, IA `0x6aa4`, `libSystem/_malloc`. |
| `0x100455e5c..0x100455e80` | For decoded control `0xb81c`, nonnull result selects index `0xb81c` / initializer block `0x10031cb3c`; null selects `0xb851` / return block `0x1004b1d68`. | Original source dispatch and fixups. |
| `0x100552ef8 -> 0x100add594 -> 0x100acd9c4` | Source-packed inner record requests 4 B at F+0x2d4; constructor continuation observes zero SP adjustment in all ten success cases. | Existing constructor/emitter contracts retained. |
| `0x1004bfb58 -> 0x100439874` | Reused inner record names P. Pointer tests at `0x1001c00fc/0x1001c0104` first read P+8=0, then P=A. | `0x1010a07c8`, IA `0x905f`. |
| Byte store `0x10028db6c` | Exactly 32 one-byte stores to A+31 through A, before the matching free. | Complete finite source journals and independent replay. |
| `0x1002dc500 -> _free` | X0=A, exactly the modeled 32 B allocation; SP=`F-0xd0` inside the retirement helper. | `0x10109ff30`, IA `0x46a2`, `libSystem/_free`. |
| `0x100309cd8..0x100309d0c` | Store result at R+8, pass canary comparison, restore X19-X29 and entry SP. | Return boundary is before `0x100309d10` RETAB. |

Initializer stores at `0x10031cb60..0x10031cb88` establish the following object and pair. The source proof uses disjoint objects as specified by VR7.

| Object offset | Width B | Initialized value |
|---|---|---|
| A+0 | 8 | P+0x30 |
| A+8 | 4 | 0x8b3dc479 |
| A+0x0c | 4 | 0x8b3dc479 |
| A+0x10 | 4 | 0x8b3dc651 |
| A+0x14 | 4 | 0x4d8916dd |
| A+0x18 | 4 | 0x8b3dc651 |
| A+0x1c | 4 | Unwritten by initializer; unspecified |
| P+0 | 8 | A |
| P+8 | 8 | 0 |

Later source reads and modifies initialized fields. Retirement overwrites the entire allocation, including its initially unspecified trailing four bytes, without reading those bytes first. No access to the allocation occurs after the modeled free. The overwrite bytes are not all zero; this report assigns no cryptographic or erasure guarantee to them. The new pair-retirement role is established for these complete paths; other control values, two populated members and aliasing pairs remain untested domains.

| Variant in each retained epoch | Decoded capability | Working mode | Source visits, epoch0 / epoch1 | Returned u32 | Construction-view bytes written over whole path |
|---|---|---|---|---|---|
| null_A | 0 | Not reached | 166 / 166 | 0x74c29d88 | Not constructed |
| null_B | 0 | Not reached | 166 / 166 | 0x74c29d88 | Not constructed |
| malloc_failure | 0 | Not reached | 379 / 379 | 0x74c29d85 | Not constructed |
| clear1 | 0 | 1 | 16532 / 16532 | 0x74c29d80 | 16 B |
| clear2 | 0x2 | 2 | 16532 / 16532 | 0x74c29d80 | 16 B |
| clear6 | 0x42 | 6 | 16532 / 16532 | 0x74c29d80 | 16 B |
| prefix | 0x8 | 2 | 17280 / 17280 | 0x74c29d85 | 48 B |
| extended | 0x28 | 5 | 89033 / 75035 | 0x74c29d85 | 48 B |

The source establishes the working modes previously isolated in the versioned ABI report. The extended cases execute five additional pairs of internal calls `0x100487194 -> 0x10041a5e0` and `0x100476aec -> 0x100427514`. Different epoch path lengths remain in the evidence; no whole-transform formula or universal termination claim follows from the samples. Returned values are opaque source words rather than named OS errors.

All allocation-success cases have 16 construction-view bytes already written before constructor entry: the pointer pair. Clear capability paths add no other writes in that 552 B view; prefix/extended paths bring total distinct source-written coverage to 48 B. The earlier isolated constructor report correctly observed zero writes in its own narrower region. These whole-root results therefore do not establish definitions for a complete 552 B request or the later API buffer identity.

There is no new incoming Mach port, outgoing destination, right descriptor or Mach emission site on these paths. The original data bind at `0x1010a39c8` names `_mach_task_self_` with import-table addend `0x7bf13863`; it is a read data import, not an invocation or message emission. Its nonzero addend is decoded and retained rather than passed through the older zero-addend-only verifier. The two modeled external calls are allocator interfaces. Existing port mappings remain in the Mach index; the selector-21 call contract remains a separate parent result.

Validation covers 16 producer cases and 299242 new source visits, 55189 read events, 15473 write events and 22 explicit allocator models. Thirty-two independent A64 replays check 598484 source visits, 518050 register effects, 561890 read B, 138618 written B and 44 allocator model boundaries. The reported sum of 30180 source-pool instruction entries is per case and includes decoded pending API/terminal boundary instructions; it is not a union count of executed instructions. Seven additional contiguous source regions retain 428 instructions / 1712 B. The nine fresh negated source obligations are UNSAT. The initializer-control proof composes a separately proved preproduct key identity with the original multiply/decode tail; it does not rely on a timed-out monolithic query.

The source engine preserves unspecified byte identities and rejects their use in arithmetic/control. The allocator model makes volatile GPR/vector/flag state unspecified rather than preserving incidental concrete values. Independent replay supplies two physical realizations of those unspecified values. Zero unspecified bytes are copied by the newly executed memory stores in these cases; register clobber realization is an emulator control, not a native sample. Prefix restoration, native APIs and terminal hardware authentication are excluded from the execution counts. Producer/auditor cost is O(snapshot+prefix+patterns*(visits+effects)) time/space; solver queries have a 30 s bound.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Establish producers/callers of entry `0x10049f358`. | High | Derive R, seed cell, decoded operation/count and valid input owners from an upstream source path or compatible native capture. |
| Explain returned-word consumers and the paths that actually reach IOKit. | High | Connect one coherent root/adapter path to selector21, match the buffer base/count/status cells and account for every required byte before asserting a transmitted request. |
| Generalize private pair retirement. | Medium | Prove control admission, both-nonnull and alias behavior, overwrite extents and exact owner retirement beyond the selected `(A,0)` fixtures. |
| Reduce extended preparation loops. | Medium | Replace finite repeated helper visits with source-derived transforms and bounded input/epoch premises. |
| Establish a compatible daemon/kext runtime pairing. | High | Match image identities, service/connection provenance and observed method/message events; numeric selector/size agreement is insufficient. |

Quality gates for this bounded increment:

- **QG1**: No normative premise is required.
- **QG2**: VR1-VR10 enumerate assumptions, dependent claims and falsification probes.
- **QG3**: Root/helper roles, local incoming/outgoing contracts, allocation lifecycle, frame/data/control flow, environment and IPC limits are covered. The full investigation remains active.
- **QG4**: Modular widths, byte extents, value increments and source/replay/model counts are distinct and reproducible.
- **QG5**: Initialization covers 28 B; retirement covers 32 B. The pair tests both null and nonnull cells. Source frame recovery does not establish native record admission. The construction/API join remains unknown.
- **QG6**: Original image, receipt/dependency hashes, source opcodes, fixups, source queries and independent CPU/RAM effects provide provenance. Native API/PAC and matching live-IDB evidence are unknown.
- **QG7**: The continuation table bounds and ranks caller admission, request joins, retirement generalization, transform reduction and native pairing.
