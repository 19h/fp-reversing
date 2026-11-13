# SIDB descriptor, metadata-size and failure-cleanup contracts

The SIDB open adapter saves the low32 return bits and classifies them as a signed integer. Nonnegative returns, including descriptor0, are forwarded to `fstat`; negative returns request the borrowed errno cell. A zero fstat result loads an eight-byte metadata word directly into a pending malloc request. The current SDK identifies that word as `struct stat.st_size`. A nonzero fstat result instead requests close on the saved descriptor and produces raw status`0x74c29dd3` under the retained close controls. No target API, allocation, file read, native descriptor acquisition/release or daemon-kext pairing is observed. [SM1-SM6; SM-A1-SM-A8]

```text
pending open(SIDB_path, flags110, stack_zero)
  + declared int32 return; errno[4] becomes unknown
  |
  +-- signed return < 0 -> ___error -> unknown errno32
  |                        + supplied errno2 -> status74c29dd1
  |                        + all other errno -> status74c29dd3
  |                        -> pending common malloc(64)
  |
  +-- signed return >= 0 -> fstat(saved_descriptor, stat_buffer)
                            + declared int32 return
                            + stat[144] and errno[4] become unknown
                            |
                            +-- result == 0 -> unknown stat+96 word[8]
                            |                  + supplied size64
                            |                  -> pending malloc(size64)
                            |
                            +-- result != 0 -> close(saved_descriptor)
                                               + declared int32 return
                                               + errno[4] becomes unknown
                                               -> status74c29dd3
                                               -> pending common malloc(64)
```

Descriptor7 is the selected full fstat continuation. Descriptor0 and`0x7fffffff` are retained through the pending fstat request; their fstat returns are not supplied. All 128 inherited open states cross both new ABI clobber patterns. The six size controls and positive return perturbations are explicit counterfactual register/output premises, not native observations. [SM2-SM4; SM-A2-SM-A6]

| Evidence | Primary artifact and scope |
| --- | --- |
| SM1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original bytes/fixups and source states retained by the [extractor](triage_evidence/recover_daemon_state_file_metadata.py). |
| SM2 | [Admission report](daemon_state_file_admission_report.md) and [parent checks](triage_evidence/daemon_state_file_admission_checks.json.zst):128 exact pending open states, ten pathname objects and inherited definedness masks. |
| SM3 | [Current checks](triage_evidence/daemon_state_file_metadata_checks.json.zst):256 contexts,6400 source intervals, API/output premises, original opcodes, GP/Q/NZCV/SP states and byte events. |
| SM4 | [Independent auditor](triage_evidence/audit_daemon_state_file_metadata.py) and [audit](triage_evidence/daemon_state_file_metadata_audit.json.zst): independent replay, state joins, metadata invalidation and nine nonvacuous source equations. |
| SM5 | [Compile-only ABI probe](triage_evidence/daemon_state_file_metadata_abi.c); canonical SDK-relative header hashes, portable command and emitted assembly retained in SM3. Historical ABI equivalence is unknown. |
| SM6 | [Publication verifier](triage_evidence/verify_daemon_state_file_metadata_publication.py): exact coverage, fresh contracts/equations/SDK comparison, decoded-payload path scrub, preserved inputs and exact publication delta. |

## Signed descriptor classification and argument forwarding

The inherited call chain supplies the incoming architectural context. These are phase-specific source roles; complete recovered function types and general call coverage remain unknown. The private adapter record and heap SIDB pathname object have distinct addresses, so their respective+28 fields are not the same storage. [SM1-SM4; SM-A2,SM-A7,SM-A8]

| Original callee entry | Incoming original call / IA | Retained record role |
| --- | --- | --- |
| 0x10043d044 | 0x100689800 /0xa499 | X0=0x6800070db8, reused caller record; current raw status later stored at+16. |
| 0x100d3e6d8 | 0x10043d324 /0xc037 | X0=0x68000600b8, private adapter record; X1=0x68000600a8, separate adapter cell; its full type is unknown. |
| 0x100d3d658 | 0x100d3e940 /0x7dde | X0=0x68000600b8, same private adapter record; X1=0x680005ffd0, separate adapter cell; its full type is unknown. This phase contains the open/fstat/allocation/close sites. |

At the inherited pending open site`0x100d8ff74`, SP is`0x680005fe50`. Source`0x100d8ff80` stores W0 to SP+`0x5c`=`0x680005feac`. Under the recorded phase W20=`0x8d4d`, the threshold computed by`0x100d8ff78..7c` is zero modulo2^32. The signed comparison at`0x100d8ff84` and subsequent flattened dispatch choose the negative branch exactly when bit31 is set. The all-u32 equation covers all return bit patterns and the saved-word store; arbitrary upper32 int-return fixtures do not become descriptor bits. [SM1-SM4; SM-A3-SM-A5]

| Supplied open return32 | Signed interpretation | Table index / original target | Next request |
| --- | --- | --- | --- |
| 0xffffffff | -1 | 0x6883 /0x100d9e2ec | ___error at0x100d9e364 |
| 0x80000000 | -2147483648; synthetic boundary control | 0x6883 /0x100d9e2ec | Same accessor |
| 0x00000000 | 0 | 0x68c1 /0x100c22c28 | fstat descriptor0 |
| 0x00000007 | 7 | 0x68c1 /0x100c22c28 | fstat descriptor7; fully continued |
| 0x7fffffff | 2147483647; synthetic boundary control | 0x68c1 /0x100c22c28 | fstat same low32 value |

The original authenticated branch is`0x100d8ffa8`, IA`0xcf29`. The nonnegative route sets X1=SP+`0x68` at`0x100c22c9c`, reloads W0 from the saved word at`0x100c22ca0`, and reaches fstat at`0x100c22ca8`, IA`0x5e4e`. The all-u32 argument equation proves zero extension into X0 and the exact output pointer; the descriptor's semantic type is signed32 at the API boundary. No descriptor has been stored in the SIDB object through these retained intervals. In particular, its field+28 remains`0xffff5b81`, inherited from the previous report. [SM1-SM5; SM-A3-SM-A7]

## Errno and status records on the negative-open route

Every supplied open return invalidates all four borrowed errno bytes. The -1 route requests `___error` at`0x100d9e364`, IA`0x6e96`; its declared pointer return reuses E=`0x6600020000`, adding neither ownership nor a value. A zero-visit interval then stops before the four-byte read at`0x100d9e368`. The second negative control stops at the accessor request without a supplied accessor return. [SM1-SM4; SM-A3,SM-A4,SM-A6]

The original block`0x100d9e368..0x100d9e380` chooses W25=`0x74c29dd1` exactly for errno2 and W25=`0x74c29dd3` for every other u32. The retained values are0,2,13 and`0xffffffff`. The preceding report's current-SDK `ENOENT=2` supplies the missing-path terminology; this report proves the original numeric mapping. All combinations remain supplied scalar controls. [SM1-SM5; SM-A4-SM-A6]

| Original store site | Destination in the retained phase | Value role |
| --- | --- | --- |
| 0x100ccedd4 | 0x68000600d4 = adapter_record+28 | Raw status32 from W25 |
| 0x10043d33c | 0x6800070dc8 = reused caller_record+16 | Raw status32 from private adapter output |
| 0x100712c9c | 0x68000659b4 | Raw status32 carried into the outer continuation |

Each retained errno continuation reaches the common call`0x1007106f0 -> 0x100436378`, IA`0x58a3`, then pending malloc(64) at`0x100710758`, IA`0x6aa4`. The three status stores are verified separately from ordinary GP return values. This caller-record+16 channel differs from the earlier lstat failure's caller-record+8 channel; reused record addresses do not imply a single immutable record type. The64 B allocation's result, payload and ownership remain unknown. [SM1-SM4; SM-A4,SM-A6-SM-A8]

## Fstat output definedness and exact size transfer

For descriptor7 the pending fstat output pointer is S=`0x680005feb8`, different from the previous lstat output address. Every modeled fstat return invalidates S..S+143 and all four errno bytes, including prior fixture fragments and private known-byte masks. No metadata value is retained from the earlier stack representation. The current SDK comparison gives `sizeof(struct stat)=144 B`, `offsetof(st_size)=96 B`, `sizeof(st_size)=8 B`, signed off_t64 and size_t64. These are compile-only current ABI facts; historical runtime layout remains SM-A5. [SM1-SM5; SM-A3-SM-A5]

Source`0x100c22cac..0x100c22cc8` partitions every u32 fstat return at zero. Index`0x44e5` reaches`0x100ce1cc4` for zero; index`0x44d3` reaches`0x100ac8ae8` for every nonzero. The original authenticated branch at`0x100c22d00` uses IA`0x37cb`. Concrete controls are0,`0xffffffff` and1;1 is a perturbation, not a native success or error result. [SM1-SM4; SM-A3-SM-A5]

The zero route stops before`0x100ce1d20`, `LDR X0,[SP,#0xc8]`, demanding exactly S+96=`0x680005ff18`, width8 B, with an all-unknown mask. Supplying only those eight bytes leaves the other 136 metadata bytes undefined. The load has an all-u64 identity equation. The next six original instructions do not modify X0 and reach malloc at`0x100ce1d3c`, IA`0x6aa4`, after seven source visits in total. No comparison, clamp, narrowing or sign-extension of that loaded word occurs in this interval. Earlier or later validation and actual filesystem control remain unknown. [SM1-SM5; SM-A3-SM-A7]

The earlier lstat mode demand and this fstat size demand use separate output addresses and separate pending API epochs. No device/inode identity comparison is established by these metadata demands. The source-paired pathname and descriptor requests therefore do not establish that both native operations refer to the same filesystem object. Native identity and contents remain unknown. [SM1-SM5; SM-A2,SM-A4,SM-A5,SM-A8]

| Supplied metadata word64 | Current-ABI off_t interpretation | Pending malloc X0 / size_t64 |
| --- | --- | --- |
| 0x0000000000000000 | 0 B | 0 |
| 0x0000000000000001 | 1 B | 1 |
| 0x0000000000001000 | 4096 B | 4096 |
| 0x0000000100000000 | 4294967296 B | 4294967296 |
| 0x8000000000000000 | -9223372036854775808 B; synthetic | 9223372036854775808 |
| 0xffffffffffffffff | -1 B; synthetic | 18446744073709551615 |

The signed entries explain the ABI bit conversion; they do not assert that a native SIDB file can have those lengths. The unsigned malloc argument preserves the same64 bits. The emitted SDK comparison for `malloc((size_t)metadata->st_size)` is likewise `LDR X0,[X0,#96]` followed by a tail branch to malloc. That comparison supports the ABI interpretation, independently of the original source's stack-based data flow. The allocation is pending and no destination buffer or file-content byte is supplied. [SM1-SM5; SM-A4,SM-A5,SM-A8]

## Failure cleanup and preserved object state

For either nonzero fstat control, source`0x100ac8b24` reloads the saved descriptor word and requests close at`0x100ac8b2c`, IA`0xee56`. Its retained W0 is7. An all-u32 equation proves the reload/IA setup. No fstat errno word is read before that request. Every supplied close return invalidates errno again. The first close-return dispatch`0x100ac8b30..0x100ac8b3c` is independent of W0 for the recorded phase, proved for all u32 return bits. The complete three retained controls0,`0xffffffff`,1 have identical source-write signatures and produce status`0x74c29dd3` through the three records above, then reach pending common malloc(64). [SM1-SM4; SM-A3-SM-A6]

The first-dispatch proof is not a proof of every possible native close effect or every possible later path. In the retained complete continuations, no close errno value is supplied or consumed. Native descriptor closure, lock release, errno provenance, asynchronous interruption and retries remain unknown. The two malloc frontiers have distinct source roles: a metadata-sized request at`0x100ce1d3c` and a 64 B common wrapper request at`0x100710758`. Their equal imported symbol establishes neither equal payloads nor shared ownership. [SM1-SM4; SM-A4,SM-A6,SM-A8]

The preceding source sequence requests release of the heap rwlock before requesting open. Its object+0 lock pointer and the open flags therefore describe separate synchronization interfaces. The current SDK names one open flag `O_SHLOCK`; native descriptor-associated locking and its release require library/runtime evidence beyond the retained pending requests. Neither interface has an established Mach-port representation or kext-facing ownership role here. [SM1,SM2,SM5; SM-A2,SM-A5,SM-A8]

Across all 6400 intervals, every inherited foreign owner other than the explicitly modeled borrowed errno cell retains its exact bytes and undefined gaps. All ten pathname objects therefore remain unchanged, including the SIDB field+28 and all lock representations. Generated J+`0x34` retains its original32 B. No interval reads or writes the previously opaque16 B once control or200 B SIDB lock storage. No new Mach message, port right, IOKit selector, kext call, native epoch join or transport correlation is established. [SM1-SM4; SM-A2-SM-A8]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SM-A1: The pinned original image, logical fixups and decoder describe the analyzed build. | All original-source claims. | Rehash the full image, compare every retained opcode and independently replay GP/Q/NZCV/SP, reads, writes and authenticated edges; any mismatch rejects the affected claim. |
| SM-A2: The 128 parent open states represent the inherited conditional source phases. | Context coverage, pathname/owner state and source continuity. | Join each of32 parent contexts x4 open cases exactly; cross both new ABI patterns. A different caller epoch, nonzero object+8 or other parent invalidates this continuation's applicability. |
| SM-A3: Imported calls return under the modeled ordinary Darwin arm64 ABI. | All post-import continuations and argument forwarding. | Cross two volatile GP/Q/NZCV patterns, retain only defined int low32 bits, preserve callee-saved lanes and check every state join. Nonreturning calls, additional callbacks or alternative ABI effects require separate evidence. |
| SM-A4: API/output premises specify only explicitly supplied effects and scalar controls. | All errno, metadata, descriptor and close-control results. | Invalidate errno on open/fstat/close and all 144 fstat bytes before any scalar supply; demand zero-visit or all-unknown reads. Reject inferred outputs from stale fixture bytes. Synthetic values are not native samples. |
| SM-A5: Current SDK layouts/prototypes are a comparison for the historical image's ABI. | `st_size`, signed off_t/descriptor and unsigned size_t terminology. | Compile exact static assertions and function signatures; retain SDK-relative header hashes and assembly. Compare a matching historical SDK/runtime before claiming native equivalence; until then that equivalence is unknown. |
| SM-A6: Borrowed E and its owner extent are valid under the inherited model. | Errno access and status mapping. | Return the existing full64 pointer without adding an owner or default value; stop before the unknown4 B load and supply only that word. A native TLS pointer or lifetime mismatch rejects the binding. |
| SM-A7: Owner masks and private stack representations retain their recorded phase meaning. | Saved descriptor, unchanged object fields and generated32 B preservation. | Independently compare exact defined-byte maps and gaps for every non-errno owner after each interval; distinguish caller+16 status from the earlier caller+8 channel. Different layouts/epochs require new joins. |
| SM-A8: Pending API sites and local record stores have no assumed native allocation, transport or lifetime effect. | Allocation roles, cleanup requests and architectural exposure boundaries. | Establish an actual allocator return, later read/consumer, native descriptor trace and transaction/epoch join before assigning buffer ownership, object+28 type or daemon-kext delivery. Those facts remain unknown. |

## Reproduction, coverage and receipts

Run with Python, Unicorn, Capstone and Z3 available, with `triage_evidence` on the module search path:

```text
python triage_evidence/recover_daemon_state_file_metadata.py
python triage_evidence/audit_daemon_state_file_metadata.py
zstd --ultra -22 -q -T1 triage_evidence/daemon_state_file_metadata_checks.json
zstd --ultra -22 -q -T1 triage_evidence/daemon_state_file_metadata_audit.json
python triage_evidence/validate_rpc502_sidecar_delivery.py
zstd --ultra -22 -q -T1 triage_evidence/interface_manifest.json
python triage_evidence/verify_daemon_state_file_metadata_publication.py
```

Check archive round trips before removing duplicate plaintext JSON files. The source binary is the original input located by the existing evidence module. The ABI probe compiles from stdin to assembly on stdout; `<SDK>` in the retained command is a portable placeholder resolved at execution. No analyst-machine path is retained in the new report, scripts, decoded interval payloads, archives or commit message. [SM1-SM6]

| Coverage | Exact count |
| --- | --- |
| Inherited pending open states | 128 |
| New contexts:128 parents x2 ABI patterns | 256 |
| Open return controls | 1280 |
| Borrowed errno accessor returns / supplied errno words | 256 /1024 |
| Fstat return controls | 768 |
| Supplied size words / close return controls | 1536 /1536 |
| Original-source intervals / visits | 6400 /680960 |
| Source reads / writes | 186368 /32256 |
| Logical edges / original source calls | 30208 /2560 |
| Nonvacuous original-source equations | 9 |

| Source equation | Exact scope |
| --- | --- |
| all_u32_open_signed_partition_and_saved_word | Every low32 open result; signed-zero threshold, dispatch index and saved word under the recorded phase constants. |
| all_u32_fstat_zero_partition | Every low32 fstat result; zero/nonzero dispatch and saved phase word. |
| all_u32_fstat_descriptor_and_output_arguments | Every saved descriptor word; zero-extended argument, output pointer and IA setup. |
| all_u32_cleanup_descriptor_argument | Every saved descriptor word forwarded to close with exact IA setup. |
| all_u64_metadata_size_original_load | Every 64-bit metadata word loaded unchanged into X0; remaining six instructions preserve X0 in the retained interval. |
| all_u32_open_errno_status_mapping | Every errno word;2 selects74c29dd1, other values select74c29dd3. |
| all_u32_adapter_record_status_store | Every raw status word stored at symbolic adapter pointer+28. |
| all_u32_caller_record_status_store | Every raw private-output word stored at symbolic caller pointer+16. |
| all_u32_close_return_independent_first_dispatch | Every low32 close return; first dispatch independent of that value under the retained phase. Complete later paths are checked for the three retained controls. |

Each query has an explicitly satisfiable unnegated setup and an unsatisfiable negated contract, with 30 s solver timeout. The independent replay checks original instructions, all GP/Q registers, NZCV/SP, source byte effects and authenticated logical edges. The publication verifier rebuilds every state contract and symbolic equation, compares canonical query structures, reruns the SDK comparison, validates decoded-path hygiene and pins all receipt/dependency hashes. Time and storage are O(parent bytes + source visits x retained register/effect state + state-join comparisons + query DAG + owned artifact bytes); each query additionally has the stated solver bound. Owner-map comparisons include the finite inherited owner set. [SM1-SM6]

A complete fresh extractor run reproduced the retained checks exactly:256 contexts,6400 intervals and680960 source visits. This reproducibility check is separate from independent instruction replay. No target API executed in either extractor run. [SM1-SM4]

| Independent replay | Exact count |
| --- | --- |
| register_values_checked | 21995520 |
| NZCV_values_checked | 687360 |
| vector_register_values_checked | 21995520 |
| source_visits | 680960 |
| write_bytes_checked | 197632 |
| read_bytes_checked | 1266688 |
| original_authenticated_edges_checked | 19968 |

The model joins verify3840 API returns,2560 scalar-output joins,124928 repeated opaque-output byte checks,110592 invalidated stat-byte checks,7680 raw status stores,512 failure-close requests and1536 metadata-sized allocation requests. These repeated byte checks are validation counts, not native allocation footprints. [SM3,SM4,SM6]

| Logical artifact | SHA-256 |
| --- | --- |
| Current checks | `5b3c1afdb63249ce5a6ea5ba39701b2a9010ba2e1ce259284fbfb1652d2e6c23` |
| Independent audit | `85528d5d16ef6269ec172e5481bcb9872c3a6145e9b41123c25f0256f7d1f51c` |
| Extractor | `961f472aae4577638ad2f9f2f8eb6467e057a0fa53c8ba15d807a8c4fbd4359c` |
| Auditor | `87989b03a9d810866710d2ccc20ec27f86bb69b86fa70d834bb52ba5aea18bd9` |

Archive hashes differ from these decoded-artifact hashes. The publication verifier checks the decoded values, exact changed-file set and preservation of all three original inputs. [SM1-SM6]

## Bounded continuation opportunities

| Impact | Follow-up | Evidence needed / bounded interpretation |
| --- | --- | --- |
| High | Resume the metadata-sized allocator frontier into the file-content consumer. | A separate returned-buffer owner or NULL result, exact initialized extents and subsequent read request. The pending size transfer alone establishes no native file content or memory defect. |
| High | Join SIDB data with daemon-to-kext payload construction. | Source producer/consumer chain plus matching native transaction epoch, call selector and message/buffer identity. The preserved generated32 B field has no established transport role here. |
| Medium | Recover the common64 B wrapper and status consumers. | Original post-allocation stores, output representation and downstream caller interpretation; retain caller+8/+16 channel distinction. |
| Medium | Establish descriptor/lock lifetime and errno provenance. | Matching historical ABI and native open/fstat/close events, including intervening errno writes and closure outcome. The local cleanup request does not prove release. |
| Medium | Join pathname metadata with opened-object metadata. | Matching native object identity and call epochs, with device/inode or equivalent evidence. Separate lstat mode and fstat size demands do not supply that identity join. |
| Medium | Resolve SIDB object+28 and the uncontinued nonzero+8 route. | Original stores and consumers from those phases; the current unchanged word is not enough to name a descriptor codec. |
| Low | Compare historical and current metadata ABIs. | Matching header/runtime evidence for stat extent, size offset and API prototypes; current SDK27.2 output is only a comparison. |

## Quality gates

- **QG1**: Pass. Factual source, ABI, model and provenance analysis.
- **QG2**: Pass. SM-A1 through SM-A8 enumerate premises, dependent results and falsification probes.
- **QG3**: Pass for this increment. All 128 parents, return partitions, metadata demand, allocation requests, failure cleanup and status channels are covered within the stated control matrix. The full interface goal remains active and incomplete.
- **QG4**: Pass. B denotes bytes; return/status words are32 bits, addresses/size words64 bits. Signed comparisons, unsigned size conversion, exact counts, extents and complexity are explicit.
- **QG5**: Pass. Descriptor0, signed boundary controls, unknown metadata/errno, reused record channels and the two allocation frontiers are distinguished. Native effects and uncontinued branches remain explicitly unknown.
- **QG6**: Pass. Full original-image hash, original opcodes/fixups, independent replay, nine rebuilt nonvacuous queries, SDK source/header hashes/assembly and exact publication receipts provide primary provenance.
- **QG7**: Pass. The impact-labeled continuation table bounds data-flow, lifetime, ABI and transport opportunities without treating them as established findings.
