# FPSD1201 session-name selection, payload ABI and failure-state reset

Request1201 selects the previously created session by comparing the received local Mach name with `CFMachPortGetPort` for its stored CF reference. It accepts marker `0x4577df4b`, stages a16-byte protected payload and, in the completed zero-input cases, returns a36-byte status `0xffff5b37`. The original failure path restores marker `0x4577df49` and resets selected fields while retaining the CF reference. A separately composed process-event callback then skips that resulting slot. These are original source/private-ABI results; native transport, right ownership and reclamation remain unknown. [FS1-FS8]

This continues the [process-event report](fpsd1200_process_report.md). The full daemon/kext/deeper-interface investigation remains active.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FS1 | The pinned thin daemon and matching live IDA bytes identify the code. All source addresses and expressions depend on this identity. | Rehash the image,320 selected spans,529 original rebases and14 bind records; compare eight additional store windows and the full14851048-byte census extent with live IDA. Thin-image and IDB-input hashes are distinct. |
| FS2 | Frozen successful FPSD1200 state supplies the pool, startup owners and post-request global bytes. Later request conclusions depend on this explicit composition. | Pin the exact decoded profile, predecessor receipt and dependencies; independently reconstruct eight owner snapshots,31 startup global spans and21395 final global-write snapshots. The earlier10093981-visit prefix is not freshly replayed in this increment. |
| FS3 | The new MIG entry, header names, word and128 zero bytes are declared receive-side inputs. Name matching and failure observations concern that local model. | Vary the received local name and modeled CF name together/separately, vary the application word, malformed complex bit and size, and move the populated slot to index1. Native receive conversion, sender rights, authorization and client/server version pairing remain unknown. |
| FS4 | CF name extraction, allocation/free, locks, once, stack probing and PAC use explicit models. Original arithmetic results are never injected. | Recompute every API argument/result/clobber and complete original CPU/read/write/RAM trace. Heap models permit only the observed336/336/324-byte owners and reject accesses outside live owner extents. Native APIs, synchronization, allocator behavior and hardware authentication remain unknown. |
| FS5 | Complete CPU frames supply marker/name-comparator phases. The all-u32 name theorem is local. | Independently lift the actual comparator instructions; solve its counterexample query; check W23=`0xc05c`, W27=`0x24df`, the original requested-name cell and marker-comparison W3. This proves no native right or permission theorem. |
| FS6 | The process-event join transfers the complete failure-produced pool and byte mask into the separately entered callback component. Callback observations depend on that composition. | Compare full initial/final pool hashes and masks, freshly replay all3999 callback visits and verify no pool store or CF invalidation/release request. Continuous scheduling and eventual CF/VM reclamation remain unknown. |
| FS7 | The offset census supplies leads rather than complete alias/object recovery. Auxiliary decompilation is a locator, not primary semantic evidence. | Rescan all source bytes, validate candidate opcodes and fresh IDA windows, trace the actual bases/value producers before assigning types. Byte-readback calls are read-only; no explicit IDB edit was requested. Automatic decompiler-analysis side effects were not independently measured. |
| FS8 | Ten complete request profiles, one callback join and the stated proof bound this increment. | Verify exact state/reply/control joins and retained provenance. Dense/nonzero128-byte inputs, successful request1201 processing, nonzero tail publishers, native effects and daemon/kext/deeper continuation remain separate obligations. |

## Primary provenance [FS1,FS2,FS7,FS8]

| Object | Identity / extent |
| --- | --- |
| Original thin arm64e daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Live IDA input metadata | SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`;320 selected spans and eight additional store windows match |
| New source catalog |21540 distinct four-byte instructions /86160 bytes; includes the request paths and callback join |
| Offset-census extent | `[0x100001058,0x100e2ac40)`,14851048 bytes; SHA-256 `1463b16f028bda1abb76d52edcf5236c3bd11bbece4a7a6b46f8029ff511236b`; complete linear decoding with zero skipped words |
| Frozen session source | `queue7_success` in [lifetime checks](triage_evidence/fpsd1200_lifetime_checks.json.zst); source-produced CF reference, pool, startup owners and global bytes; pinned prior fresh-replay receipt |
| Primary SDK | Four installed headers; arm64e compile-only checks of Mach header/name widths and offsets, complex bit, MIG_BAD_ARGUMENTS and CF name/heap API signatures |
| IDA knowledge search | Returned facts3/6/4; none supplied direct slot-tail producer/ownership evidence |

Evidence: [producer](triage_evidence/recover_fpsd1201_session.py), [source/profiles/census](triage_evidence/fpsd1201_session_checks.json.zst), [IDA/SDK attestation](triage_evidence/fpsd1201_session_ida_readback.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_session.py), [fresh receipt](triage_evidence/fpsd1201_session_audit.json.zst) and [publication verifier](triage_evidence/verify_fpsd1201_session_publication.py). No native target, Mach/CF/heap API or IOKit operation executes.

## Request, application wrapper and protected payload [FS1-FS5]

| Layer / original location | Exact contract |
| --- | --- |
| MIG table | Request1201 in family1200..1204 selects stub `0x100004720`; maximum reply36 bytes |
| Stub `0x100004720..0x100004730` | Requires a simple message and reported size164; either violation returns MIG_BAD_ARGUMENTS=-304 |
| Direct call `0x10000475c` | Calls application wrapper `0x1000072d8` with W0=request+12, W1=request+32, X2=request+36 |
| Input body | NDR at+24..31, application u32 at+32,128 inline bytes at+36..163; no OOL or port descriptor |
| Wrapper stores `0x100007428..0x10000742c` | Stages `{u32 received_local_name,u32 application_word,u64 inline128_pointer}` in16 bytes |
| Protected call `0x1000075a0` | Shared dispatcher `0x10065ffd8`; same carrier family as request1200, decoded operation label `0x8f7506ee` |
| Return `0x1000075a4..0x1000075d8` | Consumes original returned stack delta and XOR-decodes the carrier status with `0x8b3dc651` |

The stub does not copy an audit trailer. That local absence is not a native authorization conclusion: its received local name belongs to the server's port namespace and is a receive-conversion input in this model. A sender's ability to choose a destination right and the server's resulting numerical local name require native evidence. This increment does not recover the matching reference CoreFP request1201 builder or establish native client/server pairing.

At the dispatcher entry, the original staged pointer equals request+36. No protected output/status tuple is supplied by the experiment. Original source creates the carrier, follows the lookup, performs its buffer/arithmetic continuation, produces status and constructs the reply. The application-word1/2 controls have identical original instruction sequences and final status for the128-zero-byte case; this does not establish that the word is globally unused.

## Session-name and marker selection [FS2-FS5]

| Source / field | Established dependency |
| --- | --- |
| `0x1007fda5c..0x1007fda64` | Loads candidate slot+876 and compares with W3=`0x4577df4b`; the checked selector requires equality |
| `0x1005a99ec` | Reads the candidate's stored CF reference from slot+0 |
| Call `0x1005a9a4c` | Requests `CFMachPortGetPort(0x77001000)`; explicit returned name is `0x6800` or the alternate `0x6801` |
| `0x1005eb7ec`, `0x1005a9a78` | Original copy into, then read from, the requested-name cell; selected address `0x70067a98` |
| Compare `0x1005a9a90` | Obfuscated arithmetic is equivalent to equality of CF name and received local name under checked phases |
| `0x10048bfbc` | On the selected continuation, writes transient marker `0x4577df4c` at slot+876 |

For all u32 CF names n and requested names p, arithmetic is modulo2^32:

```text
v = (n XOR 0x77fedf9a) + ((n << 1) AND 0xeffdbf34)
  + 0x51cee081 - p
  = n - p + 0xc9cdc01b

(v == 0xc9cdc01b)  <=>  (n == p)
```

The original phase expression `(W23 + 0x51ce0402) XOR W27` equals `0x51cee081` for W23=`0xc05c`, W27=`0x24df`. Both the retained query and the independent lift of the actual instructions are UNSAT. This establishes a local scalar equality, without establishing actual CF-to-kernel-right identity or native access policy.

Changing only the received name to `0x6801` returns status8 without reading the128 inline bytes or changing the pool. Changing both names to `0x6801` preserves the original zero-input instruction sequence and failure result. Marker4c/4d controls also return8, before CF name extraction. In contrast, the earlier process-event callback's local predicate excludes only markers49/4a; the two consumers have distinct state predicates. Marker names4b/4c/4d here abbreviate the full values `0x4577df4b` / `0x4577df4c` / `0x4577df4d`.

## Original failures, resets and port-reference boundary [FS3-FS6]

```text
source-produced session: marker4b, stored CF reference
                         |
             simple164-byte request1201
                         |
              marker4b and name match
                         |
                    marker4c
                         |
          allocate / original input continuation
             |                         |
        first NULL                zero input read
             |                         |
       status-42028               status-42185
             +------------+------------+
                          |
             original selected-field reset
             marker49, CF reference retained
                          |
           separately composed process event
             marker49 skipped; no CF request
```

| Original location | Selected operation |
| --- | --- |
| `0x100862964` | `malloc(336)` request; NULL control returns original `0xffff5bd4` (signed32 -42028) before any inline-byte read |
| `0x1006e5e60`, `0x10058d694` | Further allocations336 and324 bytes in the nonnull cases |
| `0x10052a828`, `0x1007f4ae8`, `0x100860638` | Free requests for second336-byte,324-byte and first336-byte owners, respectively |
| `0x10041eecc` | Original store of marker `0x4577df49` |
| `0x10041eed8` | Stores `0x8b3dc651` at slot+816 |
| `0x10041eee4`, `0x10041eef0` | Stores `0x68f2e77f` / `0x3f0a0be4` at slot+868 /+872 |
| `0x1000c6d10`, `0x100054a70`, `0x100036d48` | Three16-byte pattern resets at slot+820..867, descending within each block |

Each completed selected failure has53 pool stores: transient marker4c, marker49 plus three scalar resets, and48 byte stores. The three final reset blocks are `103ca2cecc005e9228549ac6e418568a`, `28549ac6e418568ac0ec123e7cb0ce02` and `c0ec123e7cb0ce02d8040a3694c8c6fa`. Their cryptographic or object-field meanings remain unknown; this is a source-defined pattern reset.

All128 inline bytes are read in each complete nonnull zero-input case. Those cases return original `0xffff5b37` (signed32 -42185); the validation algorithm, format/error nomenclature and successful processing remain unknown. Nonzero/dense input locators reached a two-million-hook observation budget without completing. That is a bounded private observation, not a native timing, termination or work-factor result; those incomplete locators are not counted among the ten complete profiles.

No request profile clears slot+0 or requests CF invalidation/release. The completed selected failures end with marker49, unchanged CF reference and zero tail fields+880/+888. The callback join uses the complete failure-produced pool and defined-byte mask; all3999 original callback visits complete, the pool remains byte-identical and no CF cleanup request occurs. This establishes the selected source intervals and state gate. Native CF retain counts, source removal, kernel-right lifetime, slot-reuse cleanup, later reclamation and output-VM effects remain unknown; no native leak is established.

## Tail-field source census [FS1,FS7,FS8]

The complete code-extent scan finds 862 literal memory operands with displacement `0x370` or `0x378` (880 or 888 bytes), including 86 non-SP operands and eight non-SP store candidates. This is an exact literal-displacement census. Computed offsets, aliases and object identities require separate recovery.

| Original store | Observed address expression / limit |
| --- | --- |
| `0x1000d4498` | `STR XZR,[X9,#0x370]`; header/index-shaped zero store; exact base identity unknown |
| `0x1001b4724` | `STR XZR,[X12,#0x378]`; stride896 and biased base; initializer identity requires a separate join |
| `0x10025bc8c` | `STR XZR,[X10,#0x378]`; previously recovered process-callback tail clear |
| `0x1003e50b0` | `STR XZR,[X10,#0x370]`; candidate callback clear on a branch unreached by these profiles |
| `0x1005db758` | `STR XZR,[X9,#0x378]`; preceding `ADD X9,SP,#8,LSL#12` makes this a stack alias at SP+0x8378 |
| `0x1007006b0` | `STR X10,[X2,#0x378]`; nearby fields include +0x380/+0x388/+0x390/+0x39c/+0x3a0; base identity unknown |
| `0x100735e50` | `MEM64[B + 896*I + 888] = X8`, with `H=MEM64[SP+0x448]`, `B=MEM64[H]`, `I=MEM64[SP+0x62d0]`; header identity, index bounds and value producer unknown |
| `0x1009b7d2c` | `MEM64[X26+880]=MEM64[SP+0x4c0]`; preceding `0x1009b7d24` writes marker `0x4577df4d` at X26+876; base/value producers unknown |

Eight fresh 128-byte IDA windows attest these candidate stores. The last two are concrete nonzero-publication leads. Marker/stride agreement alone does not establish their object ownership or connection to successful request1201 processing. Previously recovered 872-byte registry objects must not be merged with these 896-byte session slots without an alias proof.

## Incoming names and outgoing reply construction [FS1-FS4,FS8]

| Direction / source | Exact local observation |
| --- | --- |
| Incoming request+12 | Received local name `0x6800` or control `0x6801`; consumed by the application wrapper and session-name comparison |
| Incoming request+8 | Received remote/reply name `0x6400`; copied into the reply destination field |
| `0x100004b90` | Writes reply bits `0x12` and size36 at +0/+4 |
| `0x100004b9c` | Writes reply remote `0x6400` and local0 at +8/+12 |
| `0x100004ba0` | Writes reserved0 and reply ID1301 at +16/+20 |
| `0x100004770`, `0x100004780` | Writes application status at +32 and NDR `0000000001000000` at +24 |
| `0x10000478c`, `0x10000479c` | Guard-error status/NDR construction for malformed envelopes |

Every completed profile constructs a simple 36-byte reply. These demultiplexer-entry runs reach no actual Mach send call, descriptor transfer or IOKit call. The table identifies emitted buffer fields and their original stores; native transport and right-disposition effects remain unknown.

## Finite validation and reproduction [FS1-FS8]

| Complete request profile | Original visits | Status, signed32 | Inline bytes read | Pool stores | Final marker suffix |
| --- | ---: | ---: | ---: | ---: | --- |
| matching_zero |480680|-42185|128|53|49|
| other_word |480680|-42185|128|53|49|
| other_matching_name |480680|-42185|128|53|49|
| different_name |4518|8|0|0|4b|
| allocation_NULL |6675|-42028|0|53|49|
| complex_request |37|-304|0|0|4b|
| wrong_size |40|-304|0|0|4b|
| live_slot_index1 |480713|-42185|128|53|49|
| marker4c |4431|8|0|0|4c|
| marker4d |4431|8|0|0|4d|

All ten retain the stored CF reference. Marker suffixes refer to `0x4577dfXX`. The moved-slot case targets slotbase+896; changing only the application word or both matching names preserves the baseline original instruction sequence.

| Independent audit | Checked extent |
| --- | --- |
| Request replay |1942885 original visits;291532 reads;65982 writes;79 external contracts |
| Complete request CPU frames |400 frames including202 session checkpoints; GP31, SP, NZCV and32 Q registers |
| Request final state |24412160 inherited mutable RAM bytes plus3276800 extra-region, pool and mask bytes;18548 heap-owner accesses |
| Failure-to-callback join |3999 original visits;491 reads;358 writes;9 external contracts;121 complete CPU frames including100 process checkpoints |
| Callback final state |2441216 inherited mutable RAM bytes;65536 pool bytes and65536 defined-mask bytes |
| Original source |320 live-IDA spans;21540 distinct instructions;529 format12 rebases and14 bindings |
| Local theorem |Retained UNSAT query and independently instruction-lifted UNSAT query; comparator phases checked in complete CPU frames |

The auditor does not import the new producer. It independently reconstructs declared entry/composition, heap and CF contracts, original CPU/read/write journals, final RAM and field joins. Its successful fresh receipt pins 1946884 total new original visits and88 external contracts. The frozen successful-session prefix is pinned by exact payload, predecessor receipt and dependency hashes; it is not freshly replayed here. Publication verification pins that fresh audit and checks the owned delta without replaying instructions.

```sh
env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/audit_fpsd1201_session.py

env PYTHONDONTWRITEBYTECODE=1 Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_fpsd1201_session_publication.py
```

Replay takes O(V+J+H*R+I) time and O(J+H*R+I) space for original visits V, journals J, snapshot count H, mutable bytes R and image I. Linear offset decoding takes O(I) time; SMT costs are separate. Byte extents and u32/u64 modular widths are explicit. Substantial JSON is archived using Zstandard ultra22 with exact decompression comparison. Path checks inspect decoded metadata and typed RAM; binary Base64 alphabet coincidences do not denote paths. Byte-readback calls were read-only, no explicit IDB edit was requested, and automatic auxiliary decompiler-analysis side effects were not independently measured.

## Bounded continuation opportunities [FS2-FS8]

| Impact | Discriminating next evidence |
| --- | --- |
| High | Recover the exact base/value producers for nonzero stores at `0x100735e50` and `0x1009b7d2c`, then establish ownership and a successful-session source join. |
| High | Recover the matching CoreFP request1201 builder and version pairing, including the128-byte input's format and original success continuation. |
| High | Trace source-defined reuse and cleanup after the marker49 failure reset, including nonzero tail owners, CF source removal and eventual owner reclamation. Native lifetime effects remain unknown. |
| High | Connect the recovered session operations to provider, IOKit user-client and deeper interfaces using exact call/data joins. No such external call occurs in this increment. |
| Medium | Replace the snapshot composition with a freshly checkpointed continuous source path; separately establish native event/receive conversion where evidence exists. |
| Medium | Extend the literal census with computed-address aliases before claiming complete slot-tail coverage. |

**QG1** passes: factual source, ABI and bounded state analysis. **QG2** passes: FS1-FS8 provide assumptions, dependencies and falsification probes. **QG3** passes for this increment; the broad investigation remains active. **QG4** passes: exact byte extents, counts, widths and modular arithmetic are reproducible. **QG5** passes within scope: transient marker4c versus final49, source requests versus native effects, literal offsets versus object identity and snapshot joins versus temporal continuity are explicit. **QG6** passes: original image/fixups, live IDA byte attestation, primary SDK, independent replay and source lifting support the claims; auxiliary analysis side effects remain explicitly unmeasured. **QG7** passes: remaining obligations have bounded impact labels.
