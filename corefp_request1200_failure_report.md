# CoreFP cold certificate staging, request1200 failure cleanup and fallback bypass

Original caller 0x8e81c8 now executes a coherent cold prefix through certificate staging and two different continuations. Primary discovery leaves flags 0x0a and selects request1200 builder 0x8ae0. Fallback discovery leaves flags zero and bypasses that builder, reaching the first entropy API call at 0x8eb800 after one declared sequential CASAL operation and original token restoration. No source PC range, child frame or reply status is patched to obtain either route. These are private source executions with explicit API/PAC/lock models; native transport, rights and ownership remain unknown.

Five primary profiles complete after nonzero modeled request1200 transport results. They retain the cached destination name and release the same heap/static lock pointer acquired before discovery, except that a declared unlock result 5 leaves the model ledger held. The fallback profile stops before entropy while the caller is still active; its held lock is not a completed-call leak result. The full interface investigation remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_request1200_failure.py), [checks](triage_evidence/corefp_request1200_failure_checks.json), [independent auditor](triage_evidence/audit_corefp_request1200_failure.py), [audit receipt](triage_evidence/corefp_request1200_failure_audit.json), [live-IDB snapshot](triage_evidence/corefp_request1200_failure_ida.json) and [publication verifier](triage_evidence/verify_corefp_request1200_failure_publication.py) retain this increment. Logical JSON references resolve to lossless `.json.zst` files. The preceding [caller-release report](corefp_lookup_release_report.md), [cold metadata report](corefp_cold_metadata_report.md), [predicate report](fpsd1201_predicates_report.md) and [seed report](fpsd1201_seed_report.md) retain the distinct earlier experiments.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RF1 | Pinned CoreFP and supplied daemon images identify the code under comparison. | Check image hashes, complete compiler extents/import stubs, source pointer rows and live readback. Native image pairing remains unknown. |
| RF2 | The original root receives the preceding valid private 48 B record, decoded operation 0xc1f7, zero controlled field and nonnull referents; entry X1 points to a zero u64 word. | Independently reconstruct every initial CPU register and touched page from original bytes and root fixtures. Public/native reachability and referent types remain unknown. |
| RF3 | Once, locks, allocator/free, PAC and bootstrap are sequential declared models. | Execute original cold callbacks; compare heap/static selection, caller-register clobbering and unlock results 0/5. Neither matching pointers nor balanced calls establishes native ownership. |
| RF4 | Primary discovery returns fixture name 0x5017; fallback uses primary result 1102 and name 0x5034. | Retain the original lookup outputs and actual stack read of flags at 0x8ea058. Names are private task-local fixtures, not captured kernel ports. |
| RF5 | The metadata request preserves original IDs/body while only its received envelope is adapted. | Independently repeat the supplied daemon's original rejection five times; retain -304 and the client continuation. Request1200 is never delivered to the daemon in this increment. |
| RF6 | Certificate allocation succeeds at private address 0x64000400; free marks it inactive while retaining mapped bytes for evidence. | Compare every original decode/move/copy access, decoded image container and existing DER bytes. Distinguish original container, mutated allocation and outgoing stack copy. No native free or certificate trust check occurs. |
| RF7 | NDR bytes and reply-port API outputs are explicit fixtures. | Reconstruct the NDR input and exact request bytes/arguments. The declared task-name cell is unused on these routes and establishes no task port. |
| RF8 | Request1200 returns only nonzero declared transport statuses 0x10000003/0x10000004 and writes no reply bytes. | Check API effect lists, source return paths, reply-port cleanup and separate parent record/X0 outputs. Successful response parsing and OOL ownership remain unknown. |
| RF9 | Fallback CASAL uses one successful sequential compare/exchange, with original token 0x5d96 and replacement 0xa94ef. | Independently check the instruction, memory/CPU effect and original restoration at 0x8eb7a8; stop before entropy. Concurrent ordering, retries and native exclusion remain unknown. |
| RF10 | Finite replay, algebra and bounded knowledge queries establish only their retained scope. | Compare six independent compact oracles and full client journals, two UNSAT properties, SDK assertions and live bytes. Foreign IDA memories are leads; corroborate used catalog facts in original daemon bytes. |

CoreFP arm64e SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; supplied daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. CoreFP offsets use preferred base zero; daemon addresses retain their original preferred base. Sizes are bytes, arithmetic is modulo 2^32 unless labeled u64, and fixture addresses/names are not native observations.

## Source sequence and outgoing/incoming boundaries [RF1-RF10]

```text
root 0x8e81c8, operation 0xc1f7
  -> *entry-X1 += 0x100 (u64), original store 0x8e830c
  -> cold callbacks -> write-lock model at 0x20f6cc
  -> original service lookup
       primary: com.apple.fpsd -> fixture 0x5017
         metadata1203 -> original daemon rejection -304 -> flags 0x0a
       fallback: primary result1102 -> com.apple.fairplayd -> 0x5034
         flags0, no metadata transaction
  -> malloc(760) at 0x249368 [model]
  -> original decode/shift -> DER756 -> separate stack copy
  -> free at 0x8e9fa8 [model; allocation inactive before request1200]
  -> original flags test at 0x8ea05c: flags AND 2
       nonzero -> 0x8ea0b4 -> builder0x8ae0 via call0x8ea14c
         _mig_get_reply_port at0x8b50 -> 0x5173 [model]
         _voucher_mach_msg_set at0x8b80 [model]
         _mach_msg at0x8ba8: send64, receive capacity220 [model]
           0x10000003 -> _mig_put_reply_port at0x8bdc
           0x10000004 -> _mig_dealloc_reply_port at0x8c2c
         parent marker -> cleanup0x457838 -> unlock0x1becc8 [model]
         parent returns; cache0x5017 and entry-X1 word0x100 retained
       zero -> 0x8ea19c; bypass request1200 and its status checks
         original local constructor prefix
         CASAL at0x8ea868 [one declared sequential effect]
         original token restoration at0x8eb7a8
         STOP before _arc4random at0x8eb800; parent still active
```

| Boundary | Original source location | Recovered direction / data | Evidence limit |
| --- | --- | --- | --- |
| Primary/fallback discovery | 0x1ce1bc / 0x1ce448 | Service-name input and caller output slot; imported bootstrap call | API and namespace are models |
| Client request1200 emission boundary | 0x8ba8 in builder 0x8ae0 | Outgoing destination 0x5017, local reply name 0x5173, OOL756; options3, send64, capacity220 | Stopped API replaced by nonzero result; no native message emitted |
| Reply-name acquisition | 0x8b50 | `_mig_get_reply_port` result is placed in request and receive argument | Fixture 0x5173; no native right inferred |
| Reply-name cleanup | 0x8bdc / 0x8c2c | Put versus deallocate helper selected by transport status | Distinct from cached destination retirement |
| Supplied daemon receive catalog | 0x101038040; first routine row 0x101038068 | IDs [1200,1205), lookup 0x1000044fc, first stub 0x100004530 | Original authenticated rows verified; no request1200 dispatch/delivery here |
| Lock lifecycle | 0x20f6cc / 0x1becc8 | Same selected heap/static pointer supplied to acquire/release | Declared sequential ledger, not native owner identity |

The daemon catalog declares maximum reply size 212 B. Client capacity is 220 B, a difference of 8 B. The meaning of that difference is unknown; it is not assigned to a native trailer or padding contract by arithmetic alone. Five original metadata children execute, but none dispatches request1200. The current daemon knowledge query returns two foreign notes about request1200/catalog mappings. They provide leads, not authoritative cross-image identity or proof for unvisited implementations. CoreFP's bounded query returns no entries. No IDB is mutated.

## Certificate lifetime and request layout [RF6-RF8]

Original encoded image bytes begin at 0x185c226 and span 760 B. XOR with 0xba yields a four-byte prefix `01000007` followed by a 756 B DER object. The prefix's broader semantics are unknown; it is not treated as a length. Original source processing moves the DER to the beginning of the allocation. At the free boundary the 760 B snapshot equals `decoded_container[4:] + decoded_container[-4:]`: 756 B DER plus the retained last four bytes of the original decoded container. Thus the allocation snapshot is not the original container.

The original parent copies DER756 to stack address 0x62016b50 in this private execution before freeing the heap allocation. Request1200's OOL pointer references that stack copy, not the inactive heap address 0x64000400. The payload exactly matches the existing [certificate DER](triage_evidence/corefp_fppineboard_certificate.der), SHA-256 `a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de`. This establishes byte identity and source lifetime ordering, not successful authentication, trust, native memory retirement or kernel OOL transfer semantics.

| Request offset | Width | Source-staged value / role |
| --- | --- | --- |
| +0 | 4 B | Header bits 0x80001513 |
| +4 | 4 B | Retained source stack residue; not imposed as send size |
| +8 | 4 B | Destination name 0x5017 |
| +12 | 4 B | Local reply name 0x5173 |
| +16 | 4 B | Zero voucher field |
| +20 | 4 B | Message ID1200 |
| +24 | 4 B | One descriptor |
| +28 | 8 B | OOL pointer 0x62016b50 |
| +36 | 4 B | Descriptor control bytes `00010001` |
| +40 | 4 B | OOL size756 |
| +44 | 8 B | Declared NDR fixture `0000000001000000` |
| +52 / +56 / +60 | 4 B each | Values2,2,756; broader parameter meanings not assigned here |

The separate send-size argument is exactly 64 B. The import body is not executed; a declared nonzero status is supplied without writing request or reply RAM. Therefore the +4 residue does not establish an actual delivered header size or native message rejection. The supplied task-name input cell is untouched and establishes no additional incoming/outgoing port.

## Dispatch and reply-port selector contracts [RF2,RF4,RF8,RF9]

At this source epoch W27=0xc1f7. Let `u=0xc1f7 XOR 0x51e6` and:

```text
mix = (((u + 0x562a37ee) AND 0xa9d5f9f7)
     + ((u + 0x94b9d5de) AND 0x6b45db73) + 0xfffefcad) mod 2^32
index = u XOR (mix * ((flags AND 2) == 0))
```

For all u32 flags, this selects index u when bit1 is set and u XOR mix otherwise. Original IA pointer cells at 0x1cc99c8 and 0x1cc99f0 respectively select 0x8ea0b4 and 0x8ea19c. The replay verifies the actual stack read at 0x8ea058 and the branch at 0x8ea0b0, rather than substituting a later reuse of the same stack offset. This algebraic property holds under the specified W27 epoch, not for arbitrary root controls.

Builder 0x8ae0 selects its reply-port helper from a u32 transport result s:

```text
d = (s - 0x10000002) mod 2^32
put = (d <= 14, unsigned) AND (((1 << (d AND 31)) AND 0x4003) != 0)
    = s in {0x10000002, 0x10000003, 0x10000010}
```

The second equality is proved for all u32 s. Other nonzero results take the deallocation helper; zero proceeds to reply parsing, which is not modeled here. Current SDK compile assertions identify 0x10000003 as MACH_SEND_INVALID_DEST and 0x10000004 as MACH_SEND_TIMED_OUT and check a 24 B Mach header and 16 B OOL descriptor. A modeled timeout constant establishes a source branch, not elapsed native waiting or a delivered request.

## Six bounded outcomes [RF1-RF10]

| Profile | Lookup flags / request1200 result | Reply helper | Parent record marker | Final X0 / lock ledger |
| --- | --- | --- | --- | --- |
| Primary invalid destination | 0x0a / 0x10000003 | Put | 0x45e2a2e3 | 0 / clear |
| Primary other error | 0x0a / 0x10000004 | Deallocate | 0x45e2a043 | 0 / clear |
| Cold fallback prefix | 0 / no request1200 | None | Parent has not returned | Before entropy / held |
| First lock allocation null | 0x0a / 0x10000003 | Put | 0x45e2a2e3 | 0 / static lock clear |
| Caller-register clobber | 0x0a / 0x10000003 | Put | 0x45e2a2e3 | 0 / clear |
| Unlock result5 | 0x0a / 0x10000003 | Put | 0x45e2a2e3 | 5 / retained held |

The five complete parents restore SP and X19-X30 and change only the first four bytes of the input record. Their u64 caller word remains 0x100; the original early increment is not rolled back. The two transport errors produce distinct record markers while final X0 retains the later unlock result. The invalid-destination marker is also used on a preceding discovery-failure route; equal raw markers do not equate their control-flow causes or establish a public errno mapping.

No completed primary case clears or retires cached service name 0x5017. No mach_port_deallocate executes. Reply-port helper cleanup, lock release, heap lifetime and cached destination lifetime are four separate observations. Native ownership remains unknown.

The fallback reaches CASAL with memory/compare 0x5d96 and replacement 0xa94ef at image+0x1d33108. One declared sequential effect writes the replacement and returns the old value in W8 while preserving other CPU state. Original source subsequently stores 0x5d96 back at 0x8eb7a8, then reaches the entropy API boundary. No entropy output, successful RPC reply or synthetic context is supplied. The earlier predicate/seed experiments used a PC-only gap over [0x8ea14c,0x8ea164) on their own initial state; this cold fallback prefix reaches the constructor without that gap because its original flags bypass the RPC. It does not remove the earlier experiments' assumptions or establish successful primary processing.

## Verification and reproduction

Six independently reconstructed initial CPU frames and 1835008 B of initial and the same extent of final touched RAM support independent sparse replay of 129002 original client instruction visits, 25318 reads, 16387 writes, 7186 PAC models, 129 modeled transitions, 36 checkpoints, 22 handoffs, 11 lock events, five request1200 transactions and twelve certificate lifetime events. Six compact oracles separately check lookup controls, route selection, original certificate/DER bytes, request layout, cleanup, result channels and fallback token restoration.

Twenty-three retained source spans comprise seventeen complete compiler-bounded functions and six complete 16 B import stubs, totaling 108844 B. Complete-body retention does not imply every source branch executed. Five daemon metadata rejections are repeated independently under the frozen second driver: 185 original visits and 190 steps including fixture returns, not complete daemon CPU/RAM journaling. Two 30 s bounded solver queries return UNSAT. Thirty-seven exact instruction assertions bind the algebra to original source, and the SDK assertion compile exits zero without emitting a target artifact. Live MCP readback matches 1824 original CoreFP bytes. No native target/API/IPC executes.

```text
python -P triage_evidence/recover_corefp_request1200_failure.py
python -P triage_evidence/audit_corefp_request1200_failure.py
python -P triage_evidence/verify_corefp_request1200_failure_publication.py
```

Use the existing analysis environment with Unicorn, Capstone and Z3. Time/space are O(C*(B+F+V+J+R)): profiles C, original image bytes B, normalized fixups F, visits V, journal records J and touched RAM R. Each client is bounded at 30000 source visits, each daemon child at 2000 and each solver query at 30 s. Nontrivial JSON is compressed with decoded-byte equality checks. Publication checks preserve original inputs and scrub owned text plus decoded typed RAM and commit metadata.

## Bounded continuation and self-red-team

| Impact | Discriminating continuation / significance |
| --- | --- |
| High | Establish successful request1200 reply production, parsing and later cleanup for the primary route. Nonzero transport fixtures and a fallback bypass do not supply a successful context. |
| High | Continue the coherent cold fallback prefix through explicitly bounded entropy/time dependencies and compare its source-generated constructor state against the earlier seed experiments. Their different frame epochs must remain distinct. |
| High | Establish actual service-to-image and daemon/kext/deeper lineage through native provenance or original upstream source evidence. Catalog membership and fixture names alone do not identify a live endpoint. |
| Medium | Trace callers consuming parent record markers, final X0 and the advanced u64 word. Error channels and cached-name retention have distinct source lifetimes. |
| Medium | Recover other flags epochs and successful transport branches. The all-u32 flags proof is conditioned on this operation and source epoch. |
| Medium | Recover concurrent token/lock ownership and native OOL copy/disposition behavior. Sequential CASAL, free bookkeeping and port-name fixtures do not establish kernel ordering or right retirement. |

**QG1** passes: factual analysis requires no normative judgment. **QG2** passes: RF1-RF10 enumerate assumptions and falsification probes. **QG3** passes for this increment: cold certificate staging, request1200 boundaries, transport-error cleanup, source bypass, token restoration, port/catalog mapping and explicit limits are covered; the full goal remains incomplete. **QG4** passes: byte extents, u32/u64 arithmetic, ABI assertions and execution/solver bounds are reproducible. **QG5** passes: decoded container versus shifted allocation/stack copy, native emission versus API boundary, record marker versus X0, reply cleanup versus destination retirement and stopped fallback versus completed parent remain distinct. **QG6** passes: original bytes/hashes, source fixups, independent replay/oracles, compiler/solver receipts and live readback support the claims; foreign knowledge notes are not proof. **QG7** passes: the impact table bounds the continuation. Native ownership, successful primary completion and complete daemon/kext/deeper topology remain unknown.
