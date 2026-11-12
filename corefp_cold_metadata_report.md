# CoreFP cold metadata rejection and sequential cache re-entry

Current continuation: the [cold request1200 failure and fallback report](corefp_request1200_failure_report.md) follows the original primary flags0x0a after metadata -304 into request1200 and source cleanup after two nonzero modeled transport statuses. Original fallback flags0 bypass that transaction and reach the entropy boundary through a declared sequential CASAL effect. Cached destination retention and reply-port helper cleanup are distinct; no native message is delivered.

The original cold lookup now completes both once callbacks, acquires a modeled service name, emits the original metadata request 1203, consumes the supplied daemon's original rejection reply 1303, and returns its lookup success marker. In three primary-service profiles the metadata client returns -304 while lookup returns name 0x5017 and flags 0x0a. A second invocation in the same private instance returns the retained name/flags without another bootstrap lookup or metadata RPC. Every second invocation still reaches pthread_rwlock_wrlock; native re-entry therefore remains unknown until the surrounding unlock/owner contract is established.

Six independently replayed client profiles cover primary acquisition, fallback acquisition, first-allocation failure with the static lock, caller-register clobbering, repeated primary failure and fallback failure followed by a successful retry. These are finite private source executions with explicit API/transport inputs. They establish no native daemon/kext transaction or externally reachable failure condition. The full interface goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_cold_metadata.py), [checks](triage_evidence/corefp_cold_metadata_checks.json), [independent client auditor](triage_evidence/audit_corefp_cold_metadata.py), [audit receipt](triage_evidence/corefp_cold_metadata_audit.json), [live-IDB readback](triage_evidence/corefp_cold_metadata_ida.json) and [publication verifier](triage_evidence/verify_corefp_cold_metadata_publication.py) retain the increment. Logical JSON links resolve to compressed `.json.zst` artifacts. The [cold-prefix report](corefp_lookup_initialization_report.md) and [earlier warm lookup/protocol report](corefp_lookup_report.md) supply the preceding context; this increment joins the cold path to the unchanged-ID metadata rejection and retains state across two calls.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CM1 | Original CoreFP and supplied daemon bytes identify the compared implementations. | Recheck image SHA-256, complete compiler-bounded client bodies, section-bounded import stubs, exact daemon ranges and original used fixups. Different native image selection falsifies transfer to a running system. |
| CM2 | A valid 32 B private lookup record decodes to tag 0xba27 and flag 9. | Independently rebuild its bytes, output pointers, initial CPU and every touched RAM page. External/native caller control remains unknown. |
| CM3 | Both once predicates begin incomplete and the sequential model marks completion after original callbacks return. | Retain callback entry/return frames, two constructions and two completed-predicate checks on the second call. Native predicate representation and concurrent/interrupted initialization remain unknown. |
| CM4 | Allocation, pthread initialization and write-lock success are explicit private models. | Compare heap and first-allocation-null/static-lock profiles; all six cases reach the lock twice. A native unlock/owner trace is required before inferring runnable re-entry. |
| CM5 | Bootstrap results and u32 names are declared fixtures, with output preserved on failure. | Verify every API input/output effect; test status 1102 fallback, other error 5, repeated failure and failure-to-success retry. Native namespace, actual names and failure-output behavior remain unknown. |
| CM6 | Separate engine envelopes supply received size/bits/task-local names and transport return zero. | Preserve request ID 1203, reply ID 1303 and all reply bytes from +24 onward; independently reconstruct both received envelopes. No kernel rights translation or endpoint identity is inferred. |
| CM7 | Frozen daemon normalization supplies an NDR data fixture and bypasses PAC. | Decode the original dispatch pointer and unauthenticated NDR import independently; rerun the original rejection under a second driver. Native NDR binding and hardware authentication remain unknown. |
| CM8 | Ordinary callee return permits the client's immediate postmetadata continuation. | Compare the complete client CPU/data journals and a clobber case for X1-X17/NZCV; check the six immediate original continuation instructions do not read X0/W0. Do not generalize to arbitrary non-ABI callee effects. |
| CM9 | The second invocation changes only X0, LR and PC and preserves all RAM. | Compare the exact before/after CPU frames and empty model memory-effect list. No reset, output rewrite, callback restart or native scheduling is supplied. |
| CM10 | Current IDA bytes corroborate original source, and finite replay establishes only its recorded cases. | Compare 1536 readback bytes; retain the empty metadata memory query. Automatic partial annotations are excluded from proof. Full native lock/right/daemon/kext/deeper continuity remains unknown. |

CoreFP arm64e SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Supplied daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. CoreFP addresses are relative to preferred base zero; daemon addresses use preferred base 0x100000000. Sizes are bytes; markers/names/flags are unsigned 32-bit values; -304 is signed 32-bit.

## Cold-to-rejection-to-cache sequence [CM1-CM10]

```text
first lookup 0x1cdb24; tag 0xba27, flag 9
  -> once callback 0x4a21e0
       two 200 B lock-construction attempts
       clear both cached names and 20 B metadata/control state
  -> lock helper 0x20f37c
       once callback 0x59e868
       select heap lock or static image+0x1d27bf0
       pthread_rwlock_wrlock [declared return 0]
  -> bootstrap_look_up("com.apple.fpsd") [declared success/name]
  -> selected-name cell image+0x1d44448 := 0x5017
  -> metadata flags image+0x1d3799c |= 0x0a
  -> 0x1ce274 -> builder 0x90c8 -> mach_msg at 0x914c
       request 1203, simple, send size 24 B
       |
       +-- explicit private envelope transfer
             daemon demux 0x100004b80
             -> original request-1203 stub 0x100004918
             -> simple form rejected; source reply 1303, 36 B, -304
       |
       +-- original reply body; private received envelope/transport return 0
  -> original metadata client returns -304 at 0x1ce278
  -> lookup marker 0xba1df9db; caller outputs 0x5017, 0x0a

second invocation [same RAM; explicit sequential-call premise]
  -> two once checks already complete; no callback/construction/reset
  -> same selected lock; pthread_rwlock_wrlock [declared return 0]
  -> nonzero selected-name cache
  -> no bootstrap lookup or metadata RPC
  -> lookup marker 0xba1df9db; caller outputs 0x5017, 0x0a
```

The common cached-name cell image+0x1d44448 holds either the primary-service result or the fallback-service result. The diagnostic name `PRIMARY` in helper scripts denotes that cell, not proof that its contents always identify `com.apple.fpsd`. Image+0x1d37838 remains zero in all six profiles, including fallback success. No native receive object is identified by these scalar labels.

The metadata client returns -304 through W0, but the immediate source continuation at 0x1ce278..0x1ce28f does not read X0/W0. Normal completion then copies cached outputs and stores the fixed lookup marker. The new journal checks the original path from cold metadata clearing through this return, rather than assuming metadata already starts at zero. Flags 0x0a arise from source preparation and survive the source rejection; they are not successful metadata values.

## ABI touch points and port directions [CM1,CM5-CM8,CM10]

| Boundary / direction | Original emission or use site | Recovered shape / declared value |
| --- | --- | --- |
| Bootstrap namespace input | CoreFP 0x1ce1bc and 0x1ce448 | W0=0x1b57, diagnostic input through imported bootstrap-port cell |
| Primary service lookup output | CoreFP 0x1ce1bc | Source name `com.apple.fpsd`; X2=image+0x1d44448; model writes u32 0x5017 on success |
| Fallback service lookup output | CoreFP 0x1ce448 | Source name `com.apple.fairplayd`; same X2 cell; model writes u32 0x5034 on success |
| Client reply-port acquisition | CoreFP 0x90f8 | mig_get_reply_port model returns name 0x5173 |
| Outgoing service request | CoreFP 0x914c | mach_msg options=3, send size=24 B, receive capacity=60 B, receive name=0x5173, timeout=0, notify=0 |
| Outgoing header fields | Source stores 0x9100, 0x9104, 0x9110 | Bits 0x1513; destination 0x5017; local name 0x5173; voucher=0; ID=1203 |
| Daemon received request | Private adapter before 0x100004b80 | Bits=18, size=24 B, remote=0x6403, local=0x1403, voucher=0, ID=1203; both names are daemon-task fixtures |
| Daemon reply preparation | 0x100004b80..0x100004ba0 and rejection stub | Source reply ID=request ID+100=1303, size=36 B, status=-304; recognized result=1 |
| Client received reply | Private adapter before original parser | Bits=0, size=36 B, remote=0, local=0x5173; source ID and body preserved exactly |
| Error-envelope cleanup | CoreFP 0x9204 | mach_msg_destroy receives reply pointer; explicit no-effect model, no native rights retirement |
| Caller outputs | Lookup completion under the selected tag | Two separate caller-owned u32 output slots receive selected name and flags |

All names in this table are private fixtures. Matching numerical roles across the two tasks does not establish a shared kernel port or valid received-right disposition. This increment adds no new FairPlayIOKit user-client selector or native kext emission.

The original metadata builder does not initialize the header's size word at +4 before the modeled mach_msg call. In these cold executions that word contains 0x65000100 from earlier private stack use; the separate send-size argument is 24. The adapter explicitly installs received size 24. Complete initial RAM and source write/read journals retain this distinction. A pre-call buffer dump alone therefore does not establish the kernel-delivered header size or a native information disclosure.

## Two-call outcomes and retry state [CM2-CM9]

| Profile | First lookup marker / outputs | Second lookup marker / outputs | Total bootstrap / metadata calls |
| --- | --- | --- | --- |
| Primary success, original metadata rejection | 0xba1df9db; 0x5017, 0x0a | Same retained values | 1 / 1 |
| Fallback success after primary status 1102 | 0xba1df9db; 0x5034, 0 | Same retained values | 2 / 0 |
| Primary with first allocation null/static lock | 0xba1df9db; 0x5017, 0x0a | Same retained values | 1 / 1 |
| Primary with modeled caller-register clobbering | 0xba1df9db; 0x5017, 0x0a | Same retained values | 1 / 1 |
| Primary status 5 twice | 0x45e2a2e3; both outputs retain 0xa5a5a5a5 | Same failure/preserved outputs | 2 / 0 |
| Primary 1102/fallback 5, then primary 1102/fallback success | 0x45e2a2e3; both outputs retain 0xa5a5a5a5 | 0xba1df9db; 0x5034, 0 | 4 / 0 |

Each case attempts two allocations only during its first invocation. Both callbacks execute once, while both once interfaces are called again on the second invocation. Every profile contains two modeled write-lock calls and no unlock or mach_port_deallocate call. The failure cases retain a zero selected-name cache; the next invocation retries discovery without rerunning initialization. The fallback retry overwrites caller output poison only when the later bootstrap model supplies success. These outcomes are conditional on CM4-CM6 and CM9; no native retry schedule or right retention is established.

## Independent validation and provenance

The client auditor imports no new producer code. It reconstructs six initial CPU frames, 1044480 B of initial RAM from the original image/normalized fixups and declared inputs, and sparsely replays every client instruction. It checks all 3541 source data reads, 1267 writes, 227 PAC models, 100 modeled transitions, 36 constructor/callback checkpoints, 12 lookup returns, three metadata returns and the same 1044480 B of final RAM. Six separate compact oracles check cache/output/status, call counts and retry behavior. The original-client visit total is 13345; each profile is bounded at 12000 visits.

Source identity checks cover eight complete compiler-bounded client functions plus four complete 16 B authenticated import stubs: 7372 B total. The daemon comparison covers the complete 144 B demultiplexer and 460 B request-1203 stub. A separate driver over the frozen daemon engine freshly repeats all three rejections, checking 37 original visits and one fixture-return step per child: 111 source visits, 114 total steps. It compares every original visited instruction, reply bytes, recognition result and PAC trace. This is not a complete independent daemon CPU/RAM journal; that limitation is explicit in the receipt. No imports execute on the selected daemon rejection path.

The daemon dispatch slot 0x1010380e0 decodes to authenticated IA target 0x100004918 with diversity zero and no address diversity. The NDR slot 0x1010b1e10 is an unauthenticated bind to `_NDR_record` with zero total addend; its original import row is decoded separately because the older fixup helper admits authenticated binds only. The modeled NDR bytes are `0000000001000000`. The source body and IDs remain unchanged across the adapter.

Live MCP readback from CoreFP target `c3d025e56a86` and daemon target `70f8437872ac` matches 1536 original bytes. The current daemon knowledge query for `metadata` returns zero facts/notes and is not truncated; that is a bounded query result, not absence of prior knowledge. Partial automatic function-analysis annotations are retained as readback context and supply no semantic proof. No IDB is mutated.

Reproduction uses the existing analysis Python environment with Unicorn, Capstone and Z3 available:

```text
python -P triage_evidence/recover_corefp_cold_metadata.py
python -P triage_evidence/audit_corefp_cold_metadata.py
python -P triage_evidence/verify_corefp_cold_metadata_publication.py
```

Time and space are O(C*(B+F+V+J+R)), with C profiles, B original image bytes, F normalized fixups, V retained source visits, J journal records and R touched RAM. Each daemon child has a 2000-step bound and a two-range allowlist. No new universal-input solver claim or elapsed-time/native scheduling estimate is made. Nontrivial JSON is published through lossless Zstandard compression with decoded SHA-256 checks. Original inputs remain preserved.

## Bounded continuation and self-red-team

| Impact | Discriminating continuation / significance |
| --- | --- |
| High | Recover the actual caller-held lock, unlock site and ownership transfer. A nonzero cache bypasses discovery/RPC but still reaches write-lock acquisition; assuming lock-free native cache reuse would contradict the retained call sequence. |
| High | Establish native CoreFP/daemon image selection, service registration and kernel port identity. The unchanged-ID rejection is a reference-image protocol result, not proof that these images communicate in the target deployment. |
| High | Follow retained flags 0x0a and selected-service name through the next processing request. Lookup completion and metadata validity have different source postconditions, including after a cold start. |
| Medium | Track the shared selected-name cell across primary and fallback acquisition. Assigning endpoint identity from the historical variable label alone loses the fallback result's provenance. |
| Medium | Extend the daemon check to a complete independently reconstructed CPU/RAM journal if stronger execution equivalence is needed. The present driver verifies source execution/reply, with shared frozen engine normalization and PAC semantics. |
| Low | Correlate native received-header size and ownership-bearing fields with the API boundary. The pre-call size word here is stack residue; the adapter and send-size parameter have separate provenance. |

**QG1** passes: factual interface analysis requires no normative judgment. **QG2** passes: CM1-CM10 name assumptions, dependencies and falsification probes. **QG3** passes for this increment: cold callbacks, original rejection, sequential cache/failure behavior, ABI/port directions and evidence limits are retained; the full goal remains incomplete. **QG4** passes: byte extents, u32/signed32 values, finite bounds and complexity are explicit. **QG5** passes: cache bypass is reconciled with the second lock call; common cache storage is separated from service identity; client replay and daemon-driver coverage are distinguished. **QG6** passes: original bytes, fixups, import records, SHA-256, independent journals/oracles and bounded live readback support the claims. **QG7** passes: the impact table bounds additional work and identifies its discriminating evidence. Native rights, unlock/re-entry feasibility, actual paired endpoint and daemon/kext/deeper continuity remain unknown.

## Caller-managed lookup lock release

The [cold caller cleanup increment](corefp_lookup_release_report.md) supplies a source release path outside lookup for seven selected parent failure branches. Parent 0x8e81c8 stages the child record, completes cold lookup, then wrapper 0x457838/helper 0x1be978 unlock the same heap/static pointer. This narrows the source owner/release gap; it does not establish native re-entry or the successful-request cleanup path.
