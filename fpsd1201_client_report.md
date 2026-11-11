# FPSD1201 CoreFP serializer, reply parser and daemon failure round trip

Reference CoreFP's builder `0x8d40` serializes request1201 as a simple164-byte message containing a caller scalar and128 inline bytes. Its original send call is `0x8e04`; its parser expects reply ID1301 and a simple36-byte result. A new independent replay joins that client wire to the daemon's original zero-input request1201 failure and returns the same status `0xffff5b37` (-42185) through the client parser. The join uses declared receive-header/name conversion. Native endpoint identity, successful protected processing and daemon/kext completion remain unknown. [CL1-CL8]

This extends the [server session report](fpsd1201_session_report.md) and [CoreFP client paths](corefp_client_paths_report.md). It leaves the [tail-publication lifetime](fpsd_tail_retirement_report.md) unresolved. The broader interface goal remains active.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CL1 | Retained reference CoreFP bodies and the pinned daemon identify these implementations. All offsets and wire correspondences depend on them. | Compare524 fresh IDA bytes, reference universal metadata, retained body/stubs and eleven decoded original format12 words; rehash the daemon and compare320 retained source spans. The changed installed CoreFP is not used as this reference. |
| CL2 | Entry at the client builder is a declared component boundary. | Preserve the sole table reference and caller-register origins; vary destination, reply name, scalar and all128 input bytes. Protected-export reachability and the actual request1200-result-to-request1201-destination chain remain unknown. |
| CL3 | Reply-port, NDR, voucher, transport, cleanup and PAC behavior use explicit private models. | Reconstruct every entry, API argument/result/clobber, original journal and complete final RAM; distinguish weak-absent, no-op and header-write voucher cases. No native API or hardware authentication executes. |
| CL4 | Separate receive conversions map the client request and daemon reply into the receiving component's declared namespace/header form. | Compare all164 request bytes and36 reply bytes after the exact conversion; keep140 body bytes unchanged. Equal private integers across the two modeled namespaces are declared mappings, not a native name-identity theorem. |
| CL5 | The frozen successful FPSD1200 pool supplies the daemon request's starting session. | Pin the predecessor payload and successful audit receipt, reconstruct pool/mask/globals, and freshly replay the original request1201 failure. The earlier10093981-visit session prefix is not freshly repeated. |
| CL6 | Parser-only reply fixtures expose the client grammar independently of daemon processing. | Vary status, ID, complex bit, reported size, remote/local/reserved fields and NDR. Status0 in this isolated parser experiment supplies no successful protected result. |
| CL7 | The transport cleanup theorem concerns allu32 results at the original classifier. | Solve a retained query and independently lift the original MOV/MOVK/ADD/CMP/LSL/TST sequence; compare its three-result set against header constants. Native result feasibility and cleanup effects remain unknown. |
| CL8 | Twenty-seven client profiles and one freshly replayed daemon profile bound the observations. | Independently check complete CPU/read/write/RAM evidence, exact source reply lineage and each cleanup call. Concurrency, client/export reachability, native delivery, policy and deeper-layer joins remain separate obligations. |

## Primary provenance [CL1-CL8]

| Evidence object | Identity / extent |
| --- | --- |
| Reference CoreFP universal | SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f` |
| Reference selected arm64e slice | SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; preferred base0 |
| Builder/parser | `[0x8d40,0x8ed4)`,404 bytes; SHA-256 `04ab93e723989cc20f7cd67e65f75edcf5b650b86a64bf1e2a7ed680576db272` |
| Fresh live IDA byte comparisons | Nine spans:404-byte body, seven16-byte import stubs and eight-byte literal;524 bytes total |
| Original CoreFP pointer records | One authenticated builder rebase and ten import bindings, independently bit-decoded from retained words |
| Daemon thin arm64e image | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh daemon failure replay |480680 original visits,71922 reads,16162 writes,14 external ABI/effect contracts |
| SDK primary declarations | Four freshly hashed headers: Mach message, MIG, MIG errors and NDR; repeated arm64e compile-only assertions pass |

Artifacts: [producer](triage_evidence/recover_fpsd1201_client.py), [source/profiles/proof](triage_evidence/fpsd1201_client_checks.json.zst), [read-only IDA/SDK attestation](triage_evidence/fpsd1201_client_ida_readback.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_client.py), [successful audit receipt](triage_evidence/fpsd1201_client_audit.json.zst) and [publication verifier](triage_evidence/verify_fpsd1201_client_publication.py). The retained reference already supplied the404-byte body and all stubs. Fresh IDA reads verify version/byte correspondence and the literal. No IDB edits were requested. IDA memory lookup supplied no direct session-tail publication note; a returned CF registration memory remains a lead rather than source proof for this builder.

## Caller interface and original outgoing construction [CL1-CL3]

| Input / original location | Established role |
| --- | --- |
|Entry W0|Caller-supplied destination Mach name; saved in X19|
|Entry W1|Application scalar copied unchanged to message+32|
|Entry X2|Pointer to128 inline source bytes, copied in full|
|`0x8d6c..0x8dac`|Original SIMD loads/stores stage all128 bytes at message+36..163|
|`0x8da4`|Copies eight bytes from the `_NDR_record` import referent to message+24|
|`0x8db0`|Calls `_mig_get_reply_port`; returned u32 name becomes message+12|
|`0x8db8`|Stores destination/reply names at message+8/+12|
|`0x8dbc`|Stores message bits `0x1513`|
|`0x8dc8`|Copies literal `00000000b1040000`: reserved0 and ID1201|
|`0x8ddc`|Optional `_voucher_mach_msg_set(message)` when the weak pointer is nonzero|
|`0x8e04`|Calls `_mach_msg(message,3,164,44,reply_name,0,0)`|

The sole fresh IDA reference to the builder is noncode pointer `0x1d03f08`. Its original format12 word `0x8008839000008d40` decodes to target `0x8d40`, IA discriminator8390, without address diversity. That identifies a callable table entry; its actual protected caller is unknown.

| API-boundary message offset | Width | Value / source |
| --- | --- | --- |
|0|u32|`0x1513`: COPY_SEND19 remote, MAKE_SEND_ONCE21 local, complex bit clear|
|4|u32|Retains diagnostic A5 seed; original builder does not write this word|
|8|u32|Caller W0 destination name|
|12|u32|Modeled `_mig_get_reply_port` result|
|16|u32|Literal0; optional declared voucher header-write control uses8844|
|20|u32|1201|
|24|8 bytes|NDR import bytes, declared `0000000001000000` here|
|32|u32|Caller W1|
|36|128 bytes|Caller X2 input|

The authoritative send extent at this boundary is the explicit API argument164, not the unwritten header-size word. The44-byte receive capacity is eight bytes larger than the expected36-byte reply; no actual trailer reception is established. Options3 are SEND_MSG1 plus RCV_MSG2; timeout and notification arguments are0. There is no request OOL or port descriptor. API fixture names such as6800/6400/3141/5173 are task-local integers, without native endpoint identities.

The private execution maps only the retained small code/data/stub pages and declared RAM. It does not load the changed installed CoreFP or reconstruct an entire native CoreFP instance. PAC instructions and authenticated import branches have explicit recorded models.

## Reply grammar, status and cleanup locations [CL1,CL3,CL6,CL7]

After a zero transport result, the original parser tests reply ID before the ordinary envelope checks. ID71 becomes MIG_SERVER_DIED=-308. An ID other than1301 becomes MIG_REPLY_MISMATCH=-301. For ID1301, a complex message, reported size other than36 or nonzero received remote name becomes MIG_TYPE_ERROR=-300. Otherwise the original u32 status at+32 is returned. The tested NDR, received local-name and reserved-field changes do not affect this parser's result. Its original post-transport instruction reads do not consume NDR bytes.

| Original client instruction | Effect established |
| --- | --- |
|`0x8e44..0x8e54`|ID71 / ID1301 selection|
|`0x8e58..0x8e74`|Complex-bit, size36 and remote-name0 checks|
|`0x8e78`|Loads application status from message+32|
|`0x8e38`|`_mig_put_reply_port(reply_name)` for the three classified transport results|
|`0x8e88`|`_mig_dealloc_reply_port(reply_name)` for other nonzero transport results|
|`0x8ea0`|`_mach_msg_destroy(message)` for protocol error or nonzero application status|
|`0x8eb4`|Compares the saved/current stack guard|
|`0x8ebc..0x8ecc`|Returns the selected result and reaches the authenticated epilogue|

For status0 in a well-formed parser-only reply, no cleanup import is requested in the observed body. A nonzero application status is forwarded unchanged and requests message destruction. These are API-call contracts; they do not establish native right accounting, receive-port caching or actual destruction. The return is reported as u32 and signed32 where appropriate; no universal signed64 error convention is assigned.

For allu32 transport results r, the original sequence at `0x8e0c..0x8e30` uses d=`r-0x10000002` modulo2^32 and selects put-reply-port exactly when:

```text
unsigned(d) <= 14  AND  ((1 << (d AND 31)) AND 0x4003) != 0

iff r is one of {0x10000002, 0x10000003, 0x10000010}
```

Both the retained counterexample query and independent source lift are UNSAT. The SDK names those values MACH_SEND_INVALID_DATA, MACH_SEND_INVALID_DEST and MACH_SEND_INVALID_HEADER. Every other nonzero result selects dealloc-reply-port in this classifier. The final transport result is preserved; no success is inferred from cleanup selection.

## Original daemon failure round trip [CL4,CL5,CL8]

```text
CoreFP W0 / W1 / X2
        |
 builder0x8d40 -> mach_msg call0x8e04
        |          send164 / receive44
        v
 declared receiving-header/name conversion
        |
 daemon request1201: simple164, scalar1, inline128 zero bytes
        |
 original marker/name lookup -> marker4c -> allocation/input path
        |
 original failure -42185; selected resets -> marker49
        |
 original reply: ID1301, simple36, statusffff5b37
        |
 declared receiving-header/name conversion
        |
 original CoreFP parser -> statusffff5b37 + mach_msg_destroy request
```

The client baseline uses destination6800, reply name6400, scalar1 and128 zero bytes. The declared request conversion sets bits1212, size164, received remote6400, local6800 and reserved0. It preserves all140 bytes at+24..163 and matches the predecessor's complete164-byte daemon input. This does not assert that real client/server names have equal numeric values across task namespaces.

The independent auditor freshly replays the pinned `matching_zero` daemon profile, including its original protected instructions and14 declared API contracts. No protected result is supplied or changed. Its original36-byte reply is `{bits12,size36,remote6400,local0,reserved0,id1301,NDR,statusffff5b37}`. The separate declared client receive conversion uses bits0, remote0 and local6400 while preserving the remaining body. All36 bytes then match the client model's reply. Original CoreFP returns u32 `0xffff5b37`, signed32 -42185, and requests message destruction at `0x8ea0`.

The daemon replay checks40 complete CPU frames,2441216 final inherited RAM bytes,327680 extra-region/pool/mask bytes and4637 heap-owner accesses. Original source comparison covers320 retained IDA spans;515 rebases and11 bindings accessed by this selected replay are independently checked. Earlier source-produced session construction is pinned rather than freshly replayed. Native scheduling, rights, copyin/copyout, authorization and temporal continuity remain unknown.

## Finite controls and validation [CL1-CL8]

| Client controls | Cases | Result / discriminating observation |
| --- | ---: | --- |
|Source-produced daemon failure|1|Original daemon statusffff5b37 is returned unchanged|
|Parser statuses0/8/ffffffff/80000000/7fffffff|5|Exact status forwarding; destruction requested for each nonzero status|
|Complex bit, size35/40, remote1234|4|MIG_TYPE_ERROR=-300 and message-destruction request|
|ID71 / ID1300|2|MIG_SERVER_DIED=-308 / MIG_REPLY_MISMATCH=-301|
|NDR changed; local/reserved changed|2|Original nonzero status preserved; no NDR conversion on this body|
|Scalar/128-byte pattern; reply name0; namesffffffff|3|Exact serialization; no native name validity inferred|
|Weak voucher no-op / declared header write|2|Optional call and original reload of receive name; send fields retain declared effects|
|Three put-reply transport values|3|Put-reply-port request, transport value preserved|
|Five other nonzero transport values|5|Dealloc-reply-port request, transport value preserved|

The producer and independent auditor retain all27 client profiles. Independent checks cover2389 original client visits,954 reads,729 writes,82 external contracts and136 declared PAC operations. Every serialized input has the exact128-byte source-read footprint, and the header-size word has no original writer. The auditor checks218 complete client CPU frames and2322432 final declared RAM bytes. One all-u32 transport query and one independent source lift are UNSAT. Fresh live IDA comparison covers524 bytes; four SDK headers and compile-only ABI assertions pass.

Reproduction runs the producer, independent auditor and publication verifier with the configured `$PYTHON` and Z3 environment. The scripts state linear replay/journal/state costs, with local solver cost separate. Evidence JSON and the manifest are zstd ultra22 archives, byte-compared after decompression. Owned text and decoded typed RAM are checked for analyst-path literals. The original three input files remain preserved.

| Impact | Further discriminating evidence |
| --- | --- |
|High|Recover the protected caller of table entry1d03f08 and the provenance of W0/W1/X2. Test whether request1200's returned session name becomes request1201's destination, using actual source definitions rather than equal fixture integers.|
|High|Join a source-produced initialized session through request1201 publication, later request1202 use and process-event retirement. The marker4d/+880/+888 reaching definitions remain open.|
|High|Match native image, namespace, service registration, credentials and rights to this reference wire before claiming delivery or daemon/kext/provider transaction continuity.|
|Medium|Follow the shared MIG reply-port helpers in the pinned system library to distinguish these client calls from completed right lifetime effects.|
|Medium|Recover the weak voucher helper's native header/right effects and actual presence for the selected runtime image; the no-op/header-write controls are declared models.|
|Low|Extend the adjacent request1202/1203 client parsers only where it resolves a distinct server ABI or ownership question.|

## Quality gates

- **QG1**: Factual serializer, parser and source-lifetime analysis requires no normative premise.
- **QG2**: CL1-CL8 identify assumptions, dependent results and falsification probes.
- **QG3**: Routine roles, incoming/outgoing names, exact emission/cleanup sites, data/control flow, environment and cross-layer limits are covered within the stated scope.
- **QG4**:164/36/44-byte extents,128-byte copy, u32 transport arithmetic and signed32 status conversion are reproducible; no native performance claim is made.
- **QG5**: Unwritten size word, receive conversion, parser-only status0, reply grammar priority, weak voucher models and unknown endpoint identity remain explicit.
- **QG6**: Retained reference bytes/fixups, fresh live IDA/SDK checks, independent client replay/wire oracle/solver and original daemon replay support the claims.
- **QG7**: Impact-ranked continuations preserve unresolved caller provenance, session lifetime and native daemon/kext/deeper joins. The full goal remains active.
