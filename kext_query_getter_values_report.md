# Provider version/capability values and their daemon consumption

For the pinned base-provider routes,selector22 returns version `0x4c0b0000` and selector23 returns capabilities `0x000001f8`. Original byte-bank identities,dispatch pointers,internal record stores and enclosing return loads establish these values under ordinary-return,stable-table and frame/guard premises. These routines also mutate global controllers;their constant outputs do not make them side-effect-free. The values specialize the retained daemon's query guards,cache and zero-capability fallback. Native service/connection/provider identity,live build pairing,successful transport and the individual capability-bit meanings remain unknown. [KG1-KG8]

Evidence: [original source,pointers,banks and saved IDA observation](triage_evidence/kext_query_getter_values_source.json.zst), [source models,queries and daemon outcome cases](triage_evidence/kext_query_getter_values_checks.json.zst), [extractor](triage_evidence/recover_kext_query_getter_values.py), [validator](triage_evidence/validate_kext_query_getter_values.py), [preservation](triage_evidence/kext_query_getter_values_delivery.json), [quality gates](triage_evidence/kext_query_getter_values_quality_gates.json), [sealer](triage_evidence/seal_kext_query_getter_values.py), [publication audit](triage_evidence/verify_kext_query_getter_values_publication.py). Context: [selector/query contracts](daemon_iokit_census_report.md), [daemon metadata cache](daemon_query_state_report.md), [zero-capability fallback](daemon_query_fallback_report.md), [IOKit structure-call transport](iokit_structure_arguments_report.md), [Mach-port inventory](mach_ports_report.md).

## Source identity and scope

| Evidence | Verified scope |
| --- | --- |
| Normalized kext SHA-256 |`2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`|
| Original kernel collection SHA-256 |`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`|
| Daemon thin-image SHA-256 |`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`|
| Kext entry UUID |`227f9df7-645d-39b8-b74a-685303d16b4b`|
| Original/normalized recapture |Nine complete compiler-bounded ranges,453 A64 instructions,1812 B|
| New source equations |354 nonbranch instruction instances,including getter prefixes,two leaves,result publication and result loads|
| Bank evidence |Twelve source-proved identities,3072 exhaustive byte inputs,eight original256-byte arrays|
| Prior daemon recapture |21 range instances,2904 B|
| Accepted proofs |38 UNSAT,two abstract SAT,nine retained original propositions freshly replayed|
| Integrity controls |Eight altered source/value/bank/target/discriminator/output/IDA/native records rejected|

Read-only IDA access reconnected after an initial unavailable-bridge response. The kext IDB input hash equals the normalized file hash. All five getter/helper ranges,1620 B,match the original/normalized hashes. Targeted knowledge recall returned zero matching facts. Automatic unrelated diagnostics were excluded from evidence;no remembered claim or IDB mutation supplies a proof. Validation retains this observation and freshly rechecks file bytes;it does not reobserve live IDA state. No target execution,emulation,IOKit/FairPlay request or native message send occurred. [KG1,KG8]

## Original cross-layer routes

Both dispatch records have flags3,input0 B and output4 B. The descriptor/member pointers and provider vtable slots are freshly checked against original chained-pointer records and normalized fields. The UserClient methods obtain their provider through this+0xd8,call its vtable,store low32(X0) through the output pointer,and return outer W0=0. [KG1-KG3]

| Selector | UserClient and data publication | Base-provider slot/stub | Getter and established result |
| --- | --- | --- | --- |
|22|`ucGetVersion`,entry `0xfffffe000a5050c8`;u32 store `0xfffffe000a505110`|Offset `0x8c0`,slot `0xfffffe000846c190` -> provider `uOxAg`,stub `0xfffffe000a504ed4`|`_V2F1SYee`,entry `0xfffffe000a5a299c` -> `0x4c0b0000`|
|23|`ucGetProtocolCapabilities`,entry `0xfffffe000a505120`;u32 store `0xfffffe000a505168`|Offset `0x8c8`,slot `0xfffffe000846c198` -> `Q5TC6`,stub `0xfffffe000a504edc`|`_QIWEiU`,entry `0xfffffe000a5a49d8` -> `0x000001f8`|

The four-byte outputs in the stated little-endian model are `00 00 0b 4c` and `f8 01 00 00`,respectively. The stubs transfer directly to the listed getters. The base-provider vtable is a static route;an actual runtime provider or override is not identified. The u32 metadata word is separate from the outer UserClient status. These publication stores are internal output-copy locations,not new Mach-send instructions. [KG2,KG7]

## Internal calls,records and return channels

Let F be either getter's SP after its48 B reservation. Its internal record R=F+0x10 has a prepared u32 at+0 and a u32 result at+4. The version adapter reserves64 B below the getter's current SP;its nested record N=F-0x30. Ordinary valid/disjoint frames and restored SP are explicit composition premises. [KG3-KG5]

| Source call | Original authenticated slot | Selected target | IA diversity |
| --- | --- | --- | --- |
|Version `0xfffffe000a5a2b7c`|`0xfffffe000847aaf8`|Adapter `0xfffffe000a66a5a8`|`0x5c97`|
|Capability `0xfffffe000a5a4b90`|`0xfffffe000847aa48`|Leaf `0xfffffe000a5c22a8`|`0x7787`|
|Version adapter `0xfffffe000a66a7a8`|`0xfffffe000847a918`|Leaf `0xfffffe000a5aec10`|`0x3936`|

All three pass X0=their local record at current SP+0x10. Every bank cancellation is freshly proved from original instruction expressions and original256-byte arrays before substituting its constant. All bank-read addresses,pointer/data-read addresses,four prefix-store addresses per routine,target X8,record X0 and diversity X17 are checked. The twelve exact equality substitutions are proved cuts,not sampled controller values. Independent typed controller snapshots are admitted at each read;constant target selection needs no equality between those snapshots. Stable original bank/pointer epochs are still required. Hardware authentication is not exercised. [KG2-KG4]

The decisive data flow is:

```text
version getter:
  prepare R+0 -> adapter(R)
    prepare N+4 -> status_leaf(N)
      u32[N+0] = 0x158d42ef; X0 stays N
    u32[R+4] = 0x4c0b0000 at0xfffffe000a66a7b0
    ordinary return carries X0=N
  W0 = u32[F+0x14] at0xfffffe000a5a2b80

capability getter:
  prepare R+0 -> capability_leaf(R)
    u32[R+4] = 0x1f8 at0xfffffe000a5c22b0; X0 stays R
  W0 = u32[F+0x14] at0xfffffe000a5a4b94
```

The version getter ignores the adapter's returned local pointer and replaces X0 with the zero-extended result word. No externally published pointer or lifetime is inferred from the adapter's X0. The status leaf's constant at N+0 has no established error/status meaning;the capability leaf does not inspect R+0. Exact four-byte little-endian memory and frame-offset proofs join each result store to the enclosing getter load. Original canary comparisons and RETAB epilogues delimit the ordinary-return condition. [KG3-KG5]

The source-derived prepared words are,modulo2^32:

```text
u32[R+0] in version getter =
    0x440e0fe1 * (low32(R) XOR0x841cb645) -0x007f03ff
u32[R+0] in capability getter =
    0x3d7a7ab1 -0x84d77373 * (low32(R) XOR0x6133a0c8)
```

These are private address-dependent record words,not recovered wire opcodes. Their preparation does not determine the final constants;the downstream source stores do. The six u64 controller writes across the three prefixes target `0xfffffe000ccc3368`, `0xfffffe000ccc3670`, `0xfffffe000ccc7790` and shared `0xfffffe000ccc32f8`. In the version chain the getter and adapter both update the shared cell. Complete value expressions remain in the SSA evidence;no synchronization,randomness or hardware-query interpretation is assigned. [KG3-KG6]

## Conditional daemon metadata and failure outcomes

The retained daemon calls `_IOConnectCallStructMethod` at `0x100364420` for selector22 and `0x1004ba9c4` for selector23. Each uses no input bytes and output capacity4 B. Acceptance requires status32=0 and returned size64=4;otherwise source clears that query's word. The second query still follows rejection of the first. Within that established entry/connection/frame contract,matching these provider results yields V=`0x4c0b0000`,C=`0x1f8` when both queries are accepted. [KG6-KG7]

| Offset from daemon state `0x1010b6380` | Width | Exact encoded value when both accepted |
| --- | --- | --- |
|+8|4 B|`0x0bfd3df0`|
|+0xc|4 B|`0x0e6235a5`|
|+0x10|4 B|`0x0da54c41`|
|+0x14|4 B|`0xc4969608`|

The first three encode version bytes `0x4c`,`0x0b`,`0x00`;the daemon ignores the low version byte. C is nonzero,so this matched successful route skips the zero-capability fallback. A normal returning cache helper permits caller marker byte0=`0x0a`. [KG6]

The pinned capability word has set bits3 through8. Their meanings remain unknown. For a rejected capability query,the existing daemon fallback instead derives bit3 from unsigned `V>>16 >=0x2e1e`. The pinned version has `0x4c0b >=0x2e1e`;a rejected version query supplies zero and fails that threshold. Fresh replay of the original fallback propositions gives all four conditional outcomes: [KG6-KG7]

| Version query accepted | Capability query accepted | Guarded V | Guarded C | Final encoded capability | Decoded by XOR `0xc49697f0` |
| --- | --- | --- | --- | --- | --- |
|No|No|0|0|`0xc49697f0`|0|
|No|Yes|0|`0x1f8`|`0xc4969608`|`0x1f8`|
|Yes|No|`0x4c0b0000`|0|`0xc49697f8`|`0x8`|
|Yes|Yes|`0x4c0b0000`|`0x1f8`|`0xc4969608`|`0x1f8`|

This table describes source-level composition after successful discovery/open and under the retained returning-helper contracts. It supplies no native status,size,port or successful query observation. Capability bit3 alone is therefore not evidence of an accepted capability query. Actual downstream feature decisions need the encoded-field reader and the query-outcome epoch,not only a numeric field value. [KG6-KG7]

## Assumption register

| ID | Assumption and dependent claims | Stress test or falsification probe |
| --- | --- | --- |
| KG1 |The pinned normalized image,KC and daemon captures identify the analyzed builds;all source correspondence depends on them.|Rehash originals,compare nine kext ranges and21 daemon ranges,verify original pointers/descriptor fields,and compare the saved five IDA range hashes.|
| KG2 |Original byte banks,pool/dispatch words and base-provider vtable retain their epochs;target and route claims depend on them.|Exhaust3072 byte inputs,prove each original selector expression before its cut,check pointer addresses/targets/diversities;recover actual vptr/loader epochs separately.|
| KG3 |Declared stack/record/global memory is valid and has the stated disjointness;memory/result composition depends on this.|Check exact original read/store addresses,48/64 B reservations,record widths and nested/outer separation;require native owner/lifetime evidence before applying it to real frames.|
| KG4 |ARM widths,source SSA,unscaled-access lowering and normalized pointer interpretation match the captured instructions.|Preserve original operands/bytes,prove354 translated instances and all twelve cuts;reject bank/discriminator/source changes;hardware PAC remains outside the proof.|
| KG5 |Callees return ordinarily,preserve ABI callee-saved state/SP and unrelated caller result/guard cells;returned constants depend on this continuation.|Prove the two leaf stores/pointer returns,adapter postcall store and getter loads;check canary/RETAB structure. Nonreturn,guard mismatch or external interference invalidates the returning-path conclusion.|
| KG6 |Prior daemon guard/cache/fallback source contracts apply with their original frame and normal-return premises.|Freshly replay nine original propositions,recapture their ranges,and independently specialize all four acceptance outcomes. Reject zero-result candidates with two abstract SAT controls.|
| KG7 |Static provider-to-daemon compatibility is distinct from a live connection/build pairing or bit meaning.|Require actual service/connection/provider identity,loaded-build correspondence and transaction/reader evidence;do not name bit functions or treat fallback bit3 as proof of successful query23.|
| KG8 |Saved read-only IDA observations and source proofs remain distinct from native execution and current-state reobservation.|Record observation identity/hashes and zero recall matches;exclude unrelated diagnostics;reject native-execution claims and reobserve IDA before asserting later live state.|

## Bounded continuation

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High |Trace readers of daemon state+0x14 and version fields through actual call selection|Which source facilities use bits3..8 and how the fallback-only bit3 affects routing.|
| High |Resolve the retained selector21 packet producers and their552 B consumer ABI|Connect richer daemon requests to kext processing beyond metadata compatibility.|
| High |Establish real service/connection/provider identity and loaded-build pairing|Whether these static getter values apply to an actual daemon-kext transaction.|
| Medium |Recover controller ownership,synchronization and reaching table epochs|Whether ordinary calls preserve the source assumptions under concurrent use.|
| Medium |Match broader getter callers and provider overrides|Bound reuse of these constant metadata contracts outside the inspected base route.|

## Scoped quality gates

- QG1:Source,routine,record,metadata and conditional interface analysis require no normative conclusion.
- QG2:KG1-KG8 list dependent claims and falsification probes.
- QG3:The increment establishes both getter values,three internal targets,record/return channels,controller destinations,UserClient publication and conditional daemon cache/failure outcomes. Native pairing and the wider interface goal remain active.
- QG4:453*4=1812 B;3072=12*256 bank inputs;354 nonbranch instances are translated. Outputs are u32,record/pointer arithmetic uses the stated u32/u64 widths,and stack reservations are48/64 B. Capture/lifting costs O(B+I+256R) time and retained space for bytes B,instructions I and R bank rules;solver complexity is separate,with45000 ms solver/50 s process limits per query.
- QG5:Constant returned data and controller side effects,private record words and wire commands,returned pointer and metadata value,provider data and UserClient status,accepted query and fallback capability,static and native pairing remain distinct.
- QG6:Original KC/normalized bytes,descriptor/member/vtable pointers,eight byte arrays,twelve fresh source equalities,38 UNSAT,two abstract SAT,nine original predecessor replays,saved IDA hashes and eight freshness alterations provide scoped provenance.
- QG7:Impact-ranked continuation targets encoded-field readers,selector21 ABI,native endpoint identity,mutable controller epochs and overrides;no capability-bit function or successful native exchange is invented.
