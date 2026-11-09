# Selector18 data regions, entropy request and kernel PRNG registration

The shape-selected `_zgcqcxw1qve0CY` path allocates an input-length-sized region, then an output-capacity-sized region, and prepares a28-byte `_kernel_read_random` request into the second region. The import resolves to kernel `_read_random`. Original corecrypto startup constructs the callback table consumed by `_register_and_init_prng`; its refresh/generate entries correspond to the kernel wrapper's two indirect calls. Native registration, entropy generation, input-content consumption and final output publication remain unknown. [IB1-IB13]

Forty-eight fresh private cases pass:24 preserve the preceding selected prefixes and stop before a zero-capacity allocation request;24 disjoint request fixtures with output capacity3072 B reach the entropy-call boundary. All allocator models provide register-only returns; data-buffer contents remain unknown. Fifteen source-derived proof pairs additionally establish conditional post-entropy stores/alignment and the kernel's chunk/callback argument contracts. These static downstream proofs do not execute entropy or a post-entropy continuation.

[Source contracts](triage_evidence/lskd_input_buffers_contracts.json), [retained profiles](triage_evidence/lskd_input_buffers_profiles.json), [fresh replays](triage_evidence/lskd_input_buffers_replays.json), [independent byte checks](triage_evidence/lskd_input_buffers_checks.json), [source proofs](triage_evidence/lskd_input_buffers_proofs.json), [registration token walk](triage_evidence/lskd_entropy_registration_walk.json), [source identity](triage_evidence/lskd_input_buffers_source_identity.json), [preservation](triage_evidence/lskd_input_buffers_preservation.json) and [scoped gates](triage_evidence/lskd_input_buffers_quality_gates.json) retain the evidence. The broader investigation remains active.

```text
selector18 / original core
  -> IOMallocData(input_length32)      [nonnull register return]
  -> auxiliary+0x60 = input-sized pointer
  -> IOMallocData(output_capacity32)   [nonnull register return for3072 B]
  -> auxiliary+0x1A0 = output-sized pointer
  -> kernel_read_random(output-sized pointer,28) [stop before call]
       -> FairPlay import -> kernel read_random
            -> refresh(runtime context)
            -> generate(context,u16 machine field,chunk,destination)
                 source startup binding: cckprng_generate

source registration lineage [static; native execution unknown]
  corecrypto startup constructs six authenticated pointers
    -> register_and_init_prng(context,table)
    -> authenticate at source cells / sign for destination cells
    -> publish context and callback cells
```

All offsets are hexadecimal unless explicitly decimal. B denotes bytes. Region names describe allocation-size provenance; no input copy, output format, nonce role or cryptographic meaning is inferred from them.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
|IB1 |Pinned KC, normalized kext and embedded corecrypto identify this build |Source, imports, symbols and callbacks |Rehash originals; read back kext/native/corecrypto source and exact fixups |
|IB2 |Declared private A64 semantics and abstract PAC |Private source outcomes |Audit every instruction byte and memory epoch; verify original slots/diversities; native PAC remains unknown |
|IB3 |Inherited allocators and input/output-sized allocators return explicit nonnull regions |Continued source flow |Check arguments, clobbers and zero model memory accesses; zero-capacity request remains unexecuted |
|IB4 |New request fixtures have declared disjoint extents; preceding cases retain address-only inputs |Concrete layout evidence |Check input/data extents and3072-byte result region; preceding input validity remains unknown and unread |
|IB5 |Unknown private contents stay masked; WZR probes discard values |No invented data initialization |Reconstruct all epochs,96 discard reads and120 unknown snapshots; stop before unknown value reads |
|IB6 |Source frame bank/phase epochs retain their checked lineage |Decoded targets and local lemmas |Preserve24 exact prefixes, check96 saved bank cells and exhaust512 bank inputs |
|IB7 |Only preceding selected paths are extended |Increment coverage |Compare all24 selected prefixes; preserve/hash previous rejection evidence without claiming new rejection replays |
|IB8 |Entropy normally returns and preserves callee-saved GP registers |Post-entropy stores/alignment |Source-lift under explicit phase/register premises; no such continuation executes here |
|IB9 |File-zero callback/context cells do not describe live kernel values |Native backend boundary |Retain raw bytes and source writers; recover actual boot/runtime epochs separately |
|IB10 |Corecrypto startup and registration prehelper reach their normal continuations |Source callback lineage |Check complete functions, exact registration call/import and context/table arguments; native startup remains unobserved |
|IB11 |PAC tokens represent raw targets/modifiers under successful authentication |Source transfer between pointer slots |Match constructor/authentication/re-sign modifiers at all six entries; tokens are not native signed bits |
|IB12 |Kernel callback/context/machine-field values are independent opaque runtime inputs |Chunk/argument lemmas |Prove exact register transfers over symbolic values; do not infer the u16 field's semantic name or stable cross-call context |
|IB13 |Allocation provenance and entropy request do not prove ownership, contents or publication |Whole-operation/transport boundary |Inspect subsequent consumers and actual daemon reply separately; no additional Mach exchange is established |

IB1-IB13 qualify dependent results. Native heap operations, entropy, backend initialization and callback execution remain unexecuted. No allocation failure or guard mismatch is induced.

## Allocation and entropy interfaces

| Source site | Target / exact arguments | Source effect or boundary |
| --- | --- | --- |
|0xfffffe000a56d228 |`_IOMallocData` at0xfffffe000c4ba60c;X0=zero-extended input length32 |48 nonnull register returns; source stores pointer at auxiliary+0x60 |
|0xfffffe000a56d238 |`STUR X0,[X1,#0x60]`,X1=reloaded auxiliary |48 original eight-byte pointer stores |
|0xfffffe000a56d264 |Index0x8DE ->0xfffffe000a54409c,diversity0xF457 |48 original abstract-PAC edges |
|0xfffffe000a544120 |Same IOMallocData;X0=zero-extended output capacity32 |24 capacity0 frontiers;24 modeled capacity3072 returns |
|0xfffffe000a54412c |Store returned output-sized pointer at auxiliary+0x1A0 |24 original eight-byte pointer stores |
|0xfffffe000a544160 |Nonnull index0x4B3 ->0xfffffe000a58c3bc,diversity0x7F88 |24 original abstract-PAC edges |
|0xfffffe000a58c428 |`_kernel_read_random` at0xfffffe000a508d6c;X0=output-sized region,W1=28 |24 frontiers; call unexecuted |

The output-capacity allocator uses saved u32 SP+0xD68 and saves its zero-extended request at SP+0x468. The preceding input-length-sized request is saved at SP+0x4F8. Source also preserves the first returned pointer in X20 and the input length in callee-saved X19 before the entropy call. This does not establish that either allocated region contains input data.

| Exhaustive bank | Left/right byte tables | Key / constant / additive | Index / slot / target |
| --- | --- | --- | --- |
|Output allocation |0xfffffe00079172c0 /0xfffffe0007919cb0 |0x27 /0x61 /+0x989 |0x9EA /0xfffffe0008471370 ->0xfffffe000c4ba60c |
|Entropy wrapper |0xfffffe000791d3b0 /0xfffffe0007920e10 |0x3B /0xCA /+0x947 |0xA11 /0xfffffe00084714a8 ->0xfffffe000a508d6c |

The exact bank values and original authenticated fields are retained in the contract. Each rule is checked over256 byte inputs. Internal table indices and diversity values are not Mach message identifiers or rights.

The new private layout is:

```text
input source        [0x6300020000, +length32)  unknown,unread
input-sized region  [0x6300030000, +length32)  unknown
output-sized region [0x6300050000, +3072 B)    unknown
caller output       [0x6300006000, +3072 B)    unread
workspace           [0x6300008000, +16384 B)   16 source-known bytes
auxiliary           [0x630000c000, +4096 B)    16 source-known pointer bytes
```

The exercised lengths are16 and65536 B; these new regions are disjoint. The24 preceding cases retain their earlier input-address fixtures, without treating those complete spans as valid native buffers. They stop before the capacity0 allocation. The output-region snapshot in those cases is reserved unknown backing, not a successful allocation result.

No new data-region byte is initialized by an allocator model. There is no work-region value read or extended-private-buffer access in any case. Source initializes8 auxiliary bytes in each capacity0 case and16 in each entropy-frontier case. The3072-byte declaration contains the28-byte requested entropy extent; other capacities' later behavior remains unknown.

## Import and deeper kernel ABI

| Layer | Original source / binding | Verified contract |
| --- | --- | --- |
|FairPlay wrapper |0xfffffe000a508d6c..d74 |BTI, then branch to import stub0xfffffe000a69f394 |
|FairPlay import |0xfffffe000a69f394..3a4;slot0xfffffe000847c4f8 |Original authenticated target0xfffffe000be57d68 |
|Kernel entry |0xfffffe000be57d68 |Exact `_read_random` symbol; complete172-byte function retained |
|Refresh call |0xfffffe000be57da8 |Callback from0xfffffe0007e6c9a0;X0=context from0xfffffe000cb88f48;diversity0x4D5F |
|Generate call |0xfffffe000be57de8 |Callback from0xfffffe0007e6c9a8;diversity0xEDEB |

The generate-call register contract is:

| Register | Source value |
| --- | --- |
|X0 |Reloaded u64 runtime context from0xfffffe000cb88f48 |
|X1 |Zero-extended u16 at `[TPIDR_EL1+0x1B8]`; semantic name unknown |
|X2 |Chunk size, at most256 B |
|X3 |Current destination pointer |

The wrapper calls refresh before its zero-length test. It then uses `low32(X1)` as the length, selects `min(remaining,256)`, advances the destination by that chunk and subtracts it from the remaining count. The source proofs cover all32-bit length/count values and modular64-bit pointer arithmetic. They do not prove native address validity. The context and callback are reloaded for generate calls; no cross-call identity or synchronization guarantee is inferred.

For a positive length N B, the source loop's call count is `ceil(N/256)`; the final remainder after a chunk is smaller than the old positive remainder. For this caller, N=28 B gives one generate call of28 B, conditional on the native wrapper/backend path executing normally. N=0 gives no generate call after refresh. No callback executes in the private cases.

All three consumed callback/context cells are eight zero bytes in the original file. None is an original chained-pointer binding. Their native values remain unknown; no call through a file-zero value is attempted.

## Corecrypto construction and registration lineage

The embedded corecrypto UUID is `6bdded85-b6a0-31ec-8c64-b4fd1ee511e8`. Its exact `_corecrypto_kext_start` at0xfffffe000baf476c contains the constructor at0xfffffe000baf4a30. Registration call0xfffffe000baf4ae4 passes X0=0xfffffe000cdf0670 (exact `_kprng_ctx`) and X1=SP+0x20, a48-byte table of six authenticated pointers.

Its import stub0xfffffe000bb04c0c reads original authenticated slot0xfffffe0008ab7cb8, targeting exact `_register_and_init_prng` at0xfffffe000c6393c4. That function publishes context at0xfffffe000cb88f48 and authenticates/re-signs each table pointer for its destination cell.

| Table offset | Exact raw function / address | Destination cell | Diversity | Constructor store / registry store |
| --- | --- | --- | --- | --- |
|+0x00 |`_cckprng_init`,0xfffffe000bace638 |0xfffffe0007e6c988 |0x6961 |0xfffffe000baf4a48 /0xfffffe000c639428 |
|+0x08 |`_cckprng_initgen`,0xfffffe000baf3c08 |0xfffffe0007e6c990 |0xF60A |0xfffffe000baf4a64 /0xfffffe000c639458 |
|+0x10 |`_cckprng_reseed`,0xfffffe000bad1e24 |0xfffffe0007e6c998 |0x5D01 |0xfffffe000baf4a80 /0xfffffe000c639488 |
|+0x18 |`_cckprng_refresh`,0xfffffe000ba97954 |0xfffffe0007e6c9a0 |0x4D5F |0xfffffe000baf4a9c /0xfffffe000c6394b8 |
|+0x20 |`_cckprng_generate`,0xfffffe000bacc7ec |0xfffffe0007e6c9a8 |0xEDEB |0xfffffe000baf4ab8 /0xfffffe000c6394e8 |
|+0x28 |`_cckprng_init_with_getentropy`,0xfffffe000bacea44 |0xfffffe0007e6c9b0 |0x3051 |0xfffffe000baf4ad4 /0xfffffe000c639518 |

The source-only walk decodes120 original instructions, six table stores and seven registry publications (context plus six callbacks). Eighteen PAC token operations track six constructor signatures, six authentications and six destination signatures. Tokens carry raw target/modifier provenance; they are not cryptographic signatures and do not establish native authentication success.

The constructor signs for its stack-table field addresses. Registration authenticates using those source addresses, then signs for the corresponding destination-cell addresses with the same diversity. This establishes the address-sensitive architectural interface under IB10-IB11. It does not show that registration has run on a live kernel or that the backend context has been initialized.

The complete retained registration function later prepares an additional callback address0xfffffe000be580bc in X6 at0xfffffe000c63956c before call0xfffffe000c639590. That callback's exact symbol and complete seed-source contract remain unknown. Subsequent initialization/reseed calls and the registration prehelper0xfffffe000c63962c are unexecuted boundaries.

## Conditional post-entropy control/data flow

These claims are source-local, under normal entropy return and preserved callee-saved registers. They are not replayed parent continuations.

| Source store | Conditional effect |
| --- | --- |
|0xfffffe000a58c434 |Auxiliary+0x78 = first input-sized region pointer |
|0xfffffe000a58c438 |Auxiliary+0x340 = u64 zero |
|0xfffffe000a58c440 |Workspace+0x0C = u32 zero, through source frame cell SP+0x8E8 |

The subsequent source guard tests `(input_length32 &15)==0`. Its two authenticated targets are:

| Predicate | Source index / slot / target |
| --- | --- |
|Length divisible by16 B |0x47A /0xfffffe000846e7f0 ->0xfffffe000a53a224 |
|Other lengths |0x2BC /0xfffffe000846da00 ->0xfffffe000a55a430 |

Both slots carry diversity0xA18B. Combining this conditional alignment predicate with the preceding numeric bounds leaves length values `16*k B`, for integer1<=k<=4096. This is an additional numeric condition, not content or cryptographic acceptance. Both target fragments remain unexecuted here.

## Primary provenance, verification and limitations

| Item | Verified value |
| --- | --- |
|Original KC SHA-256 |`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
|Normalized kext SHA-256 |`2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
|Fresh cases / exact preceding selected prefixes |48 /24 |
|Original private instruction visits / byte checks |663504 /2654016 B |
|Read / write epochs |56616 /62112 |
|Register-only allocator models / model memory writes |168 /0 |
|Capacity0 frontiers /28-byte entropy frontiers |24 /24 |
|Source auxiliary pointer stores / nonnull dispatch edges |72 /72 |
|Fully unknown snapshots / undefined values consumed |120 /0 |
|Source proof pairs / lifted instruction instances |15 /68 |
|Exhaustive banks / byte inputs |2 /512 |
|Kext windows / external windows / complete native functions |5 /4 /2 |
|Complete corecrypto-start readback |1 |
|Registration source walk / table stores / registry publications |120 instructions /6 /7 |

Capstone5.0.7 reports CMP's X0 operand as written at0xfffffe000a544130. The original four bytes `1f0000f1` encode `SUBS XZR,X0,#0`, so the architectural destination is XZR and X0 remains intact. The verifier checks this exact encoding before accepting the42-instruction output-pointer def/use certificate. Symbolic CMP handling and fresh register outcomes independently agree. No other destination annotation is waived.

All48 cases preserve unknown data contents and stop before unmodeled calls. The earlier rejected-input evidence remains preserved, rather than being counted as freshly replayed in this increment. No input/output format, entropy quality, accepted context, native allocator lifetime, successful cryptographic operation or actual Mach reply is established.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_lskd_input_buffers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_lskd_input_buffers.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_lskd_input_buffers.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_input_buffers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_input_buffers_preservation.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_input_buffers_delivery.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Run producer/verifier commands sequentially and wait for terminal completion. Time/retained space is O(B+C*(V+E)+I+256R), plus solver cost (30 s/query): B is pinned source bytes,C cases,V visits,E byte-event extents,I decoded/lifted instructions,R bank rules. The native chunk loop has conditional count ceil(N/256) for positive u32 N, without native execution here.

The baseline contains2202 artifacts,2196 unchanged with six declared report/index edits. Original analysis.md, C and calls inputs remain unchanged.

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
|High |Recover the first input-content consumer and successful processing route |Normal-return summaries preserving unknown entropy/buffer contents; original readers and reaching definitions |
|High |Establish actual daemon-side selector18 use |Exact connection/caller, packet and embedded-status consumer |
|High |Connect successful core state to tag/vector writers |Actual source publication path, ownership and synchronization |
|Medium |Resolve native PRNG initialization and seed interfaces |Prehelper, callback0xfffffe000be580bc, context lifecycle and actual registration epochs |
|Medium |Recover aligned/unaligned continuations |Source targets and status/cleanup effects under declared entropy-return premises |
|Medium |Check future def/use alias annotations |Original instruction destinations and byte-level certificates where decoder metadata disagrees |

No additional incoming/outgoing Mach port, right transfer, message ID or emission is established. This increment adds kernel C ABI and initialization interfaces below the kext, while leaving daemon transport and live environment claims unresolved.

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
|QG1 |Pass |Factual source/interface analysis |
|QG2 |Pass |IB1-IB13 list dependencies and falsification probes |
|QG3 |Pass for increment |Allocations, entropy import, callback ABI and source registration covered; full objective incomplete |
|QG4 |Pass |Exact widths/extents, chunk/alignment calculations, counts and sequential reproduction |
|QG5 |Pass |Source/runtime registration, PAC tokens/native authentication, unknown contents, source proofs and private execution separated |
|QG6 |Pass |48 fresh audits,24 exact prefixes,15 source proof pairs, two exhaustive banks, original imports and complete native/corecrypto readbacks |
|QG7 |Pass |Impact-labeled continuation table |
