# Keyed scalar population and the stateful 64-bit helper ABI

The selected builder path looks up encoded identifier0x7dab886f in C1, the collection at builder+8. A returned low32 marker0x74c29ded selects a stateful helper and a u32 constructor for that same identifier in C1. Other returned markers select the shared builder finish. This establishes the selected missing-key population route; the complete existing-record interpretation is not recovered here. [SG1-SG5]

The called helper is the complete compiler-bounded function0x100444dfc..0x10044a3e0:5497 instructions, no calls or conditional branches, and a final RETAB. It saves the incoming X0 pointer, later writes a full64-bit value at that pointer+8, and restores its192 B frame. This call therefore needs at least16 B of argument storage. The caller consumes only low32 of the output and converts it to a scalar operand. The helper's complete value algorithm, cryptographic identity and native timing behavior remain unknown. [SG3,SG4,SG6]

Twenty-one accepted source/byte-memory queries cover the selected interfaces, result-width conversion and found-header frontier. The translation ledger covers all282 nonbranch/noncall instructions in the fourteen main fragments and four helper projections. The other helper instructions are captured and structurally checked; their full value semantics are explicitly unproved.

Evidence: [source, helper structure, frozen episodes/field and IDA knowledge snapshot](triage_evidence/daemon_scalar_field_population_source.json), [queries and alteration checks](triage_evidence/daemon_scalar_field_population_checks.json), [extractor](triage_evidence/recover_daemon_scalar_field_population.py), [validator](triage_evidence/validate_daemon_scalar_field_population.py), [preservation](triage_evidence/daemon_scalar_field_population_delivery.json), [scoped gates](triage_evidence/daemon_scalar_field_population_quality_gates.json). Adjacent contracts: [builder ownership](daemon_builder_owner_join_report.md), [first-match lookup](daemon_constructor_lookup_report.md), [typed callers](daemon_constructor_callers_report.md), [byte codec](daemon_payload_codec_report.md), [retained XPC lineage](daemon_record_stream_report.md). No target/native execution, new emulation, native API/IPC operation or IDB mutation occurred.

| Evidence | Scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Main source |14 fragments,275 instructions,1100 B |
| Complete helper |5497 instructions,21988 B; fresh compiler-start/next-start match |
| Helper projections | Four ranges/22 instructions, contained in the complete helper |
| Accepted certificate |21 UNSAT queries,282 translated instruction instances/255 SSA definitions,ten rejected alterations |
| Static metadata |23 independently decoded original pointers;21 selected slot/modifier matches;256 helper-bank cases |
| Structural helper checks |44 direct SP accesses; no direct SP read before a source write; no saved-register read before the epilogue; no W30 clobber after the selected context-word read |
| Frozen corpus |12 lookup-miss/population episodes,12 third-constructor node/buffer pairs,12 matching wire fields; zero found-value entries |
| Prior recapture |78 ranges/9672 B |
| IDA knowledge | Three read-only recalls against database6b117c693e3b; no relevant checked semantic fact used |

Addresses/offsets/constants are hexadecimal; extents use B. K denotes the caller's shared frame, H the builder, C1=[H+8], NODE a matched record node, BUF its record buffer, CONT a code pointer, and GEN64 the helper's stored output. X6 is a full64-bit raw marker; status gates inspect its low32 bits. Arithmetic wraps at u32/u64 width unless otherwise stated. All role names are analytical, not original symbols or public declarations.

## Lookup, status and population flow [SG1-SG5]

```text
builder H
    |
    +-- C1 = [H+8]
            |
            +-- lookup encoded identifier0x7dab886f
                         |
                 returned low32 marker
                 /                    \
        0x74c29ded                    other
              |                        |
       stateful helper             common finish
       writes GEN64                    |
              |                   success/disposal
       V32 = low32(GEN64)
             XOR0xdeac5766
              |
       u32 constructor in C1
       HE=0x7dab886f, P=4 B
              |
       saved return -> common finish
```

| Stage | Exact private interface |
| --- | --- |
| Caller0x1009ab118 | CELL=H+8 in X8, HE=0x7dab886f in W9, OUT=&K[601c] in X11, continuation selector0x922 in W10; index0x3b01 ->0x100847998 |
| Entry0x100847998 | Reads C1=[CELL]; saves CONT at K+7af0 and OUT at K+4ca0; zeros node-output cell K+59b0; stages status at+84cc and encoded cursor at+8048 |
| C1==0 | Relays raw0x74c29d88 through saved CONT |
| Lookup0x10074ab80 | X8=C1,W9=HE,X11=&K[59b0],W10=0x130c; index0x18e2 reaches the previously recovered first-match lookup |
| Return0x1004e9b70 | Exact low32 success0x8b3dc651 enters found-node processing; all other markers relay unchanged |
| Relay0x1006f76a8 | Reloads CONT from K+7af0 and transfers with IA0x90ec; no value-output store |
| Builder gate0x1006985d4 | Only returned low32 marker0x74c29ded selects0x1006f0a84; every other marker selects0x10090a400 |

The prior lookup contract identifies0x74c29ded as its end-of-list miss marker. In the retained episodes that miss propagates directly through the relay and selects population. The new caller gate is proved for every raw X6 value. This is not a proof that every possible status from the uncompleted found-value workflow has a particular public meaning.

The existing builder's two producer descriptors have different encoded identifiers from0x7dab886f. Under the earlier empty-container/constructor/normal-return and stable-list premises, that supplies the source explanation for the retained initial miss. The source path writes the new record into C1 at H+8. The earlier prospective C0 metadata continuation is superseded by this actual source load.

## Found-record frontier and output limits [SG2,SG3,SG5]

A successful lookup reaches0x1009238d8. It reads NODE=[K+59b0], BUF/u64=[NODE+18] and SIZE/u32=[NODE+10], then saves BUF at K+3710. A null buffer selects the saved return with raw0x74c29d88. A valid node is required before these reads.

For a nonnull BUF,0x1005dd9c8 saves SIZE/u64 at K+a638 and the entry cursor at K+a640. The cursor representation0x797188010b5fa78c decodes to offset zero in this entry. The exact unsigned gate is SIZE>9: extents below10 B return raw0x74c29d8f; other extents reach the first header-word decoder preparation. At0x10074add4, X1=BUF, X4=0x661a590b302baf96, W8=0x8c3f and W16=0x74 identify the existing offset-zero decoder interface.

The subsequent header/type/value interpretation, all its return markers and the complete borrowed OUT-value write contract remain unknown in this increment. No retained successful profile enters this found-value branch. The null/miss relays do not themselves write through the borrowed value-output address; saving that address in the frame is distinct from initializing its pointee. Buffer ownership of SIZE bytes, stable matched-node lifetime and valid decoder context remain premises. No malformed-node or failure fixture was executed.

## Helper call and 16 B argument/output record [SG3,SG4,SG6]

Let A=K+0x10cb8. Population0x1006f0a84 writes a staged u32 at A:

```text
staged = ((low32(A) XOR0xdc40790b)*0x5973a279
          +0x0250710d) mod2^32
```

The source then supplies X0=A to0x100444dfc. The helper target is selected by the original E-bank pair0x100e99700/0x100f4e190, key0x81 and addend0xcc10. All256 byte inputs collapse to0x48, giving index0xcc58 and original slot0x1010a01b0, IA diversity0x9a7c/address diversity zero. Source queries verify controller addresses, byte addresses, table slot and argument. Actual roots and hardware authentication are separate premises.

| Argument-relative field | Captured source role |
| --- | --- |
| +0 /4 B | Caller-staged pointer-dependent word; no operation/authorization meaning assigned |
| +4 /4 B | Not classified or presumed zero by this increment |
| +8 /8 B | Full64-bit helper output store at0x10044a3bc |
| +8 /4 B | Caller load at0x1006f0b28 reads only the output's low32 bits |

The initial X0 pointer's only use before its first actual register definition is STR X0,[SP,#48]. That saved pointer cell is read only at0x10044a3b8 for the final output store; the complete direct-SP overlap census finds no intervening direct write to it. No incoming GPR data read occurs before a local definition within the body after excluding prologue saves and epilogue restores. No saved-register stack word is read before the epilogue. These structural facts support an output-argument ABI under stable saved slots and disjoint state/argument/frame owners. They are not a whole-program memory noninterference proof: other pointer aliases and native state must be established separately. The staged word is not thereby assigned semantic control over this helper.

## Stateful helper structure and context-word update [SG3,SG4,SG6]

The complete helper contains no call, conditional branch or SVC/HVC/SMC; its sole terminal control transfer is RETAB. Its prologue subtracts0xc0=192 B from SP, saves X19..X30, and stores the incoming output pointer at helper-SP+48. Its epilogue restores those registers and adds192 B to SP. Hardware PAC acceptance and computed-memory aliasing are not established by these source checks.

The ordered direct-SP census contains44 accesses, with every direct read preceded by a source write over the same bytes. The saved argument slot has exactly one direct write and one direct read; no saved-register word is read before the epilogue. These facts corroborate saved-slot structure, not complete native stack/heap safety. A computed local address derived from SP also appears in the body; it is not generalized into a complete alias proof.

The selected context sequence is:

| Site | Source relation |
| --- | --- |
| 0x100447970 /0x100447974 | Reload CTX_CELL from helper-SP+50, then CTX=[CTX_CELL] into X20 |
| 0x1004486a0 | Read COUNTER/u32 at CTX+34 into W30; X20 is not redefined between the reload and this read |
| 0x10044a394 /0x10044a398 | Reload CTX_CELL and CTX before the tail store |
| 0x10044a39c /0x10044a3a0 | Store `(COUNTER+1) mod2^32` at CTX+34; W30 has no intervening definition |
| 0x10044a3b4 /0x10044a3bc | Store `INTERNAL64 XOR0xc0eaaa2272eb67c0` at ARG+8 |

INTERNAL64 remains opaque. The context-word increment is relative to the mid-function read, not necessarily the function-entry value: earlier body writes may already have affected state. Equality of the reloaded CTX pointers requires stable pointer-cell contents. No atomicity, locking, race, entropy or cryptographic property is inferred.

The [earlier initializer analysis](arcade_subscription_report.md) identifies mutable byte-state allocations and initialization dependencies. The complete helper bytes match that retained compiler range. This increment does not rerun initialization or recover the full state/value algorithm. A separately analyzed [ADID packet route](adid_avp_packet_report.md) uses the same numeric wire key and has finite time/random dependence; equal keys alone do not prove identical semantics or exclusive environmental dependence across callers.

## Output width, constructor and wire field [SG2-SG7]

After normal helper return,0x1006f0b28 loads only W8 from A+8. It supplies:

```text
V32 = low32(GEN64) XOR0xdeac5766
C1  = [H+8]
HE  = 0x7dab886f
```

The u32 adapter saves the outer continuation selected by0x1c9 ->0x10090a400 at K+3598, checks C1 and selects typed root0x100828290. That root preserves HE/V32/C1, supplies internal tag0x86b4, encoded extent0x8b3dc655 and inner return0x222. The established constructor contract gives a32 B node and14 B record buffer under normal allocation/owner premises. Stable first-miss/list premises give insertion; replacement and failure behavior remain governed by the existing constructor contracts.

The previously established producer/serializer inverse and header codec yield:

| Wire property | Exact source-composed relation |
| --- | --- |
| Identifier | `0x7dab886f XOR0x8b3dc651 = 0xf6964e3e` |
| Discriminator | `0x86b4 XOR0x11c3 = 0x9777` |
| Payload extent | `0x8b3dc655 XOR0x8b3dc651 = 4 B` |
| Raw payload | `BE32(low32(GEN64) XOR0x55919137)` |
| Ignored result bits | GEN64 bits32..63 do not enter this scalar operand |

A byte-array component proves that the caller's little-endian32-bit load observes the low word of the preceding little-endian64-bit store. The native lifetime and no-intervening-write premises are separate. Typed constructor return reloads the saved outer continuation and core phase, then reaches common finish. Exact success publishes the builder; another returned status reaches its previously recovered disposal route. This scalar stage emits no Mach message.

## Retained episode and field evidence [SG7]

All twelve successful retained profiles contain the lookup-miss relay, one call from0x1006f0b24 to the full helper, the u32 adapter/root and return to common finish. Each profile's third node allocation is32 B and third record-buffer allocation14 B. No profile enters the found-node/type/value path described above.

The complete recorded XPC `data` bytes contain exactly one nested record with identifier0xf6964e3e, tag0x9777, extent4 B and raw payload04f2abb5. Record offsets vary with the path; the extractor parses bounds and nesting rather than using a fixed offset. The recorded packet bytes are historical private-model evidence. The [record-stream report](daemon_record_stream_report.md) supplies the earlier allocation-to-setter/send lineage and its scope.

Under the source codec composition, those bytes imply encoded scalar operand0x8fcf6de4 and helper-output low word0x51633a82. These values are inferred from wire bytes; they are not captured helper-register or output-cell snapshots. The helper's upper32 result bits remain unknown. Neither this finite equality across twelve profiles nor the separately retained environmental controls identifies the field as a checksum, nonce, random value or authentication result.

## Read-only IDA knowledge lookup [SG1,SG8]

The open database list identified `fairplayd`, database6b117c693e3b. Three read-only recalls covered builder/serialization terms, address0x100847998 and the112 B preparation region. The keyword queries returned zero results; the address query returned four unverified global facts and no relevant local semantic fact. Stored-knowledge statistics reported nine facts: four global and five local. The source artifact preserves the query arguments/results and marks all knowledge as unused for semantic claims.

This lookup attests only the selected database label and returned knowledge snapshot. It is not a fresh loaded-code/input-hash comparison. No note, rename, database save or memory write was performed. Original thin-image bytes and fixups remain the primary source for this increment.

## Complexity and premises

For k examined candidates, the reused first-match lookup costs O(k) control work and O(1) scalar traversal storage under a finite stable acyclic list. The missing-field route then executes the fixed5497-instruction helper and invokes the existing constructor, whose search/codec/allocation costs are documented separately. Fixed instruction count is not a native timing or cryptographic constant-time claim. Allocator and shared-state initialization costs remain unknown here.

Capture/check work is O(original bytes+fixups+captured instructions+frozen packet bytes). Structural helper inspection is linear in5497 instructions; parsing uses bounded nesting depth4. SSA translation is linear in282 selected instructions. SMT resource use is additional, with a15000 ms limit per query. No target CPU, helper, allocator or IPC transaction is executed by these checks.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test or falsification probe |
| --- | --- | --- |
| SG1 | Source/fixups/compiler ranges belong to the pinned thin image. All address roles depend on this build. | Rehash and recapture bytes, complete helper bounds and original pointer records; reject cross-build substitutions. IDA knowledge is not substituted for byte evidence. |
| SG2 | Compatible phases, source table and saved continuation epochs are supplied. Lookup/constructor/finish joins depend on these conditions. | Pass source register outputs into following inputs, check actual selected slots and saved return fields; equal modifiers alone are insufficient. |
| SG3 | Builder/C1/list/node/buffer/frame/argument owners are valid, disjoint where required, stable and nonwrapping for the stated accesses. Memory/lineage composition depends on these premises. | Recover owner roots, sizes, aliases and last uses; distinguish requested sizes, source effects and frozen observations. Header extent fields do not prove backing ownership. |
| SG4 | The stateful helper returns normally, required saved registers/SP/slots survive, and global pointer cells/state owners remain valid. Post-call and context-word joins depend on these conditions. | Check prologue/epilogue, direct-SP accesses, incoming-GPR uses, counter liveness and explicit64-bit output store. Computed aliases, synchronization and native PAC remain unproved. |
| SG5 | The prior first-match lookup/constructor/codec contracts and stable-list premise apply to these exact C1/HE/V operands. Missing-field insertion and wire composition depend on this reuse. | Recheck operand widths/identifiers, source cell H+8 and actual constructor root. Complete found-value interpretation remains an open separate path. |
| SG6 | GEN64 is an opaque stored output; no algorithm, security or exclusive-dependence identity is assumed. Only its source-proven low-word use is claimed. | Recover whole-helper data semantics and global state producers before stronger labels. Do not promote no incoming GPR data reads into a complete memory noninterference claim. |
| SG7 | Frozen profiles retain their recorded source, allocator/branch/packet data and model scope. Occurrence and inferred-word claims are corpus-bound. | Rehash profiles, parse nested bounds, match third allocations and label inferred values explicitly. No native relabeling or generator rerun is supplied. |
| SG8 | Public error/field meanings, complete found-reader behavior, native owners/state/credentials/ports/PAC and selector26/RPC502/700 pairing remain unknown. | Require matching public consumers, owner/state provenance and endpoint evidence before assigning those meanings. The failed open capture supplies no successful native pairing. |

## Bounded continuation opportunities

| Impact | Next static target | Question resolved |
| --- | --- | --- |
| High | Complete the found-record header/type/value continuation after the first decoder interface. | Full accessor result grammar and which existing records are accepted without population. |
| High | Recover compact value semantics of the5497-instruction helper and exact mutable-state/context roots. | Generated-word role and state evolution beyond the structural ABI. |
| High | Follow the populated C1 and remaining112 B builder fields into serialization/public consumers. | Complete builder grammar and source-to-IPC ownership/representation transfer. |
| High | Establish same-build native endpoints/owners for selector26/RPC502/700. | Actual daemon-kext/deeper transaction pairing. |
| Medium | Trace state initialization, shared pointer-cell stability and caller synchronization. | Environmental influence, lifetime epochs and concurrency premises. |
| Low | Apply the output-only pointer-route check to other calls of the same helper. | Which staged words are semantic inputs and which result widths consumers retain. |

## Scoped quality gates

- QG1: Technical source/interface/field facts require no normative conclusion.
- QG2: SG1-SG8 enumerate dependencies and falsification probes.
- QG3: The selected missing-key population, stateful helper ABI, width/codec transfer, found-header frontier and frozen wire field are covered. Whole-helper value semantics, full accessor and broad goal completion remain unproved.
- QG4: u32/u64 modular widths,192 B frame,minimum16 B argument,64-bit store/32-bit consumer,32/14 B allocations,endianness and conditional complexity are explicit.
- QG5: All282 selected main/projection instructions are translated exactly once. Structural coverage of5497 helper instructions is distinct from full value proof. Twenty-one accepted UNSAT queries and ten rejected alterations preserve those boundaries; inferred low word is not a snapshot.
- QG6: Original source/fixups/compiler bounds,complete helper bytes, frozen branches/allocations/packets and scoped queries provide primary provenance. Read-only unverified IDA notes are retained but unused semantically. No new target/native run occurred.
- QG7: Continuations are bounded and impact-labeled. Native pairing and complete goal coverage remain unknown; scoped passing gates do not establish full completion.


## Subsequent result-width refinement

The [later residue analysis](daemon_helper_result_residue_report.md) recovers bits35..32 as0x1, giving inferred low36=0x151633a82 from the retained allocation-entry X5 snapshots and source register preservation. The upper32-unknown statement above describes this earlier increment's scope; the subsequent certificate leaves only bits36..63 unresolved. It does not recover the complete helper algorithm or supply native evidence.


## Subsequent existing-record reader recovery

The [later reader certificate](daemon_existing_scalar_reader_report.md) completes the conditional found-path type/extent/output grammar under explicit stable-frame/owner/read premises. Wire9777 with PL4 and PL+10<=SIZE publishes BE32(payload) through the saved OUT; recognized8485/50db return a distinct raw marker. This supersedes the earlier found-reader unknown within that conditional source scope. No retained profile enters this branch; native context-read admissibility, owners/PAC and daemon-kext pairing remain unproved.
