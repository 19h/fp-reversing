# IORPC serialized-object producer and inverse conversion

The selected original kernel route converts an `OSDictionary` into an out-of-line (OOL) binary object stream, publishes its VM-copy descriptor, and dispatches the inverse byte stream through `OSUnserializeXML` to a binary parser entry. This extends the previous port/zero-reference converter coverage. It does not establish a FairPlay caller of `IOService::SetProperties`, native delivery, or binary-parser correctness. The daemon/kext join remains unknown.

Primary evidence: [original source and fixups](triage_evidence/iorpc_ool_serialization_source.json), [20 CPU collection cases](triage_evidence/iorpc_ool_serialization_profiles.json), [independent replay and oracles](triage_evidence/iorpc_ool_serialization_checks.json). Previous constructed actors come from [object-conversion case 0](triage_evidence/iorpc_object_conversion_profiles.json). The original kernel collection hash is recorded in source; SDK headers are hashed supplementary declarations with no matching-source-revision claim. No IDA database modification or native target/VM/IPC/parser operation occurred.

## Original function identities and inferred roles

Addresses below are unslid collection virtual addresses. Exact symbols and anonymous inferred roles are distinguished in the source JSON.

| Address | Original identity / role | Evidence boundary |
|---|---|---|
| `0xfffffe000c4a41a8` | Exact `IOService::SetProperties(OSDictionary*, callback)` | 69 original instructions; complete builder and caller validation |
| `0xfffffe000c4a3290` | Exact `IOService::SetProperties_Invoke` | 69 original instructions; nullable dictionary type guard, handler ABI and reply |
| `0xfffffe000c488ca0` | Exact `OSSerialize::binaryWithCapacity` | Factory runs; lower collection allocation is modeled |
| `0xfffffe000c47d014` | Exact `OSSerialize::initWithCapacity` | Original rounding, fields and accounting run; lower VM allocation is modeled |
| `0xfffffe000c47d618` | Exact `OSSerialize::previouslySerialized` | Binary branch reaches original writer and indexed-header update |
| `0xfffffe000c489088` | Anonymous binary object traversal/writer | 676 original instructions captured; dictionary/symbol/data paths exercised |
| `0xfffffe000c488ed0` | Anonymous binary record emission helper | 110 original instructions; object-index bookkeeping, header/payload placement and alignment |
| `0xfffffe000bdd15a4` | Anonymous VM-copy input interface | Call/arguments/bytes verified; body captured but modeled, no native copy |
| `0xfffffe000bdcb374` | Anonymous VM-copy output/map interface | Call/arguments verified; body captured but modeled |
| `0xfffffe000bdc1ec0` | Anonymous mapping-deallocation wrapper | Original caller invokes it; body captured but modeled |
| `0xfffffe000c488964` | Exact six-argument `OSUnserializeXML` overload | Original dispatcher runs; both binary forms reach the same tail target |
| `0xfffffe000c489b18` | Anonymous binary-parser entry | Entry ABI/bytes only; body intentionally unexecuted and not captured in this source set |

The retained/new capture contains 168 complete functions / 14631 instructions. Ninety-two original binding records cover 91 unique slots, including 57 serialization bindings. A binding is not evidence that its callee executed. Three metadata allocation methods, memo-array initialization, index-data initialization, object references, byte-copy APIs, VM operations, transport and parser results are explicit models.

## Control and data flow

```text
SetProperties(self, dictionary, callback)
  -> original 108-byte kernel request builder
  -> OSMetaClassBase::Invoke -> original remote helper
  -> original request object converter
       self -> existing IOMachPort registry -> port descriptor
       dictionary -> binaryWithCapacity -> original binary writer
                  -> declared VM-copy input -> OOL descriptor
  -> common kernel transport entry [model or stop]

exact emitted packet + bytes, supplied to separate inverse component
  -> original inverse converter
       port -> original registry resolution -> self object slot
       OOL -> declared VM-copy output -> original OSUnserializeXML
           -> binary parser entry [declared object result or stop]
           -> declared deallocation -> original descriptor clearing
```

Each case starts from the exact 173-object published actor snapshot, then adds 20 private actors. The populated dictionary contains one nominal `OSSymbol` key `key` and one `OSData` value. The original string getter reads the packed length from `u32(object+0xc) >> 14`, subtracts one, and the writer includes the terminating NUL. The fixture supplies `4 << 14`, not an unpacked length. The original CString getter authenticates the pointer at object+0x10 logically; hardware PAC is not executed. [OS1-OS4]

## Kernel packet and emission locations

The request and reply buffer capacities are not wire sizes. All offsets are bytes relative to the kernel-form message. These are not user-form Mach descriptor widths.

| Field | Builder / transport form | Source location |
|---|---|---|
| Request size / descriptor count | 108 bytes / 2 | Builder `0xfffffe000c4a41a8` |
| Request version | `0x4da2b68c` | Message+0x1c |
| Self port descriptor | 16 bytes at +0x24 | Existing original port-conversion path; transport descriptor contains private port identity |
| OOL descriptor | 16 bytes at +0x34 | Builder signs logical placeholder `0x20` at `0xfffffe000c4a4224` |
| OOL control word | Initial `0x01000100`, converted `0x01000000` at +0x3c | Initial store `0xfffffe000c4a4214`; converted store pair `0xfffffe000c596624` |
| OOL byte extent | u32 at +0x40 | `0xfffffe000c596624` |
| Method / content | `0xd8a753ea156f9162` / +0x44 | Original builder constant and source stores |
| Content flags / object references | Initially 0 / 2; remote transport flags 5 | +0x4c / +0x54 |
| Self / dictionary logical object slots | +0x5c / +0x64, both cleared before transport | Dictionary clear `0xfffffe000c596618` |
| VM-copy descriptor pointer | Logical copy identity at +0x34, data discriminator `0x5d4f` | Original signing/store at `0xfffffe000c5966f4` |
| Lower VM-copy input call | `(map, bytes, extent, 0, out_copy)` | `0xfffffe000c5965b4` -> `0xfffffe000bdd15a4` |
| Transport emission frontier | `(message, 108, 128, 0, 0, moved_out)` | Existing helper call `0xfffffe000c595e08` -> `0xfffffe000bcf59e0` |
| Handler adapter | `(self, dictionary)`; callback discriminator `0xe4fe` | Original `SetProperties_Invoke`; result supplied as zero |
| Success reply | 60 bytes; version `0x4da2b68d`; same method; flags 8; refs/count 0 | Original Invoke reply stores; exact reply transferred to original outer validator |

The custom builder callback discriminator is `0xed39`. Default NULL callback selects the original Invoke route. The OOL payload is not a Mach port: its pointer denotes the supplied VM-copy object. The self-object port and remote destination port remain separate roles. Native rights, destination identity and actual delivery are unknown. [OS1-OS3, OS6]

## Binary bytes and storage accounting

The factory receives a 4096-byte capacity request. Original initialization computes `(4096 + 16383) & ~16383 = 16384 bytes`, requests that extent, and increments the private VM accounting cell `0xfffffe000cb5b630` by 16384 bytes. This cell is distinct from the earlier heap-accounting cell at `0xfffffe000cb5b638`. The modeled allocation returns status in W0 and address in X1; treating X0 alone as the buffer pointer would misrepresent this machine ABI. The map cell at `0xfffffe0007f860a8` is a runtime fixture; its file value does not establish native map identity. [OS2-OS3]

An optional OSData index allocation is tolerated when NULL. With index data, the first word is `0xd4 | (index_data_length_bytes << 6)`; without it, the first word remains `0xd3`. The read-only comparison bytes at `0xfffffe0007045578` are `d3 00 00 00`.

| Input | Indexed D4 extent | Non-indexed D3 extent | Exercised cases |
|---|---:|---:|---|
| Empty dictionary | 12 bytes | 8 bytes | 2/3; 16 |
| One `key` -> empty OSData | 24 bytes | Not exercised | 4 |
| One `key` -> 1-byte OSData | 28 bytes | Not exercised | 5 |
| One `key` -> 3-byte OSData | 28 bytes | Not exercised | 6 |
| One `key` -> 4-byte OSData | 28 bytes | Not exercised | 7 |
| One `key` -> 5-byte OSData | 32 bytes | 28 bytes | 8/11/12; 17 |
| One `key` -> 32-byte OSData | 56 bytes | Not exercised | 9 |
| NULL dictionary | No serializer or VM-copy input call; zero pointer/extent | Same route | 10 |

For the selected one-pair inputs, `aligned(N) = 4 * ceil(N/4)` bytes, D4 extent is `24 + aligned(N)` bytes and D3 extent is `20 + aligned(N)` bytes. For N=5 bytes, `aligned=8 bytes`, so the independently checked extents are 32 and 28 bytes. These equations describe the exercised object shape, not arbitrary graphs.

Exact N=5 outputs, little-endian u32 words:

```text
D4: 000003d4 81000001 00000007 08000004
    0079656b 8a000005 7a55300b 0000009f
D3: 000000d3 81000001          08000004
    0079656b 8a000005 7a55300b 0000009f
```

The source rounds record extents to four-byte alignment. It copies the stated payload length; padding zeros here follow the supplied private memory initialization. This does not prove zeroed native padding or native allocator contents. Only the selected dictionary/symbol/OSData graph was exercised; other scalar/container classes, shared-reference graphs and growth beyond the initial capacity remain unknown. [OS4-OS5]

## Inverse conversion and cleanup

Five inverse cases use exact original emitted packets and bytes. The copyout call at `0xfffffe000c596bc0` supplies `(map, out_address, copy, extent, 1)`. The wrapper call at `0xfffffe000c596bf0` supplies `(mapped_bytes, extent, filter=NULL, context=NULL, options=0, error_out=NULL)`. In the D3 case the original `_strcmp` equality selects binary dispatch; in the D4 case the original first-byte comparison selects it. Both tail branches at `0xfffffe000c4889ec` reach `0xfffffe000c489b18`. The XML-named interface therefore cannot be classified as XML-only.

Three modeled-parser cases return a declared distinct dictionary identity. Original caller code then invokes `(map, mapped_bytes, extent)` deallocation at `0xfffffe000c596c08`, clears OOL descriptor pointer/extent, and publishes that identity in the dictionary object slot. Two frontier cases stop before the parser body and preserve the OOL pointer/extent at that point. There is no semantic parse/serialize round-trip proof: the parser result is supplied, and the original bytes are checked only at its entry. [OS3, OS7]

Two supplied nonzero transport cases return raw `0x10000003` with moved=0 or moved=1. Original port cleanup differs according to that signal. In these cases the OOL pointer and 32-byte extent remain in the caller buffer. This is a field observation under declared transport results; it establishes neither native ownership retention nor a leak. A native ownership-balance claim requires lower VM-copy/transport/release semantics and authentic object lifetime. [OS6-OS7]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| OS1 | The hashed collection and exact symbols/fixups are the intended static artifact; all address identities depend on it | Recapture all 168 functions and 92 binding records; reject byte/symbol/slot mismatch; verify actual runtime UUID before native pairing |
| OS2 | Published actor snapshot plus explicit compatible metaclasses/service/server/queue fixtures represent this selected component | Compare all 173 prior final objects byte-for-byte; verify native producers/hierarchy separately; alternate native ancestry can change routing |
| OS3 | Declared collection initialization, VM map/buffer/copy identities and W0/X1 result ABI permit source continuation | Fresh replay verifies arguments/effects; compare original lower allocator/copy bodies and authentic initialization before asserting native state |
| OS4 | Nominal one-pair dictionary, packed key field and OSData layout are valid inputs for the selected writer path | Original getters and source output checked; vary payload 0/1/3/4/5/32; native constructors and arbitrary graph layouts remain unverified |
| OS5 | Private initialized memory and byte-copy model determine padding in these finite cases | Separate copied payload from untouched alignment bytes; use nonzero allocator memory in future before making padding-initialization claims |
| OS6 | Transport result and moved signal are supplied; successful reply is exact adapter-produced data | Compare independent source reply transfer; exercise both moved signals on error; inspect authentic transport ownership before lifetime claims |
| OS7 | Binary parser result, mapping and deallocation are models; inverse behavior after them is conditional | Stop at parser for both D3/D4; recover/execute actual parser on valid generated inputs before claiming round-trip or parsing correctness |
| OS8 | Generic IORPC/OOL machinery is architectural context, not a demonstrated FairPlay SetProperties use | Find original FairPlay caller, concrete service/controller identity, and authentic destination/receive continuity; absence leaves the join unknown |

## Verification and bounded continuation

Twenty fresh CPU replays check 31054 original instruction visits, 5331 writes / 39854 bytes, 8117 reads / 57819 bytes, 1573 logical authentication steps, 797 indirect edges, 376 API models and 163 declared memory effects / 5416 bytes. All 20 final boundaries, 3860 final object records, source/environment/registry/serialization globals and RPC buffers match. Twelve independent binary-byte/extent oracles and five exact packet/byte transfers pass. Logical PAC steps are recorded, not cryptographically verified.

Reproduction uses the pinned interpreter and existing modules; the scripts never issue native target operations:

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_iorpc_ool_serialization.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_iorpc_ool_serialization.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iorpc_ool_serialization.py
```

Recovery is O(image bytes + symbol records + captured instructions) time/space. Collection/replay are O(original visits + journal/model effects) time and O(image + journals + private memory) space; each case maps 1048576 private bytes. The finite alignment calculations have exact integer results and no measurement error; they are not statistical estimates. The report does not claim exhaustive object-graph behavior.

| Impact | Bounded continuation | Evidence it would add |
|---|---|---|
| High | Recover actual binary parser on these valid source-generated forms | Replace declared parse identity with source-created objects and compare semantic contents |
| High | Resolve authentic lower VM-copy and transport ownership transitions | Establish who consumes the OOL copy on success/error, independently of caller buffer fields |
| High | Find concrete FairPlay service/daemon callers before extending generic IORPC coverage | Distinguish shared architectural machinery from an actual FairPlay exchange |
| Medium | Valid shared-reference, nested-object and capacity-growth cases | Determine index/reference representation and growth behavior beyond the current shape |
| Low | Compare file/SDK revision and native packed-string constructor output | Refine version-specific layout attribution |

QG1: Technical evidence only; no normative judgment required.
QG2: OS1-OS8 enumerate assumptions, dependent claims and falsification probes.
QG3: Scoped function roles, incoming/outgoing descriptor roles, emission PCs, data/control/environment context and respective report updates are covered. The broad investigation remains active.
QG4: All sizes/offsets are bytes, arithmetic is explicit, machine widths and wire/capacity differences are retained; commands and complexity are reproducible.
QG5: D3/D4 paths, packed key length, NULL input, alignment, moved cleanup, parser frontier and modeled round-trip limits are reconciled. Unexamined graphs and native ownership are explicitly unknown.
QG6: Original hashes, exact symbols/fixups, fresh replay, source-byte recapture and unmatched supplementary SDK declarations are separated; no current IDA/native pairing claim.
QG7: Impact-labelled continuation is bounded to unresolved interfaces above.

[Preservation audit](triage_evidence/iorpc_ool_serialization_delivery.json), [scoped gates](triage_evidence/iorpc_ool_serialization_quality_gates.json), [publication verifier](triage_evidence/verify_iorpc_ool_serialization_publication.py). Original inputs and unrelated prior artifacts are preserved.
