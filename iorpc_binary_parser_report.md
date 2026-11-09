# IORPC binary object reconstruction and filter ABI

The original binary parser now runs on the previously emitted D3/D4 byte streams. It returns a distinct dictionary whose entry count, key/value pair, OSData length and payload are established by original parser/collection code under explicit lower API models. Nine inverse-converter cases publish that actual parser return into the dictionary object slot. Two exact state transfers then pass the reconstructed dictionary through the original SetProperties adapter and its type guard. This replaces the previous whole-parser result model for the selected valid inputs; native parsing, ownership, symbol interning and a FairPlay SetProperties caller remain unknown.

Primary evidence: [source and fixups](triage_evidence/iorpc_binary_parser_source.json), [19 collection cases](triage_evidence/iorpc_binary_parser_profiles.json), [independent replay and semantic oracles](triage_evidence/iorpc_binary_parser_checks.json). Inputs are exact [previously emitted packets and bytes](triage_evidence/iorpc_ool_serialization_profiles.json), using the [published source-created registry actors](triage_evidence/iorpc_object_conversion_profiles.json). The original collection hash and all dependencies are recorded. Original files, IDBs and unrelated published artifacts are preserved; no native target, IPC, VM, hardware or PAC operation executes.

## Function identities and source roles

The retained/new source set contains 191 complete functions / 17506 instructions, including the complete 882-instruction parser. There are 110 recaptured binding records / 109 unique slots, including 18 new parser/collection binding records. Capture does not imply execution of every function or branch.

| Address | Identity / role | Evidence |
|---|---|---|
| `0xfffffe000c489b18` | Anonymous six-argument binary object parser | Complete original body; record dispatch, class construction calls, references, nesting, filters, cleanup and root return |
| `0xfffffe000c44d70c` | Exact `OSDictionary::initWithCapacity(unsigned)` | Original buffer-pointer, count/capacity/increment and accounting stores |
| `0xfffffe000c44cd64` | Exact `OSDictionary::setObject(OSSymbol const*, OSMetaClassBase const*)` | Three-instruction public entry sets W3=0 and branches to core |
| `0xfffffe000c44cd70` | Anonymous dictionary insertion/replacement core | Original selected insertion path writes key, value and count |
| `0xfffffe000c44ab74` | Exact `OSData::initWithBytes(void const*, unsigned)` | Original capacity call, copy arguments and length store |
| `0xfffffe000c44ac2c` | Exact `OSData::initWithCapacity(unsigned)` | Original allocation ABI, signed pointer publication, capacity and accounting |
| `0xfffffe000c484334` | Exact `OSSymbol::withCString(char const*)` | Original parser call and exact key bytes; intern body captured but modeled |
| `0xfffffe000bcfe5b8` | Previously recovered raw typed-allocation interface | Original dictionary/data calls; declared X0 pointer / X1 actual byte extent |
| `0xfffffe000bcff0b8` | Anonymous typed buffer resize/allocation interface | Parser bookkeeping calls; body captured, effects modeled |
| `0xfffffe000bcfec48` | Anonymous typed buffer free interface | Original parser cleanup calls; body captured, effects modeled |
| `0xfffffe000c488964` | Exact `OSUnserializeXML` overload | Original D3/D4 dispatch, with six arguments retained |
| `0xfffffe000c4a3290` | Exact `IOService::SetProperties_Invoke` | Accepts the source-reconstructed dictionary and produces reply fields |

The parser entry has no exact symbol in this collection. Its binary-parser role follows original wrapper dispatch and executed record/object behavior. SDK declarations are supplementary, previously hashed references; no source-revision equality is asserted. [BP1]

## Provenance through the object boundary

```text
original writer, prior increment
  -> exact D3/D4 bytes + exact kernel-form packet
  -> original inverse converter
       self port -> original wrapper resolution -> self slot
       OOL copy -> declared map -> original XML/binary dispatcher
       -> original binary parser
            nominal dictionary allocation [model]
            -> original dictionary initialization
            -> symbol intern [model, exact source key argument]
            -> nominal data allocation [model]
            -> original data initialization + declared byte-copy effects
            -> original dictionary key/value/count stores
            -> original reference/nesting cleanup -> dictionary return
       -> declared map deallocation -> original OOL clearing/root publication
  -> exact 203-object/global snapshot transfer
  -> original SetProperties_Invoke type guard
  -> declared handler result -> original reply fields
```

The former supplied parser object at private address `0x650007b000` is unused as a parser result here. The original body returns `0x6500090000`, the identity provided only by its lower dictionary allocation model. Its fields are then written by the original initializer and insertion routines. This proves finite field reconstruction under lower premises, not authentic allocation or a native object lifecycle. [BP2-BP4]

## Selected record semantics and reconstructed fields

The exercised record headers are dictionary `0x81000000`/`0x81000001`, symbol `0x08000004`, and data `0x8a000000 | N`. Original code extracts low-24-bit counts/lengths, uses the type field for dispatch, and uses the high bit in collection completion control. The symbol path checks the stated final NUL before calling the interning interface. The source-generated dictionary bytes are unchanged from the prior increment.

| Source input | Binary form / encoded extent | Reconstructed result |
|---|---|---|
| Empty dictionary | D4 / 12 bytes | Count 0; no data object |
| `key` -> 0-byte OSData | D4 / 24 bytes | Count 1; data length 0; buffer pointer NULL |
| `key` -> 1-byte OSData | D4 / 28 bytes | Exact `0b` payload |
| `key` -> 3-byte OSData | D4 / 28 bytes | Exact `0b 30 55` payload |
| `key` -> 4-byte OSData | D4 / 28 bytes | Exact `0b 30 55 7a` payload |
| `key` -> 5-byte OSData | D4 / 32 bytes | Exact `0b 30 55 7a 9f` payload |
| `key` -> 32-byte OSData | D4 / 56 bytes | All 32 original bytes match |
| Empty dictionary | D3 / 8 bytes | Count 0; no data object |
| `key` -> 5-byte OSData | D3 / 28 bytes | Same semantic key/value as D4 |

For populated inputs, dictionary+0x14 is the source-written u32 entry count; dictionary+0x20 is the authenticated pair-storage pointer. Original core stores the key at `0xfffffe000c44d09c`, value at `0xfffffe000c44d120`, and incremented count at `0xfffffe000c44d180`. The mutation word at +0xc becomes 1. Nominal object vptr/reference words are supplied by allocation models.

The data length at +0xc and buffer pointer at +0x18 follow original initialization; source copy arguments point into the exact emitted byte stream. The copy API's bytes are modeled and independently checked. The N=0 path calls the copy API with NULL destination and zero length; the declared zero-byte model has no memory effects. Native library behavior at that call remains untested. No malformed-input or fault-injection claim is made. [BP3-BP5]

In the exercised D4 paths, original parser-body reads cover the first byte and dictionary record header, while source pointer accounting advances past the extra dictionary index word. No parser-body read of that index-word value occurs in these read journals. This observation is bounded to the selected valid graphs and does not establish that all indexed record forms ignore all index metadata. The wrapper/strcmp and symbol-intern bodies have separately modeled reads. [BP5]

## Allocation returns, fields and accounting

The two lower allocation conventions must remain distinct:

| Interface | Input unit | Declared output registers | Source consumer |
|---|---|---|---|
| Serializer VM allocation, prior increment | Bytes | W0=status, X1=buffer address | Serializer storage publication |
| Raw typed allocation, this increment | Bytes | X0=buffer address, X1=actual byte extent | Dictionary/data capacity and accounting |
| Parser bookkeeping resize/allocation | Bytes | X0=buffer address, X1=actual byte extent | Reference/nesting capacities |

Dictionary initialization requests `16 * entry_capacity` bytes. The declared backend returns at least 16 bytes in these cases, including a zero-byte request for an empty dictionary. Original code derives one pair slot from `16 bytes / 16 bytes per pair = 1`, publishes that capacity, and selects increment 1. This is a supplied extent policy, not evidence of native allocator rounding.

For nonzero data N, the backend returns `max(N,16)` bytes; original code stores that capacity, selects the corresponding increment, and accounts the returned extent. For zero-length data no raw data-buffer allocation occurs. Under this fixture the source accounting cell `0xfffffe000cb5b630` ends at 16 bytes for empty/N=0, 32 bytes for N=1/3/4/5, and 48 bytes for N=32. Example: N=5 requests 5 bytes, receives a declared 16-byte extent, and contributes `16 dictionary bytes + 16 data bytes = 32 bytes`. The earlier heap counter at `0xfffffe000cb5b638` remains a distinct cell. [BP3]

Original parser code requests separate 512-byte reference and nesting arrays. Each declared extent yields `512 bytes / 8 bytes per entry = 64 entries`. Empty dictionaries need the reference array only; populated dictionaries use both. Source reference entries are the dictionary, key and data identities in order. On successful completion, original cleanup calls release non-root entries, frees the reference buffer, and frees the nesting buffer when allocated. Lower releases/frees are no-effect models; no native ownership-balance inference follows. [BP3, BP6]

## External callback and options ABI

The IORPC inverse caller supplies `(filter=NULL, context=NULL, options=0, error_out=NULL)`. Eight separate parser-component cases instead use a non-NULL filter, private context and error-output slot with options 0 through 7. These components do not demonstrate that the IORPC caller exposes those parameters externally.

| Options, low three bits | Dictionary callback calls | Observed result |
|---|---:|---|
| 0, 2, 4, 6 | 0 | Direct original dictionary insertion |
| 1, 3, 5, 7 | 1 | Filter result passed to original dictionary insertion |

Original authenticated callback at `0xfffffe000c48a3a0` uses discriminator `0xfa46` and arguments `(context, dictionary, key, value)`. The callback is a declared pass-through returning the input value. Source code then inserts that result and performs its reference calls. The original parser clears the supplied eight-byte error-output slot before parsing and returns the dictionary. The NULL-callback IORPC cases never take this callback edge. Array/set filter paths, transformed callback results, error reporting and arbitrary options remain unknown. [BP4-BP5]

## Inverse-converter and adapter continuity

Nine cases run the original parser as part of the original inverse converter. A return frame at `0xfffffe000c596bf4` records its dictionary identity before the original caller performs mapping-deallocation calls, clears OOL pointer/extent, and publishes the result at message+0x64. The self slot at +0x5c contains the independently resolved object. VM mapping/deallocation remain models; no native right or VM-copy ownership is established. [BP6]

The D4 and D3 five-byte cases transfer every one of the 203 final private object records plus final source/environment/registry/serialization globals into separate original SetProperties adapter components. The original dictionary metaclass guard accepts both; each handler frame carries `(self, reconstructed_dictionary)` and the exact key/data payload. The handler result is supplied as zero.

Original adapter reply fields are size 60 bytes, reply version `0x4da2b68d`, method `0xd8a753ea156f9162`, content flags 8, reference count 0 and descriptor count 0. The adapter preserves transport-header fields and bytes outside the 60-byte wire extent in these private 128-byte buffers. This is not a native reply emission or a claim that the entire capacity is reply data. No additional named Mach endpoint has been established. [BP6-BP8]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| BP1 | Hashed collection/symbol/fixup metadata is the intended artifact; all static addresses depend on it | Recapture all 191 functions and 110 binding records; verify runtime UUID before native pairing |
| BP2 | The exact published 173-object base plus explicit compatible class/registry/map fixtures permit this component | Compare actor bytes and transferred globals; recover authentic native initialization before runtime identity claims |
| BP3 | Nominal class allocations, raw actual-extent returns and bookkeeping buffers represent declared lower outcomes | Verify X0/X1 frames and original derived fields/counters; compare actual lower allocator semantics before rounding/ownership claims |
| BP4 | Interning returns the supplied symbol identity for exact `key` bytes; reference and optional filter outcomes are models | Record exact source arguments; execute authentic intern/reference/filter implementations before lifetime or arbitrary transformation claims |
| BP5 | Source-generated empty/one-pair graphs cover the selected semantics; byte-copy effects and NULL/zero-byte behavior are declared | Compare every key/value/length and original source store; cover valid nested/shared-reference graphs and original copy body before wider claims |
| BP6 | Copyout/deallocation, object/port releases and bookkeeping free effects are modeled | Compare caller frames and slot clearing; follow authentic lower ownership and VM-copy paths before native balance claims |
| BP7 | Exact state transfer proves component continuity under the saved private epoch, not native scheduling | Compare all 203 object records and all transferred globals; preserve concrete runtime task/port/context identity before a live exchange claim |
| BP8 | Generic SetProperties reconstruction is architectural context; no FairPlay caller is established | Find a concrete original FairPlay call and actual service/destination/receive continuity; otherwise the daemon/kext join stays unknown |

## Verification and bounded continuation

Nineteen fresh CPU replays check 15189 original visits, 2261 writes / 17072 bytes, 2859 reads / 20833 bytes, 543 logical authentication steps, 208 indirect edges, 318 API models and 187 declared memory effects / 20550 bytes. All 19 final boundaries and 3857 final object records match, along with source/environment/registry/serialization globals and RPC buffers. Seventeen actual parser-root return frames, 15 original insertion-store cases, nine inverse publications, two reconstructed adapter handoffs and all eight low-three-bit option combinations pass. Logical authentication is not hardware PAC proof.

Reproduction:

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_iorpc_binary_parser.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_iorpc_binary_parser.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iorpc_binary_parser.py
```

Recovery is O(image bytes + symbol records + captured instructions) time/space. Collection/replay are O(source visits + journal/model effects) time and O(image + journals + private memory) space; each case maps 1048576 private bytes. Byte/entry arithmetic uses exact integers with no measurement error. These are finite field round trips, not exhaustive parser validation.

| Impact | Bounded continuation | Evidence it would add |
|---|---|---|
| High | Follow original VM-copy ownership beneath conversion/transport | Resolve consumption/release independently of descriptor-field clearing |
| High | Establish a concrete FairPlay service caller and daemon receive continuity | Connect generic IORPC context to an actual FairPlay exchange |
| Medium | Valid nested/container/shared-reference round trips | Extend object graph, completion and reference semantics beyond one pair |
| Medium | Authentic symbol intern/reference and allocator extent paths | Replace identity, lifetime and rounding premises |
| Low | Original byte-copy body and matching SDK/source revision | Remove remaining primitive/version attribution limits |

QG1: Technical evidence only; no normative judgment is required.
QG2: BP1-BP8 enumerate assumptions, dependencies and falsification probes.
QG3: Scoped anonymous/named roles, descriptor-to-object flow, source emission/consumption sites, callback ABI and respective report updates are covered; the broader objective remains active.
QG4: Bytes, entries, register widths, capacities and wire extents are distinguished; calculations and script complexity are reproducible.
QG5: D3/D4, empty/zero-length inputs, original versus modeled object fields, allocator return conventions, callback options and out-of-wire bytes are reconciled. Native ownership and other graphs remain explicitly unknown.
QG6: Original byte/symbol/fixup recapture, exact producer state, independent replay, source stores and separately modeled effects have primary artifacts; no native or current IDA identity claim.
QG7: Impact-labelled continuation is bounded to unresolved architectural interfaces above.

[Preservation audit](triage_evidence/iorpc_binary_parser_delivery.json), [scoped gates](triage_evidence/iorpc_binary_parser_quality_gates.json), [publication verifier](triage_evidence/verify_iorpc_binary_parser_publication.py). The complete investigation remains active.
