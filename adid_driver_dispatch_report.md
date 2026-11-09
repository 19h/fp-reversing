# CoreADI adid: protected dispatch edges, output-pointer provenance and consumer polarity

Three sites in the provider's large protected request routine resolve to caller `0x1000590ac`, which constructs the initialization-helper record and reaches the previously recovered IOKit stages. The request routine itself prepares the three encoded output pointers; the immediate consumers compare the returned byte to `0x1f`, with opposite polarity at the third site. Complete feasible request paths to those sites remain unknown. The local execution cases explicitly supply entry state and skip intervening gates; they are not end-to-end admission or native reachability proofs.

Additional byte-table reductions distinguish record helper `0x100059ce8`, a host-UUID interface and a file-truncation interface from IOKit calls sharing authentication modifiers. The available matching kernel collection does not contain the searched Avp plaintext literals. That is a bounded corpus result, not proof that the Avp implementation is absent from runtime or other images.

## Identity, assumptions and evidence

Provider addresses are preferred virtual addresses in `/System/Library/PrivateFrameworks/CoreADI.framework/adid`, selected arm64e slice base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The [caller report](adid_iokit_caller_report.md) establishes the downstream caller, two-stage IOKit flow, distinct caches and Avp selector 100. The [context report](adid_context_report.md) and [receiver report](adid_receiver_report.md) establish the preceding request boundary and error paths. Address spaces and evidence scopes remain separate.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| D1: pinned provider/fixups, collection and SDK describe the inspected references | Addresses, target metadata, byte tables, widths and corpus counts | Fresh bytes, compiler ranges, dyld_info, SDK compilation and whole-collection hash agree. Actual loaded images/frameworks and native port pairing remain unknown. |
| D2: the original source prefix and declared private models produce the retained request frame | Frame/pointer provenance | Ordered visits match the prefix of the frozen context case. A fresh execution reproduces all saved mutable guest regions, registers and retained model state. Native state, hardware PAC, environment and API behavior are unproved. |
| D3: explicit local state/entry overrides describe the selected fragments | Twelve upstream caller/consumer continuations | Every case records entry overrides and one jump over intervening gates. Original initialization, constructor, callee and immediate consumer instructions execute. Feasible predecessors, selector-to-state mapping and whole-request reachability remain unknown. |
| D4: the declared table/frame bindings apply to a local lookup prefix | Seven table reductions | Every byte-table input is checked, original slots/fixups are read back and frame-based pointer operands agree. Whole-function register lifetime and arbitrary predecessors are not established. |
| D5: one additional X15 binding describes the second host-UUID candidate | Conditional target at `0x1001fb804` only | It requires X15=`0x100294330`. The captured frame's X15 differs, and no reaching writer is proved. This row remains a conditional candidate. |
| D6: error/identity-response and context patches define the stated controls | Downstream statuses, two-stage flow and output-byte alternatives | Error returns `0xe00002c7`; identity-response preserves bytes and returns zero. Context-tag patches are explicit analyst writes. No authentic driver response, transformation, authorization or successful protected operation is established. |
| D7: local arithmetic/alias proofs use their exact state and alignment prefixes | Keys, table indices, pointer aliases and predicate polarity | Four full-domain local proofs pass. The third constructor key requires pointer bit 1 clear; the original 16-byte aligned frame gives an 8-modulo-16 record address. Unaligned or other state paths are outside that corollary. |
| D8: exact plaintext/module-name search bounds the stated corpus only | Avp search result | All bytes and all 362 fileset names are checked. Other encodings, caches, collections, modules, firmware and runtime loading remain unexamined. |
| D9: SDK declarations and local argument preparation explain interface shapes | gethostuuid/ftruncate touch points and timeout widths | Fresh arm64e compilation checks UUID/timespec/off_t/___ widths. Source prepares two zero u64 timeout fields. Effective arguments, UUID values, descriptors, native timeout behavior and resource lifetime remain unknown. |

Artifacts: [profiles](triage_evidence/adid_driver_dispatch_profiles.json), [original request frame](triage_evidence/adid_driver_dispatch_frame.json), [contracts/tables/proofs/corpus search](triage_evidence/adid_driver_dispatch_contracts.json), [producer](triage_evidence/probe_adid_driver_dispatch.py), [recoverer](triage_evidence/recover_adid_driver_dispatch.py), [fresh checks](triage_evidence/adid_driver_dispatch_checks.json), [validator](triage_evidence/validate_adid_driver_dispatch_delivery.py), [quality gates](triage_evidence/adid_driver_dispatch_quality_gates.json), [SDK declarations](triage_evidence/adid_driver_dispatch_layouts.c) and [assembly](triage_evidence/adid_driver_dispatch_layouts.s). Earlier source readers, producers, proofs, profiles, original inputs and IDBs remain preserved.

## Original request frame and explicit control boundary [D1-D3]

The original XPC callback at `0x100029fc8` runs with the frozen peer/request fixtures until the boundary before `0x10019bb18`. This first frame case has 40149 hooks and 40082 retained original instruction visits. Its visit stream is an exact prefix of the earlier `context_error_producer` stream. No fragment entry or jump is applied to this run.

The captured large-function frame has private SP=`0x7a02dc10`, FP=`0x7a037c00`, so `FP-SP=0x9ff0` bytes. The reused caller-record address is `FP-0xa8 = 0x7a037b58`. The main table base is `0x1002c40c0`, present in X27, X24 and frame slot `SP+0x1658` at this boundary. These are private observations under D2, not native addresses.

```text
original XPC callback 0x100029fc8
         |
original request/persistence/context prefix
         |
saved frame before 0x10019bb18
         |
  [analyst entry/state selection; feasible predecessor unproved]
         |
original output-byte initialization
         |
  [one explicit analyst jump over intervening gates]
         |
original record constructor at A / B / C
         |
original indirect call -> 0x1000590ac -> 0x1000208fc
         |                              |
         |                   optional Avp26 -> primary26
         |                              |
         +------ encoded output byte <--+
         |
original immediate comparison / CSET
         |
stop before subsequent protected control flow
```

Each local case starts from the complete saved frame. Its declared overrides supply a scalar state component, the table register, the global-state pointer restored from `SP+0x1660`, and arithmetic constant `0x801ffa49`. Source output initialization runs first, then one recorded jump enters the constructor. These controls deliberately do not prove the skipped metadata/predecessor gates. The checkpoint additionally retains the request lock model, umask model and lock-call count; these remain sequential fixtures.

## Source producers of encoded output pointers [D1,D2,D7]

A separate original-prefix run watches the three discovered frame slots. Original stores, rather than analyst substitutions, produce all three values:

| Frame slot | Original store | Decoded output location | Private decoded address |
| --- | --- | --- | --- |
| `SP+0x148` | `0x1001664f8` | `SP+0x2ede` | `0x7a030aee` |
| `SP+0x150` | `0x100166538` | `SP+0x28e3` | `0x7a0304f3` |
| `SP+0x158` | `0x100166528` | `SP+0x16db` | `0x7a02f2eb` |

Each slot contains the decoded pointer plus `0x7e1f59740c8f6451`, modulo 2^64. The receiving caller decodes it with addition of `0x81e0a68bf3709baf`. The source slot values survive into the local record constructors unchanged. This establishes provenance and pointer correspondence; these pointer-sized fields are not Mach port names or port descriptors.

The output initializers are source instructions at `0x1001f4c24..0x1001f4c34`, `0x1001f5478..0x1001f5484` and `0x1001f583c..0x1001f584c`. They initialize the selected output byte to `0x1f`. A and C construct a base `SP+0x2728`; their respective fields are +`0x1bb` and +`0x7b6`. B addresses `SP+0x6dc+0xfff`. A full 64-bit local proof equates these consumer addresses with the decoded producer pointers, including modular arithmetic.

## Three source caller edges and records [D1-D4,D7]

| Site | Constructor entry | Supplied local state | Original call | Original return | Output slot |
| --- | --- | --- | --- | --- | --- |
| A | `0x1001f4cc4` | W9=`0x1106` | `0x1001f4d88` | `0x1001f4d8c` | `SP+0x150` |
| B | `0x1001f550c` | W8=`0x161c` | `0x1001f55d8` | `0x1001f55dc` | `SP+0x158` |
| C | `0x1001f58c0` | W8=`0x1713` | `0x1001f5990` | `0x1001f5994` | `SP+0x148` |

All three select the original authenticated pointer cell `0x1002d86c8`, target `0x1000590ac`, diversity `0xc745`, key IA, address-diversity zero. The original pointer-read event and subsequent callee entry agree. Private PAC bypass is declared; native authentication is not validated.

For caller-record address P, the canonical local key is:

```text
K(P) = ((low32(P) XOR 0x834674ac) * 0x0a42990d) mod 2^32
```

The original constructors produce this 16-byte accessed prefix:

| Byte offset / width | Source-derived value |
| --- | --- |
| 0 / 8 | Original encoded output pointer from the indicated frame slot |
| 8 / 4 | `K(P) XOR 0x237f` |
| 12 / 4 | Encoded caller status after return |

A uses state component `0x1106`, then adds `0x1279` to obtain basis `0x237f`. B obtains component `0x8f6` from `0x161c-0xd26` and adds `0x1a89`. C obtains `0x583` from `0x1713-0x1190` and adds `0x1dfc`. These are local state relationships; they are not mapped to the six public signed request selectors.

The first two original key expressions reduce over the full 32-bit address domain. The third reduces to the canonical key when `(low32(P) AND 2)=0`. Here P is 8 modulo 16 under the observed stack layout. The proof preserves that prerequisite; it does not promote an aligned pointer observation to an unconditional identity.

The original callee then constructs the helper's basis-`0x25` record and executes the source IOKit path described in the [caller report](adid_iokit_caller_report.md). In the three two-stage controls, distinct private connections `0x580a` and `0x5804` reach the Avp direct-96-byte and primary descriptor-16-byte selector-26 API boundaries respectively. Underlying native Mach emission, rights and port-object identity remain unknown.

## Immediate byte consumers and distinct status axes [D1-D3,D6,D7]

| Site | Source load / comparison | Original predicate | Result for `0x1f` | Result for `0x20` |
| --- | --- | --- | --- | --- |
| A | Load `0x1001f4d8c`; compare `0x1001f4d94` | CSET W9, EQ at `0x1001f4d98` | 1 | 0 |
| B | Load `0x1001f55e0`; compare `0x1001f55e8` | CSET W9, EQ at `0x1001f55ec` | 1 | 0 |
| C | Load `0x1001f5994`; compare `0x1001f599c` | CSET W8, NE at `0x1001f59a0` | 0 | 1 |

All three compare the loaded byte to `0x1f`, derived through their original local state expressions. The full byte-domain predicate proof establishes equal polarity for A/B and opposite polarity for C under those prefixes. It does not assign a public true/false meaning to the encoded bytes or to subsequent control-flow outcomes.

The complete local cases distinguish caller status from the byte tested by the immediate consumer:

| Explicit downstream control, repeated at A/B/C | Raw caller status | Output byte | A/B predicate | C predicate |
| --- | --- | --- | --- | --- |
| Primary transport error | `0x00587c93` | `0x1f` | 1 | 0 |
| Primary identity-response, original cold outer context | `0x00587c85` | `0x1f` | 1 | 0 |
| Avp then primary identity-response | `0x0059248f` | `0x1f` | 1 | 0 |
| Primary identity-response plus explicit matching outer context patch | `0x0059248f` | `0x20` | 0 | 1 |

The immediate comparison consumes the output byte rather than the caller's status field at record+12. The last row patches context byte `0x1002dcee0` to `0x41` and tag `0x1002dcf00` to `0x527e14b6`, as in the prior caller report. Its source and modified bytes are retained. Real valid state production, response grammar, subsequent status consumers and final XPC reply effects remain unknown.

## Local table reductions and environmental touch points [D1,D4,D5,D9]

For byte tables A/B, the original patterns have:

```text
j XOR B[A[j] XOR key] = constant, for every j in 0..255
index = base + constant
slot = 0x1002c40c0 + 8*index
```

All seven table-use records retain both original 256-byte tables and all 256 results: 1792 byte-domain checks. One pair/key is reused at two different index bases; these are separate uses of the same byte identity. The `MVN` variant is evaluated with its low-byte XOR-`0xff` meaning. A full u32 proof establishes that the final UXTB selection discards the irrelevant upper bits under the checked byte identity.

| Site | Base + byte constant | Original selected cell | Target / evidence boundary |
| --- | --- | --- | --- |
| `0x1001f4d88` | `0x2825+0x9c=0x28c1` | `0x1002d86c8` | `0x1000590ac`; original controlled continuation and pointer read |
| `0x1001f55d8` | `0x28bc+0x05=0x28c1` | `0x1002d86c8` | Same target; distinct original constructor |
| `0x1001f5990` | `0x285e+0x63=0x28c1` | `0x1002d86c8` | Same target; distinct constructor and consumer polarity |
| `0x100263a00` | `0x2873+0x63=0x28d6` | `0x1002d8770` | Record helper `0x100059ce8`, under local table/frame prefix; semantics unknown |
| `0x1001d45a0` | `0x278f+0xe2=0x2871` | `0x1002d8448` | `libSystem/_gethostuuid`, under local table/frame prefix |
| `0x1001fb804` | `0x2826+0x4b=0x2871` | `0x1002d8448` | Conditional `_gethostuuid` candidate; requires unproved X15 binding |
| `0x10025d12c` | `0x27e1+0xd7=0x28b8` | `0x1002d8680` | `libSystem/_ftruncate`, under local X24/table/frame prefix |

The first/second byte-table pointer slots used by A/B/C are part of the source-produced frame. The host-UUID A and truncate patterns likewise load their byte-table pointers from inspected frame slots. The second host-UUID pattern instead uses X15 for its second table. The required value is `0x100294330`; the captured frame's X15 is `0x1002ae000`. Consequently, stable-register inference from that frame would be invalid. A reaching writer or another source state is required before promoting that candidate.

These results refine the [earlier constant-modifier candidate list](adid_iokit_caller_report.md). The old table records retained private observations; the new environmental bindings have the different, explicitly conditional local table/frame scope above. Modifier equality alone remains insufficient.

The original host-UUID argument preparations at `0x1001d452c..0x1001d4548` and `0x1001fb798..0x1001fb7ac` put an output pointer in X0, a second pointer in X1 and store two zero u64 words through X1. The arm64e SDK declaration `gethostuuid(uuid_t,const struct timespec *)` has a 16-byte UUID output and a 16-byte timespec: signed 64-bit seconds at +0 and signed 64-bit nanoseconds at +8. The local zero record thus has the shape 0 s / 0 ns under that interface interpretation. Native timeout behavior and returned host identity are unobserved.

For ftruncate, SDK `int ftruncate(int,off_t)` gives a four-byte descriptor argument/return and an eight-byte length argument. The source places values in X0/X1 at the listed site; complete descriptor provenance, signed length reconstruction and file effects are unknown. These calls identify additional environment/file interfaces without classifying them as driver calls.

## Bounded Avp implementation search [D1,D8]

The inspected collection is `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. It contains 362 fileset entries. The complete fileset list and whole-byte literal counts are retained.

| Exact plaintext literal | Occurrences in this collection |
| --- | --- |
| `AvpFairPlayDriver` | 0 |
| `AvpFairPlayUserClient` | 0 |
| `AvpFairPlayUserClient.access` | 0 |
| `com_apple_driver_FairPlayIOKit` | 221 |

A case-insensitive module-name filter for `avp`, `fairplay` or `virt` returns only `com.apple.driver.FairPlayIOKit`. The Avp implementation was not located by these searches. An encoded name, differently named module, another collection or another runtime environment is not excluded. No native loaded-module or service-registry query was performed in this increment.

## Verification and bounded continuation

The [fresh validator](triage_evidence/validate_adid_driver_dispatch_delivery.py) passes 24011 assertions across 14 private cases, 21915 unique original instruction records in 26 compiler ranges and 1207098 retained source visits. It verifies 12 upstream record observations, 12 immediate byte comparisons, three two-stage upstream cases, all three original frame-slot producers, 1792 byte-domain checks, four full-domain local proofs, nine source windows and the 362-entry collection search. Five complete fresh runs reproduce 373259 hook steps; the original-frame replay additionally reproduces every saved mutable region, register and retained model-state field.

The exhaustive lookup work takes O(C*256) time and O(C*256) retained evidence for C table uses. Whole-corpus search is linear in the pinned corpus size for a fixed literal set. The validator takes O(B+F+R+V) time/space in source/artifact bytes B, fixups F, retained records R and source visits V; every private execution has a finite cap. SDK declarations were freshly compiled to assembly. Original inputs remain unchanged. No native target, loader, IOKit, Mach, target-file/environment or synchronization API was executed.

| Impact | Remaining interface | Concrete next evidence |
| --- | --- | --- |
| High | Feasible public-request path to the three callers | Recover the skipped metadata/predecessor gates and map original selector/record state to the supplied local states; then follow the subsequent branches to final reply construction |
| High | Real driver/provider behavior | Locate the Avp implementation and actual image/service/UserClient pairing; recover authentic selector26/100 responses and connect raw record consumers to protected kext operations and RPC502/700 selection |
| Medium | Output-byte/status interpretation | Recover later consumers of record+12 and the three predicate results, all context/tag writers, and actual semantics of the encoded `0x1f`/`0x20` outputs |
| Medium | Remaining indirect targets | Recover the X15 writer at the second host-UUID candidate, record helper `0x100059ce8`, additional caller patterns and full frame/register lifetimes |
| Medium | Environment/file contracts | Recover UUID output use, actual timeout/status handling, truncation descriptor/length provenance, retries, synchronization and complete ownership |
| Low | Additional implementation corpus | Inspect an independently identified Avp-bearing image/collection if available, preserving exact build and source-to-runtime boundaries |

QG1-QG7 pass for this bounded increment: descriptive findings; D1-D9 dependencies/probes; concrete routine, port-name, ABI/control/data/environment progress; reproducible widths, units, aliases and proofs; explicit control overrides, unproved X15 binding and bounded search interpretation; primary source/fixup/SDK provenance; and impact-labeled continuation. Complete request feasibility, native pairing, successful algorithms, rights/lifetimes and full architecture remain unknown. The full goal remains active and incomplete.
