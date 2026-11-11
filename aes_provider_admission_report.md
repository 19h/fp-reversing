# Descriptor-AES guards, mutable key control and command scheduling

The nominal `IOAESAccelerator::performAES` entry checks a full64 length in `[1,8388608]` B and requires 16-byte alignment. Its aligned numeric domain is therefore 16..8388608 B. This is a provider entry guard, not a descriptor-capacity theorem. The [middle-span caller](lskd_hardware_staging_report.md) caps copies at 81920 B while submitting its saved total count; that distinction remains unresolved at the native descriptor/backing boundary. [PA1-PA8]

The provider also clears bit31 of key-data word `+0x24` and may replace the incoming key-data pointer with a matching provider-table entry plus eight. The earlier [sample state](sample_state_report.md) and [sample transfer](sample_transfer_report.md) establish that a constructed state base reaches the typed key-data argument. Together these identify its formerly unnamed `+0x24` control word as a low31 provider selector. Algorithm names, key provenance and complete acceptance semantics remain **unknown**. [PA2-PA5,PA8]

[Evidence](triage_evidence/aes_provider_admission_checks.json.zst), [extractor](triage_evidence/recover_aes_provider_admission.py) and [publication audit](triage_evidence/verify_aes_provider_admission_publication.py) retain seven spans / 568 instructions / 2272 B and 16 original authenticated slots. Twenty-nine UNSAT obligations cover 27 selected source pieces / 91 lifted instructions; the remaining retained instructions supply independently decoded control-flow and access evidence. This is not a complete symbolic execution of the provider. No target, provider, crypto or IDB operation executes.

```text
performAES descriptor entry
  -> virtual getSupportedOptions [before argument guards]
  -> descriptor/key nonnull; length aligned16 and 1..8388608 B
  -> key+24 low31 publication -> further key policy [partially recovered]
       optional matching provider entry -> key pointer = entry+8
  -> prepare(input,0), prepare(output,0)
  -> getPhysicalAddress for each role; provider-mask alignment checks
  -> getCommand(true) -> fill command, progress=0
  -> gate.runAction(provider action, command, NULL, NULL, NULL)
  -> immediate attempt or queue
       queue + callback NULL -> commandSleep(command,0)
       scheduler -> quantum=min(length-progress, operation limit)
       -> virtual performAESQuantum [native effects/completion open]
```

Addresses and field offsets are hexadecimal; byte counts are decimal. Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Fileset `LC_FUNCTION_STARTS` bounds five routines; kernel function starts bound the physical-address wrapper; the four-instruction import stub has an explicit fixed span. The provider/queue/start/base-options bytes match the frozen [handoff source](triage_evidence/kext_aes_handoff_contracts.json.zst). The original three supplied inputs remain unchanged.

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| PA1 | Pinned original KC, compiler catalogs and chained-pointer metadata identify the selected build | Source spans, slots and exact method names | Rehash/independently decode all spans and original slots; match a native image separately |
| PA2 | Original descriptor-AES ABI and the prior caller/sample pointer identities apply | Length, key/IV roles and cross-report field correspondence | Replay caller certificates; compare frozen state/transfer contracts; bind actual reaching argument epochs |
| PA3 | Scalar conditions, u32/u64 arithmetic, writeback and signed extension describe retained instructions | Numeric guards, header mutation, command fields and quantum | Regenerate fail-closed source cuts and replay counterexample queries; audit surrounding branch opcodes |
| PA4 | Receiver, key data, selected table entry, command and frame storage are valid, stable and have the required nonaliasing bounds | Loads/stores and selected-key correspondence | Recover native allocation extents, aliases, ownership and concurrent writers |
| PA5 | Returning calls preserve required callee-saved registers and relevant storage | Guard-to-command and queue/result composition | Inspect actual callees, pointer aliases and epochs; guard entry alone does not prove a call returns |
| PA6 | Scheduler progress<length and configured quantum>0 when interpreting a positive bounded quantum | Mathematical quantum bound | Recover all progress/limit writers and actual initialization; do not assume zero/underflow cases are excluded natively |
| PA7 | Static vptr/slot identities describe nominal classes; authentication and runtime overrides are not executed | Exact method bindings and class-specific option values | Match actual provider/descriptor class, vptr, PAC state and operation configuration |
| PA8 | Complete key policy, descriptor extent acceptance, device effects, completion and daemon transport remain unproved | Interpretation and completeness boundaries | Follow remaining branches, descriptor/DMA range consumers, completion progress and actual daemon serialization |

## Entry guards and mutable key-data control

The provider saves incoming length X3 in X25 without truncation. Source `abff3e0..abff3ec` computes `T=(L-8388608-1) mod 2^64`, then tests carry from `T+8388608`. The certificate proves that carry is set exactly when `1<=L<=8388608` under unsigned64 ordering. Together with `TST L,#15`, the admitted numeric set is positive multiples of 16 through 8 MiB. Null input descriptor, output descriptor or key-data pointer and failed length tests select raw `0xe00002c2`. This does not describe every later rejection. [PA1-PA5]

At `abff3f8..abff404`, the provider reads original key-data `+0x24`, retains the original word in W8, and writes `word & 0x7fffffff` back through that pointer. Later policy can still reject. Thus failure does not imply that the key-data control word was unchanged. For the middle-span caller's incoming P+184 pointer, this initial write addresses P+1a8. The correspondence is source arithmetic, not a new native context observation. [PA2-PA5]

| Selected policy component | Source-established role | Limit |
| --- | --- | --- |
| Key-data word +24, low31 | Numeric selector consumed by range/equality filters | Public/business names unknown |
| Selector 2100..2999 | Provider key-table lookup arm | Actual lookup result/count/lifetime unknown |
| Provider +d0 / +d8 | Table base / u32 entry count on that arm | No native table snapshot recovered |
| Entry stride 52 B | Candidate-entry address progression | Table backing/bounds remain premises |
| Matched entry +8 | Replacement key-data pointer; selected control word at entry+2c | Input pointer is not universally forwarded unchanged |
| Selectors 3000..3999 and 4000..4004 | Further provider flag/capability policy ranges | Complete policy and accepted operation combinations unproved |

The earlier sample-state controls 2201 and 2204 fall within the table-lookup range; 3000 and 3100 enter other policy ranges. The state header's raw 128 matches one numeric word checked on an ordinary key-header route. These correspondences refine field roles; they do not establish algorithms, bit-count units, keys or successful native acceptance. [PA2-PA5,PA8]

## Descriptor preparation and address checks

The provider requests `prepare(0)` for both descriptor roles at `abff5c8` and `abff6c0`. The caller can supply the same descriptor twice; two roles do not imply distinct objects or balanced native preparation. A failed request takes a separate error path. After both succeed, calls at `abff70c` and `abff724` reach import stub `abffaf4`, original slot `0xfffffe000858a620`, exact kernel `IOMemoryDescriptor::getPhysicalAddress()` at `0xfffffe000c53c2c4`. [PA1,PA4-PA7]

That wrapper tail-calls nominal descriptor virtual +158, exact `IOGeneralMemoryDescriptor::getPhysicalSegment(offset64,length64_pointer,options32)`, with `(0,NULL,0)`. It requests a base physical address; this source does not request a segment-length output. The provider tests each returned address with `physical64 & zero_extend32((provider_u32_at_b0-1) mod 2^32)`. The interpretation as an alignment guarantee requires additional properties of the configured parameter; those properties and descriptor extent remain unknown. [PA3-PA4,PA7-PA8]

## Command carrier and scheduling interfaces

The provider obtains a command through nominal `IOCommandPool::getCommand(true)`. The following fields are assigned after the retained policy/preparation frontiers; reaching them is conditional on those earlier paths. No memory allocation or command-pool operation executes in this increment. [PA4-PA7]

| Command field | Width | Source value |
| --- | --- | --- |
| +20 / +28 | 8 B each | Input/output descriptor |
| +30 / +38 | 8 B each | Full64 length / IV pointer |
| +40 | 4 B | Operation low32 |
| +48 | 8 B | Selected key-data pointer, possibly remapped |
| +50 / +58 | 8 B each | Full64 source/destination offsets |
| +60 | 8 B | Provider-derived operation-specific quantum limit |
| +68 | 8 B | Progress initialized to zero |
| +70 | 8 B | Quantum published by `_startCommand` |
| +78 | 4 B | Status read after a successful queued wait |
| +80 / +88 | 8 B each | Completion function/context |

For operation 1, the original read-only operation-offset table selects provider field +e8 for command +60. This differs from provider +a8, which is used as an immediate-attempt length threshold. Actual values and initialization of these fields remain unknown. The scheduler stores `min((L-progress) mod 2^64,limit)` at command+70 and sets provider byte+110 to 1. Under PA6 the quantum is positive and no greater than either remaining length or limit; no complete progress/completion invariant is established. [PA3-PA6,PA8]

`_queueLocked` attempts `performImmediateAES` only when provider byte+110 bit0 is clear, command length<=provider+a8, and completion function is NULL. A particular immediate result `0xe00002d0` falls back to queueing; other immediate results take descriptor completion and pool-return paths. Queueing with a NULL completion function reaches `commandSleep(command,0)`; after a zero wait result it reads command+78 and returns the command to its pool. A nonzero wait result diverts to a separate helper. NULL completion alone does not prove that a native wait occurs. [PA1,PA3-PA5,PA7-PA8]

| Nominal class/interface | Selected method / behavior |
| --- | --- |
| IOAESAccelerator +8a0 | Base `getSupportedOptions`: 3 if provider+a8 is nonzero, otherwise 1 |
| AppleS8000AESAccelerator +8a0 | Override: 0x3d if unsigned field+128>4, otherwise 0x1d |
| IOCommandGate +1e8 | `runAction(action,command,NULL,NULL,NULL)`; action loaded from provider+f0 |
| IOAESAccelerator +8b8 / +8d8 | `performImmediateAES` / `_startCommand` |
| AppleS8000AESAccelerator +8a8 | Exact `performAESQuantum(IOAESAcceleratorCommand *)`, target `0xfffffe0009d50a28` |

The nominal AppleS8000 quantum target is a lower frontier, not an executed hardware operation or a match to the live receiver. No new Mach-port acquisition, message emission or right transfer is established; these touch points are object fields, virtual methods, a command pool, a command gate and command records. [PA7-PA8]

## Reproduction, bounded follow-up and quality gates

The extractor's `--verify` regenerates exact source evidence. The publication audit replays 29 new and 36 frozen caller UNSAT obligations plus the frozen caller's SAT width control, rechecks original bytes/function catalogs/fixups/nlist, audits branch and register boundaries, preserves inputs, and checks manifest delta and path hygiene. The register census treats CMP/CMN/TST as flag-only aliases after checking the encoded zero destination and S bit; their operand-access metadata can overreport writes. Extraction/expression work is O(N+I) time/space for source/index bytes N and lifted instructions I; SMT cost is separate. Numeric widths and byte units are explicit. Table lookup uses O(entry count) target work; complete provider/scheduler/hardware costs remain unknown.

| Impact | Bounded follow-up | Discriminating evidence |
| --- | --- | --- |
| High | Establish descriptor extent and DMA acceptance | Follow AppleS8000 quantum setup and descriptor range methods with the actual total/copy counts |
| High | Establish native provider configuration | Recover +a8/+b0/+e8 initialization, actual class and busy/progress writers |
| High | Complete selected-key policy and ownership | Resolve active table entries, flag/capability branches, remapping and key-header writes under matched lifetimes |
| High | Establish completion and IV effects | Follow lower quantum, command progress, completion status, wakeup/callback and typed IV mutation |
| High | Join native daemon and kext callers | Match IOKit serialization, wrapper inputs and returned-status consumers in one epoch |
| Medium | Establish pool/gate/descriptor accounting | Trace both descriptor roles through all failure and completion paths without assuming distinct objects |

**QG1**: No normative claim is required. **QG2**: PA1-PA8 identify assumptions, dependent claims and falsification probes. **QG3**: Guards, key-control mutation/remapping, descriptor/address requests, command carrier and scheduling frontiers are covered; full key policy and native transport remain open. **QG4**: Widths, byte units, modular arithmetic and bounded algorithm costs are explicit. **QG5**: Entry length, copied chunk, immediate threshold, scheduler limit, physical mask and descriptor capacity remain distinct. **QG6**: Original code/catalogs/fixups/nlist, frozen contracts and reproducible queries provide primary provenance. **QG7**: Impact-ranked follow-up bounds remaining data, control, environmental and architectural interfaces.
