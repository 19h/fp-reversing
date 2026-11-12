# Daemon post-block dispatch and selector-21 buffer join

Four declared interior-state paths now reach the pending `_IOConnectCallStructMethod` at `0x100478a04`. They connect the preceding block transform to selector 21 with 552 B input, the same user input/output pointer, and a 552 B capacity cell. The API buffer is `F+0x6a8`, 168 B after construction view `F+0x600`; the processed block occupies API offset `+0x20`. Local working modes 2 and 5 become request word 0. These joins are source-bound to the retained fixtures; the API call, native admission and daemon/kext pairing remain unexecuted or unknown.

The actual 552 B view has 44 source-defined bytes for mode 2 and 60 for mode 5. The remaining bytes retain explicit unspecified origins. Thus the source address/field join is established without claiming a fully defined packet or an observed transaction.

Primary evidence: [generator](triage_evidence/recover_daemon_postblock_dispatch.py), [source/proofs/journals and API-byte provenance](triage_evidence/daemon_postblock_dispatch_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_postblock_dispatch.py), [A64 replays and kernel readback](triage_evidence/daemon_postblock_dispatch_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_postblock_dispatch_publication.py). Parent contracts: [block processing](daemon_nested_helper_processing_report.md), [constructor](daemon_versioned_header_report.md), [root ownership](daemon_versioned_root_report.md), [selector-21 kernel/provider ABI](versioned_request_abi_report.md), [Mach index](mach_ports_report.md).

Original daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. F is the root's post-prologue SP. I=F+0x8d8 is reused record storage; G=F-0x130 is the new helper's SP. B denotes bytes; fields are little-endian; u32/u64 operations wrap at their declared width. Preferred daemon image base is `0x100000000`.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| PD1 | 24 daemon receipts, 25 source dependencies and two additional ABI receipts identify this increment. | Rehash pins, source opcodes, fixups and kernel dependencies; compare original and normalized kernel bytes. |
| PD2 | Callback, ingress, preparation and processing prefixes are restored without new execution credit. | Check opcode/read consistency during source restoration; independently restore and compare all initial registers/flags/RAM. |
| PD3 | The prior decoded object word is explicitly zero; operand profiles remain baseline. | Preserve the declaration and original partial fixtures; require an admitted upstream producer before claiming native reachability. |
| PD4 | Private owners remain live; unspecified bytes are retained as origins. | Independent backing patterns, allocation-lifetime checks, strict unknown-dependent computation stops and a complete 552 B boundary comparison. |
| PD5 | Logical PAC/return transfers model source control without hardware authentication. | Check original slots, modifiers, stack guard, fixed frame and all callee-saved GPRs. |
| PD6 | Record/frame/global cells are accessible and disjoint without wrapping. | Ten fresh UNSAT obligations and two concrete frame placements. Caller/decoder key agreement is explicitly restricted to even I. |
| PD7 | An import-bound pending call proves its source arguments, without native port/right ownership. | Stop before BLRAA; check the connection's source cell, original binding and boundary registers. |
| PD8 | The pinned kernel contract is statically compatible; runtime build/peer pairing remains unknown. | Re-read two original/normalized functions, selector record and three pointer records; require matched runtime identities for a native transaction claim. |

```text
retained block output at F+0x6c8
  -> 0x100383700: mode / fixed word / generated word / count
  -> mode 5: copy 16 B through XOR 0x98
  -> both modes: 0x100620780 -> helper 0x1004601d0
       shared-u64 updates; decode operation 0x5784
       I+4 = 0x8b3dc651; return 0x100620784
  -> 0x100478988: form API arguments
  -> STOP before 0x100478a04 BLRAA
       selector 21, buffer F+0x6a8, input 552 B, in-place user addresses
       static compatibility only -> pinned kernel selector-21 contract
```

| Pending API argument | Source-proved value | Producer / provenance |
|---|---|---|
| W0 connection | `0x82da5774` in these captured states. | `0x1004789d8` reads u32 at `0x1010b6384`, through state pointer `0x1010b6380`. |
| W1 selector | 21 / `0x15`. | `0x1004789f8`. |
| X2 input | F+0x6a8. | X20=F+0x698 from `0x100383718`; add 16 at `0x1004789ec`. |
| X3 input size | 552 B / `0x228`. | `0x1004789fc`. |
| X4 output | Same user pointer F+0x6a8. | `0x1004789f0`. |
| X5 output-size pointer | F+0x3f0, still holding u64 552. | Constructor initialization, preserved through all restored/new stages; address at `0x1004789f4`. |

Original slot `0x1010a0640` binds IOKit `_IOConnectCallStructMethod`, import ordinal 104, IA diversity `0x7a6c`. The logical target `0x7c006800` is an analysis import token, not a native function address. The captured connection word is not evidence of a live Mach-port name, send right, receiver, service connection or authorization [PD7]. No new direct Mach message or port-transfer location is established.

| API-relative region | Recovered definition | Reaching source |
|---|---|---|
| +0 .. +3 | Working mode 2 or 5, now joined to request scalar 0. | `0x100383724`, from F+0x37c. |
| +4 .. +7 | u32 `0xb4d3a486`. | `0x100383728`. |
| +8 .. +0xb | BE32 of the constructor's four generated bytes, stored as a little-endian u32. | `0x10038374c`, decoding F+0x3b4 with XOR `0x8b3dc651`. |
| +0xc .. +0x1b | Mode 5 only: each byte of F+0x610..+0x61f XOR `0x98`. Mode 2 remains unspecified here. | `0x1003161b0..0x100316270`; all-16-byte source proof. |
| +0x20 .. +0x2f | Final 16 B output from the preceding nested helper. | Processing-stage writers `0x10002c0d0`, preserved to the API boundary. |
| +0x30 .. +0x3b | Twelve earlier source-defined bytes; no further semantic role assigned. | Ingress writer `0x100577248`; exact visits retained per byte. |
| +0x220 .. +0x223 | Input count u32 16. | `0x100383750`, decoding F+0x38c with XOR `0x8b3dc651`. |
| +0x224 .. +0x227 | Unspecified in these fixture inputs; distinct from both internal record results. | No reaching definition in the retained stages. |

The complete known-offset sets are `[0,12) U [32,60) U [544,548)` for mode 2, and additionally `[12,28)` for mode 5. These contain 44 and 60 B respectively; `552-44=508` and `552-60=492` B remain unspecified. Per-byte last writers and origin identities cover the entire view. No inference about native memory initialization or kernel access to those unspecified bytes follows.

The new helper record reuses I, which previously began with a u64 workspace pointer. The caller now overwrites its first u32 with an encoded operation. Its decoder reads u32 I+0 and the selected return writes u32 I+4; this storage reuse does not make the two record layouts interchangeable. The record begins 8 B after the API buffer's exclusive end, F+0x8d0. Its result at I+4 is outside the API structure.

The decoder's key is `K=u32((low32(I) XOR 0x966e5812)*0x592e2f77)`. The source caller agrees with this key exactly when I is even; the retained records are aligned and satisfy that domain. The packed word decodes as `u32(raw-K)=phase-0x372c`; phase `0x8eb0` gives operation `0x5784`. The selected path stores `0x8b3dc651` at I+4 and returns at `0x100337004` to `0x100620784`, where the caller reads the result. The helper reserves 304 B / `0x130`, restores X19-X29 and SP, and performs no further external call here.

Before decoding the record, the helper updates shared u64 cells C=`0x1010b8e48` and D=`0x1010c4670`. With old values c/d, helper SP G and M=`0x0a5cd4cf`, the source effects are:

```text
t  = (d-c) XOR (G+0x80)
C' = t*M + 0x98c1c57ff8a0fd3a                 modulo 2^64
D' = (t XOR 0x73d046208eaed1a6)*M             modulo 2^64
```

No native synchronization or PRNG interpretation is assigned to those updates. The selected routine is an address-keyed phase decoder with shared-state effects and an out-of-band status; its other operation paths remain unknown. IA `0x0a74` also occurs on slots for targets `0x10043ac5c`, `0x100abebe4` and `0x100412ebc`; actual slot `0x1010a0520` selects `0x1004601d0`. All four original pointers are checked. Modifier equality is insufficient for function identity.

The kernel comparison freshly re-reads the two functions retained by the [selector-21 report](versioned_request_abi_report.md): 60 instructions / 240 B match both original collection and normalized kext. It checks the 48 B descriptor and three pointer records. The descriptor retains flags 3, input/output 552 B, UserClient target `0xfffffe000a50500c`, and provider adapter `0xfffffe000a504ea0`. Collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`.

The older kernel source contract forwards request words 0/4/8, spans +0xc/+0x20 and count +0x220. This increment supplies those source-side word values and block identity on the declared paths. Input count 16 is compatible with that wrapper's numeric limit 512. User input/output pointer equality does not prove kernel input/output aliasing. The kernel's eventual provider status at output +0x224, its mutable output count and the daemon's API return encoding remain distinct, without any new execution evidence for them [PD7,PD8].

Validation retains eight daemon regions, 362 instructions / 1,448 B and ten fresh UNSAT obligations. Four source cases execute 1,330 visits: 304 per mode-2 case and 361 per mode-5 case. They contain 308 read events and 120 write events. The per-case source-pool sum 1,334 includes the four pending call boundaries; these are not four executed API calls.

Eight independent A64 replays check 2,660 visits, 2,416 register effects, 40 NZCV effects, 3,272 read B, 1,248 written B and 240 write effects. No unspecified byte is copied in these new journals. The auditor additionally compares 8*552=4,416 B of boundary RAM against the origin-preserving source views; those comparisons are not instruction reads or native API consumption. Prefixes remain restored, external API models are absent, and the call remains pending.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Establish the admitted upstream producer. | High | Compose a real source path that supplies the declared zero object word and its input owners. |
| Establish connection/build/peer identity. | High | Recover acquisition and lifetime of the connection in the same execution context and match the kernel endpoint/build. |
| Recover kernel use of the joined fields. | High | Connect the mode, generated scalar, optional span and 16 B block to concrete provider/core consumers. |
| Establish full buffer definitions or access requirements. | High | Recover missing reaching definitions or prove the actual consumer's required bytes; unspecified fixture origins do not establish native behavior. |
| Follow returning API paths. | High | Separate API return, provider output status and mutable count with explicit return/output provenance. |
| Generalize the new helper. | Medium | Recover other operation/tag paths and the purpose/lifetime of both shared-u64 cells. |

Quality gates for this increment:

- **QG1**: Factual technical analysis requires no normative premise.
- **QG2**: PD1-PD8 identify assumptions, dependent claims and falsification probes.
- **QG3**: Mode serialization, data/control flow, record reuse, state effects, API arguments and static kernel compatibility are covered. The full goal remains active.
- **QG4**: Byte extents, count/capacity/status roles, source/replay totals, algebra widths and restored/new scopes are reproducible and distinct.
- **QG5**: Declared fixtures, unspecified bytes, pending calls, import tokens, native ports and kernel aliases are not conflated.
- **QG6**: Original daemon/kernel bytes, fixups/imports, pinned receipts, ten source proofs and independent A64 effects support the claims. Native delivery/admission and matching live-IDB evidence remain unknown.
- **QG7**: Continuation bounds admission, endpoint identity, concrete kernel consumers, required byte definitions, return contracts and helper generalization.
