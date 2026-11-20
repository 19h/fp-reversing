# FairPlayIOKit discovery redispatch

The saved redispatch arguments are a 64-bit context value and a 32-bit marker. The block at `0x1006205f8` copies them from S+0x808 B and S+0x40c B into S+0x8c8 B and S+0x914 B, where the post-cleanup path reloads them. Four offline replays start with the same failed primary open and zero saved flag. Only the case with a nonnull restored context and a marker unequal to `0x8b3dc651` reaches a second primary `IOServiceMatching` request, after reacquiring the cached lock. The other three cases store `0x74c29d88` at S+0x804 B. [Original-byte audit](triage_evidence/audit_daemon_class_redispatch.py) [Receipt](triage_evidence/daemon_class_redispatch_audit.json.zst)

## Saved arguments

S is the retained outer stack pointer. The outer entry initializes S+0x808 B to zero at `0x100559d40` and S+0x40c B to `0x8b3dc651` at `0x100559d4c`. At `0x1005492d8` and `0x1005492e0`, original code forms the addresses of both cells in X11 and X23. The exact reaching writes that replace the initial values with an admitted pair remain unknown. Direct stores to the same numeric offsets elsewhere in the instruction range require frame and path attribution before they can establish causality. [Outer phase producer](daemon_class_status_route_report.md)

| Site | Input or condition | Output |
| --- | --- | --- |
| `0x10062c2a0` | Saved phase `0xb306`, incoming W8=1 | Index `0xaeb2`, slot `0x101091480`, IA `0xfe2b` reaches `0x1006205f8` with W10=`0x5bca`. |
| `0x10062c2a0` | Same phase, W8=0 | Index `0x183f`, slot `0x1010460e8`, IA `0xfe2b` reaches `0x10052b5e8`. |
| `0x100620610`–`0x100620614` | S+0x808 B, u64 | Copy to X19 and S+0x8c8 B. |
| `0x100620630`–`0x100620634` | S+0x40c B, u32 | Copy to W11 and S+0x914 B. |
| `0x10062064c` | Incoming W10=`0x5bca`, context nonnull | Slot `0x101068020`, IA `0x4abe` reaches `0x100639894` with W8=0 and W9=`0x65a1`. |
| `0x10062064c` | Same W10, context NULL | Slot `0x101067d40`, IA `0x4abe` reaches `0x10051ac30`. |

After cleanup, `0x1004c896c` and `0x1004c8970` reload the saved pair and `0x1004c89a4` reaches the same gate with W8=1. In the gate, `0x1006398b4` saves that flag and `0x1006398d8`–`0x10063990c` select index `0x65b3` for the nonnull, marker-unequal case. The other cases select `0x65a1` and return directly to the status gate at `0x1004c620c` with W21=`0x74c29d88`, W8=1 and W10=`0x5847`. That gate selects the relay that stores the replacement marker. [Status gate](daemon_class_status_route_report.md) [Lock gate](daemon_class_lock_gate_report.md)

## Replayed outcomes

All replays model one primary type-0 open failure `0xe00002c2`, service release, iterator release and cached lock release. The replay declares the two saved cells before the first gate and confirms their values at the second gate. The copy block is audited independently from those replays.

| Restored context | Restored marker | Result after redispatch |
| --- | --- | --- |
| NULL | `0x8b3dc651` | Store `0x74c29d88` at `0x10052b5f0`. |
| NULL | `0x8b3dc650` | Store `0x74c29d88` at `0x10052b5f0`. |
| Nonnull | `0x8b3dc651` | Store `0x74c29d88` at `0x10052b5f0`. |
| Nonnull | `0x8b3dc650` | Request a second write lock on the same cached pointer, call modeled `IOMainPort`, and reach pending `IOServiceMatching("com_apple_driver_FairPlayIOKit")` at `0x100079bf0`. |

The last case stops inside the class frame with SP=S−0x150 B. The import boundary supplies the expected class string. Its result, a second matching-services exchange, a second open, and additional port names remain unknown. The archived trace supports the original failed-open and retirement order. Attribution of the redispatch and its inputs to a native frame remains unknown. [Archived open and port retirement](archived_iokit_open_retirement_report.md)

## Assumptions and verification

| Assumption | Dependent result | Stress test |
| --- | --- | --- |
| A1. Original bytes and logical chained targets come from the pinned arm64e image with UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. | Branch sites, table indices and import boundaries. | Verify 96 original chained words. Resolve both incoming W8 controls and both context controls in the isolated source windows. Hardware PAC remains unknown. |
| A2. The two saved words have the declared values in the retained frame. | Conditional second lookup or marker replacement. | Run all four combinations and check the actual restored registers, original target and output store or pending call. Earlier native values remain unknown. |
| A3. The completed environment cache and ordinary modeled external returns match the previous primary-only failure case. | First failed-open cleanup and reacquisition order. | Require one open and unlock in each profile, check retained port ownership at the pending call and require the second write-lock request only in the admitted case. |

Four replays retain 294 logical transfers. Four isolated edges and ten bit-vector obligations verify the source relations at arbitrary context and marker widths. The replay takes O(V) time for V instruction visits and retains O(T) transfer records for T visits to authenticated transfers, excluding the pinned image and solver. Reproduce with `python3 -B triage_evidence/audit_daemon_class_redispatch.py` in the existing Unicorn, Capstone and Z3 environment. [Audit](triage_evidence/audit_daemon_class_redispatch.py) [Compressed receipt](triage_evidence/daemon_class_redispatch_audit.json.zst)

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Native reaching state of S+0x808 B and S+0x40c B | High | Track writes through the two stack addresses and prove they reach the copy on an original predecessor path. |
| Whether a second lookup advances to a new open | High | Resolve ordinary matching return and correlate the second class call with matching-services and port activity in the same execution. |
| Consumer of the replacement marker | Medium | Follow S+0x804 B beyond the store to its first read and outgoing result. |
