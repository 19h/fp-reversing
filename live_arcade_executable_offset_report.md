# Executable slice offset from image activation to fairplayd

The installed kernel’s `_proc_getexecutableoffset` independently confirms that process +`0x5a0` holds the executable file offset sent in Mach request `61471`. The ordinary `posix_spawn` and shared `execve` paths obtain the value from image activation and publish it alongside the executable vnode. `fairplayd` captures the 8 B value in its input record. In three retained `fairplayd` runs differing only in that value, the pre-send path never reads its slot and produces identical CoreFP XPC payloads. Native transaction data and daemon use after the send boundary remain unknown. [Kernel request and reply](live_arcade_subscription_outcome_report.md) [Reproducible instruction and profile audit](triage_evidence/live_arcade_executable_offset_audit.json.zst)

```text
Mach-O image -> image parameters +0x90 -> process +0x5a0
                                              |
                                              v
CoreFP XPC <- path branch in fairplayd <- Mach request 61471
                       |
                       +-- offset stored in input record +0x18
```

## Kernel producer and transport

The evidence uses macOS build `26C5035r`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`. All kernel addresses are unslid. Apple’s source supplies the image activator and `exec_resettextvp` names [A2]. The fileset independently supplies the exported getter’s name. [XNU image activation and executable vnode state](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c) [XNU executable offset getter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L2168-L2172)

| Transition | Installed instruction evidence | Effect |
| --- | --- | --- |
| Enter shared image activation | `posix_spawn` at `0xfffffe000c2f2b1c`, shared `execve` at `0xfffffe000c2f5f14` | Both call `0xfffffe000c2f3c08`, passing their image-parameter record in X0. |
| Initialize image range | `0xfffffe000c2f3fbc`, `0xfffffe000c2f3fc4` | Clear image parameters +`0x90` to zero and record file size at +`0x98`. The zero offset represents the whole-file starting point. |
| Select a universal binary slice | `0xfffffe000c2f412c` calls `0xfffffe000c2ebe5c`. `0xfffffe000c2ec088` takes the selected 32-bit file offset from the architecture record for `_vn_rdwr_64`. On success, `0xfffffe000c2ec0e8` through `0xfffffe000c2ec0f0` widen and store the selected offset and extent. | `ushll` zero-extends both 32-bit fields to 64 bits. The 16 B store places the offset at image parameters +`0x90` and the size at +`0x98`. Return code `-2` causes the enclosing dispatcher to repeat activation on the selected slice. |
| Publish executable vnode and offset | `0xfffffe000c2f2e78` and `0xfffffe000c2f6098` both call `0xfffffe000c2f4a4c`, passing the process in X0 and the same image-parameter register in X1 as each path used for activation. | The callee loads image vnode +`0x20` and offset +`0x90`. Stores at `0xfffffe000c2f4b2c` and `0xfffffe000c2f4b30` publish the signed vnode pointer at process +`0x598` and the offset at +`0x5a0`. A failed vnode reference clears both fields. |
| Read and emit the offset | `_proc_getexecutableoffset` at `0xfffffe000c30bb64` reads process +`0x5a0`, matching the inline load at `0xfffffe000bd29c94`. The MIG client stores X3 at `0xfffffe000bdda304` and submits the RPC at `0xfffffe000bdda33c`. | All 8 B are carried into `61471` at user-message offset `0x38`. The destination is the registered anonymous daemon send reference. |

The selected byte position locates the Mach-O slice in the executable vnode. Apple’s source passes the same vnode and offset to the code-directory hash lookup, corroborating its role in identifying an on-disk slice [A2]. The 8 B Mach scalar is distinct from the preceding out-of-line path count. [XNU process fields](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_internal.h#L351-L357) [XNU process CDHash lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L1940-L1947) [Arcade wire layout](live_arcade_registration_report.md) [Process-launch AST](live_arcade_ast_report.md)

## Observed fairplayd data flow

The pinned daemon’s wrapper stores X3 at `0x10000598c` in the 40 B input record. The four retained runs below read that record at offsets `0`, `8` and `32` at PCs `0x1005984a0`, `0x1005984a4` and `0x1005984a8` respectively. Those reads consume the local receive name, out-of-line path pointer and decision-output pointer. The simulator stops at the synchronous XPC call at `0x10077e614`, after the daemon assigns the serialized bytes to dictionary key `data` at `0x10077e5c4`. [Original daemon argument and send code](arcade_subscription_report.md) [Retained daemon profiles](triage_evidence/arcade_subscription_profiles.json.zst)

| Retained input | Executable-offset bit pattern | XPC `data` length | Payload comparison |
| --- | --- | --- | --- |
| Baseline | `0x1122334455667788` | 160 B | Reference |
| Change offset only | `0x0000000000000000` | 160 B | Exact baseline bytes |
| Change offset only | `0xffffffffffffffff` | 160 B | Exact baseline bytes |
| Change path only | `0x1122334455667788` | 112 B | Different bytes |

The finite comparisons [A3] establish absence of a read of the offset slot through this observed branch. Other branches and post-reply uses remain unknown. The synthetic offset values exercise storage and comparison in the retained model. The current kernel’s checked universal-binary path obtains its offset from a zero-extended 32-bit architecture record.

## Assumption register and quality gates

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The inspected collection matches the running boot cohort. | Installed-code sites and displacements. | Check `kern.uuid` and build, then require exact fileset hash and UUIDs. |
| A2. Pinned XNU supplies the role names for same-shaped compiled routines. | `exec_fat_imgact`, `exec_resettextvp`, architecture and vnode argument names. | Compare against exact-build types. Independently check the fat magic, file-I/O argument, publication stores, matching callers and `exec_resettextvp` diagnostic. |
| A3. The retained model records every read from the argument record within the selected interval. | No offset read in the four tested traces. | Extend the recorded interval or instrument aliased copies of the argument record. A matching native transaction would also test the modeled call boundary. |

High impact attaches to the binary-backed join from launch selection to RPC. Medium impact attaches to the observed path-only contribution of these two fields to the outgoing XPC payload. A transaction-linked FairPlayIOKit call remains unknown. The audit checks 33 instruction anchors and ten direct calls, retains 327 instructions, verifies both image identities, and compares four pinned daemon profiles. Validation takes O(B + P + I) time and space for fileset bytes B, expanded profile bytes P and retained instructions I. All sizes and displacements are exact bytes. [Audit script](triage_evidence/audit_live_arcade_executable_offset.py)

```sh
python3 -B triage_evidence/audit_live_arcade_executable_offset.py \
  "$BOOT_FILESET" triage_evidence/arcade_subscription_profiles.json.zst
```
