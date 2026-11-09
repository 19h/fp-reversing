# Produced RPC502 request through application records and original libbsm PID extraction

Two exact constructor/kernel-produced RPC502 requests with68-byte trailers now
execute continuously through the original daemon callback, MIG stub, application
wrapper, string scan, audit copies, protected operation and selected original
cached libbsm body. Both paths select the original PID-zero continuation and
stop before `_pthread_self`. The audit extraction is executed from original
library instructions rather than supplied by an API result model. [RA1-RA8]

Each path has2967 instruction visits, including19 in the35-instruction libbsm
body. No CPU, stack or request reset occurs at application entry. Native
framework delivery and actual library pairing remain unknown; successful
application processing, native credentials and a FairPlay reply are not
established. The broader interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| RA1 | Pinned daemon/kernel corpus and installed-cache bytes identify the selected sources | Static addresses and local composition | Rehash daemon, prior transport evidence, three cache files and all source ranges; establish native build pairing separately |
| RA2 | Prior kernel VM/copy/retirement and cross-task/framework premises apply | Exact delivered USER/OOL/token contents | Preserve prior artifacts; compare complete delivered buffers and freshly replay both callback producers; attest actual framework reception separately |
| RA3 | The callback CPU and memory state reaches application entry intact | Continuous application call | Compare all saved GP/SP/NZCV/Q values, ordered read/write prefix and complete private-RAM/stack hashes with prior independently replayed terminal states |
| RA4 | Private malloc succeeds and the stack-check import preserves all registers and memory | Original protected-frame setup and continuation | Check actual calls, all before/after registers and journal effects; recover the matching stack-check implementation and native stack context separately |
| RA5 | Logical original pointers/PAC and one selected libbsm import binding stand in for loading/authentication | Original daemon-to-library call and return | Decode157 original fixup/import words, verify exact library export/UUID/body and compare actual loader/rebase/PAC state separately |
| RA6 | The29-byte string and zero audit token are the declared transport fixture | String scan and PID0 result | Compare every string read and three complete copy edges to delivered bytes; do not infer native file existence, PID or authorization |
| RA7 | Source byte stores define initialized fields; untouched poison bytes remain undefined | Private record and output observations | Check complete120/32-byte record oracles and ordered writes; do not interpret untouched result cells as outputs |
| RA8 | Pthread identity entry is a stopping boundary | Downstream environmental and scheduling scope | Execute the matching thread/QoS/environment implementations with independently established context before claiming their effects |

## Primary provenance

The daemon is [the original arm64e image](</Users/___/Downloads/zut/fairplayd.arm64e>),
SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
The exact delivered inputs and previous callback boundary are recorded in
[request consumption](daemon_request_consumption_report.md) and
[kernel delivery](kernel_request_delivery_report.md). Their prior artifacts
remain frozen. The historical RAX trace remains a separate observation without
these RPC exchanges; no daemon is launched here. [RA1,RA2]

| Source | Identity / verified extent |
| --- | --- |
| Original daemon reviewed ranges | 53 ranges /3808 captured instructions; range count is not a complete-function count |
| Installed dyld cache | UUID2bd06591-e751-3e84-963f-b08dab6af23a |
| `/usr/lib/libbsm.0.dylib` in that cache | UUIDa01677ab-bd20-3c62-8b0f-c805062f95bd |
| Exact export `_audit_token_to_au32` | 0x20638d758..0x20638d7e4;140 bytes /35 instructions |
| Original body SHA-256 | 76ed6c9a5a2b1b51e22d1fd36ca9802e734187970d71868438eb981b52e613e5 |
| Daemon import slot | 0x1010a0500, original auth-bind to `libbsm/_audit_token_to_au32` |
| Explicit private binding | That slot resolves to0x20638d758; actual native loader pairing remains unknown |

[Source capture](triage_evidence/daemon_request_application_source.json) retains
original daemon ranges, cache function/export/nlist identity and three complete
cache-file hashes. [Profiles](triage_evidence/daemon_request_application_profiles.json)
retain continuous execution journals, complete saved CPU frames and private
record observations. [Independent checks](triage_evidence/daemon_request_application_checks.json)
recapture the source and replay the old producers and new paths separately.
No IDB query or modification was required. [RA1,RA3,RA5]

## Continuous data/control flow

```text
exact produced USER request + OOL string + trailer68
  -> original callback 0x100425f78
  -> demux 0x100005274 -> MIG stub 0x1000050c8
  -> application 0x100422d48 [same CPU and RAM]
       -> first byte / NUL scan: exactly29 input bytes
       -> R120: service, string, CPU, origin, audit, fixed-output pointers
       -> F32: encoded operation0xbc84919b and R pointer
       -> protected adapter 0x10065ffd8 -> core 0x10061a2d0
       -> audit record -> temporary1 -> temporary2
       -> actual cached audit_token_to_au32
            token word5 -> sole enabled PID output
       -> original PID0 continuation 0x1005c18c8
       -> stop before imported pthread_self
```

The prior331-visit callback/MIG prefix is identical for each case, including
all source reads/writes and malloc arguments/clobbers. At application entry,
GP registers, SP, NZCV, Q registers, the entire1 MiB private message region
and512 KiB stack match the preceding independently replayed terminal state.
The only new initial image binding concerns libbsm and is not read by that
prefix. The application does not receive fabricated argument records. [RA3-RA5]

The original entry reads OOL byte0 at0x100422edc, then advances through
0x10008a958 until byte28, the NUL terminator. All29 ordered byte reads match
the produced payload at0x6500004000. This establishes this normal string's
data flow; it is not a general bound or a claim about malformed inputs. [RA6]

## Private argument and encoded control records

Let E be application-entry SP, S=E-0x150, R=S+0x28, U=S+0xa0 and F=S+0xc0.
Observed E=0x70077f00, R=0x70077dd8 and F=0x70077e70. R is120 bytes in this
partial layout. Values below are independently predicted from the incoming
request and MIG output destinations, then compared with the whole record.
Widths and offsets are bytes; integer fields are little endian. [RA3,RA7]

| R offset | Width | Established value / state |
| ---: | ---: | --- |
| 0 | 4 | Receiving-service name0x303 |
| 4 | 4 | Unwritten alignment padding, observedA5 |
| 8 | 8 | OOL string pointer0x6500004000 |
| 16 | 8 | CPU type0x0100000c |
| 24 | 8 | CPU subtype0 |
| 32 | 8 | Origin1 |
| 40 | 32 | Complete copied audit token, zero in these fixtures |
| 72 | 8 | Fixed output-record destination reply+0x44 |
| 80 | 8 | Fixed output-record destination reply+0xcc |
| 88 | 32 | OOL result cells/padding not populated at this frontier; observedA5 |

The original32-byte audit-copy calls form these exact edges. Every destination
byte is written by the original local helper; none is supplied by a copy model.
[RA6,RA7]

| Edge | Source | Destination | Bytes |
| --- | --- | --- | ---: |
| MIG token to argument record | 0x70077f30 | R+40 =0x70077e00 | 32 |
| Argument record to protected temporary1 | 0x70077e00 | 0x7006e6e0 | 32 |
| Protected temporary1 to temporary2 | 0x7006e6e0 | 0x70072fa0 | 32 |

With x=low32(F) and p=((x XOR0xeaae0ac9)*0x7398180b) modulo2^32, the full
observed32-byte control record is independently reconstructed as follows.
The final8-byte region remains the declared poison pattern at this boundary;
it is not a valid returned result. [RA7]

| F offset | Width | Value |
| ---: | ---: | --- |
| 0 | 8 | U XOR0x1c0b9f7ce10f2255 |
| 8 | 4 | p XOR0x00006cf4 |
| 12 | 4 | p XOR0xbc84919b |
| 16 | 8 | R |
| 24 | 8 | Result/padding observation A5; no result produced yet |

## Original cached libbsm ABI

The daemon's call at0x1007fc754 reaches the chosen cached export through the
explicitly bound original slot. The API's32-byte aggregate is passed
indirectly through X0, pointing to protected temporary2. Its output pointers
follow in registers and the first stack argument. [RA5]

| ABI location | Source-level/body role | Value in these cases |
| --- | --- | --- |
| X0 | Pointer to32-byte token argument storage | 0x70072fa0 |
| X1..X5 | Optional outputs for token words0..4 | All null |
| X6 | Optional PID output for token word5 | 0x7006b540 |
| X7 | Optional output for token word6 | Null |
| Entry SP+0 | Optional terminal-information output | Null |

The recovered library body conditionally stores token words0..6 through the
corresponding nonnull output pointers. Its terminal-output branch can call a
helper at0x20639ae94; that branch is not visited here because the final pointer
is null. The executed path has19 original instructions, not all35 captured
instructions. At0x20638d7b0 it loads the32-bit token word at+20, then at
0x20638d7b4 writes that value through X6. The complete selected output is0.
The function's residual X0 is not interpreted as a return-status value. [RA5,RA6]

The original return reaches0x1007fc758 with the saved frame restored. The
daemon's own predicate chooses0x1005c18c8, then calls `_pthread_self` at
0x1005c195c. Execution stops at the imported target before obtaining a thread
identity. No thread/QoS, CSR, BootPolicy, filesystem or later processing result
is synthesized. The zero token is an input fixture, not a native credential
observation or an authorization conclusion. [RA6,RA8]

## Verification and bounded continuation

Fresh independent replay checks5934 instruction visits:5896 daemon visits and
38 cached libbsm visits. It checks1208 reads /5978 bytes,688 writes /4646 bytes,
44 saved CPU frames,22 application/record frames, two full CPU/RAM entry
handoffs and3145728 final private-memory bytes. Complete USER/OOL/reply
observations cover49920 bytes. Two additional fresh callback-producer replays
check662 visits and the same-sized complete private-state observations.
These totals count repeated private fixtures, not native mapped extents.

All157 accessed original daemon fixup/import words are decoded. Original
rebase/authentication metadata and import-table/pointer addends remain distinct.
Loading imported data-cell addresses during protected setup does not establish
that an OS logging or task/IPC API was called. The selected libbsm binding,
two malloc contracts and two stack-check preservation contracts remain explicit.
[RA4,RA5]

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_request_application.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_request_application.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_request_application.py
```

Extraction/replay costs O(B+H+V+J+F) time and O(B+R+J+F) space for image bytes B,
streamed cache-hash bytes H, source visits V, journals J, fixups F and private
memory R. For this normal NUL-terminated string of L=28 non-NUL bytes, the
scan reads L+1=29 bytes and takes O(L+1) time/O(1) extra scan space. No exhaustive
application-semantics or native transport proof is claimed.

| Impact | Further requirement / opportunity | Completing or falsifying evidence |
| --- | --- | --- |
| High | Actual framework and library pairing | Effective callback/cache history, loader dependency identities and original post-receive buffers |
| High | Produced request through environmental processing | Original pthread/QoS/CSR/BootPolicy inputs and implementations, with complete state preserved from this boundary |
| High | Real private output construction and reply | Original success-status producer, fully initialized records/OOL extents and matching kernel reply transport |
| Medium | Stack-check implementation | Exact matching export/reexport/entry and original stack-access semantics; name similarity is insufficient |
| Medium | General cached token-conversion ABI | Recover terminal-information helper and verify the remaining optional-output paths separately |
| Medium | RPC700 alternate endpoint | Actual slot34 publication, object identity and matching server body remain unknown |

[Preservation](triage_evidence/daemon_request_application_delivery.json) and
[scoped quality gates](triage_evidence/daemon_request_application_quality_gates.json)
record the retained baseline and intended reporting/index changes.

QG1: factual analysis. QG2: RA1-RA8 with dependent results and probes.
QG3: continuous produced-request/application/token-extraction increment covered;
full goal active. QG4: byte extents,32/64-bit operations, counts and complexity
explicit. QG5: initialized fields, undefined padding/results, selected library
paths, native credentials and API stopping boundaries remain distinct.
QG6: primary daemon/cache bytes, exact export, three file hashes,157 original
fixup/import words, fresh independent execution and complete record oracles.
QG7: impact-bounded continuation table above.
