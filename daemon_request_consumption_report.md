# Exact kernel-produced requests at the daemon callback and MIG502 application boundary

The exact requests produced by the original kext/kernel constructor and receive
paths now enter the original daemon callback in a separate private CPU model.
RPC502 with the produced68-byte trailer reaches application entry0x100422d48
with the expected port/string/length/CPU/origin arguments and a copied32-byte
audit token. The produced8-byte trailer instead gives signed status-309 and
reaches request destruction. RPC700 returns from this callback without a
demultiplexer, reply allocation or application call. This tests local ABI
composition; the actual slot34/RPC700 receiver remains unknown. [DC1-DC8]

No framework call delivers these buffers in this increment. The cross-image
transfer preserves their exact bytes and virtual addresses, then explicitly
invokes the callback ABI in a new private address space. Native reception,
port-object identity, scheduling, PAC and successful FairPlay processing remain
unknown. The historical ZUT trace is unchanged and does not contain these
exchanges. The broad interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| DC1 | Pinned kernel and daemon bytes identify the intended corpus | Static addresses and local ABI composition | Rehash original images, reproduce source ranges and match a native build separately |
| DC2 | Earlier kernel private contexts and lower VM/copy/retirement contracts apply | Produced message, OOL and trailer contents | Freshly replay all eight delivery cases; replace contracts with native effects only when independently observed |
| DC3 | The delivered buffers are passed unchanged to the recovered callback | Cross-image local dispatch | Compare every transferred byte and original kernel final RAM; attest actual framework and effective callback/cache history separately |
| DC4 | The callback receives a fresh private stack and opaque CF object/context | Local inherited-register and stack execution | Replay the complete ordered read/write journal and CPU handoffs; test actual registration and framework ABI independently |
| DC5 | Logical original fixups/PAC stand in for loader/hardware behavior | Indirect control transfers and pointers | Recheck all34 accessed original chained words/imports; verify actual rebases and hardware authentication separately |
| DC6 | A384-byte private reply allocation succeeds; volatile registers are clobbered under the declared model | Four RPC502 paths after allocation | Check original allocation arguments, explicit clobber formula and all resulting source reads; native allocation success is unknown |
| DC7 | The29-byte NUL-terminated string and zero audit words are fixture values | Marshalled contents, including audit token | Compare OOL bytes and all32 copied audit bytes; do not infer a native file, PID, identity or authorization result |
| DC8 | Application entry, destruction entry and callback return are stopping boundaries | Bounded control/ownership conclusions | Require original callee/API execution for processing, deallocation or native reply emission claims; none occurs here |

## Provenance and exact transfer

Primary executable: [original daemon](</Users/___/Downloads/zut/fairplayd.arm64e>),
SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Primary kernel: [original kernel collection](</Users/___/Downloads/fpx/img4_dump/kernelcache.macho>),
SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
The daemon slice/container and earlier IDB associations are recorded separately
in [the ABI report](interface_abi_report.md). No new IDA query or mutation was
needed: the supplied/reference evidence and original images suffice here.

[Source capture](triage_evidence/daemon_request_consumption_source.json)
contains36 reviewed ranges /1287 instructions, including the complete MIG502
stub and the previously recovered callback continuations/demultiplexers. This
range count is not a count of complete functions. [Profiles](triage_evidence/daemon_request_consumption_profiles.json)
retain all ordered source/read/write journals and CPU frames.
[Independent checks](triage_evidence/daemon_request_consumption_checks.json)
recapture source, decode34 used original fixups, replay both components and
check separate packet/reply/argument oracles. The NDR pointer is an
unauthenticated format12 data bind; it is decoded explicitly rather than
treated as an authenticated branch pointer. [DC1,DC5]

Each of four original constructor/request producers supplies two previously
verified kernel delivery results, using receive capacities88 and148 bytes.
Their inline request size is80 bytes; the corresponding trailers are8 and68
bytes. USER=`0x6500001000`, OOL=`0x6500004000`. The daemon model imports the
complete8192-byte USER observation and16384-byte OOL observation, preserving
all payload and guard/padding bytes. It does not import kernel registers,
objects, address-space ownership or thread execution into userspace. [DC2,DC3]

```text
original kext constructor -> kernel RPC/queue -> original kernel copyout
                                                   |
                               exact USER/OOL bytes and addresses
                               explicit cross-image/framework premise
                                                   |
                                     daemon callback 0x100425f78
                                                   |
                   +-------------------------------+------------------+
                   |                                                  |
                ID502                                               ID700
                   |                                                  |
          demux 0x100005274                                   callback return
          stub  0x1000050c8                                no local dispatch
                   |
          +--------+--------------------+
          |                             |
     trailer8                      trailer68
     status-309                    copy audit32
     clear request.remote          marshal application ABI
     stop before destroy           stop at 0x100422d48
```

## Exact request and application ABI

All offsets and extents below are bytes; integer fields are little endian.
The request is complex with one OOL descriptor. [DC2,DC3]

| Request offset | Width | Delivered value |
| ---: | ---: | --- |
| 0 | 4 | Bits0x80001112 |
| 4 | 4 | Inline size80 |
| 8 | 4 | Reply send-once name0x207 |
| 12 | 4 | Service receive name0x303 for502,0x403 for700 |
| 16 | 4 | Voucher0 |
| 20 | 4 | Message ID502 or700 |
| 24 | 4 | Descriptor count1 |
| 28 | 8 | OOL pointer0x6500004000 |
| 36 | 4 | Descriptor flags/type0x01000101 |
| 40 | 4 | OOL extent29 |
| 44 | 8 | NDR bytes0000000001000000 |
| 52 | 4 | Repeated extent29 |
| 56 | 8 | CPU type0x0100000c |
| 64 | 8 | CPU subtype0 |
| 72 | 8 | Origin1 |
| 80 | 4 | Trailer type0 |
| 84 | 4 | Trailer size8 or68 |

At0x100005128, the stub compares the advertised trailer size with31 and
accepts the higher unsigned values on the type0 path. At0x1000051cc and
0x1000051d0 it reads two16-byte vectors at trailer+20 and+36, then copies
them to its own stack. The normal68-byte fixture contains all those bytes.
The8-byte fixture fails the size check before either vector load. These
observations do not characterize every other advertised size or malformed
trailer. [DC5,DC7,DC8]

| Application entry argument | Value in both extended RPC502 cases | Provenance |
| --- | --- | --- |
| W0 | 0x303 | Request local receive name+12 |
| X1 | 0x6500004000 | Request OOL pointer+28 |
| W2 | 29 | Descriptor extent+40 |
| X3 | 0x0100000c | Request+56 |
| X4 | 0 | Request+64 |
| X5 | 1 | Request+72 |
| X6 | 0x70077f30 | Stub-owned copy of request bytes100..131, all zero |
| X7 | Reply+0x44 | Output region in the384-byte allocation |
| SP+0 | Reply+0xcc | Additional output region |
| SP+8 | Reply+0x1c | First output descriptor address |
| SP+16 | Reply+0x178 | First output extent cell |
| SP+24 | Reply+0x2c | Second output descriptor address |
| SP+32 | Reply+0x17c | Second output extent cell |

The call instruction is0x1000051f8; the application entry is0x100422d48.
The string has28 deterministic nonzero ASCII bytes followed by NUL; no native
file is opened. The token is copied intact; zero audit words do not establish
the authenticated identity of a native sender. [DC7,DC8]

## Direction, reply preparation and ownership boundaries

| Producer / trailer | Cases | Daemon visits per case | Established terminal boundary |
| --- | ---: | ---: | --- |
| RPC502 fresh/prebound reply /8 | 2 | 462 | Before `_mach_msg_destroy(request)` |
| RPC502 fresh/prebound reply /68 | 2 | 331 | Before application execution |
| RPC700 fresh/prebound reply /8 or68 | 4 | 223 | Callback returned without allocation/demux |

For RPC502 the original demultiplexer initializes a36-byte simple reply:
bits18, destination0x207, local/voucher0 and ID602. On the minimal-trailer
path, the stub writes NDR and signed status-309. The callback then clears
request.remote at0x10006ce34 and reaches the destruction call at0x10006ce90.
The prepared reply still retains0x207. Execution stops at the imported
destruction API; no OOL/right disposal or reply emission executes. [DC6,DC8]

On the extended path, the stub initializes the two prospective output
descriptor flag words at reply+36 and+52 to0x01000101. Other output cells
retain their declared pre-call contents. No application-produced success
reply is inferred. The already recovered daemon send site0x100035184 remains
a separate downstream boundary; see [receive control and emission](daemon_receive_interface_report.md).
The kext request emission site remains0xfffffe000bcf5ba8. [DC6,DC8]

RPC700's exclusion here is conditional on invoking this shared callback.
It does not assign slot34 to fairplayd, establish slot34 contents or exclude
another server. [The bounded receiver inventory](rpc700_namespace_report.md)
still records the actual receiver as unknown. [DC1,DC3]

## Verification and bounded continuation

Fresh replay checks2478 original daemon instruction visits,474 reads /2768
bytes,212 writes /1568 bytes,38 complete CPU frames and eight final boundaries.
Complete private-RAM comparisons cover12582912 bytes across those cases.
Four explicit malloc contracts are checked; destruction and application
operations remain unexecuted. Eight freshly replayed kernel delivery cases
check20700 instruction visits and8388608 final RAM bytes. The exact imported
USER/OOL observations total196608 bytes; full final message/OOL/reply oracles
cover199680 bytes. These totals count repeated fixture observations, not
distinct native mapped memory. [DC2-DC8]

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_request_consumption.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_request_consumption.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_request_consumption.py
```

Extraction/replay costs O(B+V+J+F) time and O(B+R+J+F) space for original
image bytes B, instruction visits V, journal bytes J, fixups F and private RAM
R. This is finite source execution and explicit byte-oracle validation, not
an exhaustive proof of application semantics or native transport.

| Impact | Further opportunity / boundary | Falsifying or completing evidence |
| --- | --- | --- |
| High | Actual framework-to-callback transfer | Effective CF object/callback cache history and post-receive/post-voucher buffer bytes |
| High | Application handling of this exact request | Execute original application prefix with produced string/token; preserve all environmental/API boundaries |
| High | Alternate RPC700 receiver | Actual host slot34 publication/object identity and matching receiving implementation |
| Medium | Error-path disposal and reply emission | Original destroy/send implementation and concrete namespace/OOL effects under the produced error reply |
| Medium | Audit provenance and service identity | Native sender credential capture, receiving task namespace and registration history |
| Low | Provenance normalization detail | Retain unauthenticated data binds separately from authenticated control pointers in future source captures |

[Preservation](triage_evidence/daemon_request_consumption_delivery.json) and
[scoped quality gates](triage_evidence/daemon_request_consumption_quality_gates.json)
record retained artifacts and six reporting/index changes.

QG1: factual interface analysis. QG2: DC1-DC8 with dependent results and probes.
QG3: exact produced-buffer/callback/MIG/application-entry increment complete;
full goal active. QG4: byte units, finite counts, integer widths and complexity
explicit. QG5: RPC700 endpoint, normal trailers, prepared replies, ownership
and native observations remain distinct. QG6: pinned primary images, source
recapture,34 fixup checks, two independent execution journals and complete
byte oracles. QG7: impact-bounded continuation table above.
