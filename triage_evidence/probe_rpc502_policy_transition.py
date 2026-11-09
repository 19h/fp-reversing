#!/usr/bin/env python3
"""Original initialized-worker file-version/certificate-policy exploration.

Both file byte strings are explicit inputs set before any guest instruction.
The first file remains64 bytes;size/copy/knownness declarations stay aligned.
No internal record,PC,register,gate or arithmetic result is overridden.
No native target/filesystem/Mach/IOKit/loader/synchronization API execution.
O(B+V+E+S) bounded source work and journals.
"""
import hashlib
from pathlib import Path
from probe_rpc502_auth import AuthProbe,ROOT,SOURCE

class PolicyProbe(AuthProbe):
 def __init__(self,second_raw,fixture,first_raw):
  assert len(first_raw)==64
  super().__init__(second_raw,fixture)
  self.pattern=first_raw;self.declared_first_raw=first_raw
 def finish(self,r):
  r=super().finish(r);r.update(policy_scope=__doc__,policy_generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),declared_first_input_hex=self.declared_first_raw.hex());return r
