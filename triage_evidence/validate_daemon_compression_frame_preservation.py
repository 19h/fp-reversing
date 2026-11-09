#!/usr/bin/env python3
"""Verify prior owned artifacts and original inputs without target execution.
O(total artifact bytes) time, O(manifest bytes) space.
"""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='8434062c97fe04cbe608bdd50392584fe4f27bd252c11e548161f21f2fe86376'
ALLOWED={'obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1048576):h.update(b)
 return h.hexdigest()
def main():
 p=ROOT/'daemon_compression_frame_prior_manifest.json';assert sha(p)==BASELINE_SHA;old=json.loads(p.read_text());assert len(old['files'])==4009;unchanged=0;changes=[]
 for r in old['files']:
  p=BASE/r['path'];h=sha(p)
  if h==r['sha256']:assert p.stat().st_size==r['size_bytes'];unchanged+=1
  else:assert r['path']in ALLOWED,r['path'];changes.append({'path':r['path'],'prior_sha256':r['sha256'],'current_sha256':h})
 assert unchanged==4003 and {r['path']for r in changes}==ALLOWED
 for r in old['inputs_preserved']:p=BASE/r['path'];assert p.stat().st_size==r['size_bytes']and sha(p)==r['sha256']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'baseline_manifest_sha256':BASELINE_SHA,'prior_artifacts_checked':4009,'unchanged_prior_artifacts':unchanged,'allowed_existing_changes':changes,'original_inputs_preserved':old['inputs_preserved'],'all_checks_pass':True,'full_goal_complete':False};(ROOT/'daemon_compression_frame_preservation.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4009,'unchanged_prior_artifacts':unchanged,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
