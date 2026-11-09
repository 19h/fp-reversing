#!/usr/bin/env python3
"""Verify frozen prior artifacts and original inputs; no native target runs.
O(total artifact bytes) time,O(manifest bytes) space.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='ce58e16a69a415b2577bc91f668a57047fbb9e29f55af15ecf1ee5c7855741b2'
ALLOWED={'obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 p=ROOT/'daemon_entropy_return_prior_manifest.json';assert sha(p)==BASELINE_SHA;old=json.loads(p.read_text());assert len(old['files'])==2895;unchanged=0;changed=[]
 for r in old['files']:
  p=BASE/r['path'];h=sha(p)
  if h==r['sha256']:assert p.stat().st_size==r['size_bytes'];unchanged+=1
  else:assert r['path']in ALLOWED,r['path'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'current_sha256':h})
 assert unchanged==2889 and {r['path']for r in changed}==ALLOWED
 for r in old['inputs_preserved']:p=BASE/r['path'];assert sha(p)==r['sha256']and p.stat().st_size==r['size_bytes']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'baseline_manifest_sha256':BASELINE_SHA,'prior_artifacts_checked':2895,'unchanged_prior_artifacts':unchanged,'allowed_existing_changes':changed,'original_inputs_preserved':old['inputs_preserved'],'all_checks_pass':True,'full_goal_complete':False};(ROOT/'daemon_entropy_return_preservation.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':2895,'unchanged_prior_artifacts':unchanged,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
