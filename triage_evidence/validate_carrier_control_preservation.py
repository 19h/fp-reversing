#!/usr/bin/env python3
"""Hash every preceding artifact and original input; write only a new record.

O(total preceding bytes) time, O(manifest bytes) retained space.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='444f98e76a7fc72292ecd1c7a09b2a87e3e3426c92de4dd3ea7276b926890276'
ALLOWED={'obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 source=ROOT/'carrier_control_prior_manifest.json';assert sha(source)==BASELINE_SHA;old=json.loads(source.read_text());assert len(old['files'])==1390;unchanged=[];changed=[]
 for row in old['files']:
  p=BASE/row['path'];same=p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
  if same:unchanged.append(row['path'])
  else:assert row['path']in ALLOWED,row['path'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'current_sha256':sha(p)})
 assert {r['path']for r in changed}==ALLOWED and len(unchanged)==1384
 for row in old['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'baseline_manifest_path':source.name,'baseline_manifest_sha256':BASELINE_SHA,'prior_artifacts_checked':1390,'unchanged_prior_artifacts':1384,'allowed_existing_changes':changed,'original_inputs_preserved':old['inputs_preserved'],'all_checks_pass':True,'full_goal_complete':False};(ROOT/'carrier_control_preservation.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':1390,'unchanged_prior_artifacts':1384,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
