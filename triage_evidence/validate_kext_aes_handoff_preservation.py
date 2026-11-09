#!/usr/bin/env python3
"""Prior-artifact/input readback;writes only this increment's new record.

O(total prior artifact bytes) work,O(manifest bytes) retained space.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
ALLOWED={'obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
BASELINE_SHA='b4fd588a6ea50d10cf8a16e0af2745a19e8f1d2b37ec4f88c436fad246a76400'
def sha(path):
 h=hashlib.sha256()
 with path.open('rb')as stream:
  while chunk:=stream.read(1<<20):h.update(chunk)
 return h.hexdigest()
def main():
 source=ROOT/'kext_aes_handoff_prior_manifest.json';assert sha(source)==BASELINE_SHA;old=json.loads(source.read_text());assert len(old['files'])==1239;unchanged=[];changed=[]
 for row in old['files']:
  path=BASE/row['path'];same=path.stat().st_size==row['size_bytes']and sha(path)==row['sha256']
  if same:unchanged.append(row['path'])
  else:assert row['path']in ALLOWED,row['path'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'current_sha256':sha(path)})
 assert set(v['path']for v in changed)==ALLOWED
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert path.stat().st_size==row['size_bytes']and sha(path)==row['sha256']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'baseline_manifest_path':source.name,'baseline_manifest_sha256':BASELINE_SHA,'prior_artifacts_checked':len(old['files']),'unchanged_prior_artifacts':len(unchanged),'allowed_existing_changes':changed,'original_inputs_preserved':old['inputs_preserved'],'all_checks_pass':True,'full_goal_complete':False};(ROOT/'kext_aes_handoff_preservation.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:out[k]for k in ['prior_artifacts_checked','unchanged_prior_artifacts','all_checks_pass']}),flush=True)
if __name__=='__main__':main()
