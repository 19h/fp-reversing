#!/usr/bin/env python3
"""Hash every prior published artifact/input; only six indexes may change.

O(total artifact bytes) time, O(manifest entries) space. With an explicit prior
manifest argument,write this increment's ledger;without arguments verify the
retained ledger without mutations. No prior producer/API/target is executed.
"""
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
ALLOWED={'obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while chunk:=f.read(1<<20):h.update(chunk)
    return h.hexdigest()


def main():
    output=ROOT/'notify_ipc_preservation.json'
    if len(sys.argv)==2:
        prior_path=Path(sys.argv[1]);prior=json.loads(prior_path.read_text());baseline=prior['files'];inputs=prior['inputs_preserved'];prior_sha=sha(prior_path)
    else:
        retained=json.loads(output.read_text());baseline=retained['prior_manifest_entries'];inputs=retained['original_inputs_preserved'];prior_sha=retained['prior_manifest_sha256']
    unchanged=[];changed=[]
    for row in baseline:
        path=BASE/row['path'];h=sha(path);same=h==row['sha256'] and path.stat().st_size==row['size_bytes'];r={'path':row['path'],'prior_sha256':row['sha256'],'current_sha256':h,'unchanged':same}
        if row['path'] in ALLOWED:changed.append(r);assert not same,row['path']
        else:assert same,row['path'];unchanged.append(r)
    assert len(baseline)==847 and len(unchanged)==841 and {r['path'] for r in changed}==ALLOWED
    for row in inputs:
        path=BASE/row['path'];assert path.stat().st_size==row['size_bytes'] and sha(path)==row['sha256']
    result={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'prior_manifest_sha256':prior_sha,'prior_artifacts':len(baseline),'unchanged_prior_artifacts':len(unchanged),'prior_manifest_entries':baseline,'unchanged_prior_entries':unchanged,'allowed_changed_artifacts':changed,'original_inputs_preserved':inputs,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False}
    if len(sys.argv)==2:output.write_text(json.dumps(result,indent=2)+'\n')
    else:assert result==retained
    print(json.dumps({'prior':len(baseline),'unchanged':len(unchanged),'allowed_changes':len(changed),'original_inputs':len(inputs)}),flush=True)

if __name__=='__main__':main()
