#!/usr/bin/env python3
"""Source identity, preservation and scoped delivery checks for IOKit group work.

O(total pinned bytes + report links) time, O(largest JSON/source) space.
No native startup/registry/lock/resource operation or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='5ce15c18688390ff4ec2b86be393bebb556c807719cfde468c48fe83d000b6c2'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 baseline=ROOT/'iolib_group_prior_manifest.json';assert sha(baseline)==BASELINE_SHA;old=read(baseline.name);assert len(old['files'])==1463
 c=read('iolib_group_contracts.json');p=read('iolib_group_profiles.json');proof=read('iolib_group_proofs.json');checks=read('iolib_group_checks.json');fresh=read('iolib_group_replays.json');preserve=read('iolib_group_preservation.json')
 for obj,name in[(c,'recover_iolib_group.py'),(p,'probe_iolib_group.py'),(proof,'prove_iolib_group.py'),(checks,'validate_iolib_group.py'),(fresh,'validate_iolib_group.py'),(preserve,'validate_iolib_group_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'iolib_group_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases'];assert proof['contracts_sha256']==sha(ROOT/'iolib_group_contracts.json')
 for row in proof['proofs']:assert sha(ROOT/row['file'])==row['sha256']and row['result']=='unsat'
 expected={'kernel_functions':12,'original_data_spans':8,'census_words':2540432,'page_ADRP_candidates':1106,'bounded_references':86,'bounded_writers':1,'direct_startup_callers':1,'proofs_unsat':2,'fresh_initial_states':144,'fresh_source_stages':528,'source_visits':32432,'source_byte_checks':129728,'group_source_written_bytes':47232,'completed_cold_wrappers':128,'original_helper_name_bytes':864,'modeled_call_boundaries':512,'ordered_publication_sequences':128,'warm_repeats':128,'composed_RW_prefixes':256,'late_phase_stops':16};assert checks['verified_counts']==expected
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert k.function(int(f['start'],16))==f
 for d in c['data']:assert k.read(int(d['address'],16),len(bytes.fromhex(d['bytes_hex']))).hex()==d['bytes_hex']
 syms=k.symbols([int(a,16)for a in c['exact_symbols']]);assert syms==c['exact_symbols']
 for a,name in[(0xfffffe000c4b91a8,'_IOLibInit'),(0xfffffe000c47c364,'_OSlibkernInit'),(0xfffffe000bd03ec4,'_lck_mtx_alloc_init'),(0xfffffe000c4bb6e4,'_IORWLockAlloc'),(0xfffffe000c4bb780,'_IORWLockFree')]:assert name in[r['name']for r in syms[hex(a)]]
 for a in[0xfffffe000bd037e0,0xfffffe000bceb1d0,0xfffffe000bdc1800,0xfffffe000bddc5bc,0xfffffe000c4bcc70,0xfffffe000cb524a8,0xfffffe000cb52628]:assert not syms[hex(a)]
 identity={'scope':'Build-specific IOLibInit/static group construction and publication, modeled backend ABI, source ready commit and stopped RW API compositions.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'exact_symbols':syms,'original_data_spans':c['data'],'contracts_sha256':sha(ROOT/'iolib_group_contracts.json'),'native_target_executed':False,'native_startup_proved':False,'registry_backend_executed':False,'synchronization_executed':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'iolib_group_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1457
 for row in old['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['iolib_group_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'iolib_group_quality_gates.json',(name,target);links+=1
 report=(BASE/'iolib_group_report.md').read_text()
 for term in['GI9','QG7','144','528','32432','129728','47232','864','512','0xfffffe000ccceab8','unknown','328','1106','2540432','10161728','0xfffffe000cba36b0','0xfffffe000c4bcca8']:assert term in report,term
 evidence=['Factual technical source/interface analysis.','GI1-GI9 define assumptions, dependent results and falsification probes.','Current group construction/publication, startup order, modeled resource ABI, bounded census and RW prefixes covered; broader objective incomplete.','Fixed unsigned widths, byte epochs, finite counts and complexity are explicit.','Group/cached object, image/runtime, early/stopped phase and model/native effects distinguished.','Original source and exact symbols rechecked, 144 fresh cases, two local proofs and independently reconstructed writes.','Impact-labeled bounded continuation table.'];outputs=['iolib_group_contracts.json','iolib_group_profiles.json','iolib_group_replays.json','iolib_group_checks.json','iolib_group_proofs.json','iolib_group_preservation.json'];out={'scope':'Static group/source publication and conditional private compositions; native startup/registry/resource validity and cached FairPlay lock publication remain unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'prior_artifacts_checked':1463,'unchanged_prior_artifacts':1457,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'iolib_group_source_identity.json'),'native_target_executed':False,'native_startup_proved':False,'registry_backend_executed':False,'synchronization_executed':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'iolib_group_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_initial_states':144,'proofs_unsat':2,'prior_artifacts_checked':1463,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
