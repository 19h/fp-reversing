#!/usr/bin/env python3
"""Seal clock/value-lookup contracts and the three actual source frontiers.
O(owned artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_object_clock_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
from replay_daemon_descriptor_producers import unpack
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_object_clock_contracts.json','recover_daemon_object_clock.py'),('daemon_object_clock_context.json','capture_daemon_object_clock.py'),('daemon_object_clock_proofs.json','prove_daemon_object_clock.py'),('daemon_object_clock_profiles.json','probe_daemon_object_clock.py'),('daemon_object_clock_checks.json','validate_daemon_object_clock.py'),('daemon_object_clock_preservation.json','validate_daemon_object_clock_preservation.py')];c,ctx,p,r,k,keep=[checked(n,g)for n,g in pairs];assert k['all_checks_pass']and keep['all_checks_pass'];v=k['verified_counts']
 expected={'restored_parent_contexts':3,'parent_source_visits_reconstructed':6436959,'parent_effects_reconstructed':1512380,'original_source_spans':25,'distinct_original_opcodes':2488,'original_fixups':101,'exhaustive_bank_inputs':256,'live_IDB_ranges':7,'live_IDB_raw_bytes':848,'rebuilt_source_obligations_unsat':25,'SMT_files_unsat_and_formula_matched':50,'source_lift_visits':178,'persisted_A64_cases':96,'freshly_recomputed_A64_cases':96,'source_visits_checked':1843436,'ordered_source_reads_checked':348224,'ordered_source_writes_checked':89296,'clock_API_models_checked':192,'other_API_models_checked':192,'tail_field_stores_checked':288,'lock_creator_frontiers_checked':48,'matched_value_paths_checked':24,'empty_or_missing_value_paths_checked':24,'complete_twist_passes':128,'finite_twist_word_updates_checked':79872,'nonzero_sampler_bytes':432,'sampler_zero_retries':8,'sampler_readbacks_checked':440,'private_padding_reads':0}
 for n,x in expected.items():assert v[n]==x,(n,v[n],x)
 assert len(p['proofs'])==25 and len(list(ROOT.glob('daemon_object_clock_*.smt2')))==50
 assert c['new_object_publication_established']is False and c['new_port_emission_established']is False and c['SDK_compile']['exit_code']==0
 assert read('daemon_object_clock_ida_bytes.json')['isError']and not read('daemon_object_clock_ida_retry.json')['isError']and not read('daemon_object_clock_ida_more.json')['isError']
 api_shapes=clock_reads=0
 for row in r['cases']:
  t=unpack(row);F=int(t['entry_SP'],16);out=row['outcome'];fixtures=t['extension_fixtures'];aux=[int(x['address'],16)for x in fixtures if x['provenance']=='declared auxiliary state'];assert aux==sorted(aux)
  for m in t['API_models']:
   if m['binding']['symbol']=='_gettimeofday':
    s=m['sample'];assert m['writes']==[{'address':hex(F+0x3ca0),'bytes_hex':(s['seconds']&((1<<64)-1)).to_bytes(8,'little').hex()},{'address':hex(F+0x3ca8),'bytes_hex':(s['microseconds']&0xffffffff).to_bytes(4,'little').hex()}];assert int(m['returned_X0'],16)==((out['return_upper32']<<32)|(s['status32']&0xffffffff));api_shapes+=1
  reads=[e for e in t['events']if e['kind']=='read'and F+0x3ca0<=int(e['address'],16)<F+0x3cb0];assert reads==([{'kind':'read','pc':'0x100d2fa48','address':hex(F+0x3ca0),'size_bytes':4,'bytes_hex':(out['seconds']&0xffffffff).to_bytes(4,'little').hex()}]if out['status32']==0 else[]);clock_reads+=len(reads)
  assert not any(e['kind']=='read'and int(e['address'],16)==F+0x2a18 for e in t['events'])
 assert api_shapes==192 and clock_reads==72
 assert sha(ROOT/'daemon_object_clock_prior_manifest.json')==BASELINE_SHA;old=read('daemon_object_clock_prior_manifest.json');changed={x['path']:x for x in keep['allowed_existing_changes']};assert len(old['files'])==3766 and keep['unchanged_prior_artifacts']==3760 and set(changed)==ALLOWED and len(ALLOWED)==6
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 reports=['daemon_object_clock_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_object_clock_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['OC14','QG7','1,843,436','6,436,959','entry+8','entry+10','07F4','1010C6840','36-byte','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 scripts=list(ROOT.glob('*daemon_object_clock*.py'));assert len(scripts)==7
 for f in scripts:ast.parse(f.read_text(),filename=str(f))
 evidence=['Factual clock,record,lock,heap and callback interface analysis.','OC1-OC14 register source,restoration,frame,clock,opaque API,state,lock,registry,cache,PAC and scope premises with probes.','Clock/tail/callback/value lookup and separate36-byte cache request covered; full object lifetime and interface goal remain active.','u32/u64 equations,16/200/32/36/872-byte owners,seconds semantics,N:u32 scan bounds,software counts and complexity explicit.','Entry+8 value separated from+10 head;G andQ separated;cache publication is static;native lock success and872-byte publication unknown.','Original bytes/fixups,25 proof pairs,3 reconstructed contexts,96 freshly recomputed A64 cases,independent byte/state ledgers,SDK compile and848 IDB bytes verified.','Bounded caller/object/cache/record/state/port continuation questions retained with impact labels.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'source_sha256':sha(source),'source_lift_counts':p['source_lift_counts'],'prior_artifacts_checked':3766,'unchanged_prior_artifacts':3760,'checked_report_links':links,'new_python_files_syntax_checked':len(scripts),'clock_API_write_shapes_checked':api_shapes,'clock_seconds_reads_checked':clock_reads,'saved_main_port_slot_read_in_increment':False,'live_IDB_outputs':{n:sha(ROOT/n)for n in ['daemon_object_clock_ida_bytes.json','daemon_object_clock_ida_retry.json','daemon_object_clock_ida_more.json']},'inputs_preserved':old['inputs_preserved'],'new_object_publication_established':False,'new_port_emission_established':False,'cache_return_store_source_only':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_clock_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'proof_pairs':25,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
