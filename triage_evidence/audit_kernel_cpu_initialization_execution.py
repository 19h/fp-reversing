#!/usr/bin/env python3
"""Independent CPU/cache/context formulas, prefix relation and source controls.
Linear journals/pages/source work; inherited rescans may be quadratic.
Retained SMT obligations use a separate 30 s per-query budget.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_kernel_early_logging_execution import hydrate,publication_row
from replay_kernel_boot_cpu_identity import pages,get,put
from audit_kernel_early_logging_contract import source_proofs as logging_proofs
import recover_kernel_cpu_initialization_execution as R
import probe_kernel_cpu_initialization_execution as CPU
from replay_kernel_cpu_initialization_execution import Replay
P=0x6500000000;SIZE=1048576;MASK=(1<<32)-1
def memory_at(row,visit,im):
 m=pages(row['initial_image_pages'])
 for a in range(P,P+SIZE,4096):m[a]=bytearray(4096)
 for r in row['initial_private_fixtures']:
  raw=bytes.fromhex(r['bytes_hex']);put(m,int(r['address'],16),len(raw),raw)
 for w in row['source_writes']:
  if w['source_visit_index']>=visit:break
  a=int(w['address'],16);put(m,a,w['size_bytes'],bytes.fromhex(w['after_hex']))
 return m
def oracle(row,e,im):
 lo=row['CPU_entry_checkpoint']['before_visit'];m=memory_at(row,lo,im);checks=[];expected=[]
 def u(a,n):return int.from_bytes(get(m,a,n),'little')
 def w(a,n,v):put(m,a,n,int(v&((1<<(n*8))-1)).to_bytes(n,'little'))
 def ok(label,p):assert p,('CPU_initializer_contract',label);checks.append(label)
 profile=row['architectural_input_profile'];regs=profile['registers'];cpu=R.CPU;thread=row['CPU_entry_checkpoint']['system']['tpidr_el1'];cache=0xfffffe000cb8a810;stat=0xfffffe000cab3218
 ok('declared_profile_exact_no_native_attestation',profile==R.PROFILE and not profile['native_values_attested'])
 ok('bootstrap_source_ownership',u(thread+0x1c0,8)==cpu and u(cpu,2)==0 and u(cpu+4,4)!=0x0100000c)
 ok('uncontended_empty_context_debug_and_statistics_premises',u(0xfffffe000cb87968,8)==0 and u(0xfffffe000cb87998,4)==0 and u(0xfffffe000cb11544,12)==0 and u(0xfffffe000cb0bce0,8)==0 and u(thread+0x1c8,4)==0 and not u(cpu+0x4c,1)&4 and not u(stat-4,4)&0x80000000)
 count=u(0xfffffe0007ef8bec,4);array=u(0xfffffe0007ef8c08,8);hits=[j for j in range(count) if u(array+136*j+4,4)==(regs['mpidr_el1']&0xffff)]
 ok('MPIDR_matches_original_startup_record',hits==[0] and u(array+20,4)==0 and u(0xfffffe000cb8a808,1)==0)
 w(cpu+4,4,0x0100000c);w(cpu+0x118,8,cpu+0x118);w(cpu+0x120,8,cpu+0x118);w(cpu+0x140,8,u(0xfffffe000700dc58,8));w(cpu+0x128,8,0);w(cpu+0x148,8,0x144);w(cpu+0x150,8,(1<<64)-1)
 midr=(regs['midr_el1']&0xfff0ffff)|0xd0000;w(0xfffffe0007ef81c8,4,midr)
 for j in range(3):w(0xfffffe000cb8ab70+4*j,4,1)
 w(0xfffffe000cb8a808,1,1);w(cache+0x30,8,regs['clidr_el1']&MASK)
 for j in range(7):w(cache+0x38+8*j,8,0);w(cache+0x70+8*j,8,0)
 ccsidr=profile['CCSIDR_by_CSSELR']['0'];w(cache+0x70,8,ccsidr);w(0xfffffe0007ef81d0,8,cache)
 ok('unified_L1_only_declared_profile',regs['clidr_el1']==4 and set(profile['CCSIDR_by_CSSELR'])=={'0'} and regs['id_aa64dfr0_el1']==0 and regs['daif']==0x3c0)
 line=16<<(ccsidr&7);ways=((ccsidr>>3)&0x3ff)+1;sets=((ccsidr>>13)&0x7fff)+1;capacity=(line*ways*sets)&MASK;policy_index=((ccsidr>>28)-1)&MASK;policy=u(0xfffffe00070139fc+4*policy_index,4) if policy_index<=7 else 4
 for off,value in [(0,1),(4,1),(8,capacity),(0x10,capacity),(0x18,policy),(0x1c,line),(0x20,ways),(0x24,0),(0x28,capacity),(0x2c,capacity)]:w(cache+off,4,value)
 capability=u(0xfffffe00070135c8+4*(((midr>>16)&15)-12),4);w(cpu+8,4,capability);w(cpu+12,4,0)
 before_stat=u(stat,4)
 for j in range(10):w(cpu+0x358+144*j,8,0);w(cpu+0x360+144*j,8,0x11)
 w(stat,4,before_stat+10)
 for off in [0x890,0x8a0,0x8b0]:w(cpu+off,8,0)
 w(cpu+0x69,1,1);w(cpu+0x1e0,4,u(cpu+0x1dc,4));w(cpu+0x1dc,4,0)
 sys={**row['CPU_entry_checkpoint']['system'],'csselr_el1':0}
 indices=[0,1,2,3,4,5,6,7,9,10]
 for j,k in enumerate(indices):name='s3_2_c15_c'+str(k)+'_0';sys[name]=u(cpu+0x240+16*j,8);expected.append({'register':name,'value':hex(sys[name])})
 context=0xfffffe0007013bf8;ok('literal_default_context_flags_clear',not u(context+0xd0,1)&1 and not u(context+0xd1,1)&1)
 a=u(context,8)&0xffffffffbffffeff;b=u(context+8,8)&0x3000003ff00
 for name,value in [('s3_1_c15_c1_0',b),('s3_1_c15_c7_2',b),('s3_1_c15_c0_0',a)]:sys[name]=value;expected.append({'register':name,'value':hex(value)})
 for k in indices[2:]:name='s3_2_c15_c'+str(k)+'_0';sys[name]=0;expected.append({'register':name,'value':'0x0'})
 for off in range(0x258,0x2d8,8):w(cpu+off,8,0)
 end=row['CPU_return_checkpoint'];ok('complete_CPU_return_boundary',end is not None and end['PC']==hex(R.STOP) and row['boundary']['pc']==hex(R.STOP) and row['CPU_frontier'] is None)
 for group in ['image_globals','additional_image_globals','registry_image_globals','phase_one_image_globals','CPU_initializer_image_globals']:
  for r in end.get(group,[]):
   a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex'])
   if any(lo<=a and a+len(raw)<=lo+n for lo,n in R.REGIONS):ok('whole_declared_output_'+hex(a),get(m,a,len(raw))==raw)
 # Reconstruct final regions from journal writes for comparison with the
 # independent host formula; no output-byte seed is used.
 actual_m=memory_at(row,len(row['source_visits']),im)
 for a,n in R.REGIONS:ok('whole_output_region_'+hex(a),get(actual_m,a,n)==get(m,a,n))
 events=[v for v in row['logical_effects'] if v['before_visit']>=lo and v['kind']=='msr' and v['operands'].startswith('s3_')];actual=[{'register':v['operands'].split(', ')[0],'value':hex(v['system_after'][v['operands'].split(', ')[0]])} for v in events]
 ok('all_21_context_register_writes_order_and_values',actual==expected);ok('complete_logical_system_formula',row['final_system']==sys)
 ok('CPU_call_return_order_and_original_frame',sorted(v['entry_index'] for v in row['original_CPU_returns'])==list(range(8)) and not row['unfinished_CPU_entry_indices'] and end['SP']==row['CPU_entry_checkpoint']['SP'] and end['registers31'][19:30]==row['CPU_entry_checkpoint']['registers31'][19:30])
 ok('two_uncontended_lock_calls',[r['arguments6'][0] for r in row['original_CPU_entries'] if r['PC']==hex(R.LOCK)]==[hex(0xfffffe000cb0bce0),hex(cpu+0x358)])
 ok('two_inherited_models_only',len(row['API_models'])==2 and all(m['before_source_visit_index']<lo for m in row['API_models']))
 old=json.loads(read(ROOT/(R.B.P+'_audit.json')))['component'];oldchars=bytes(v['character_u32'] for v in old['original_character_calls']);chars=bytes(v['character_u32'] for v in row['original_character_calls']);message=f'[  203.613264]: do_cacheid() - {2*capacity} bytes Unknown cache (I:{capacity} D:{capacity} (unified)), {ways}-way assoc, {line} bytes/line\n'.encode('ascii');ok('source_cache_logging_stream_and_inherited_prefix',chars==oldchars+message)
 atomics=[v for v in row['source_writes'] if v['source_visit_index']>=lo and v['address']==hex(stat)];ok('ten_atomic_statistics_stores',len(atomics)==10 and [int.from_bytes(bytes.fromhex(v['after_hex']),'little') for v in atomics]==[(before_stat+j)&MASK for j in range(1,11)])
 return {'checks':checks,'entry_visit':lo,'return_visit':len(row['source_visits']),'added_source_visits':len(row['source_visits'])-lo,'cache_class':0,'cache_descriptor':hex(cache),'cache_descriptor_bytes':168,'line_bytes':line,'ways':ways,'sets':sets,'capacity_bytes':capacity,'source_diagnostic_aggregate_bytes':2*capacity,'policy_code':policy,'context_records':10,'context_stride_bytes':144,'statistics_u32_before':before_stat,'statistics_u32_after':(before_stat+10)&MASK,'context_register_writes':expected,'complete_output_region_bytes':sum(n for _,n in R.REGIONS),'new_character_bytes':len(message),'new_character_text':message.decode(),'MIDR_global_u32':hex(midr),'capability_u32':capability,'architectural_register_reads':len(row['architectural_register_reads'])}
def preservation(row,im):
 old=hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['component'],im);lo=row['CPU_entry_checkpoint']['before_visit'];assert lo==len(old['source_visits'])==821831 and row['source_visits'][:lo]==old['source_visits']
 for key in ['source_reads','source_writes']:assert [v for v in row[key] if v['source_visit_index']<lo]==old[key]
 for key in ['API_models','initial_private_RAM','initial_private_fixtures','initial_image_fixtures']:assert row[key]==old[key]
 extra=R.PROFILE['registers']
 def strip(event):
  return {k:({a:b for a,b in v.items() if a not in extra} if k in ['system_before','system_after'] else v) for k,v in event.items()}
 assert [strip(v) for v in row['logical_effects'] if v['before_visit']<lo]==old['logical_effects']
 c=row['CPU_entry_checkpoint'];assert c['private_RAM']==old['final_private_RAM'] and c['vectors']==old['final_vectors'] and {k:v for k,v in c['system'].items() if k not in extra}==old['final_system']
 for key in ['SP','NZCV','registers31']:assert c[key]==old['boundary'][key]
 for p,h in old['final_page_sha256'].items():assert c['mapped_page_sha256'][p]==h
 for p in c['mapped_page_sha256'].keys()-old['final_page_sha256'].keys():assert c['mapped_page_sha256'][p]==sha256(im.logical_page(int(p,16))).hexdigest()
 for key in ['callback_entries','callback_returns','original_image_lookup_entries','original_image_lookup_returns','original_character_calls','original_logging_entries','original_logging_returns']:
  assert [v for v in row[key] if v['before_visit']<lo]==old[key]
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'exact_prefix_visits':lo,'all_prefix_reads_writes_exact':True,'initial_RAM_and_all_fixture_records_exact':True,'GPR_SP_NZCV_vectors_private_RAM_at_previous_frontier_exact':True,'all_prior_page_hashes_at_previous_frontier_exact':len(old['final_page_sha256']),'additional_unchanged_original_pages_at_previous_frontier':len(c['mapped_page_sha256'])-len(old['final_page_sha256']),'logical_effects_equal_after_removing_only_declared_register_keys':sorted(extra),'all_prior_callback_lookup_logging_journals_preserved':True,'API_models_exact_and_unchanged':2}
def audit(cached=None):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=logging_proofs(e);im=R.B.B.BootImage();row=hydrate(cached,im) if cached else CPU.Probe(im).run();contract=oracle(row,e,im);kept=preservation(row,im);replay=Replay(im,row).run();negative=[]
 for label,pc in [('omit_cache_capacity_store',0xfffffe000be79e94),('omit_context_state_store',0xfffffe000be95524),('omit_default_register_install',0xfffffe000be94f90)]:
  p=CPU.Probe(im,pc)
  for page in row['initial_image_pages']:p.ensure(int(page['address'],16),4096)
  q=p.run();keys=['configuration','entry_PC','entry_SP','entry_NZCV','entry_registers31','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages','initial_system','architectural_input_profile'];assert all(q[k]==row[k] for k in keys)
  try:oracle(q,e,im)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_CPU_source_accepted',label))
  assert q['boundary']['pc']==hex(R.STOP);negative.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','all_initial_fields_match':True,'same_initial_fields':keys,'CPU_return_reached':True,'source_visits':len(q['source_visits']),'oracle_rejection':rejection,'journal_sha256':sha256(json.dumps({k:q[k] for k in ['source_visits','source_reads','source_writes','logical_effects']},sort_keys=True,separators=(',',':')).encode()).hexdigest()});print('rejected',label,flush=True)
 totals={'components':1,'source_visits':len(row['source_visits']),'added_original_CPU_visits':contract['added_source_visits'],'preserved_prefix_visits':kept['exact_prefix_visits'],'source_reads':len(row['source_reads']),'source_writes':len(row['source_writes']),'retained_logging_queries_rebuilt':len(proofs),'semantic_checks':len(contract['checks']),'mapped_pages':len(row['final_page_sha256']),'remaining_API_models':len(row['API_models']),'new_API_models':0,'CPU_helper_entries_and_returns':len(row['original_CPU_returns']),'context_records':10,'context_register_writes':21,'original_registry_callbacks_returned':len(row['callback_returns']),'character_callbacks':len(row['original_character_calls']),'source_controls':len(negative),'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_cpu_initialization_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'retained_logging_proofs':proofs,'retained_logging_coverage':coverage,'component':publication_row(row,im),'independent_CPU_oracle':contract,'prior_prefix_comparison':kept,'negative_source_controls':negative,'independent_totals':totals,'independent_replay_totals':replay,'native_target_executed':False,'hardware_PAC_executed':False,'native_register_values_attested':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
