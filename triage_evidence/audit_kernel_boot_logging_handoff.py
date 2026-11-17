#!/usr/bin/env python3
"""Boot-state custody, logging/range source relations and complete case audit.
Linear source/journal/page/symbol work; timeline sort O(J log J) in retained
contracts. SMT search separate, 30 s/query. No native target effects.
"""
import json,struct
from collections import defaultdict
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_fixup_projection import Model as Parent
from audit_kernel_mapping_context import DEC
from audit_kernel_early_logging_contract import source_proofs as prior_proofs
from replay_kernel_early_logging_execution import hydrate,publication_row,prior_row
import replay_kernel_longterm_bootstrap_execution as TIMER
from replay_kernel_boot_cpu_identity import pages,get,put
from probe_rpc502_vm_handoff import decode
from lskd_values_symbolic import resize
import recover_kernel_boot_logging_handoff as R
import probe_kernel_boot_logging_handoff as CPU
from replay_kernel_boot_logging_handoff import Replay

class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='sbfx':
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1;o=i.operands;value=self.read(i.reg_name(o[1].reg));lsb,width=o[2].imm,o[3].imm;self.write(i.reg_name(o[0].reg),z3.SignExt(value.size()-width,z3.Extract(lsb+width-1,lsb,value)));continue
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
  return self

def source_proofs(e):
 retained,retained_coverage=prior_proofs(e);proofs=[];coverage=[];B=0x6c00000000
 def fresh():v=Model(e);v.regions=[(B,4096),(0xfffffe0007e6d000,4096),(0xfffffe000cba2000,4096),(0xfffffe000cb51000,4096)];return v
 def cut(v,a,b,linked=False):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.run('cut') if linked else v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count});print('proved',label,flush=True)
 address,base,length=z3.BitVecs('BH_address64 BH_base64 BH_length64',64);field=z3.BitVec('BH_filetype32',32)
 v=fresh();v.seed('x8',B);v.setmem(B+12,4,field);cut(v,0xfffffe000c48fc98,0xfffffe000c48fca4);prove('header_filetype12_enters_image_lookup_arm',v,v.next!=z3.If(field==12,resize(0xfffffe000c48fca4,64),resize(0xfffffe000c48fd48,64)))
 v=fresh();v.seed('x0',address);cut(v,0xfffffe000c478d34,0xfffffe000c478d3c);canonical=(z3.If(address&(1<<55)!=0,resize((1<<64)-1,64),resize(0,64))&~((1<<47)-1))|(address&((1<<47)-1));prove('lookup_sign55_and_low47_canonicalization',v,v.read('x19')!=canonical)
 v=fresh();v.seed('x0',address);cut(v,0xfffffe000c478d1c,0xfffffe000c478d20);prove('null_lookup_argument_bypasses_frame',v,v.next!=z3.If(address==0,resize(0xfffffe000c478f7c,64),resize(0xfffffe000c478d20,64)))
 count=z3.BitVec('BH_count32',32);v=fresh();v.setmem(0xfffffe000cba2638,4,count);cut(v,0xfffffe000c478d3c,0xfffffe000c478d48);prove('zero_interval_count_skips_table_lock_and_search',v,v.next!=z3.If(count==0,resize(0xfffffe000c478e04,64),resize(0xfffffe000c478d48,64)))
 v=fresh();v.setmem(0xfffffe000cb51b00,8,base);cut(v,0xfffffe000c478e7c,0xfffffe000c478e88);prove('null_fallback_registry_selects_zero_result',v,v.next!=z3.If(base==0,resize(0xfffffe000c478f68,64),resize(0xfffffe000c478e88,64)))
 v=fresh();cut(v,0xfffffe000c478f68,0xfffffe000c478f6c);prove('miss_result_is_zero',v,v.read('x0')!=0)
 for tag,start,lo,hi in [('first',0xfffffe000be763b8,*R.PAIRS[0]),('second',0xfffffe000be763e4,*R.PAIRS[1])]:
  target=0xfffffe000be763e4 if tag=='first' else 0xfffffe000be76410;v=fresh();v.seed('x0',address);v.setmem(lo,8,base);cut(v,start,start+16);prove(tag+'_range_lower_gate_is_unsigned',v,v.next!=z3.If(z3.UGT(base,address),resize(target,64),resize(start+16,64)))
  v=fresh();v.seed('x0',address);v.seed('x8',base);v.setmem(hi,8,length);cut(v,start+16,start+36);prove(tag+'_range_end_gate_uses_modular_base_plus_length',v,v.next!=z3.If(z3.UGE(address,base+length),resize(target,64),resize(start+36,64)))
 v=fresh();v.seed('x0',address);v.setmem(R.PAIRS[2][0],8,base);v.setmem(R.PAIRS[2][1],8,length);cut(v,0xfffffe000be76410,0xfffffe000be76430);prove('third_range_returns_halfopen_unsigned_membership',v,v.read('w0')!=z3.If(z3.And(z3.ULE(base,address),z3.ULT(address,base+length)),resize(1,32),resize(0,32)))
 end=z3.BitVec('BH_end64',64);v=fresh();v.seed('x13',B);v.seed('x19',address);v.setmem(B,8,base);v.setmem(B+8,8,end);cut(v,0xfffffe000c478db0,0xfffffe000c478dc8);prove('24B_table_candidate_uses_halfopen_interval',v,v.next!=0xfffffe000c478dc8,[z3.UGE(address,base),z3.ULT(address,end)])
 v=fresh();v.seed('x13',B);v.setmem(B+16,8,B+128);v.setmem(B+128+32,8,B+256);v.setmem(B+256+80,8,base);cut(v,0xfffffe000c478dc8,0xfffffe000c478de0);prove('candidate_object_chain_checks_plus16_plus32_plus80',v,z3.Or(v.read('x20')!=B+256,v.read('x8')!=base,v.next!=0xfffffe000c478de0),[base!=0])
 for pc in [0xfffffe000c5e73e0,0xfffffe000c5e73ec]:
  flag=z3.BitVec('BH_console_flag32',32);v=fresh();v.seed('w9',flag);cut(v,pc,pc+4);prove('console_flag_bit0_gate_'+hex(pc),v,v.next!=z3.If(flag&1!=0,resize(0xfffffe000c5e74d0,64),resize(pc+4,64)))
 return proofs,coverage,retained,retained_coverage

def legacy_image(im):
 old=Image.__new__(Image);old.__dict__.update(im.__dict__);old.pages=defaultdict(list,im.pages);return old

def preservation(row,im):
 old=hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0],legacy_image(im));c=row['configuration_consumer_checkpoint'];end=c['before_visit'];assert end==len(old['source_visits'])==510723 and row['source_visits'][:end]==old['source_visits'];old_reads=old['source_reads'];new_reads=[r for r in row['source_reads'] if r['source_visit_index']<end];assert len(old_reads)==len(new_reads);deltas=[]
 for a,b in zip(old_reads,new_reads):
  if a!=b:
   x,y=dict(a),dict(b);before,after=x.pop('bytes_hex'),y.pop('bytes_hex');assert x==y and x['pc'] in ['0xfffffe000c639a94','0xfffffe000c48fc90'] and x['address']=='0xfffffe0007f8b528' and before=='a5'*8 and after==im.globals[0xfffffe0007f8b528].to_bytes(8,'little').hex();deltas.append({'event':x,'before_hex':before,'after_hex':after})
 assert len(deltas)==2 and [w for w in row['source_writes'] if w['source_visit_index']<end]==old['source_writes'] and c['private_RAM']==old['final_private_RAM']
 for j,(a,b) in enumerate(zip(old['boundary']['registers31'],c['registers31'])):assert a==b if j!=8 else a=='0xa5a5a5a5a5a5a5a5' and b==hex(im.globals[0xfffffe0007f8b528])
 assert old['boundary']['SP']==c['SP'] and old['boundary']['NZCV']==c['NZCV'] and old['final_vectors']==c['vectors'] and old['final_system']==c['system']
 assert old['initial_private_RAM']==row['initial_private_RAM'] and old['initial_private_fixtures']==row['initial_private_fixtures'] and old['initial_image_fixtures']==row['initial_image_fixtures'][:-9]
 assert row['initial_image_fixtures'][-9]['address']=='0xfffffe000ca921c8' and bytes.fromhex(row['initial_image_fixtures'][-9]['bytes_hex'])==im.k.read(0xfffffe000ca921c8,16)
 memory=pages(row['initial_image_pages'])
 for w in row['source_writes']:
  if w['source_visit_index']<end and not TIMER.P<=int(w['address'],16)<TIMER.P+1048576:put(memory,int(w['address'],16),w['size_bytes'],bytes.fromhex(w['after_hex']))
 for pg,h in c['mapped_page_sha256'].items():assert sha256(memory[int(pg,16)]).hexdigest()==h
 for a in im.globals:put(memory,a,8,bytes([0xa5])*8)
 assert old['final_page_sha256'].keys()<=c['mapped_page_sha256'].keys()
 for pg,h in old['final_page_sha256'].items():assert sha256(memory[int(pg,16)]).hexdigest()==h
 model_deltas=[]
 for j,(a,b) in enumerate(zip(old['API_models'],row['API_models'])):
  if a!=b:
   x,y=dict(a),dict(b);left,right=x.pop('arguments8'),y.pop('arguments8');assert x==y and x['pc']=='0xfffffe000c47cce0' and left[1:]==right[1:] and left[0]=='0xa5a5a5a5a5a5a5a5' and right[0]=='0xfffffe0007004000';model_deltas.append({'model_index':j,'PC':x['pc'],'argument_index':0,'prior_value':left[0],'boot_value':right[0],'result_and_no_RAM_premise_unchanged':True})
 assert len(row['API_models'])==len(old['API_models'])==3 and len(model_deltas)==1 and row['callback_entries']==old['callback_entries'] and row['callback_returns']==old['callback_returns']
 for key,field in [('logical_effects','before_visit'),('original_API_entries','before_visit'),('original_API_returns','before_visit'),('original_call_entries','source_visit_index')]:assert [v for v in row[key] if v[field]<end]==old[key]
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'identical_source_prefix_visits':end,'read_value_deltas':deltas,'retained_model_input_deltas':model_deltas,'source_writes_private_RAM_system_vectors_preserved':True,'only_boundary_GPR_delta':'X8','boot_word_domain_bytes':64,'all_old_mapped_pages_match_after_declared_boot_word_mask':True,'unchanged_prior_fixture_records':len(old['initial_image_fixtures']),'additional_initial_fixture_records':9,'additional_timer_destination_bytes':16,'original_callbacks_preserved':1029,'new_API_result_models':0}

def oracle(row,e,im):
 checks=[]
 def ok(label,p):assert p,('boot_logging_contract',label);checks.append(label)
 ok('exact_boot_word_precedence',[(r['address'],r['boot_bytes_hex']) for r in row['boot_word_initial_precedence']]==[(hex(a),v.to_bytes(8,'little').hex()) for a,v in im.globals.items()] and all(r['prior_fixture_bytes_hex']=='a5'*8 for r in row['boot_word_initial_precedence']))
 prior=TIMER.oracle(prior_row(row),json.loads(read(ROOT/(R.B.B.P+'_checks.json'))));c=row['logging_join_checkpoints'][0];memory=pages(row['initial_image_pages'])
 for key,values in c.items():
  if key=='image_globals' or key.endswith('_image_globals'):
   for r in values:raw=bytes.fromhex(r['bytes_hex']);put(memory,int(r['address'],16),len(raw),raw)
 def u(a,n):return int.from_bytes(get(memory,a,n),'little')
 def w(a,n,v):put(memory,a,n,v&((1<<(8*n))-1))
 calls=row['original_image_lookup_entries'];returns=row['original_image_lookup_returns'];ok('original_image_queries_return_zero',len(calls)==3 and [r['X0'] for r in returns]==['0x0']*3 and not row['unfinished_image_lookup_entry_indices'])
 ok('two_format_address_lookups_and_one_caller_range_check',[r['PC'] for r in calls]==[hex(R.LOOKUP),hex(R.CONTAINS),hex(R.LOOKUP)] and [r['arguments2'][0] for r in calls]==['0xfffffe0007052b8b','0xfffffe000bd64f70','0xfffffe0007052b8b'])
 range_values=[{'base_slot':hex(a),'length_slot':hex(b),'base_u64':hex(u(a,8)),'length_u64':hex(u(b,8))} for a,b in R.PAIRS];ok('six_range_words_remain_declared_poison',all(u(a,8)==u(b,8)==0xa5a5a5a5a5a5a5a5 for a,b in R.PAIRS));ok('empty_original_lookup_registries',u(0xfffffe000cba2638,4)==0 and u(0xfffffe000cb51b00,8)==0)
 header_reads=[r for r in row['source_reads'] if r['pc']=='0xfffffe000c48fc98'];ok('two_actual_root_header_filetype_reads',len(header_reads)==2 and all(r['address']=='0xfffffe000700400c' and r['size_bytes']==4 and r['bytes_hex']=='0c000000' for r in header_reads))
 ok('two_proved_joins_without_DAIF',len(row['proved_logging_joins'])==len(row['logging_join_checkpoints'])==2 and all(r['phase_u32']==3 and not r['DAIF_value_supplied'] for r in row['proved_logging_joins']) and 'daif' not in row['final_system'])
 clock=u(0xfffffe000ca8c000,4);micro=u(0xfffffe000ca8c004,4);expected=b''
 for cut in row['logging_join_checkpoints']:
  stamp=int(cut['registers31'][21],16);expected+=(f'[{stamp//clock:5d}.{(stamp%clock)//micro:06d}]: Longterm timer threshold: 1 ms\n').encode()
 ok('two_independent_timestamp_message_strings',bytes(r['character_u32'] for r in row['original_character_calls'])==expected and len(expected)==94)
 lock=0xfffffe000cad0108;ring=0xfffffe000cb2fe28;header=0xfffffe000caa3070;thread=row['final_system']['tpidr_el1'];w(lock+8,4,0x02020144);w(lock+12,4,0);w(thread+0x1c8,4,0);w(header+8,4,len(expected));put(memory,ring,len(expected),expected);w(0xfffffe000caab110,1,1)
 for a,n in [(0xfffffe000cbe9ec0,2),(0xfffffe000cbe9eb0,2),(0xfffffe000cbe9e58,1)]:w(a,8,u(a,8)+n)
 # The remainder of the original timer initializer has the same documented
 # initialized outputs as its published disabled case, plus nonzero threshold.
 f=clock
 def ticks(v):return ((v//1000000000)*f+((v%1000000000)*f)//1000000000)&((1<<64)-1)
 base=0xfffffe000ca920a8;w(0xfffffe000ca92100,8,ticks(1000000));w(0xfffffe000ca92108,8,ticks(1000000)//10);put(memory,0xfffffe000ca921c8,16,im.k.read(0xfffffe000700eb10,16))
 for off,n,value in [(0,8,base),(8,8,base),(0x10,8,0),(0x28,8,0x44000000),(0x30,8,0x144)]:w(base+off,n,value)
 for off,n in [(0x68,16),(0x88,16),(0x98,16),(0xa8,16),(0xb8,16),(0xc8,16),(0xe8,16),(0xf8,16)]:put(memory,base+off,n,bytes([255])*n if off==0x68 else bytes(n))
 for a,n,v in [(base+0x90,8,0),(base+0x98,8,0x11),(base+0xd8,8,TIMER.R.CALLBACK),(base+0xe0,8,base),(0xfffffe000cb7d0b8,8,base),(0xfffffe000cadd708,8,f//100000)]:w(a,n,v)
 src=0xfffffe000ca93e08;dst=0xfffffe000cb2a4b4
 for off in [0,4,8]:w(dst+off,4,ticks(u(src+off,4)))
 for soff,doff,n in [(0xc,0xc,16),(0x1c,0x1c,4),(0x48,0x4c,16),(0x58,0x5c,8),(0x90,0x94,16),(0xa0,0xa4,8)]:put(memory,dst+doff,n,get(memory,src+soff,n))
 for soff,doff in [(0x20,0x24),(0x28,0x2c),(0x30,0x34),(0x38,0x3c),(0x40,0x44),(0x60,0x64),(0x68,0x6c),(0x70,0x74),(0x78,0x7c),(0x80,0x84),(0x88,0x8c)]:w(dst+doff,8,ticks(u(src+soff,8)))
 for src,dst in [(0xfffffe000ca92088,0xfffffe000cadd6e8),(0xfffffe000ca92090,0xfffffe000cb7d0c8)]:w(dst,8,ticks((u(src,8)*1000)&((1<<64)-1)))
 compared=0
 for r in row['final_image_globals']:
  a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex']);ok('whole_final_global_'+r['address'],get(memory,a,len(raw))==raw);compared+=len(raw)
 ok('timer_return_before_original_CPU_initializer_BL',row['longterm_initializer_returned'] and row['boundary']['pc']==hex(TIMER.R.STOP) and row['boundary']['kind']=='original_timer_return_before_CPU_initializer_BL')
 ok('outer_printf_return_observed',row['printf_return_checkpoint']['PC']=='0xfffffe000bd64f70');ok('logging_calls_all_returned',len(row['original_logging_entries'])==len(row['original_logging_returns']) and not row['unfinished_logging_entry_indices']);ok('no_new_system_value_or_API_model',row['final_system']==c['system'] and len(row['API_models'])==3)
 return {'checks':checks,'prior_longterm_contracts':prior,'range_premises':range_values,'expected_character_text':expected.decode(),'characters':len(expected),'threshold_nanoseconds':1000000,'timebase_hertz':f,'threshold_ticks':ticks(1000000),'threshold_tenth_ticks':ticks(1000000)//10,'whole_global_bytes_compared':compared,'timer_returned':True,'native_console_emission_established':False}

def audit(cached=None):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage,retained,retained_cov=source_proofs(e);im=R.BootImage();row=hydrate(cached,im) if cached else CPU.Probe(im).run();kept=preservation(row,im);contracts=oracle(row,e,im);replay=Replay(im,row).run();negative=[]
 for label,pc in [('omit_header_filetype_load',R.FRONTIER),('omit_lookup_zero_result',0xfffffe000c478f68)]:
  control=CPU.Probe(im,mutate=pc)
  for page in row['initial_image_pages']:control.ensure(int(page['address'],16),4096)
  q=control.run();keys=['configuration','entry_PC','entry_SP','entry_NZCV','entry_registers31','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(q[k]==row[k] for k in keys)
  if pc==R.FRONTIER:assert q['boundary']['kind']=='control_header_gate_boundary' and q['boundary']['pc']=='0xfffffe000c48fd48';rejected='filetype12_path_did_not_enter_lookup'
  else:assert q['boundary']['kind']=='control_lookup_return_boundary' and q['original_image_lookup_returns'][0]['X0']!='0x0';rejected='empty_registries_and_missing_ranges_did_not_return_zero'
  negative.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','same_initial_fields':keys,'all_initial_fields_match':True,'positive_original_pages_eagerly_mapped_before_control':True,'source_visits':len(q['source_visits']),'boundary':q['boundary'],'oracle_rejection':rejected,'journal_sha256':sha256(json.dumps({k:q[k] for k in ['source_visits','source_reads','source_writes']},sort_keys=True,separators=(',',':')).encode()).hexdigest()});print('rejected',label,flush=True)
 totals={'components':1,'source_visits':len(row['source_visits']),'prefix_visits_preserved':kept['identical_source_prefix_visits'],'additional_visits':len(row['source_visits'])-kept['identical_source_prefix_visits'],'source_queries_unsat':len(proofs),'retained_source_queries_rebuilt':len(retained),'proved_block_transitions':len(row['proved_logging_joins']),'contracted_original_words':9*len(row['proved_logging_joins']),'boot_global_words':8,'boot_global_bytes':64,'boot_pages_rehydrated':4967,'image_lookup_calls_returned':len(row['original_image_lookup_returns']),'logging_calls_returned':len(row['original_logging_returns']),'character_callbacks':len(row['original_character_calls']),'source_reads':len(row['source_reads']),'source_writes':len(row['source_writes']),'semantic_checks':len(contracts['checks']),'mapped_pages':len(row['final_page_sha256']),'changed_source_controls':len(negative),'new_system_register_values':0,'new_API_result_models':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_boot_logging_handoff.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'kernel_collection_sha256':im.k.sha256,'source_proofs':proofs,'proof_coverage':coverage,'retained_source_proofs_rebuilt':retained,'retained_proof_coverage':retained_cov,'component':publication_row(row,im),'independent_oracle':contracts,'prior_poisoned_case_comparison':kept,'negative_source_controls':negative,'independent_totals':totals,'independent_replay_totals':replay,'boot_page_hydration_checked':sorted(map(hex,im.checked)),'additional_raw_untouched_pages_checked':sorted(map(hex,im.untouched)),'native_target_executed':False,'hardware_PAC_executed':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
