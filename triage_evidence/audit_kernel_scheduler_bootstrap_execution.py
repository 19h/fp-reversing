#!/usr/bin/env python3
"""Scheduler source obligations, input custody and independent host checks.
Linear journals/pages/source; SMT separate, 30 s/query.
"""
import json
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_kernel_early_logging_execution import hydrate,publication_row
from replay_kernel_boot_cpu_identity import pages,get,put
from audit_kernel_initializer_pointer_signing import Model
from audit_kernel_early_logging_contract import source_proofs as logging_proofs
from audit_kernel_cpu_initialization_execution import memory_at
from lskd_values_symbolic import resize
import recover_kernel_scheduler_bootstrap_execution as R
import probe_kernel_scheduler_bootstrap_execution as CPU
from replay_kernel_scheduler_bootstrap_execution import Replay
P=0x6500000000;SIZE=1048576
def source_proofs(e):
 proofs=[];coverage=[];base=0x6e00000000
 def fresh():v=Model(e);v.regions=[(base,1024)];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));offset=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[offset:offset+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad):
  common=v.owned();counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count});print('proved',label,flush=True)
 kind,flag=z3.BitVecs('SB_CPU_type32 SB_group_flags32',32);cluster=z3.BitVec('SB_cluster_index32',32)
 v=fresh();v.regions.append((0xfffffe0007ef8c20,8));v.setmem(0xfffffe0007ef8c20,8,base);v.setmem(base,4,cluster);cut(v,0xfffffe000bd17354,0xfffffe000bd17368);prove('main_scheduler_forwards_published_boot_cluster_index_and_original_topology_base',v,z3.Or(v.read('x0')!=z3.ZeroExt(32,cluster),v.read('x1')!=0xfffffe0007ef8be8,v.next!=R.CLASSIFY,v.read('x30')!=0xfffffe000bd17368))
 for label,a,b,yes,no,value in [('E',0xfffffe000bd16ea0,0xfffffe000bd16ea8,0xfffffe000bd16ec0,0xfffffe000bd16ea8,1),('P',0xfffffe000bd16ea8,0xfffffe000bd16eb0,0xfffffe000bd16e64,0xfffffe000bd16eb0,2),('M',0xfffffe000bd16eb0,0xfffffe000bd16eb8,0xfffffe000bd16eb8,0xfffffe000bd170bc,3)]:
  v=fresh();v.seed('w14',kind);cut(v,a,b);prove('CPU_type_'+label+'_gate',v,v.next!=z3.If(kind==value,resize(yes,64),resize(no,64)))
 mask=z3.BitVec('SB_group_membership64',64);v=fresh();v.regions += [(0xfffffe0007f8b4f0,4),(R.GROUP_BASE+0x50,8)];v.seed('x19',0xfffffe0007f8b000);v.setmem(0xfffffe0007f8b4f0,4,0);v.setmem(R.GROUP_BASE+0x50,8,mask);cut(v,0xfffffe000bd1736c,0xfffffe000bd1738c);prove('bootstrap_ordinal0_selects_first_group_only_when_member_bit0_set',v,z3.Or(v.read('x0')!=R.GROUP_BASE,v.next!=z3.If(mask&1!=0,resize(0xfffffe000bd173b4,64),resize(0xfffffe000bd1738c,64))))
 v=fresh();v.regions += [(R.GROUP_BASE+0x3f60,4)];v.seed('x0',R.GROUP_BASE);v.setmem(R.GROUP_BASE+0x3f60,4,flag);cut(v,0xfffffe000bd173bc,0xfffffe000bd173d8);node=resize(0xfffffe000cad0118,64)+(z3.ZeroExt(32,flag)<<6);expected=z3.If(((node^0xfffffe000cad0118)&0xffc0000000000000)==0,resize(0xfffffe000bd173dc,64),resize(0xfffffe000bd173d8,64));prove('group_flags_select_64B_root_node_and_high_bit_check',v,z3.Or(v.read('x10')!=node,v.next!=expected))
 pointer=z3.BitVec('SB_checked_pointer64',64);v=fresh();v.seed('x10',pointer);cut(v,0xfffffe000bd173d8,0xfffffe000bd173dc);prove('group_pointer_poison_replaces_only_high16_bits',v,v.read('x10')!=((pointer&0xffffffffffff)|(0xc8a2<<48)))
 v=fresh();v.regions += [(R.GROUP_BASE+0x3f60,4),(0xfffffe0007e644b8,8)];v.seed('x8',base);v.seed('x9',R.GROUP_BASE);v.seed('x20',0xfffffe0007e64000);v.setmem(R.GROUP_BASE+0x3f60,4,flag);v.setmem(0xfffffe0007e644b8,8,R.GROUP_BASE);cut(v,0xfffffe000bd17410,0xfffffe000bd17420);prove('empty_group_root_publishes_exact_head_type_and_processor_group_argument',v,z3.Or(v.load(base,8)!=R.GROUP_BASE,v.load(base+16,4)!=flag,v.read('x2')!=R.GROUP_BASE))
 queues=[0xfffffe000cb0bca0,0xfffffe000cadd5a8,0xfffffe000cb0c6c8,0xfffffe000cadd658,0xfffffe000cadd768];v=fresh();v.regions += [(a,16) for a in queues];cut(v,0xfffffe000bd17448,0xfffffe000bd17484);prove('five_original_queue_heads_are_self_linked_pairs',v,z3.Or(*[v.load(a+8*j,8)!=a for a in queues for j in range(2)]))
 ordinal=z3.BitVec('SB_bootstrap_ordinal32',32);v=fresh();v.regions += [(0xfffffe0007f8b4f0,4)];v.seed('x19',0xfffffe0007f8b000);v.setmem(0xfffffe0007f8b4f0,4,ordinal);cut(v,0xfffffe000bd17484,0xfffffe000bd17490);prove('processor_tail_receives_fixed_boot_processor_and_u32_ordinal',v,z3.Or(v.read('x0')!=R.PROCESSOR,v.read('x1')!=z3.ZeroExt(32,ordinal)))
 return proofs,coverage
def oracle(row,e,im):
 from replay_kernel_secure_dt_execution import decode
 lo=row['scheduler_entry_checkpoint']['before_visit'];before=memory_at(row,lo,im);after=memory_at(row,len(row['source_visits']),im);checks=[]
 def u(a,n=8,m=after):return int.from_bytes(get(m,a,n),'little')
 def ok(label,p):assert p,('scheduler_bootstrap_contract',label);checks.append(label)
 initial=memory_at(row,0,im);parsed=decode({'initial_pages':[{'address':hex(a),'bytes_hex':bytes(b).hex()} for a,b in sorted(initial.items())],'fixture_extent_bytes':row['fixture_extent_bytes'],'fixture_node_addresses':row['fixture_node_addresses']});properties=parsed['CPU_properties'];prop=properties[0].get('cluster-type');raw_type=0 if prop is None else int.from_bytes(bytes.fromhex(prop['bytes_hex']),'little');cpu_type={0x45:1,0x50:2,0x4d:3}.get(raw_type,0)
 ok('one_original_tree_CPU_and_exact_declared_property',len(properties)==1 and ((prop is None and row['scheduler_input_case']=='missing') or (row['scheduler_input_case']=='E' and prop['size_bytes']==4 and raw_type==0x45)))
 cpu=0xfffffe0007ef8260;cluster=0xfffffe0007ef8ae0;group=R.GROUP_BASE;node=0xfffffe000cad0118;p=R.PROCESSOR;thread=row['scheduler_entry_checkpoint']['system']['tpidr_el1']
 ok('original_parser_publishes_class_and_boot_cluster',u(cpu+0x14,4,before)==cpu_type and u(cluster,4,before)==0 and u(cluster+0x10,8,before)==1 and u(0xfffffe0007ef8c20,8,before)==cluster)
 class_stores=[w for w in row['source_writes'] if w['source_visit_index']<lo and int(w['address'],16)==cpu+0x14];expected_stores=[('0xfffffe000be83808',0)]+([('0xfffffe000be838b8',1)] if prop else []);ok('original_CPU_class_stores_are_source_linked',[(w['pc'],int.from_bytes(bytes.fromhex(w['after_hex']),'little')) for w in class_stores]==expected_stores)
 ok('no_scheduler_leaf_return_model',len(row['API_models'])==2 and all(v['before_source_visit_index']<lo for v in row['API_models']))
 ok('entry_uses_inherited_profile_and_original_main_frame',row['architectural_input_profile']==R.B.PROFILE and row['scheduler_entry_checkpoint']['SP']=='0x65000eff40' and row['scheduler_entry_checkpoint']['PC']==hex(R.CALL))
 ok('two_original_global_lock_records',[u(a,8) for a in [0xfffffe000cadce10,0xfffffe000cad01d8]]==[0,0] and [u(a+8,8) for a in [0xfffffe000cadce10,0xfffffe000cad01d8]]==[0x11,0x11])
 if not cpu_type:
  ok('original_invalid_class_diagnostic_entry',row['boundary']['pc']==hex(R.PANIC) and row['scheduler_frontier']['format_X0']=='0xfffffe000704e91b' and row['scheduler_return_checkpoint'] is None and row['boundary']['registers31'][14]=='0x0')
  sp=int(row['boundary']['SP'],16);ok('diagnostic_stack_arguments_and_line',u(sp)==0 and u(sp+8)==0xfffffe000704e865 and u(sp+16)==0x833)
  ok('diagnostic_precedes_group_and_processor_setup',len(row['source_visits'])-lo==91 and [v['PC'] for v in row['original_scheduler_entries']]==[hex(R.INIT),hex(R.CLASSIFY)] and row['original_scheduler_returns']==[])
  ok('all_group_storage_unchanged_before_diagnostic',get(before,group,3*0x4200)==get(after,group,3*0x4200));ok('no_processor_publication_before_diagnostic',u(0xfffffe0007ef8f20)==u(0xfffffe0007ef8f20,8,before))
  return {'checks':checks,'input_CPU_type':cpu_type,'input_property':prop,'entry_visit':lo,'scheduler_source_visits':len(row['source_visits'])-lo,'scheduler_returned':False,'diagnostic_line_u32':0x833,'class_source_stores':class_stores,'host_queue_bytes_checked':0}
 ok('selected_E_case_bootstrap_set_type0',cpu_type==1 and u(group+0x3f60,4)==0 and u(group,1)==u(group+1,1)==0 and u(group+0x50)==1)
 ok('root_group_and_node_pointer_publication',u(0xfffffe0007e644b8)==group and u(0xfffffe0007e644c8)==node and u(node)==group and u(node+0x10,4)==0 and u(group+0x3f58)==node and u(group+0x3f50)==0)
 ok('root_node_membership_and_online_masks',[u(node+d) for d in [0x18,0x20,0x38]]==[1,1,1]);ok('set_identity_dictionary_and_counts',u(0xfffffe000cbc9618)==1 and u(0xfffffe0007e66d8c,1)==1 and u(0xfffffe0007e66d98,1)==0 and u(0xfffffe0007e66da0)==group)
 ok('per_cluster_record_fields',[u(0xfffffe000cad05a0+d,n) for d,n in [(0,1),(4,4),(8,8),(0x10,8),(0x18,8)]]==[0,1,1,0,0])
 # Queue records are derived from source layout constants and pristine incoming
 # bytes. Padding and untouched holes remain part of each whole-record compare.
 host_bytes=0
 for j in range(31):
  a=group+0x460+32*j;expected=a.to_bytes(8,'little')*2+((1<<64)-1).to_bytes(8,'little')+(0xffffffff00000000).to_bytes(8,'little');ok('whole_priority_queue_'+str(j),get(after,a,32)==expected);host_bytes+=32
 for j in range(6):
  for role,offset in [('base',0xaf8),('class',0x2508)]:
   a=group+offset+0x458*j;expected=bytearray(get(before,a,0x458))
   def w(off,n,value):expected[off:off+n]=int(value&((1<<(8*n))-1)).to_bytes(n,'little')
   w(0,1,j);w(1,1,int(role=='class'));w(2,1,0)
   if role=='base':w(8,8,0xffffffff);expected[0x10:0x320]=bytes(0x310)
   else:w(8,4,0xffffffff);expected[0x10:0x328]=bytes(0x318)
   expected[0x420:0x440]=bytes(32);w(0x440,8,(1<<64)-1);w(0x448,8,u(0xfffffe000cb628a0+8*j,8,before));w(0x450,8,0);ok('whole_'+role+'_queue_record_'+str(j),get(after,a,0x458)==expected);host_bytes+=0x458
 ok('six_original_nested_queue_initializer_arguments',[v['arguments6'][0] for v in row['original_scheduler_entries'] if v['PC']=='0xfffffe000bd2d3cc']==[hex(group+0x2510+0x458*j) for j in range(6)])
 for a in [0xfffffe000cb0bca0,0xfffffe000cadd5a8,0xfffffe000cb0c6c8,0xfffffe000cadd658,0xfffffe000cadd768]:ok('original_self_linked_queue_'+hex(a),get(after,a,16)==a.to_bytes(8,'little')*2);host_bytes+=16
 ok('processor_group_and_ordinal',u(p+0x20)==group and u(p+0x64,4)==0);ok('processor_state_fields',[u(p+d,n) for d,n in [(0,4),(4,1),(0x690,4),(0x6fa,1),(0x6fb,1),(0x6fc,1),(0x6fd,1),(0x700,4)]]==[0,1,1,0,0,0,1,0xffffffff])
 callbacks=[0xfffffe000bd15b88,0xfffffe000bd2df7c,0xfffffe000be3f2ac,0xfffffe000bd2e064]
 for j,target in enumerate(callbacks):
  a=p+0xa0+0x80*j;ok('callout_'+str(j)+'_pointer_context_lock_and_idle_fields',u(a+0x50)==target and u(a+0x58)==p and u(a+0x10)==0x11 and u(a+8)==0 and u(a+0x30)==(1<<64)-1 and u(a+0x70)==0)
 auth=[v for v in row['logical_effects'] if v.get('scope')=='original_scheduler_callout_pointer'];ok('four_original_authentication_operand_pairs',len(auth)==4 and [v['X16'] for v in auth]==list(map(hex,callbacks)) and all(v['X17']=='0x73d8' for v in auth))
 ok('processor_identity_array_and_list_publication',[u(a) for a in [0xfffffe0007ef8f20,0xfffffe0007e644d0,0xfffffe0007e64008]]==[p,p,p] and u(p+0x678)==0 and u(0xfffffe0007e6a414,4)==1)
 ok('processor_set_masks_and_cardinality',[u(group+d,n) for d,n in [(8,4),(12,4),(16,4),(0x58,8),(0xa0,8)]]==[0,0,1,1,1]);ok('global_processor_state_bitsets',[u(0xfffffe000cad01e8),u(0xfffffe000cad01f0),u(0xfffffe000ca90790)]==[0,1,1])
 ok('preemption_DAIF_and_architectural_inputs_retained',u(thread+0x1c8,4)==u(thread+0x1c8,4,before)==0 and row['final_system']==row['scheduler_entry_checkpoint']['system'])
 b=row['scheduler_return_checkpoint'];ok('original_scheduler_tail_returns_to_main',b is not None and b['PC']==hex(R.STOP) and b['SP']==row['scheduler_entry_checkpoint']['SP'] and b['registers31'][19:30]==row['scheduler_entry_checkpoint']['registers31'][19:30] and not row['unfinished_scheduler_entry_indices'] and sorted(v['entry_index'] for v in row['original_scheduler_returns'])==list(range(23)))
 message=b'[  203.613264]: [processor_init] processor 0 belongs to processor set 0 of type 0\n';chars=bytes(v['character_u32'] for v in row['original_character_calls']);ok('original_processor_diagnostic_character_stream',chars.endswith(message) and len(chars)==207+len(message));ok('all_1029_startup_callbacks_retained',len(row['callback_entries'])==len(row['callback_returns'])==1029)
 return {'checks':checks,'input_CPU_type':cpu_type,'input_property':prop,'entry_visit':lo,'scheduler_source_visits':len(row['source_visits'])-lo,'scheduler_returned':True,'class_source_stores':class_stores,'processor_set':hex(group),'processor_set_type_u32':0,'processor':hex(p),'host_queue_bytes_checked':host_bytes,'priority_queue_records':31,'nested_queue_records':12,'nested_leaf_initializers':6,'callout_targets':list(map(hex,callbacks)),'callout_modifier':'0x73d8','new_diagnostic_bytes':len(message),'new_diagnostic_text':message.decode()}
def preservation(rows,im):
 old=hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['component'],im);row=rows['missing'];lo=row['scheduler_entry_checkpoint']['before_visit'];assert lo==len(old['source_visits'])==831956 and row['source_visits'][:lo]==old['source_visits']
 for key in ['source_reads','source_writes']:assert [v for v in row[key] if v['source_visit_index']<lo]==old[key]
 for key in ['API_models','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','architectural_input_profile','initial_system']:assert row[key]==old[key]
 assert [v for v in row['logical_effects'] if v['before_visit']<lo]==old['logical_effects']
 c=row['scheduler_entry_checkpoint'];assert c['private_RAM']==old['final_private_RAM'] and c['vectors']==old['final_vectors'] and c['system']==old['final_system']
 for key in ['SP','NZCV','registers31']:assert c[key]==old['boundary'][key]
 for p,h in old['final_page_sha256'].items():assert c['mapped_page_sha256'][p]==h
 for p in c['mapped_page_sha256'].keys()-old['final_page_sha256'].keys():assert c['mapped_page_sha256'][p]==sha256(im.logical_page(int(p,16))).hexdigest()
 for key in ['callback_entries','callback_returns','original_image_lookup_entries','original_image_lookup_returns','original_character_calls','original_logging_entries','original_logging_returns','original_CPU_entries','original_CPU_returns']:assert [v for v in row[key] if v['before_visit']<=lo]==old[key]
 e=rows['E'];keys=['entry_PC','entry_SP','entry_NZCV','entry_registers31','initial_vectors','initial_system','initial_image_fixtures','architectural_input_profile'];assert all(e[k]==old[k] for k in keys)
 fixtures=e['initial_private_fixtures'];assert fixtures[:len(old['initial_private_fixtures'])]==old['initial_private_fixtures'] and len(fixtures)==len(old['initial_private_fixtures'])+3
 zero,tree,args=fixtures[-3:];assert zero['address']==tree['address']=='0x6500010000' and args['address']=='0x6500004000' and len(bytes.fromhex(tree['bytes_hex']))==852 and bytes.fromhex(zero['bytes_hex'])==bytes(852)
 original=memory_at(old,0,im);declared=memory_at(e,0,im);expected=bytearray(get(original,P,SIZE));expected[0x10000:0x10000+852]=bytes.fromhex(tree['bytes_hex']);expected[0x4068:0x406c]=(852).to_bytes(4,'little');assert get(declared,P,SIZE)==bytes(expected)
 old_args=bytearray(get(original,0x6500004000,1152));old_args[0x68:0x6c]=(852).to_bytes(4,'little');assert bytes.fromhex(args['bytes_hex'])==bytes(old_args)
 expected_config={**old['configuration'],'label':'declared_E_type_to_scheduler','CPUs':[{'cluster-type':0x45}],'extent':852};assert e['configuration']==expected_config and e['fixture_extent_bytes']==852
 for name,r in rows.items():
  a={v['address']:v['bytes_hex'] for v in r['initial_image_pages']};b={v['address']:v['bytes_hex'] for v in old['initial_image_pages']};assert all(a[k]==v for k,v in b.items())
  for k in a.keys()-b.keys():assert bytes.fromhex(a[k])==im.logical_page(int(k,16))
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'missing_case_exact_prefix_visits':lo,'all_prefix_reads_writes_logical_effects_exact':True,'missing_case_all_initial_fixture_records_exact':True,'whole_previous_private_RAM_GPR_SP_NZCV_vectors_system_exact':True,'all_prior_page_hashes_at_previous_frontier_exact':len(old['final_page_sha256']),'additional_unchanged_original_pages_at_previous_frontier':len(c['mapped_page_sha256'])-len(old['final_page_sha256']),'all_prior_callback_CPU_lookup_logging_journals_preserved':True,'E_case_same_initial_fields':keys,'E_case_only_private_input_changes':{'tree_address':'0x6500010000','tree_size_bytes':852,'old_tree_size_bytes':812,'boot_extent_u32_address':'0x6500004068','CPU_property':{'cluster-type':0x45}},'E_case_no_midexecution_CPU_record_repair':True}
def audit(cached=None):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);retained,retained_coverage=logging_proofs(e);im=R.B.B.B.BootImage();rows={};contracts={};replays={}
 for kind in ['missing','E']:
  row=hydrate(cached[kind],im) if cached else CPU.Probe(im,kind).run();rows[kind]=row;contracts[kind]=oracle(row,e,im);replays[kind]=Replay(im,row).run();print('audited_and_replayed',kind,flush=True)
 kept=preservation(rows,im);negative=[];positive=rows['E']
 for label,pc in [('omit_empty_root_head_publication',0xfffffe000bd17418),('omit_boot_processor_array_publication',0xfffffe000bd178b8)]:
  p=CPU.Probe(im,'E',pc)
  for page in positive['initial_image_pages']:p.ensure(int(page['address'],16),4096)
  q=p.run();keys=['configuration','entry_PC','entry_SP','entry_NZCV','entry_registers31','initial_vectors','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages','initial_system','architectural_input_profile','scheduler_input_property'];assert all(q[k]==positive[k] for k in keys)
  try:oracle(q,e,im)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_scheduler_source_accepted',label))
  assert q['boundary']['pc']==hex(R.STOP) and len(q['API_models'])==2;negative.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','all_initial_fields_match':True,'same_initial_fields':keys,'scheduler_return_reached':True,'source_visits':len(q['source_visits']),'oracle_rejection':rejection,'journal_sha256':sha256(json.dumps({k:q[k] for k in ['source_visits','source_reads','source_writes','logical_effects']},sort_keys=True,separators=(',',':')).encode()).hexdigest()});print('rejected',label,flush=True)
 totals={'components':2,'source_visits':sum(len(r['source_visits']) for r in rows.values()),'source_reads':sum(len(r['source_reads']) for r in rows.values()),'source_writes':sum(len(r['source_writes']) for r in rows.values()),'new_source_queries':len(proofs),'new_source_query_PCs':len(set(pc for r in coverage for pc in r['PCs'])),'retained_logging_queries_rebuilt':len(retained),'semantic_checks':sum(len(c['checks']) for c in contracts.values()),'missing_case_prefix_visits':kept['missing_case_exact_prefix_visits'],'missing_case_scheduler_visits':contracts['missing']['scheduler_source_visits'],'E_case_scheduler_visits':contracts['E']['scheduler_source_visits'],'E_case_scheduler_entries_and_returns':len(positive['original_scheduler_returns']),'E_case_host_queue_bytes_checked':contracts['E']['host_queue_bytes_checked'],'E_case_priority_queues':31,'E_case_nested_queues':12,'E_case_callouts_installed':4,'E_case_character_callbacks':len(positive['original_character_calls']),'remaining_API_models_per_case':2,'new_API_models':0,'source_controls':len(negative),'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_scheduler_bootstrap_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_proofs':proofs,'source_coverage':coverage,'retained_logging_proofs':retained,'retained_logging_coverage':retained_coverage,'components':{k:publication_row(r,im) for k,r in rows.items()},'independent_scheduler_oracles':contracts,'prior_prefix_and_input_comparison':kept,'negative_source_controls':negative,'independent_totals':totals,'independent_replay_totals':replays,'native_target_executed':False,'hardware_PAC_executed':False,'native_register_values_attested':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
