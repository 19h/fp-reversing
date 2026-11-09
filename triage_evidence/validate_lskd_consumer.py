#!/usr/bin/env python3
"""Fresh operation-selector replays, source byte epochs and complete-word proofs.

O(B+C*(V+E)+256R+I) time/space, plus solver-dependent cost (30 s/query).
No operation leaf, native target/API/heap, crypto or IPC execution.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from recover_lskd_fields import census
from probe_lskd_consumer import Consumer,cases
from probe_lskd_response import P,M64,OBJECT,PARAM,OUT,WORK,AUX,RESPONSE,SEPARATED_AUX
from probe_lskd_request import OTHER_OUT
from lskd_consumer_symbolic import queries,preparation_cells
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def rec(tag,b):return struct.pack('>HH',tag,len(b))+b
def provider_request(case,p):
 packet=rec(0x72,struct.pack('>Q',case['context64']));extra=[]
 if case['provider']=='vault':extra=[(0x8b,struct.pack('<Q',OTHER_OUT))]
 elif case['provider']=='avd':extra=[(t,struct.pack('<Q',PARAM+off))for t,off in[(0x6b,0),(0x6c,0xa0),(0x89,0x60),(0x8a,0xbc)]]
 elif case['provider']=='allowed':extra=[(0x7e,struct.pack('>I',0x13579bdf))]
 for tag,b in extra:packet+=rec(tag,b)
 obj=bytearray(160);struct.pack_into('<4I',obj,0,1,p['operation32'],p['entry_limit32'],p['capacity32']);obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,1+len(extra),len(packet));return obj
def workspace(request,out,aux,status=None):
 raw=bytearray(b'\xa5'*0x4000);known=bytearray(0x4000);key=((WORK^0xae0701e7)*0x952f3cb7)&0xffffffff
 for off,fmt,v in[(0,'Q',request),(8,'Q',WORK+64),(16,'I',key^0x563),(24,'Q',aux),(32,'Q',WORK+0x4000),(40,'Q',aux+0x1000),(56,'Q',out)]+([]if status is None else[(48,'I',status)]):
  b=struct.pack('<'+fmt,v);raw[off:off+len(b)]=b;known[off:off+len(b)]=b'\1'*len(b)
 return raw,known
def audit(r,c,prior,ctor,fields,execute,k,counts):
 state={};known=set();prov={};initial={};events={};snaps={};case=r['input'];globals=prior['mutable_globals']+ctor['additional_mutable_globals']+fields['additional_mutable_globals']+execute['additional_mutable_globals']+c['additional_mutable_globals']
 for j,d in enumerate(globals):
  a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if case['global_fixture']=='original'else 0 if case['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
 fixtures=[(OUT,struct.pack('<Q',case['out_initial64'])),(OTHER_OUT,bytes(8)),(PARAM,bytes.fromhex(r['initial_params256_hex']))]+[(int(s['address'],16),bytes.fromhex(s['bytes_hex']))for s in r['fixture_additions']]
 for a,raw in fixtures:
  for x,v in enumerate(raw,a):initial[x]=v;known.add(x);prov[x]=3
 guard=int(prior['guard']['address'],16);initial.update({guard+n:b for n,b in enumerate(bytes.fromhex(prior['guard']['original8_hex']))})
 def base(a):
  if a in initial:return initial[a]
  if P<=a<P+0x20000:return 0xa5
  try:return IMAGE.read(a,1)[0]
  except ValueError:return k.read(a,1)[0]
 def bytes_at(a,n):return bytes(state.get(x,base(x))for x in range(a,a+n))
 def snap(s):
  a=int(s['address'],16);n=s['size_bytes'];assert bytes_at(a,n).hex()==s['bytes_hex'];assert bytes(int(x in known)for x in range(a,a+n)).hex()==s['known_mask_hex'];assert bytes(prov.get(x,0)for x in range(a,a+n)).hex()==s['provenance_hex']
 for e in r['source_reads']:events.setdefault(e['source_visit_index'],[]).append(('read',e))
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append(('write',e))
 for call in r['source_calls']:snaps.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload','destination_before','argument_bytes','workspace_header','response_before','delta_cell']if n in call)
 for o in r['observations']:snaps.setdefault(o['source_visit_index'],[]).extend(o[n]for n in['out_reference','object']if n in o)
 if r['execution_input']is not None:
  x=r['execution_input'];snaps.setdefault(x['source_visit_index'],[]).extend([x['response_reference'],x['request']])
 if r['shared_prepare_entry'] is not None:
  x=r['shared_prepare_entry'];snaps.setdefault(x['source_visit_index'],[]).extend([x['operation_scratch'],x['auxiliary_frame_cell']])
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snaps.get(ix,[]):snap(s)
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert bytes_at(a,n).hex()==e['bytes_hex']
    if e['probe_only']:assert e['pc']in['0xfffffe000a5a1cdc','0xfffffe000a5a1cf0']and n==1;counts['discarded_probe_read_epochs']+=1
    if P<=a<a+n<=P+0x20000 and not e['probe_only']:assert all(x in known for x in range(a,a+n))
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in globals)
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);prov[x]=1
    counts['source_write_epochs']+=1
 for n in['workspace','auxiliary','actual_auxiliary','response','object','params','out_reference','execution_response_reference_final']:snap(r[n])
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1

def main():
 c=read('lskd_consumer_contracts.json');response=read('lskd_response_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');p=read('lskd_consumer_profiles.json');proof=read('lskd_consumer_proofs.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in [(c,'recover_lskd_consumer.py'),(p,'probe_lskd_consumer.py'),(proof,'prove_lskd_consumer.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for caller in c['additional_callers']:
  a=int(caller['start'],16);assert function(k,e,a)==caller['function']and k.symbols([a])[hex(a)]==caller['symbols'];counts['additional_original_callers']+=1
 calls=census(0xfffffe000a50c508);assert {x['pc']for x in calls['direct_calls']}=={x['execution_call']for x in c['additional_callers']+c['prior_provider_callers']};counts['bounded_direct_execution_callers']=len(calls['direct_calls'])
 for obj in [prior,tlv,ctor,fields,execute,response]:
  for b in obj['bank_rules']:
   l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 for n in c['nodes']:
  for edge in n['edges']:assert pointer(k,int(edge['original_pointer']['slot'],16))==edge['original_pointer'];counts['classifier_original_edges']+=1
  from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
  from lskd_consumer_symbolic import written_registers
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ss=next(s for s in c['spans']if s['label']=='node_'+n['label'])
  for ins in cs.disasm(bytes.fromhex(ss['bytes_hex']),int(n['start'],16)):
   assert 'sp'not in written_registers(ins)
   if ins.mnemonic in ['str','stp','strb','strh']:
    m=ins.operands[2 if ins.mnemonic=='stp'else 1];assert ins.reg_name(m.mem.base)=='sp'and not m.mem.index and not ins.writeback
    size=(4 if ins.reg_name(ins.operands[0].reg).startswith('w')else 8)*(2 if ins.mnemonic=='stp'else 1);assert m.mem.disp>=0 and m.mem.disp+size<=0x190
  counts['source_fixed_frame_nodes']+=1
 assert pointer(k,int(c['table_address'],16)+8*0x3b5)['target']==c['nodes'][0]['start'];counts['preparation_root_slot']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[];coverage=Counter();callers=Counter();leaf_counts=Counter();node_byaddr={n['start']:n for n in c['nodes']};leaf_addresses={*c['leaf_map'].values(),c['default_leaf']}
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Consumer(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits'])
  assert not r['undefined_private_value_reads']and r['operation_selection_executed_in_private_guest']
  for flag in ['native_API_executed','native_heap_executed','native_request_execution_executed','selected_operation_callee_executed','native_business_operation_executed','positive_publication_executed','external_IPC_emission_proved','full_goal_complete']:assert not r[flag],flag
  assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,response,prior,ctor,fields,execute,k,counts)
  assert not any(v['pc']in leaf_addresses or 0xfffffe000a522e38<=int(v['pc'],16)<0xfffffe000a522e5c or int(v['pc'],16)in [0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]for v in r['source_visits'])
  for call in r['source_calls']:assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64']=={f'd{v}':hex(0x1122334455660000+v)for v in range(8,12)};counts['FP64_contexts_preserved']+=1
  probes=[v for v in r['source_reads']if v['probe_only']];assert len(probes)==len(r['probe_only_reads'])==1 and all(v['loaded_register']=='wzr'and v['mapped_private_page_only']for v in r['probe_only_reads']);counts['original_stack_probe_calls']+=1
  assert r['actual_auxiliary']['bytes_hex']=='a5'*4096 and r['actual_auxiliary']['known_mask_hex']==r['actual_auxiliary']['provenance_hex']=='00'*4096;counts['auxiliary_storage_untouched_cases']+=1
  assert r['response']['bytes_hex']=='00'*160 and r['response']['known_mask_hex']==r['response']['provenance_hex']=='01'*160;counts['original_response_clear_bytes']+=160
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled'];counts['register_only_models']+=1
  assert len(r['models'])==3+int(case['kind']!='execute')
  op=case['operation32'];ap=AUX if case['auxiliary_location']=='adjacent'else SEPARATED_AUX
  if case['kind']!='execute':
   x=r['execution_input'];assert x['request_pointer']==hex(OBJECT);caller=next(v for v in (fields['providers']if case['kind']=='provider'else c['additional_callers'])if v['label']==case.get('provider',case.get('caller')));callers[caller['execution_call']]+=1
   if case['kind']=='provider':obj=provider_request(case,caller);counts['prior_provider_source_lineages']+=1
   else:
    packet=rec(0x66,bytes((11+37*x)&255 for x in range(8)))if case['caller']=='span'else b'';obj=bytearray(160);struct.pack_into('<4I',obj,0,1,op,1 if packet else 0,len(packet));obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,int(bool(packet)),len(packet));counts['additional_caller_source_lineages']+=1
    if packet:
     sc=[v for v in r['source_calls']if v['kind']=='provider_span'];assert len(sc)==1 and sc[0]['pc']=='0xfffffe000a5056ac'and sc[0]['registers8'][:4]==[hex(OBJECT),'0x66',hex(P+0x7400),'0x8']and sc[0]['argument_bytes']['bytes_hex']==packet[4:].hex();counts['additional_span_source_packets']+=1
   assert x['pc']==caller['execution_call']and x['request']['bytes_hex']==r['object']['bytes_hex']==obj.hex()and r['object']['provenance_hex']=='01'*160
   assert r['execution_response_reference_final']['bytes_hex']=='00'*8 and r['execution_response_reference_final']['provenance_hex']=='01'*8;out=int(x['response_reference']['address'],16);counts['source_constructed_packet_bytes']+=int.from_bytes(obj[156:160],'little')
   cr=[v for v in r['source_calls']if v['kind']=='constructor_record'];assert len(cr)==1 and int(cr[0]['record']['address'],16)&15==8;counts['aligned_source_constructor_records']+=1
  else:
   out=OUT;assert r['execution_response_reference_final']['bytes_hex']==struct.pack('<Q',case['out_initial64']).hex()and r['execution_response_reference_final']['provenance_hex']=='03'*8;counts['standalone_operation_fixtures']+=1
  top,known=workspace(OBJECT,out,ap);assert r['workspace']['bytes_hex'][:128]==top[:64].hex()and r['workspace']['known_mask_hex'][:128]==r['workspace']['provenance_hex'][:128]==known[:64].hex();counts['source_top_header_bytes']+=sum(known[:64])
  reads=[v for v in r['source_reads']if v['pc']in ['0xfffffe000a56b454','0xfffffe000a53533c']];assert[(v['address'],v['bytes_hex'])for v in reads]==[(hex(OBJECT),'01000000'),(hex(OBJECT+4),struct.pack('<I',op).hex())];copies=[v for v in r['source_writes']if v['pc']=='0xfffffe000a535340'];assert len(copies)==1 and copies[0]['address']==hex(WORK+0x118)and copies[0]['after_hex']==struct.pack('<I',op).hex();counts['source_operation_word_lineages']+=1
  pre=r['shared_prepare_entry'];sp=int(pre['SP'],16);regs=[int(x,16)for x in pre['registers31']];assert pre['operation_scratch']['bytes_hex']==struct.pack('<I',op).hex()and pre['auxiliary_frame_cell']['bytes_hex']==struct.pack('<Q',ap).hex();assert regs[24]==WORK+0x80 and regs[27]==OBJECT and regs[22]==WORK+0x118
  first=r['classifier_entries'][0];assert first['node']=='root'and first['SP']==pre['SP'];cells={}
  for w in r['source_writes']:
   if w['source_visit_index']>=first['source_visit_index']:break
   for a,b in enumerate(bytes.fromhex(w['after_hex']),int(w['address'],16)):cells[a]=b
  expected_cells=preparation_cells(WORK+0x80,ap,regs[25],regs[21]);expected_cells.update({0x78:WORK+0xa0,0x120:WORK+0x80})
  for off,val in expected_cells.items():assert bytes(cells[sp+off+x]for x in range(8))==struct.pack('<Q',val);counts['source_preparation_pointer_cells']+=1
  for reg,val in [(19,OBJECT),(20,ap+0x20),(27,ap+0x28),(25,WORK+0x98),(22,WORK+0x84)]:assert int(first['registers31'][reg],16)==val
  counts['shared_frame_preparation_contexts']+=1
  addr=c['nodes'][0]['start'];path=[]
  signed=op if op<0x80000000 else op-(1<<32)
  while addr in node_byaddr:
   n=node_byaddr[addr];pred=signed<n['threshold32']if n['condition']=='lt'else signed>=n['threshold32']if n['condition']=='ge'else op==n['threshold32'];outcome='true'if pred else'false';edge=next(v for v in n['edges']if v['condition_outcome']==outcome);path.append((n,edge));coverage[n['label']+'_'+outcome]+=1;addr=edge['original_pointer']['target']
  assert addr==c['leaf_map'].get(hex(op),c['default_leaf'])==r['boundary']['pc']and r['boundary']['kind']=='selected_operation_leaf';leaf_counts[addr]+=1;assert len(path)==len(r['classifier_entries'])==len(r['classifier_table_loads'])
  for (n,edge),en,load in zip(path,r['classifier_entries'],r['classifier_table_loads']):
   assert en['node']==load['node']==n['label']and en['pc']==n['start']and en['SP']==pre['SP'];assert int(en['registers31'][8],16)&0xffffffff==op
   for reg,val in n['input_constants'].items():assert int(en['registers31'][int(reg[1:])],16)&0xffffffff==int(val,16)
   ptr=edge['original_pointer'];assert load['pc']==n['table_load_pc']and load['index32']==edge['index32']and load['slot']==ptr['slot']and load['target_from_memory']==ptr['target'];lr=[v for v in r['source_reads']if v['source_visit_index']==load['source_visit_index']];assert len(lr)==1 and lr[0]['address']==ptr['slot']and lr[0]['size_bytes']==8 and lr[0]['bytes_hex']==struct.pack('<Q',int(ptr['target'],16)).hex()
   branches=[v for v in r['source_dispatches']if v['pc']==n['branch_pc']];assert len(branches)==1 and branches[0]['target']==ptr['target']and int(branches[0]['registers31'][17],16)==int(n['modifier16'],16);counts['source_classifier_edges']+=1
  if addr==c['default_leaf']:assert int(r['boundary']['registers31'][8],16)&0xffffffff==0x5e5571af;counts['default_error_preparations']+=1
  for w in r['source_writes']:
   if w['source_visit_index']>=pre['source_visit_index']:assert sp<=int(w['address'],16)<int(w['address'],16)+w['size_bytes']<=sp+0x1a8;counts['classifier_frame_write_epochs']+=1
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert len(callers)==8 and len(coverage)==28 and all(coverage.values())and len(leaf_counts)==13
 assert counts['fresh_cases']==175 and counts['source_visits']==497160 and counts['register_only_models']==669
 deps={n:sha(ROOT/n)for n in ['recover_lskd_consumer.py','probe_lskd_consumer.py','lskd_consumer_spec.py','lskd_consumer_symbolic.py','prove_lskd_consumer.py','lskd_consumer_contracts.json','lskd_consumer_profiles.json','lskd_consumer_proofs.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py','recover_lskd_fields.py']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'selected_operation_callee_executed':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_consumer_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'edge_coverage':dict(coverage),'direct_caller_coverage':dict(callers),'leaf_coverage':dict(leaf_counts),'bounded_reference_census':calls,'fresh_replays_sha256':sha(ROOT/'lskd_consumer_replays.json'),'all_checks_pass':True,'native_target_executed':False,'selected_operation_callee_executed':False,'positive_publication_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_consumer_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
