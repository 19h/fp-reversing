#!/usr/bin/env python3
"""Independent A64 continuation from a restored private interior context.

O(patterns*cases*(prefixes+owner+visits+effects)) time/space;30 s/query.
Prefixes restored, object word explicitly declared; no native API/IPC/PAC.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from replay_daemon_context_transfer import evaluate
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_versioned_ingress import Check as IngressCheck,scalar
import recover_daemon_remainder_preparation as R

class Check(IngressCheck):
 def __init__(self,snapshot,old,original,case,pattern):
  super().__init__(snapshot,old,original,pattern);c=case['configuration'];cut=c['parent_entry_source_visits'];regs=dict(original['trace']['initial_registers']);flags=original['trace']['initial_NZCV'];ram={};models={m['after_source_visits']:m for m in original['API_models']}
  for j,row in enumerate(original['trace']['steps'][:cut]):
   if j in models:
    m=models[j]
    for shape in m['register_effects'].values():
     for term in shape.get('terms',[]):
      if isinstance(term,dict):self.backing.setdefault(term['origin'],self.unknown_byte(term['origin']))
    if m['name']=='malloc':
     a=int(c['allocation'],16)
     for at in range(a,a+32):self.backing[at-self.F]=self.unknown_byte(at-self.F);ram[at]=self.backing[at-self.F]
    regs.update(m['register_effects']);flags=0xf0000000 if pattern==3 else 0
   assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
   for event in row['events']:
    if event['kind']=='write':
     a=int(event['address'],16);data=evaluate(event['value'],self.backing);ram.update({a+k:b for k,b in enumerate(data)})
   regs.update(row['registers_after']);flags=row.get('NZCV_after',flags)
  self.write_ram(ram)
  for n,shape in regs.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int.from_bytes(evaluate(shape,self.backing),'little'))
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,flags);assert flags==case['trace']['initial_NZCV']
  for n,shape in case['trace']['initial_registers'].items():assert self.register(n)==int.from_bytes(evaluate(shape,self.backing),'little'),('restored register',n)
  a=int(c['allocation'],16)+16;assert int.from_bytes(self.u.mem_read(a,4),'little')==int(c['prior_raw_object_word'],16)
  self.u.mem_write(a,int(c['declared_raw_object_word'],16).to_bytes(4,'little'));self.case=case;self.trace=case['trace'];self.model_cursor=0;self.allocated=True;self.retired=False;self.snap={**snapshot,'boundary':{'pc':hex(R.ENTRY)}}

def interfaces(case):
 c=case['configuration'];rows=case['trace']['steps'];f=int(c['caller_SP'],16)-0x9d0;regs=dict(case['trace']['initial_registers']);ram={};points={};writes=[];calls=[]
 def val(n):return scalar(regs[n])
 def get(a,n):
  data=[ram[a+j]for j in range(n)];assert all(isinstance(x,int)for x in data);return int.from_bytes(bytes(data),'little')
 for j,row in enumerate(rows):
  if row['pc']in ['0x100530720','0x10049d42c',hex(R.HELPER),'0x10042365c','0x1004236c4']:points[row['pc']]={'visit':j,'registers':regs.copy()}
  if row['mnemonic']=='blraa':calls.append({'pc':row['pc'],'target':row['target'],'modifier16':row['modifier16']})
  for event in row['events']:
   a=int(event['address'],16);shape=event['value'];data=list(bytes.fromhex(shape['hex']))if'hex'in shape else shape['terms'];ram.update({a+k:b for k,b in enumerate(data)})
   if event['kind']=='write':writes.append({'visit':j,'pc':row['pc'],**event})
  regs.update(row['registers_after'])
 b=case['trace']['boundary'];assert not case['API_models']and not any(row['pc']=='0x100478a04'for row in rows)
 result={'epoch':c['epoch'],'variant':c['name'],'frame_SP':hex(f),'declared_decoded_object_word':c['declared_decoded_object_word'],'native_admission_established':False,'all_checks_pass':True}
 field_writes=[e for e in writes if int(e['address'],16)<f+0x564 and f+0x560<int(e['address'],16)+e['size_bytes']]
 if c['declared_decoded_object_word']:
  assert not field_writes and not calls and b['pc']=='0x10063736c'and not points
  read=rows[-1]['events'][0];assert read['address']==hex(f+0x560)and read['value']=={'terms':[{'origin':f+0x560+j-0x640000b520}for j in range(4)]}
  result.update(conditional_writer_executed=False,nested_helper_entered=False,unknown_read=read)
 else:
  assert [(e['pc'],e['value']['hex'])for e in field_writes]==[('0x100530748','0c000000')]
  assert get(f+0x4ec,4)==get(f+0x560,4)==get(f+0x3c4,4)==12
  assert any(row['pc']=='0x100530778'and row['target']=='0x100537880'for row in rows)
  assert calls==[{'pc':'0x10049d42c','target':hex(R.HELPER),'modifier16':'0x9298'}]and b['pc']==hex(R.STOP)
  call=points['0x10049d42c']['registers'];entry=points[hex(R.HELPER)]['registers'];record=scalar(call['x0']);assert record==f+0x8d8 and scalar(call['x1'])==0 and scalar(entry['sp'])==f and scalar(entry['x0'])==record
  k=(((record&0xffffffff)^0xb521e742)*0x74cae98d)&0xffffffff;opcode=get(record+24,4)^k;tag=(get(record+40,4)-k)&0xffffffff
  decoded=points['0x10042365c']['registers'];dispatch=points['0x1004236c4']['registers'];g=f-0x2f0
  assert get(record,8)==f+0x610 and get(record+32,8)==f+0x600 and get(record+8,8)==get(record+16,8)==f+0x6c8
  assert tag==0x2530 and scalar(decoded['x1'])==tag and get(g+0x1c,4)==opcode and get(g+0x20,8)==record and get(g,8)==16
  assert scalar(dispatch['x15'])==0x2570 and scalar(dispatch['x1'])==R.TABLE and scalar(regs['x15'])==0x1000bba74 and scalar(regs['sp'])==g
  result.update(conditional_writer_executed=True,frame_word_u32=12,field_writer=field_writes[0],equality_target='0x100537880',nested_helper_entered=True,call=calls[0],record_address=hex(record),
   record_fields={'pointer0':hex(get(record,8)),'range8':hex(get(record+8,8)),'range10':hex(get(record+16,8)),'decoded_operation_u32':hex(opcode),'pointer20':hex(get(record+32,8)),'decoded_tag_u32':hex(tag)},
   helper_frame_SP=hex(g),helper_normalized_control_u32=get(g,8),helper_initial_dispatch_index='0x2570',helper_initial_dispatch_slot=hex(R.TABLE+0x2570*8),helper_loaded_target='0x1000bba74',helper_target_entered=False)
 return result

def main():
 pins,old,parent=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')))
 assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and e['source_regions']==R.source()
 assert e['source_fixups']==R.R.R.verify_fixups({int(a,16)for c in e['cases']for a in c['trace']['used_fixups']})
 fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 runs=[];joins=[];totals=Counter()
 for case in e['cases']:
  c=case['configuration'];original=next(v for v in parent['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant']);joins.append(interfaces(case))
  for pattern in [0,3]:
   r=Check(pins['daemon_callback_revisit_snapshot.json'],old,original,case,pattern).run();r.update(epoch=c['epoch'],variant=c['name']);runs.append(r);totals.update(r['verified_counts']);print(json.dumps({'epoch':c['epoch'],'variant':c['name'],'pattern':pattern,'source_visits':r['verified_counts']['source_visits']}),flush=True)
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'parent_pins':R.PINS,'dependencies':e['dependencies'],
  'ingress_auditor_sha256':sha(ROOT/'audit_daemon_versioned_ingress.py'),'modifier9298_collision_fixup_records':R.R.R.verify_fixups({int(r['slot'],16)for r in e['modifier9298_collision_slots']}),'verified_counts':e['verified_counts'],'source_proofs_unsat':len(fresh),'interface_joins':joins,'independent_replays':runs,'independent_totals':dict(totals),'all_checks_pass':True,
  **{k:False for k in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']}}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
