#!/usr/bin/env python3
"""Independent A64 effects and record/block/return joins for nested processing.

O(patterns*cases*(restored prefixes+owner+visits+effects)) time/space.
Prefixes restored; operand changes declared; no native API, IPC or hardware PAC.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,TABLE,qword
from replay_daemon_context_transfer import evaluate
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_remainder_preparation import Check as PreparationCheck,scalar
import recover_daemon_nested_helper_processing as R

class Check(PreparationCheck):
 def __init__(self,snapshot,old,original,previous,case,pattern):
  super().__init__(snapshot,old,original,previous,pattern);regs=dict(previous['trace']['initial_registers']);flags=previous['trace']['initial_NZCV'];ram={}
  for row in previous['trace']['steps']:
   assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex']
   for event in row['events']:
    if event['kind']=='write':
     a=int(event['address'],16);data=evaluate(event['value'],self.backing);ram.update({a+j:b for j,b in enumerate(data)})
   regs.update(row['registers_after']);flags=row.get('NZCV_after',flags)
  self.write_ram(ram)
  for n,shape in regs.items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),int.from_bytes(evaluate(shape,self.backing),'little'))
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,flags);assert flags==case['trace']['initial_NZCV']
  for n,shape in case['trace']['initial_registers'].items():assert self.register(n)==int.from_bytes(evaluate(shape,self.backing),'little'),('restored initial register',n)
  c=case['configuration'];offset=R.PROFILES[c['operand_profile']];f=int(c['caller_SP'],16)-0x9d0
  assert len(c['operand_overlays'])==int(offset is not None)
  for row in c['operand_overlays']:
   a=int(row['address'],16);assert a==f+offset and row['xor_mask_u8']==1
   actual=bytes(self.u.mem_read(a,1));assert actual.hex()==row['old_byte_hex']and bytes([actual[0]^1]).hex()==row['new_byte_hex'];self.u.mem_write(a,bytes.fromhex(row['new_byte_hex']))
  self.case=case;self.trace=case['trace'];self.model_cursor=0;self.allocated=True;self.retired=False;self.snap={**snapshot,'boundary':{'pc':hex(R.ENTRY)}}

def interfaces(case,previous):
 c=case['configuration'];rows=case['trace']['steps'];f=int(c['caller_SP'],16)-0x9d0;g=f-0x2f0;i=f+0x8d8;data=f+0x6c8;p0=f+0x610;p20=f+0x600;aux=g+0x270
 regs=dict(case['trace']['initial_registers']);points={};events=[]
 for j,row in enumerate(rows):
  if row['pc']in ['0x10015f9f4','0x10015fa38',hex(R.RETURN),'0x1006236d4']:points[row['pc']]={'visit':j,'registers':regs.copy()}
  for event in row['events']:events.append({'visit':j,'pc':row['pc'],**event})
  regs.update(row['registers_after'])
 assert not case['API_models']and not any(r['mnemonic']in ['bl','blr','blraa','svc']for r in rows)and not any(r['pc']=='0x100478a04'for r in rows)
 def selected(pc,kind):return [e for e in events if e['pc']==hex(pc)and e['kind']==kind]
 def vector(ee,base,n=16):
  ram={}
  for e in ee:
   a=int(e['address'],16);assert 'hex'in e['value'];raw=bytes.fromhex(e['value']['hex']);assert len(raw)==e['size_bytes'];ram.update({a+j:b for j,b in enumerate(raw)})
  assert set(ram)==set(range(base,base+n));return bytes(ram[base+j]for j in range(n)).hex()
 def descending(ee,base):assert len(ee)==16 and all(e['size_bytes']==1 for e in ee)and [int(e['address'],16)for e in ee]==list(range(base+15,base-1,-1))
 pre_read=selected(0x1000bc21c,'read');pre_write=selected(0x1000bc2b4,'write');aux_read=selected(0x10015d3dc,'read');aux_write=selected(0x10015d40c,'write');post_read=selected(0x10002c014,'read');post_write=selected(0x10002c0d0,'write')
 for ee,base in [(pre_read,data),(pre_write,data),(aux_read,p0),(aux_write,aux),(post_read,data),(post_write,data)]:descending(ee,base)
 core_input=[e for e in events if e['kind']=='read'and p20<=int(e['address'],16)<p20+16];assert len(core_input)==16
 writes=[e for e in events if e['kind']=='write'];middle=[e for e in writes if data<=int(e['address'],16)<data+16 and e['pc']not in ['0x1000bc2b4','0x10002c0d0']];assert len(middle)==16 and all(e['size_bytes']==1 for e in middle)
 assert vector(middle,data)==vector(post_read,data)
 assert not any(e['kind']=='write'and p20<=int(e['address'],16)<p0+16 for e in events)
 outside=[e for e in writes if not g<=int(e['address'],16)<int(e['address'],16)+e['size_bytes']<=g+0x2f0]
 assert len(outside)==49 and all(data<=int(e['address'],16)<data+16 or(e['pc']=='0x10015fa00'and e['address']==hex(i+0x1c)and e['size_bytes']==4)for e in outside)
 result=selected(0x10015fa00,'write');caller=selected(R.RETURN,'read');assert len(result)==len(caller)==1 and result[0]['address']==caller[0]['address']==hex(i+0x1c)and result[0]['value']==caller[0]['value']=={'hex':'51c63d8b'}
 assert scalar(points['0x10015f9f4']['registers']['x9'])==0x0c67c7c7
 entry_regs=dict(previous['trace']['initial_registers'])
 for row in previous['trace']['steps']:
  if row['pc']==hex(R.Parent.HELPER):break
  entry_regs.update(row['registers_after'])
 returned=points['0x10015fa38']['registers'];assert scalar(returned['sp'])==f and scalar(returned['x30'])==R.RETURN
 for n in ['x'+str(k)for k in range(19,30)]:assert returned[n]==entry_regs[n],('callee-saved',n)
 returns=[r for r in rows if r['mnemonic']in ['ret','retaa','retab']];assert len(returns)==1 and returns[0]['pc']=='0x10015fa38'and returns[0]['target']==hex(R.RETURN)
 assert scalar(points['0x1006236d4']['registers']['x8'])==0x554a and scalar(regs['x28'])==0x8b3dc651
 transfers=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']}for r in rows if r['pc']in ['0x10049d43c','0x1006236e8']]
 assert transfers==[{'pc':'0x10049d43c','target':'0x10062369c','modifier16':'0x4df7'},{'pc':'0x1006236e8','target':hex(R.STOP),'modifier16':'0x1d9f'}]
 assert qword(TABLE+0x524a*8)==0x10062369c and qword(TABLE+0x554a*8)==R.STOP and case['trace']['boundary']['pc']==hex(R.STOP)and case['trace']['boundary']['SP']==hex(f)
 return {'epoch':c['epoch'],'variant':c['name'],'operand_profile':c['operand_profile'],'root_SP':hex(f),'helper_SP':hex(g),'record':hex(i),'block':hex(data),'pointer0':hex(p0),'pointer20':hex(p20),'decoded_pointer0_local':hex(aux),
  'input_block_hex':vector(pre_read,data),'input_pointer0_hex':vector(aux_read,p0),'input_pointer20_hex':vector(core_input,p20),'preprocessed_block_hex':vector(pre_write,data),'decoded_pointer0_hex':vector(aux_write,aux),'core_block_hex':vector(middle,data),'output_block_hex':vector(post_write,data),
  'core_output_store_PCs':[e['pc']for e in middle],'record_status_u32':'0x8b3dc651','record_status_offset':'0x1c','guard_u32':'0xc67c7c7','returned_X0':hex(scalar(returned['x0'])),'callee_saved_GPRs_preserved':11,'return_PC':'0x10015fa38','return_target':hex(R.RETURN),'caller_status_index':'0x554a','caller_transfers':transfers,'external_API_calls':0,'IOKit_calls':0,'all_checks_pass':True}

def profile_relations(joins):
 out=[]
 for epoch in [0,1]:
  for variant in ['prefix_word0','extended_word0']:
   group={p:next(j for j in joins if j['epoch']==epoch and j['variant']==variant+'_'+p)for p in R.PROFILES};base=group['baseline']
   assert group['block_bit0']['output_block_hex']==group['pointer0_bit0']['output_block_hex']
   for profile,field in [('block_bit0','input_block_hex'),('pointer0_bit0','input_pointer0_hex'),('pointer20_bit0','input_pointer20_hex')]:
    row=group[profile]
    for other in ['input_block_hex','input_pointer0_hex','input_pointer20_hex']:
     a,b=bytes.fromhex(base[other]),bytes.fromhex(row[other]);assert bytes(x^y for x,y in zip(a,b))==bytes([1]+[0]*15)if other==field else a==b
    distances={field:sum((a^b).bit_count()for a,b in zip(bytes.fromhex(base[field]),bytes.fromhex(row[field])))for field in ['preprocessed_block_hex','decoded_pointer0_hex','core_block_hex','output_block_hex']}
    out.append({'epoch':epoch,'preparation_variant':variant,'profile':profile,'single_changed_input':field,'output_distances_bits':distances,'paired_block_pointer0_output_equal':True,'all_checks_pass':True})
 return out

def main():
 pins,old,ingress,previous=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')))
 assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and e['source_regions']==R.source()
 assert e['source_fixups']==R.Parent.R.R.verify_fixups({int(a,16)for case in e['cases']for a in case['trace']['used_fixups']})
 assert e['caller_branch_slots']==R.Parent.R.R.verify_fixups({TABLE+n*8 for n in [0x524a,0x553e,0x554a]})
 fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==7
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 replays=[];joins=[];totals=Counter();counts=Counter()
 for case in e['cases']:
  c=case['configuration'];prior=next(v for v in previous['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['preparation_variant']);original=next(v for v in ingress['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant']);joins.append(interfaces(case,prior));counts.update(case['counts'])
  for pattern in [0,3]:
   row=Check(pins['daemon_callback_revisit_snapshot.json'],old,original,prior,case,pattern).run();row.update(epoch=c['epoch'],variant=c['name']);replays.append(row);totals.update(row['verified_counts']);print(json.dumps({'epoch':c['epoch'],'variant':c['name'],'pattern':pattern,'source_visits':row['verified_counts']['source_visits']}),flush=True)
 verified={'cases':len(e['cases']),'epochs':2,'variants_per_epoch':8,**dict(counts)};assert verified==e['verified_counts']
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'parent_pins':R.PINS,'dependencies':e['dependencies'],'verified_counts':verified,'source_proofs_unsat':len(fresh),'interface_joins':joins,'profile_relations':profile_relations(joins),'independent_replays':replays,'independent_totals':dict(totals),'all_checks_pass':True,
  **{k:False for k in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']}}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':verified,'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
