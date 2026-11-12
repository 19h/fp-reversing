#!/usr/bin/env python3
"""Independent post-block A64 replay, API-byte provenance and kernel ABI readback.

O(patterns*cases*(prefixes+owner+visits)+kernel image) time/space.
All API execution stops at call entry; no native Mach, IOKit, API or hardware PAC.
"""
import json,struct
from pathlib import Path
from collections import Counter
import z3
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,TABLE,FIXUPS,selected
from replay_daemon_context_transfer import evaluate
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_nested_helper_processing import Check as ProcessingCheck,scalar
import recover_daemon_postblock_dispatch as R
ABI_PINS={'versioned_request_abi_source.json':'43319db5d7d5471ded1d52b78319db4821b460088e407ccbb5a44091d9a6285d',
 'versioned_request_abi_checks.json':'2e5decc7fdc4c39fd5a3a01be9d6dced22749aea75c581ac2b0b458dafa86da0'}

class Check(ProcessingCheck):
 def __init__(self,snapshot,old,original,preparation,previous,case,pattern):
  super().__init__(snapshot,old,original,preparation,previous,pattern);regs=dict(previous['trace']['initial_registers']);flags=previous['trace']['initial_NZCV'];ram={}
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
  self.case=case;self.trace=case['trace'];self.snap={**snapshot,'boundary':{'pc':hex(R.ENTRY)}}
 def run(self):
  out=super().run();view=self.case['api_view'];at=int(view['address'],16);assert bytes(self.u.mem_read(at,552))==evaluate(view['source_shape'],self.backing)
  out['api_view_bytes_checked']=552;out['api_unspecified_bytes_preserved']=view['unassigned_bytes'];return out

def kernel_comparison():
 for n,d in ABI_PINS.items():assert sha(ROOT/n)==d,n
 from kernel_native_reader import Kernel
 from kext_port_tools import IMAGE as KI,SOURCE as KS
 from recover_kext_cold_init import pointer
 s=json.loads(read(ROOT/'versioned_request_abi_source.json'));c=json.loads(read(ROOT/'versioned_request_abi_checks.json'));assert c['all_checks_pass'];k=Kernel();assert k.sha256==s['kernel_collection_sha256']and sha(KS)==s['kext_sha256']
 for fragment in s['kext_fragments'].values():
  a=int(fragment['start'],16);raw=bytes.fromhex(fragment['bytes']);assert k.read(a,len(raw))==KI.read(a,len(raw))==raw
 descriptor=s['selector21'];assert all(pointer(k,int(descriptor[n]['slot'],16))==descriptor[n]for n in ['descriptor_pointer','member_pointer','provider_slot'])
 at=int(descriptor['descriptor_pointer']['target'],16);assert k.read(at,48).hex()==descriptor['original_record48_bytes'];fields=struct.unpack('<6Q',KI.read(at,48));assert list(map(hex,fields))==descriptor['normalized_fields6']and fields== (0,0xfffffe000a50500c,0,3,552,552)
 return {'kernel_collection_sha256':k.sha256,'normalized_kext_sha256':sha(KS),'function_instructions':sum(len(f['instructions'])for f in s['kext_fragments'].values()),'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in s['kext_fragments'].values()),'selector21':descriptor,'native_pairing_established':False,'all_checks_pass':True}

def interfaces(case,original,preparation,previous,processing_join):
 c=case['configuration'];f=int(c['caller_SP'],16)-0x9d0;i=f+0x8d8;a=f+0x6a8;rows=case['trace']['steps'];regs=dict(case['trace']['initial_registers']);ram={};writers={};points={};events=[]
 cut=c['parent_entry_source_visits']
 for stage,seq in [('ingress',original['trace']['steps'][:cut]),('preparation',preparation['trace']['steps']),('processing',previous['trace']['steps']),('postblock',rows)]:
  for j,row in enumerate(seq):
   if stage=='postblock'and row['pc']in [hex(R.HELPER),'0x100336fcc','0x100620780','0x100620784','0x1004789ec']:points[row['pc']]={'visit':j,'registers':regs.copy()}
   for event in row['events']:
    at=int(event['address'],16);s=event['value'];data=list(bytes.fromhex(s['hex']))if'hex'in s else s['terms']
    if event['kind']=='write':
     ram.update({at+k:b for k,b in enumerate(data)})
     for off in range(max(at,a)-a,min(at+len(data),a+552)-a):writers[str(off)]={'stage':stage,'visit':j,'pc':row['pc']}
    if stage=='postblock':events.append({'visit':j,'pc':row['pc'],**event})
   if stage=='postblock':regs.update(row['registers_after'])
 def get(at,n):
  data=[ram[at+j]for j in range(n)];assert all(isinstance(x,int)for x in data);return int.from_bytes(bytes(data),'little')
 view=case['api_view'];terms=[ram.get(a+j,{'origin':a+j-0x640000b520})for j in range(552)];known=[j for j,x in enumerate(terms)if isinstance(x,int)]
 assert view['source_shape']=={'terms':terms}and view['known_offsets']==known and view['last_writers']==writers and view['unassigned_bytes']==552-len(known)
 mode=2 if c['parent_variant']=='prefix'else 5;expected_known=list(range(12))+ (list(range(12,28))if mode==5 else[])+list(range(32,60))+list(range(544,548));assert known==expected_known
 assert get(a,4)==mode and get(a+4,4)==0xb4d3a486 and get(a+544,4)==16 and get(f+0x3f0,8)==552
 generated=bytes(ram[f+0x2d4+j]for j in range(4));assert get(a+8,4)==int.from_bytes(generated,'big')and get(f+0x3b4,4)==(int.from_bytes(generated,'big')^0x8b3dc651)
 assert bytes(ram[a+0x20+j]for j in range(16)).hex()==processing_join['output_block_hex']
 if mode==5:assert bytes(ram[a+12+j]for j in range(16))==bytes(ram[f+0x610+j]^0x98 for j in range(16))
 call=points['0x100620780']['registers'];entry=points[hex(R.HELPER)]['registers'];assert scalar(call['x0'])==i and scalar(entry['sp'])==f and scalar(entry['x0'])==i
 key=(((i&0xffffffff)^0x966e5812)*0x592e2f77)&0xffffffff;assert(get(i,4)-key)&0xffffffff==0x5784 and get(i+4,4)==0x8b3dc651
 returned=points['0x100620784']['registers'];assert scalar(returned['sp'])==f
 for n in ['x'+str(j)for j in range(19,30)]:assert returned[n]==call[n]
 calls=[{'pc':r['pc'],'target':r['target'],'modifier16':r['modifier16']}for r in rows if r['mnemonic']=='blraa'];assert calls==[{'pc':'0x100620780','target':hex(R.HELPER),'modifier16':'0xa74'}]
 b=case['trace']['boundary'];assert b['kind']=='before_uninspected_call'and b['pc']=='0x100478a04'and b['target']=='0x7c006800'and b['modifier16']=='0x7a6c'and b['SP']==hex(f)and not case['API_models']
 args=[scalar(b['registers31'][j])for j in range(6)];assert args==[0x82da5774,21,a,552,a,f+0x3f0]
 conn=[e for e in events if e['pc']=='0x1004789d8'];assert len(conn)==1 and conn[0]['address']=='0x1010b6384'and conn[0]['value']=={'hex':'7457da82'}
 return {'epoch':c['epoch'],'variant':c['name'],'root_SP':hex(f),'construction_view':hex(f+0x600),'current_base':hex(f+0x698),'API_buffer':hex(a),'API_minus_construction_B':168,'block_API_offset':'0x20','mode_word_u32':mode,'second_word_u32':'0xb4d3a486','generated_word_u32':hex(get(a+8,4)),'input_count_u32':16,'known_API_bytes':len(known),'unassigned_API_bytes':552-len(known),'pending_API_args_X0_X5':list(map(hex,args)),'connection_source':'0x1010b6384','helper_record':hex(i),'helper_operation_u32':'0x5784','helper_result_offset':'0x4','helper_result_u32':'0x8b3dc651','helper_call':calls[0],'API_call_executed':False,'native_pairing_established':False,'all_checks_pass':True}

def main():
 pins,old,ingress,preparation,previous=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')));pa=json.loads(read(ROOT/'daemon_nested_helper_processing_audit.json'))
 assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS and e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and e['source_regions']==R.source()
 assert e['source_fixups']==R.Parent.Parent.R.R.verify_fixups({int(a,16)for c in e['cases']for a in c['trace']['used_fixups']})
 assert e['collision_fixups']==R.Parent.Parent.R.R.verify_fixups({int(r['slot'],16)for r in e['modifier0a74_collision_slots']})and len(e['modifier0a74_collision_slots'])==4
 fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==10
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 kernel=kernel_comparison();runs=[];joins=[];counts=Counter();totals=Counter()
 for case in e['cases']:
  c=case['configuration'];original=next(v for v in ingress['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant']);prep=next(v for v in preparation['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['preparation_variant']);prior=next(v for v in previous['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['name']);join=next(v for v in pa['interface_joins']if v['epoch']==c['epoch']and v['variant']==c['name']);joins.append(interfaces(case,original,prep,prior,join));counts.update(case['counts'])
  for pattern in [0,3]:
   r=Check(pins['daemon_callback_revisit_snapshot.json'],old,original,prep,prior,case,pattern).run();r.update(epoch=c['epoch'],variant=c['name']);runs.append(r);totals.update(r['verified_counts']);print(json.dumps({'epoch':c['epoch'],'variant':c['name'],'pattern':pattern,'source_visits':r['verified_counts']['source_visits']}),flush=True)
 verified={'cases':len(e['cases']),'epochs':2,'variants_per_epoch':2,**dict(counts)};assert verified==e['verified_counts']
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'parent_pins':R.PINS,'dependencies':e['dependencies'],'ABI_pins':ABI_PINS,'kernel_dependencies':{n:sha(ROOT/n)for n in ['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py']},'kernel_comparison':kernel,'verified_counts':verified,'source_proofs_unsat':len(fresh),'interface_joins':joins,'independent_replays':runs,'independent_totals':dict(totals),'all_checks_pass':True,
  **{k:False for k in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']}}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':verified,'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
