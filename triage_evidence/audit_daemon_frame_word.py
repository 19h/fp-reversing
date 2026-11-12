#!/usr/bin/env python3
"""Independent original-A64 controls and retained partial-path checks.

O(text words+parent visits+control effects) time/space;30 s/query.
Logical PAC branches only; no native calls or continuation of unknown data.
"""
import json,struct
from pathlib import Path
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_versioned_ingress import interfaces,scalar
import recover_daemon_frame_word as R

def independent_census(expected):
 a,n=R.text_section();raw=IMAGE.read(a,n);hits=[]
 # Explicit instruction classes; widths/displacements come from Capstone,
 # independently of the producer's unsigned scale and Q-pair arithmetic.
 singles={0x39000000,0x79000000,0xb9000000,0xf9000000,0x3d000000,0x7d000000,0xbd000000,0xfd000000,0x3d800000}
 pairs={0xad000000,0xad800000,0xac000000};widths={'w':4,'x':8,'b':1,'h':2,'s':4,'d':8,'q':16}
 for j,(word,)in enumerate(struct.iter_unpack('<I',raw)):
  if word&0x3e0!=0x3e0 or word&0xffc00000 not in singles|pairs:continue
  pc=a+4*j;i=next(R.DEC.disasm(raw[j*4:j*4+4],pc));assert i.mnemonic in ['str','strb','strh','stp','stnp']
  op=i.operands[-1];assert i.reg_name(op.mem.base)=='sp'and not op.mem.index
  reg=i.reg_name(i.operands[0].reg);width=1 if i.mnemonic=='strb'else 2 if i.mnemonic=='strh'else 8 if reg in ['fp','lr']else widths[reg[0]]
  extent=width*(2 if i.mnemonic in ['stp','stnp']else 1);off=op.mem.disp
  if off<0x564 and 0x560<off+extent:hits.append((hex(pc),off,width,extent,bytes(i.bytes).hex()))
 assert hits==[(r['pc'],r['SP_displacement_B'],r['element_B'],r['extent_B'],r['bytes_hex'])for r in expected['candidates']]
 return {'candidates':len(hits),'raw_text_sha256':expected['text_sha256'],'all_checks_pass':True}

def replay(case):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();counts=Counter();trace=case['trace'];cursor=0;events=[];pending=None
 def put(a,data):
  for p in range(a&~4095,(a+len(data)+4095)&~4095,4096):
   if p not in pages:u.mem_map(p,4096);pages.add(p)
  u.mem_write(a,data)
 for name,a,b in R.SPECS:put(a,IMAGE.read(a,b-a))
 for c in case['initial_cells']:put(int(c['address'],16),int(c['value'],16).to_bytes(c['size_B'],'little'))
 f=int(case['initial_registers']['sp'],16);expected={k:int(x,16)for k,x in case['initial_registers'].items()};flags=int(case['initial_NZCV'],16)
 for k,x in expected.items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+k.upper()),x)
 u.reg_write(ar.UC_ARM64_REG_NZCV,flags)
 def finish():
  nonlocal pending,flags
  if pending is None:return
  assert events==pending['events'],('effects',pending['pc'],events,pending['events'])
  expected.update({k:int(x,16)for k,x in pending['registers_after'].items()});flags=int(pending.get('NZCV_after',hex(flags)),16)
  for k,x in expected.items():assert u.reg_read(getattr(ar,'UC_ARM64_REG_'+k.upper()))==x,('register',pending['pc'],k)
  assert u.reg_read(ar.UC_ARM64_REG_NZCV)==flags,('NZCV',pending['pc'])
  counts['register_values_checked']+=len(expected);counts['NZCV_values_checked']+=1;pending=None
 def code(engine,a,n,d):
  nonlocal cursor,pending,events
  finish();assert cursor<len(trace)and a==int(trace[cursor]['pc'],16)
  pending=trace[cursor];events=[];cursor+=1;assert n==4 and bytes(engine.mem_read(a,4))==IMAGE.read(a,4)==bytes.fromhex(pending['bytes_hex']);counts['source_visits']+=1
  if pending['mnemonic']=='braa':
   i=next(R.DEC.disasm(IMAGE.read(a,4),a));target=engine.reg_read(getattr(ar,'UC_ARM64_REG_'+i.reg_name(i.operands[0].reg).upper()));mod=engine.reg_read(ar.UC_ARM64_REG_X17)
   assert target==int(pending['target'],16)and mod==int(pending['modifier16'],16);counts['logical_PAC_transfers']+=1;engine.reg_write(ar.UC_ARM64_REG_PC,target)
 def memory(engine,kind,a,n,value,d):
  assert pending is not None
  write=kind==uc.UC_MEM_WRITE;x=value&((1<<(8*n))-1)if write else int.from_bytes(engine.mem_read(a,n),'little')
  events.append({'kind':'write'if write else'read','address':hex(a),'size_B':n,'value':hex(x)});counts['write_B_checked'if write else'read_B_checked']+=n
 u.hook_add(uc.UC_HOOK_CODE,code);u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,memory)
 u.emu_start(int(trace[0]['pc'],16),int(case['boundary'],16),count=len(trace)+1);finish()
 assert cursor==len(trace)and u.reg_read(ar.UC_ARM64_REG_PC)==int(case['boundary'],16)
 a=int(case['value_u32'],16);b=int(case['limit_u32'],16);c=int(case['companion_u32'],16)
 assert int.from_bytes(u.mem_read(f+0x560,4),'little')==a and int.from_bytes(u.mem_read(f+0x564,4),'little')==c and case['less_than']==(a<b)
 if a<b:assert int.from_bytes(u.mem_read(f+0x258,4),'little')==(a+0x2f95a328)&0xffffffff
 return {'epoch':case['epoch'],'value_u32':case['value_u32'],'limit_u32':case['limit_u32'],'less_than':a<b,'boundary':case['boundary'],'verified_counts':dict(counts),'all_checks_pass':True,'native_target_executed':False}

def main():
 parent=R.inputs();e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e['generator_sha256']==sha(ROOT/('recover_'+R.P+'.py'))and e['parent_pins']==R.PINS
 assert e['dependencies']=={n:sha(ROOT/n)for n in R.DEPS}and e['source_regions']==R.source()and e['source_fixups']==R.Parent.R.verify_fixups(set(R.SLOTS))
 fresh=R.obligations();assert [r['label']for r in fresh]==[r['label']for r in e['source_proofs']]
 for row in e['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.from_string(row['query']);assert str(s.check())==row['result']=='unsat'
 assert e['actual_frontiers']==R.actual(parent);joins=[]
 for c in parent['cases']:
  config=c['configuration']
  if config['kind']!='caller'or config['name']not in ['prefix','extended']:continue
  j=interfaces(c);r=next(r for r in e['actual_frontiers']if r['epoch']==config['epoch']and r['variant']==config['name']);states=r['entry_states']
  assert j['root_frame_SP']==r['frame_SP']and j['unresolved_frame_word']['value']==r['unknown_read']['value']
  assert scalar(states['0x10063735c']['x9'])==0x871a and scalar(states['0x10063735c']['x23'])==R.Parent.TABLE
  assert scalar(states['0x10063ac7c']['x12'])==0 and scalar(states['0x10063ac7c']['x10'])==12
  joins.append({'epoch':r['epoch'],'variant':r['variant'],'frame_SP':r['frame_SP'],'word_origin_matches_parent':True,'alternate_fields':[0,12],'reader_phase':'0x871a','partial_case_resumed':False,'all_checks_pass':True})
 cases=e['control_cases'];assert cases==R.controls();runs=[replay(c)for c in cases];totals=Counter()
 for r in runs:totals.update(r['verified_counts'])
 census=independent_census(e['bounded_store_census'])
 out={'scope':__doc__,'generator_sha256':e['generator_sha256'],'auditor_sha256':sha(Path(__file__)),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'parent_pins':R.PINS,'dependencies':e['dependencies'],'parent_auditor_sha256':sha(ROOT/'audit_daemon_versioned_ingress.py'),
  'verified_counts':e['verified_counts'],'source_proofs_unsat':len(fresh),'independent_census':census,'actual_frontier_checks':joins,'independent_controls':runs,'independent_totals':dict(totals),'all_checks_pass':True,
  'parent_A64_replays_repeated':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'actual_partial_fixture_resumed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(R.P+'_audit.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
