#!/usr/bin/env python3
"""Restore cache-allocation boundaries with byte masks and pointer provenance.
O(retained visits+effects+defined bytes) time, O(largest journal) space.
Clock/opaque API summaries are replayed as declared effects, not native calls.
"""
import json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM,ARM64_OP_REG
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from recover_daemon_object_creation import sha
from replay_daemon_descriptor_producers import unpack
from capture_daemon_object_clock import canonical,memory_width,groups
from validate_daemon_object_clock import initial_bytes

def restore(parent,t):
 data=initial_bytes(parent,t);writers={a:'retained source/declared input'for a in data};regs={n:int(a,16)for n,a in parent['register_pointer_origins'].items()};spills={int(a,16):int(v,16)for a,v in parent['memory_pointer_origins'].items()};cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={}
 for pc,row in t['source_pool'].items():
  a=int(pc,16);b=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(a,4)==b;pool[a]=next(cs.disasm(b,a))
 pos=0;apis={int(x['pc'],16):x for x in t['API_models']};vectors=set();invalidated=[]
 def put(a,b,writer):
  for at in list(spills):
   if a<at+8 and at<a+len(b):spills.pop(at)
  for j,x in enumerate(b):data[a+j]=x;writers[a+j]=writer
 def invalidate(a,n,why):
  for j in range(n):data.pop(a+j,None);writers.pop(a+j,None)
  for at in list(spills):
   if a<at+8 and at<a+n:spills.pop(at)
  invalidated.append({'address':hex(a),'size_bytes':n,'reason':why})
 for pc,raw in t['steps']:
  i=pool[pc];assert bytes(i.bytes).hex()==raw
  if pc in apis:
   api=apis[pc]
   for r in api.get('writes',[]):put(int(r['address'],16),bytes.fromhex(r['bytes_hex']),'declared API '+hex(pc))
   if api['binding']['symbol']=='_gettimeofday':invalidate(int(api['arguments2'][0],16)+12,4,'clock padding unavailable')
   else:
    e=api['opaque_effect'];invalidate(int(e['address'],16),e['size_bytes'],e['kind'])
   for j in list(range(18))+[30]:regs.pop('x'+str(j),None)
   continue
  before=regs.copy();effects=[]
  if any(o.type==ARM64_OP_MEM for o in i.operands):
   need=memory_width(i);got=0
   while got<need:
    e=t['events'][pos];pos+=1;assert e['pc']==hex(pc);got+=e['size_bytes'];effects.append(e)
   assert got==need
  reads,writes=i.regs_access()
  for v in writes:regs.pop(canonical(i.reg_name(v)),None)
  for v in reads:
   name=i.reg_name(v)
   if name.startswith(('q','v','d','s'))and name[1:].isdigit():vectors.add(name)
  for e in effects:
   if e['kind']=='write':put(int(e['address'],16),bytes.fromhex(e['after_hex']),e['pc'])
  if i.mnemonic in ['ldr','ldur']and i.reg_name(i.operands[0].reg).startswith('x'):
   es=[e for e in effects if e['kind']=='read'and e['size_bytes']==8]
   if len(es)==1:
    a=int(es[0]['address'],16);origin=a if a in FIXUPS else spills.get(a)
    if origin is not None:regs[canonical(i.reg_name(i.operands[0].reg))]=origin
  elif i.mnemonic=='mov'and len(i.operands)==2 and i.operands[1].type==ARM64_OP_REG:
   origin=before.get(canonical(i.reg_name(i.operands[1].reg)))
   if origin is not None:regs[canonical(i.reg_name(i.operands[0].reg))]=origin
  elif i.mnemonic in ['str','stur']and i.reg_name(i.operands[0].reg).startswith('x'):
   es=[e for e in effects if e['kind']=='write'and e['size_bytes']==8];origin=before.get(canonical(i.reg_name(i.operands[0].reg)))
   if origin is not None and len(es)==1:spills[int(es[0]['address'],16)]=origin
  elif i.mnemonic in ['ldp','stp']and all(i.reg_name(o.reg).startswith('x')for o in i.operands[:2]):
   kind='read'if i.mnemonic=='ldp'else'write';es=[e for e in effects if e['kind']==kind];assert sum(e['size_bytes']for e in es)==16;first=int(es[0]['address'],16)
   for j,o in enumerate(i.operands[:2]):
    name=canonical(i.reg_name(o.reg));a=first+8*j;origin=(a if a in FIXUPS else spills.get(a))if kind=='read'else before.get(name)
    if origin is not None:
     if kind=='read':regs[name]=origin
     else:spills[a]=origin
 assert pos==len(t['events'])and not vectors;assert regs['x8']==0x10109ff58
 return {'known_byte_groups':groups(data,writers),'known_bytes':len(data),'register_pointer_origins':{n:hex(a)for n,a in sorted(regs.items())},'memory_pointer_origins':{hex(a):hex(v)for a,v in sorted(spills.items())},'invalidated_ranges':invalidated,'source_visits_consumed':len(t['steps']),'source_effects_consumed':pos,'vector_reads':sorted(vectors)}
def main():
 profiles=json.loads((ROOT/'daemon_object_clock_profiles.json').read_text());parents=json.loads((ROOT/'daemon_object_clock_context.json').read_text());rows=[]
 for j,row in enumerate(profiles['cases']):
  if row['boundary']['pc']!='0x1009c0148':continue
  t=unpack(row);parent=parents['contexts'][row['parent_case_index']];state=restore(parent,t);rows.append({'clock_case_index':j,'parent_case_index':row['parent_case_index'],'parent_configuration':parent['configuration'],'parent_outcome':row['outcome'],'parent_payload_sha256':row['payload_sha256'],'boundary':t['boundary'],'allocated_owners':t['allocated_owners'],'owner_snapshots':t['owner_snapshots'],**state});print(json.dumps({'clock_case':j,'known_bytes':state['known_bytes'],'groups':len(state['known_byte_groups']),'source_visits':len(t['steps'])}),flush=True)
 assert len(rows)==24
 deps=['daemon_object_clock_profiles.json','daemon_object_clock_context.json','daemon_object_clock_checks.json','probe_daemon_object_clock.py','validate_daemon_object_clock.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'contexts':rows,'unavailable_state':['pre-allocation NZCV','vector registers','opaque library object bytes','native allocator behavior'],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache36_context.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
