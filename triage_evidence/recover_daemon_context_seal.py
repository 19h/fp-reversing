#!/usr/bin/env python3
"""Recover 552-byte arena context sealing inputs, outputs and pointer lifetime.
O(cases*(snapshot+source visits+effects)) time, O(largest trace) space.
No native APIs, target execution, authentication or IDB edits.
"""
import json,hashlib,zlib,base64
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_callback_revisit import snapshot_read

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(r):return json.loads(zlib.decompress(base64.b64decode(r['payload_zlib_base64'])))
def num(s):return int.from_bytes(bytes.fromhex(s['hex']),'little')
def main():
 snap=json.loads((ROOT/'daemon_context_lock_snapshot.json').read_text());p=json.loads((ROOT/'daemon_context_lock_profiles.json').read_text());ex=json.loads((ROOT/'daemon_context_lock_success.json').read_text());F=int(snap['frame_SP'],16);D=0x6500115b20;N=552;rows=[]
 for case in p['cases']+[ex['case']]:
  t=unpack(case);reg=t['initial_registers'].copy();block=bytearray(snapshot_read(snap,D,N));stack=bytearray(snapshot_read(snap,F+0x30,64));entry=None;out=None;writes=[];seed_inputs=None;code_reads=[];initial_code_fold=None;A=int.from_bytes(snapshot_read(snap,0x1010ca2a8,8),'little')^0x12af5504870a589f
  for j,s in enumerate(t['steps']):
   if s['pc']=='0x1003c41d4':seed_inputs={'address':hex(num(reg['x16'])),'coefficient32':hex(num(reg['x6'])&0xffffffff),'code_fold32':hex(num(reg['x17'])&0xffffffff)}
   if s['pc']=='0x1003c4030':initial_code_fold=hex(num(reg['x10'])&0xffffffff)
   if s['pc']=='0x1003c41dc':
    assert num(reg['x16'])==D and num(reg['x12'])==0;entry={'source_visit_index':j,'seed32':hex(num(reg['x17'])&0xffffffff),'before_hex':block.hex(),'stack_index_vectors_hex':stack.hex(),'seed_inputs':seed_inputs,'initial_code_fold32':initial_code_fold,'vector_constants':{k:reg[k]for k in ['q15','q26','q27','q28','q29','q30','q31']}}
   if s['pc']=='0x1003c4324':out=block.hex()
   for e in s['events']:
    a=int(e['address'],16)
    if e['kind']=='read'and A<=a<A+32768:
     assert e['size_bytes']==4 and IMAGE.read(a,4).hex()==e['value']['hex'];code_reads.append({'pc':s['pc'],**e})
    if e['kind']!='write':continue
    a=int(e['address'],16);b=bytes.fromhex(e['value']['hex']);lo=max(a,D);hi=min(a+len(b),D+N)
    if lo<hi:block[lo-D:hi-D]=b[lo-a:hi-a];writes.append({'pc':s['pc'],'address':e['address'],'size_bytes':len(b),'source_visit_index':j})
    lo=max(a,F+0x30);hi=min(a+len(b),F+0x70)
    if lo<hi:stack[lo-F-0x30:hi-F-0x30]=b[lo-a:hi-a]
   reg.update(s['registers_after'])
  assert entry is not None and out is not None;seed=int(entry['seed32'],16);perm=list(range(69))
  for i in range(68,0,-1):j=((((seed+i)&0xffffffff)^seed)*0x01000193&0xffffffff)%i;perm[i],perm[j]=perm[j],perm[i]
  encoded_offset=perm.index(1)*8;rows.append({'name':case['configuration']['name'],'address':hex(D),'extent_bytes':N,**entry,'after_hex':out,'writes':writes,'code_reads':code_reads,'raw_lock_field_offset_bytes':8,'encoded_lock_field_offset_bytes':encoded_offset,'encoded_lock_word_hex':bytes.fromhex(out)[encoded_offset:encoded_offset+8].hex(),'raw_lock_value_before_seal':hex(int.from_bytes(bytes.fromhex(entry['before_hex'])[8:16],'little')),'raw_lock_value_after_seal':hex(int.from_bytes(bytes.fromhex(out)[8:16],'little'))})
 deps=['daemon_context_lock_snapshot.json','daemon_context_lock_profiles.json','daemon_context_lock_success.json'];a=0x1003c41dc;z=0x1003c4324;out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'source_span':{'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()},'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_seal_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'extent_bytes':N,'seeds':sorted({r['seed32']for r in rows}),'source_index_vectors':rows[0]['stack_index_vectors_hex']}),flush=True)
if __name__=='__main__':main()
