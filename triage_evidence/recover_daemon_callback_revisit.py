#!/usr/bin/env python3
"""Recover callback copies, byte/state adapters, text readers and context encoding.
O(snapshot+journal bytes+source visits) time/space; no native target/API/PAC.
"""
import json,hashlib,zlib,base64,struct
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,verify_original_fixups
SPANS=[('adapter_prologue',0x100add598,0x100add5ac),('adapter_state_step',0x100add6c0,0x100add6cc),('adapter_allocation',0x100add72c,0x100add750),('adapter_return_delta',0x100add7d8,0x100add7e8),('adapter_inner_bias',0x100acdb14,0x100acdb20),('caller_SP_delta',0x100301508,0x100301518),('byte_record_key',0x100acdb20,0x100acdb54),('byte_record_decode',0x100acdb54,0x100acdb80),('caller_record_pack',0x1003013e8,0x100301444),('byte_code_reader',0x100a0c9bc,0x100a0ca78),('word_code_reader',0x100462660,0x1004626f0),('context_vector_block',0x100462848,0x1004628ac),('context_tail_block',0x1004628e0,0x100462910),('context_shuffle',0x100462924,0x100462974),('byte_fill',0x1004c831c,0x1004c83b4),('creator_caller',0x1004925a4,0x100492648)]
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(p):return json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'])))
def snapshot_read(s,a,n):
 out=bytearray(n);mask=bytearray(n)
 for region in s['regions']:
  lo=int(region['address'],16);hi=lo+region['size_bytes'];left=max(a,lo);right=min(a+n,hi)
  if left<right:b=zlib.decompress(base64.b64decode(region['bytes_zlib_base64']));out[left-a:right-a]=b[left-lo:right-lo];mask[left-a:right-a]=bytes([1])*(right-left)
 assert all(mask),(hex(a),n);return bytes(out)
def verify_fixups(addresses):
 # Frozen verifier accepts authenticated binds. The new stack-canary GOT
 # word is an unauthenticated format-12 bind24 with a zero signed addend.
 ordinary=[a for a in addresses if FIXUPS[a]['kind']=='bind']
 out=verify_original_fixups([a for a in addresses if a not in ordinary])
 from resolve_kernel_collection_interfaces import commands
 data=SOURCE.read_bytes();at=next(o for o,c,n in commands(data,0) if c==0x80000034);fo=struct.unpack_from('<I',data,at+8)[0];_,_,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',data,fo);assert(fmt,symfmt)==(2,0)
 for a in ordinary:
  word=int.from_bytes(IMAGE.read(a,8),'little');assert word>>62==1 and ((word>>24)&255)==0
  ordinal=word&0xffffff;assert ordinal<count; iw,addend=struct.unpack_from('<Ii',data,fo+imports+ordinal*8);start=fo+symbols+(iw>>9);name=data[start:data.index(0,start)].decode();inline=(word>>32)&0x7ffff;inline-=0x80000 if inline&0x40000 else 0
  assert addend==inline==0 and FIXUPS[a]['target'].split('/',1)[1]==name
  out['records'].append({'address':hex(a),'word':hex(word),'pointer_format':12,'authenticated':False,'bind':True,'import_ordinal':ordinal,'library_ordinal':iw&255,'import_name':name,'import_addend':addend,'pointer_addend':inline})
 return out

def main():
 snap=json.loads((ROOT/'daemon_callback_revisit_snapshot.json').read_text());profile=json.loads((ROOT/'daemon_callback_revisit_profiles.json').read_text());trace=unpack(profile);F=int(snap['frame_SP'],16);H=int(snap['arena_owner'],16);reg=dict(trace['initial_registers']);checkpoints={};fillentries=[];fills=[];code_reads=[];cache=int.from_bytes(snapshot_read(snap,0x1010c8268,8),'little');codeaddr=int.from_bytes(snapshot_read(snap,0x1010ca2a8,8),'little')^0x12af5504870a589f;calls=[]
 points={0x100add594,0x100add6bc,0x100add72c,0x100add7d4,0x100add7d8,0x100acd9c4,0x100a0c9bc,0x100301508,0x100462818,0x100462924,0x100462974,0x1003fae50}
 previous=None
 for j,step in enumerate(trace['steps']):
  pc=int(step['pc'],16)
  if pc in points:checkpoints.setdefault(hex(pc),[]).append({'source_visit_index':j,'registers':reg.copy()})
  if pc==0x1004c831c and previous!=0x1004c83bc:fillentries.append({'source_visit_index':j,'registers':reg.copy()})
  if step['mnemonic']=='blraa':calls.append({'pc':hex(pc),'target':step['target'],'modifier16':step['modifier16'],'registers8':{f'x{k}':reg[f'x{k}']for k in range(8)}})
  for e in step['events']:
   a=int(e['address'],16)
   if e['kind']=='read'and codeaddr<=a<codeaddr+32768:code_reads.append({'pc':step['pc'],**e})
   if pc==0x1004c8398 and e['kind']=='write':
    if not fills or a!=fills[-1]['last_address']-1:fills.append({'first_address':a,'last_address':a,'writes':0})
    fills[-1]['last_address']=a;fills[-1]['writes']+=1
  reg.update(step['registers_after']);previous=pc
 for entry,group in zip(fillentries,fills):
  assert int.from_bytes(bytes.fromhex(entry['registers']['x12']['hex']),'little')==group['writes'];group.update(start=hex(group['last_address']),end=hex(group['first_address']+1),initial_index=entry['registers']['x16'])
 point=checkpoints['0x100462818'][0];D=int.from_bytes(bytes.fromhex(point['registers']['x15']['hex']),'little');seed=int.from_bytes(bytes.fromhex(point['registers']['x16']['hex']),'little')&0xffffffff;before=bytearray(snapshot_read(snap,D,2184));known=bytearray(zlib.decompress(base64.b64decode(snap['heap_owner']['known_mask_zlib_base64']))[D-H:D-H+2184]);after=None
 for j,step in enumerate(trace['steps']):
  if j==point['source_visit_index']:assert all(known);before_snapshot=bytes(before)
  if step['pc']=='0x100462974'and after is None:after=bytes(before)
  for e in step['events']:
   if e['kind']!='write':continue
   a=int(e['address'],16);lo=max(D,a);hi=min(D+2184,a+e['size_bytes'])
   if lo<hi:
    value=bytes.fromhex(e['value']['hex']);before[lo-D:hi-D]=value[lo-a:hi-a];known[lo-D:hi-D]=bytes([1])*(hi-lo)
 assert after is not None
 spans=[]
 for label,a,z in SPANS:
  b=IMAGE.read(a,z-a);ins=list(CS.disasm(b,a));assert sum(i.size for i in ins)==len(b);spans.append({'label':label,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':bytes(i.bytes).hex()}for i in ins]})
 fix=verify_fixups([int(a,16)for a in trace['used_fixups']]);deps=['daemon_callback_revisit_snapshot.json','daemon_callback_revisit_profiles.json','daemon_callback_revisit_replays.json','daemon_callback_simd_checks.json','daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_proofs.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'source_fixups':fix,'checkpoints':checkpoints,'calls':calls,'fill_entries':fillentries,'fill_ranges':fills,'cached_table_address':hex(cache),'selected_code_address':hex(codeaddr),'selected_code_reads':code_reads,'context_payload':{'address':hex(D),'extent_bytes':2184,'seed32':hex(seed),'before_hex':before_snapshot.hex(),'after_hex':after.hex(),'vector_constants':{name:point['registers'][name]for name in ['q15','q26','q27','q28','q29','q30','q31']}},'final_registers':reg,'creator_boundary':trace['boundary'],'unknown_inputs':trace['origins'],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'fixups':len(fix['records']),'source_calls':len(calls),'fill_calls':len(fills),'code_reads':len(code_reads),'context_seed':hex(seed)}),flush=True)
if __name__=='__main__':main()
