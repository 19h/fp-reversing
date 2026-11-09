#!/usr/bin/env python3
"""Recover arena/global lock gates, descriptor construction and bounded readers.
O(source visits+snapshot bytes+annotations) time/space. Saved comments are
candidates; current IDB bytes and original fixups are independently compared.
"""
import json,hashlib,zlib,base64,ast
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,qword
from daemon_import_bindings import binding
from recover_daemon_callback_revisit import verify_fixups,snapshot_read
SPANS=[('first_creator_call_gate',0x10049263c,0x100492680),('second_creator_prekey',0x1003ae510,0x1003ae53c),('second_creator_pack_gate',0x1003ae594,0x1003ae640),('global_buffer_allocation',0x10038eb04,0x10038eb98),('failure_pointer_publication',0x1003c4388,0x1003c43c4),('failure_context_reader',0x10039cb60,0x10039cbb0),('failure_indirect_read',0x1003868c0,0x100386914),('header_vector_codec',0x1003c41ec,0x1003c4250),('header_word_remainder',0x1003c42d4,0x1003c42e8),('array_setup',0x100393d68,0x100393dc0),('array_record_loop',0x100407458,0x100407498),('return_epilogue',0x1002db818,0x1002db870),('candidate_buffer_reader',0x100a63750,0x100a6379c),('candidate_lock_reader',0x10021ed4c,0x10021ee20)]

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(r):return json.loads(zlib.decompress(base64.b64decode(r['payload_zlib_base64'])))
def integer(s):return int.from_bytes(bytes.fromhex(s['hex']),'little')
def ida_output(r):
 s=r['content'][0]['text'];a=s.index('[assist:tool-output]')+len('[assist:tool-output]');z=s.index('[/assist:tool-output]');return json.loads(s[a:z])
def main():
 snap=json.loads((ROOT/'daemon_context_lock_snapshot.json').read_text());p=json.loads((ROOT/'daemon_context_lock_profiles.json').read_text());extended=json.loads((ROOT/'daemon_context_lock_success.json').read_text());cases=p['cases']+[extended['case']];F=int(snap['frame_SP'],16);R=F+0xaf8;paths=[];allfix=set();allpool={};points={0x100492644,0x100492658,0x100492664,0x10049267c,0x1003ae608,0x1003ae60c,0x1003ae63c,0x10038eb5c,0x1003c4388,0x1003c43b4,0x10039cb84,0x1003868d8,0x1002db86c,0x100407458,0x10040748c,0x10038eb60,0x100393d34}
 for case in cases:
  t=unpack(case);reg=t['initial_registers'].copy();checkpoints=[];records=[];memory={};allfix.update(int(a,16)for a in t['used_fixups']);allpool.update(t['source_pool'])
  for a,n in [(R,24),(0x1010c9298,8),(0x1010c8218,24),(0x6500115b28,8)]:memory.update((a+j,b)for j,b in enumerate(snapshot_read(snap,a,n)))
  def bytes_at(a,n):return bytes(memory[a+j]for j in range(n))
  for j,step in enumerate(t['steps']):
   pc=int(step['pc'],16)
   if pc in points:checkpoints.append({'pc':step['pc'],'source_visit_index':j,'registers':reg.copy()})
   if step['mnemonic']=='blraa'and step.get('target')=='0x10043a240':records.append({'call_pc':step['pc'],'source_visit_index':j,'record':hex(R),'bytes_hex':bytes_at(R,24).hex(),'destination':hex(int.from_bytes(bytes_at(R+8,8),'little'))})
   for e in step['events']:
    if e['kind']=='write'and'hex'in e['value']:
     a=int(e['address'],16);b=bytes.fromhex(e['value']['hex']);memory.update((a+j,v)for j,v in enumerate(b))
   reg.update(step['registers_after'])
  paths.append({'configuration':case['configuration'],'source_visits':len(t['steps']),'creator_records':records,'checkpoints':checkpoints,'boundary':t['boundary'],'final_global_descriptor_hex':bytes_at(0x1010c8218,24).hex(),'final_context_pointer':hex(int.from_bytes(bytes_at(0x1010c9298,8),'little')),'final_arena_lock_cell':hex(int.from_bytes(bytes_at(0x6500115b28,8),'little')),'api_models':t['api_models'],'allocated_owners':t['allocated_owners']})
 spans=[]
 for name,a,z in SPANS:
  b=IMAGE.read(a,z-a);ins=list(CS.disasm(b,a));assert sum(i.size for i in ins)==len(b);spans.append({'label':name,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 ann=Path('/Users/___/Downloads/fpx/analysis/fp_annotate.py');tree=ast.parse(ann.read_text());node=next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='DATA'for t in n.targets));saved=ast.literal_eval(node);candidates=[{'pc':hex(r[0]),'comment':r[1],'repeatable':r[2]}for r in saved['comments']if r[0]in [0x100a63754,0x10021ed4c]];assert len(candidates)==2
 slot=POOL+0x6bb*8;target=qword(slot);assert(target+0xffffffffd5a43965)&((1<<64)-1)==0x1010c8218;allfix.add(slot)
 ida=json.loads((ROOT/'daemon_context_lock_ida_bytes.json').read_text());assert not ida.get('isError');live=ida_output(ida);matches=[]
 for row in live['results']:
  a=int(row['address'],16);b=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(b))==b
  partial=[]
  for i in row['instructions']:
   visible=bytes.fromhex(i['bytes']);assert len(visible)<=i['size']and IMAGE.read(int(i['address'],16),len(visible))==visible
   if len(visible)!=i['size']:partial.append({'address':i['address'],'logical_size_bytes':i['size'],'reported_bytes_count':len(visible),'disasm':i['disasm']})
  matches.append({'address':row['address'],'size_bytes':len(b),'instructions_checked':len(row['instructions']),'macro_rows_with_partial_bytes':partial,'sha256':hashlib.sha256(b).hexdigest()})
 deps=['daemon_context_lock_snapshot.json','daemon_context_lock_profiles.json','daemon_context_lock_success.json','daemon_context_lock_live_ida.json','daemon_context_lock_ida_bytes.json','daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_proofs.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'source_fixups':verify_fixups(allfix),'source_pool_opcodes':len(allpool),'paths':paths,'API_bindings':{hex(a):binding(a)for a in [0x10109ff58,0x1010a0dd0]},'saved_annotation_candidates':{'path':str(ann),'sha256':sha(ann),'records':candidates,'semantic_names_authoritative':False},'conditional_pool_resolution':{'premise':'dynamic pool index ==0x6BB; saved comments propose this for candidate reader sites, not proved from arbitrary incoming state','slot':hex(slot),'original_decoded_rebase':hex(target),'bias':'0xFFFFFFFFD5A43965','effective_global':'0x1010c8218'},'live_IDB_byte_matches':matches,'live_IDB_instruction_rows':sum(r['instructions_checked']for r in matches),'live_IDB_automatic_analysis_complete':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'paths':len(paths),'source_spans':len(spans),'fixups':len(out['source_fixups']['records']),'IDA_instruction_rows':out['live_IDB_instruction_rows']}),flush=True)
if __name__=='__main__':main()
