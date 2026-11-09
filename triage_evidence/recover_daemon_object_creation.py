#!/usr/bin/env python3
"""Original-source allocation/predecessor contracts, not native reachability.
O(text bytes + fixups + 256*bank rules) time/space; no target code executes.
"""
import json,hashlib,struct,re
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS,selected,qword
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output
from recover_daemon_iokit_census import text_section
from daemon_import_bindings import binding

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def span(n,a,z):
 b=IMAGE.read(a,z-a)
 return {'label':n,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]}
def auth_indices(div):
 return sorted((a-TABLE)//8 for a,r in FIXUPS.items()if a>=TABLE and (a-TABLE)%8==0 and f'div=0x{div:04X} ad=0 key=IA' in r['annotation'])
def meta(i):
 a=TABLE+i*8;r=FIXUPS.get(a)
 return {'index':hex(i),'slot':hex(a),'target':hex(r['target'])if r and isinstance(r['target'],int)else r['target']if r else None,'fixup':r}
def phases(b):
 l=((b+0xeffc4ff6)&0xffffffff)&0x10035fbd;h=((b+0x5bf03876)&0xffffffff)&0xa40f773d
 return l,h,(l+h-0x8da5)&0xffffffff
def main():
 spans=[span(n,a,z)for n,a,z in [('save_dispatch',0x100a035f0,0x100a03688),('marker_set',0x1009f735c,0x1009f737c),('malloc872',0x100c11650,0x100c116e4),('zero_entry',0x1009c5844,0x1009c5868),('zero_junction',0x100abe63c,0x100abe680),('zero_phase',0x1009c1404,0x1009c1458),('lazy_gate',0x10064ffbc,0x100650004),('nonnull_frontier',0x1006534bc,0x1006534ec),('null_result',0x100cb2ba8,0x100cb2be0),('callback_entry',0x100b280c8,0x100b28100)]]
 valid=auth_indices(0xe9b9);assert valid==[0x9768,0x978f,0x97df,0x97e8,0x97f1,0x97fb,0xc3de]
 pairs=[]
 for b in valid:
  l,h,d=phases(b);i=b|d
  pairs.append({'marker0_index':hex(b),'incoming_w8':hex((b-0x354d)&0xffffffff),'L':hex(l),'H_phase_Q':hex(h),'delta':hex(d),'marker1_index':hex(i),'both_IA_E9B9_metadata':i in valid})
 assert [x['incoming_w8']for x in pairs if x['both_IA_E9B9_metadata']]==['0x621b']
 marker=[{'byte':m,**meta(0x9768|((m*0x93)&0xffffffff))}for m in range(256)]
 banks=[{'label':'malloc872',**selected(0x100e99a00,0x100f4e390,0x9c,0xcbdf)}]
 indices=set(valid)|{0x994,0xa39a,0x344f,0x3456,0x5e53,0x7e9,0x443f,0x447c,0x8068,0x8050,0x1fd7,0x48df,0x895d,0x8965,0x4730,0x4731,0x4737,0x4732}
 indices.update(int(r['index'],16)for r in marker if r['fixup'])
 slots=[meta(i)for i in sorted(indices)];fix={int(r['slot'],16)for r in slots};fix.update(int(r['slot'],16)for r in banks)
 live=[]
 r=json.loads((ROOT/'daemon_object_creation_ida_bytes.json').read_text());assert not r.get('isError')
 for row in ida_output(r)['results']:
  a=int(row['address'],16);b=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(b))==b
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes'])
  live.append({'start':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'display_rows':len(row['instructions']),'partial_macro_rows':sum(len(bytes.fromhex(i['bytes']))<i['size']for i in row['instructions']if 'size'in i),'undecoded_byte_rows':sum('size'not in i for i in row['instructions'])})
 a,n=text_section();raw=IMAGE.read(a,n);branch=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w==0xd2800000|(0xe9b9<<5)|17:
   pc=a+j*4;nexti=list(CS.disasm(IMAGE.read(pc+4,4),pc+4))
   if len(nexti)==1 and nexti[0].mnemonic=='braa':branch.append({'modifier_pc':hex(pc),'branch_pc':hex(pc+4),'bytes_hex':IMAGE.read(pc,8).hex(),'branch_operands':nexti[0].op_str})
 assert len(branch)==6
 literal=[a+j*4 for j,(w,)in enumerate(struct.iter_unpack('<I',raw))if w in[0x52800000|(872<<5),0xd2800000|(872<<5)]];assert literal==[0x100c116a8]
 deps=['daemon_receive_fixups.txt','daemon_receive_tools.py','daemon_object_creation_ida_bytes.json','daemon_object_creation_ida_functions.json','daemon_object_creation_ida_xrefs.json','daemon_object_consumers_contracts.json','daemon_mode471c_lifecycle_contracts.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{x:sha(ROOT/x)for x in deps},'source_sha256':sha(SOURCE),'spans':spans,'IA_E9B9_slots':[meta(i)for i in valid],'binary_marker_candidate_pairs':pairs,'all_marker_bytes':marker,'banks_exhaustive256':banks,'slots':slots,'original_fixups':verify_used_fixups(fix),'live_IDB_matches':live,'text_census':{'address':hex(a),'size_bytes':n,'sha256':hashlib.sha256(raw).hexdigest(),'literal_E9B9_braa_pairs':branch,'literal_malloc872_sites':[hex(x)for x in literal],'exclusions':'Computed sizes/modifiers and other instructions excluded; not a complete caller census.'},'original_malloc_binding':binding(0x10109ff58),'assumptions':{'entry':'Analyst cutpoint at A035F0 with W8=621B; no continuous native caller established.','marker':'Native address and producer unknown; 0/1 protocol is a tested precondition, not a global invariant.','roots':'SP+2998=100E99A00,SP+2990=100F4E390,SP+29A0=TABLE; readable controller owners supplied.','allocation':'Imported ABI outcome is an explicit private model; native malloc, object type and registry publication unknown.','PAC':'Original words and discriminator equality only; no native authentication.'},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_object_creation_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'fixups':len(fix),'marker_bytes':len(marker),'IDB_bytes':sum(x['size_bytes']for x in live),'matching_binary_phase_candidates':1}),flush=True)
if __name__=='__main__':main()
