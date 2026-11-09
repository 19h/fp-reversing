#!/usr/bin/env python3
"""Read-only dual-slice launchd interface capture; optional proc metadata snapshot.
O(B+F+I) time and space: file bytes B, fixups F, selected instructions I.
Never executes launchd, registers ports, changes services, or acquires a task port.
"""
import bisect,ctypes,errno,json,os,re,struct,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
from bootpolicy_cache_reader import CS
from recover_rpc700_namespace import binary
from recover_managed_fairplay_bridge import Native,sha,h
from resolve_kernel_collection_interfaces import macho,commands,string
from recover_host_special_registration import fixup_reference,SDK
ROOT=Path(__file__).resolve().parent;P='launchd_variant_binding';PATH=Path('/sbin/launchd')
FLAGS=['target_executed','target_emulated','host_special_port_set','native_port_identity_proved','hardware_PAC_checked','native_RPC700_exchange','full_goal_complete']
DEPS=['recover_rpc700_namespace.py','recover_managed_fairplay_bridge.py','resolve_kernel_collection_interfaces.py','recover_host_special_registration.py','bootpolicy_cache_reader.py','host_special_registration_source.json']
LLVM=Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump')
class Variant(Native):
 def prepare(self,label):
  cmd=[str(LLVM),'--macho','--arch='+label,'--disassemble',str(PATH)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0
  self.llvm={}
  for line in r.stdout.splitlines():
   m=re.match(r'^([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+){4})(\S+)(?:\s+(.*))?$',line)
   if m:self.llvm[int(m[1],16)]={'bytes':bytes.fromhex(m[2]).hex(),'mnemonic':m[3],'operands':(m[4]or'').split(';')[0].strip()}
  self.llvm_record={'command':cmd,'exit_code':r.returncode,'stdout_sha256':h(r.stdout.encode()),'stderr':r.stderr,'stderr_sha256':h(r.stderr.encode()),'global_invalid_encoding_warnings':r.stderr.count('invalid instruction encoding'),'global_full_decode_proved':False}
 def function(self,a):
  ix=self.starts.index(a);end=self.starts[ix+1];raw=self.read(a,end-a);out=[];extended=[]
  for pc in range(a,end,4):
   b=self.read(pc,4);ll=self.llvm[pc];assert ll['bytes']==b.hex()and ll['mnemonic']not in['.long','.word','<unknown>']
   cc=list(CS.disasm(b,pc));ins={'ea':hex(pc),'mnemonic':cc[0].mnemonic if cc else ll['mnemonic'],'operands':cc[0].op_str if cc else ll['operands'],'bytes':b.hex(),'decoder':'Capstone'if cc else'LLVM','LLVM':ll}
   if not cc:extended.append(ins)
   out.append(ins)
  return {'start':hex(a),'end':hex(end),'bytes':raw.hex(),'sha256':h(raw),'instructions':out,'extended':extended}
def variant(meta,sl,raw):
 data=raw[sl['offset']:sl['offset']+sl['size_bytes']];m=macho(data,0,'launchd variant');loads=[];imports=[]
 for at,c,z in commands(data,0):
  if c in(0xc,0x80000018,0x8000001f,0x80000023,0x20):loads.append(string(data,at+struct.unpack_from('<I',data,at+8)[0]))
  if c==0x80000034:
   fo,fs=struct.unpack_from('<II',data,at+8);ver,st,im,sy,n,fmt,sf=struct.unpack_from('<7I',data,fo);assert(ver,sf)==(0,0)and fmt in(1,2)
   for j in range(n):
    iw=struct.unpack_from('<I',data,fo+im+(4 if fmt==1 else 8)*j)[0];lib=iw&255;lib=lib-256 if lib&128 else lib;imports.append({'ordinal':j,'name':string(data,fo+sy+(iw>>9)),'library_ordinal':lib})
 for row in imports:row['library']=loads[row['library_ordinal']-1]if 0<row['library_ordinal']<=len(loads)else'special ordinal'
 return Variant({**meta,'selected_slice':sl,'uuid':m['uuid'],'segments':m['segments'],'sections':m['sections'],'loads':loads,'imports':imports})
def refs(n,target):
 t=next(r for r in n.meta['sections']if r['section']=='__text');raw=n.read(t['address'],t['size']);out=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  pc=t['address']+4*j
  if w&0x9f000000==0x90000000:
   imm=((w>>29)&3)|((w>>5&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm
   if j*4+8>len(raw):continue
   w2=struct.unpack_from('<I',raw,j*4+4)[0];rd=w&31
   if w2&0xff000000!=0x91000000 or w2&31!=rd or(w2>>5&31)!=rd:continue
   value=(pc&~4095)+(imm<<12)+((w2>>10&4095)<<(12 if w2>>22&1 else 0))
  elif w&0x9f000000==0x10000000:
   imm=((w>>29)&3)|((w>>5&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm;value=pc+imm
  else:continue
  if value==target:out.append({'site':hex(pc),'containing_start':hex(n.starts[bisect.bisect_right(n.starts,pc)-1])})
 return out
def branches(n,target):
 t=next(r for r in n.meta['sections']if r['section']=='__text');out=[]
 for j,(word,)in enumerate(struct.iter_unpack('<I',n.read(t['address'],t['size']))):
  if word&0x7c000000!=0x14000000:continue
  imm=word&0x3ffffff;imm=imm-0x4000000 if imm&0x2000000 else imm;pc=t['address']+4*j
  if pc+4*imm==target:out.append({'site':hex(pc),'target':hex(target),'word':hex(word),'containing_start':hex(n.starts[bisect.bisect_right(n.starts,pc)-1])})
 return out
def capture(n,label):
 n.prepare(label);stubs={}
 for s in n.meta['sections']:
  if s['section']=='__auth_stubs':
   for a in range(s['address'],s['address']+s['size'],16):
    row=n.stub(a);stubs[row['binding']['symbol']]=row
 sym={int(r['address'],16):name for name,r in stubs.items()};hits=branches(n,int(stubs['_host_set_special_port']['address'],16));roles={}
 for hit in hits:
  body=n.function(int(hit['containing_start'],16));prev=next(i for i in body['instructions']if int(i['ea'],16)==int(hit['site'],16)-4)['operands'];role={'w1, #0x16':'fixed22','w1, #0x10':'fixed16','w2, #0':'cleanup','x1, x21':'publisher'}[prev];assert role not in roles;roles[role]=body;hit['role']=role
 def internal(body):return list(dict.fromkeys(int(i['operands'][1:],0)for i in body['instructions']if i['mnemonic']=='bl'and i['operands'].startswith('#')and int(i['operands'][1:],0)in n.starts))
 sec=next(s for s in n.meta['sections']if s['section']=='__cstring');buf=n.read(sec['address'],sec['size']);key=sec['address']+buf.index(b'HostSpecialPort\0');rr=refs(n,key);cand={r['containing_start']for r in rr};assert len(cand)==1;roles['parser']=n.function(int(cand.pop(),16));parents=refs(n,int(roles['parser']['start'],16));cand={r['containing_start']for r in parents};assert len(cand)==1;roles['constructor']=n.function(int(cand.pop(),16))
 for a in internal(roles['parser']):
  body=n.function(a)
  if any(i['mnemonic']=='str'and i['operands']=='w1, [x0, #0x50]'for i in body['instructions']):assert 'task_field'not in roles;roles['task_field']=body
 pub=roles['publisher']['instructions'];sets={}
 for k,i in enumerate(pub):
  if i['mnemonic']=='bl'and k and pub[k-1]['mnemonic']=='mov'and pub[k-1]['operands']in['w1, #2','w1, #3']:sets.setdefault(pub[k-1]['operands'],set()).add(int(i['operands'][1:],0))
 cand=sets['w1, #2']&sets['w1, #3'];assert len(cand)==1;roles['owner_query']=n.function(cand.pop())
 cs=[int(i['operands'][1:],0)for k,i in enumerate(pub)if i['mnemonic']=='bl'and k and pub[k-1]['mnemonic']=='mov'and pub[k-1]['operands']=='w1, #1'];assert len(set(cs))==1;roles['send_name']=n.function(cs[0])
 candidates=[]
 for a in internal(roles['send_name']):
  body=n.function(a)
  if any(i['mnemonic']=='bl'and sym.get(int(i['operands'][1:],0))=='_xpc_mach_send_create_with_disposition'for i in body['instructions']):candidates.append(body)
 assert len(candidates)==1;roles['send_object']=candidates[0]
 for a in internal(roles['publisher']):
  body=n.function(a)
  if any(i['mnemonic']=='b'and sym.get(int(i['operands'][1:],0))=='_host_set_exception_ports'for i in body['instructions']):assert 'exception'not in roles;roles['exception']=body
 owner=roles['owner_query']['instructions'];idx=next(j for j,i in enumerate(owner)if i['mnemonic']=='ldrsw'and i['operands']=='x16, [x17, x16, lsl #2]');table=int(owner[idx-2]['operands'].split('#')[1],0)+int(owner[idx-1]['operands'].split('#')[1],0);base=int(owner[idx+1]['operands'].split('#')[1],0);jump={'address':hex(table),'relative_base':hex(base),'bytes':n.read(table,40).hex(),'targets':[hex(base+v)for v in struct.unpack('<10i',n.read(table,40))]}
 section_records=[]
 for name in['__text','__cstring','__auth_got','__got']:
  s=next(s for s in n.meta['sections']if s['section']==name);section_records.append({'name':name,'address':hex(s['address']),'size_bytes':s['size'],'sha256':h(n.read(s['address'],s['size']))})
 return {'label':label,'uuid':n.inv['uuid'],'slice':n.inv['selected_slice'],'compiler_starts':len(n.starts),'import_count':len(n.inv['imports']),'fixups_count':len(n.fixups),'fixup_reference':fixup_reference(n),'LLVM':n.llvm_record,'roles':roles,'stubs':stubs,'setter_branch_candidates':hits,'host_property_literal':{'address':hex(key),'text':n.cstring(key),'references':rr},'parser_code_references':parents,'owner_query_jump_table':jump,'file_backed_sections':section_records}
def build():
 meta=binary(PATH);raw=PATH.read_bytes();variants=[capture(variant(meta,s,raw),label)for s,label in zip(meta['slices'],['arm64e','arm64e.x1'])];assert len(meta['slices'])==2
 counts={'variants':2,'roles_per_variant':11,'function_bodies':sum(len(v['roles'])for v in variants),'instructions':sum(len(b['instructions'])for v in variants for b in v['roles'].values()),'function_bytes':sum(len(bytes.fromhex(b['bytes']))for v in variants for b in v['roles'].values()),'LLVM_only_selected_words':sum(len(b['extended'])for v in variants for b in v['roles'].values()),'fixups_compared':sum(v['fixups_count']for v in variants),'setter_branch_candidates':sum(len(v['setter_branch_candidates'])for v in variants),'text_words_scanned':sum(s['size_bytes']//4 for v in variants for s in v['file_backed_sections']if s['name']=='__text')}
 return {'generator_sha256':sha(__file__),'dependencies':{p:sha(ROOT/p)for p in DEPS},'source_path':str(PATH),'source_sha256':sha(PATH),'source_size_bytes':len(raw),'variants':variants,'tools':[{'path':str(p),'sha256':sha(p)}for p in[LLVM,Path('/usr/bin/dyld_info')]],'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in[SDK/'usr/include/mach/machine.h',SDK/'usr/include/sys/proc_info.h',SDK/'usr/include/libproc.h']],'verified_source_counts':counts,'runtime_selected_slice':'unknown','native_observation_sha256':sha(ROOT/(P+'_observations.json')),**{k:False for k in FLAGS}}
def observe():
 path=ROOT/(P+'_observations.json');assert not path.exists(),'Frozen observation already exists'
 lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True);lib.proc_pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int];lib.proc_pidinfo.restype=ctypes.c_int;lib.proc_pidpath.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];lib.proc_pidpath.restype=ctypes.c_int
 rows=[]
 for pid in[1,os.getpid()]:
  buf=ctypes.create_string_buffer(8);ctypes.set_errno(0);ret=lib.proc_pidinfo(pid,19,0,buf,8);err=ctypes.get_errno();rows.append({'function':'proc_pidinfo','pid':pid,'flavor':19,'arg':0,'buffer_size_bytes':8,'return_value':ret,'errno':err,'errno_name':errno.errorcode.get(err,'0'),'raw_buffer_hex':buf.raw.hex(),'architecture_valid':ret==8,'cpu_type':struct.unpack('<ii',buf.raw)[0]if ret==8 else None,'cpu_subtype':struct.unpack('<ii',buf.raw)[1]if ret==8 else None})
 buf=ctypes.create_string_buffer(4096);ctypes.set_errno(0);ret=lib.proc_pidpath(1,buf,4096);err=ctypes.get_errno();rows.append({'function':'proc_pidpath','pid':1,'buffer_size_bytes':4096,'return_value':ret,'errno':err,'path':buf.value.decode()if ret>0 else None})
 obj={'generator_sha256':sha(__file__),'captured_utc':datetime.now(timezone.utc).isoformat(),'queries':rows,'scope':'Read-only libproc metadata; no task ports, privilege changes, target execution or service/port mutation. Valid architecture requires exactly eight returned bytes. Snapshot never refreshed by validation.','runtime_selected_slice':'unknown',**{k:False for k in FLAGS}};path.write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({'observation_path':str(path),'queries':rows}))
def main():
 if sys.argv[1:]==['--observe']:observe();return
 assert not sys.argv[1:];s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
if __name__=='__main__':main()
