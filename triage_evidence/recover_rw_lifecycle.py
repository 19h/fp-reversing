#!/usr/bin/env python3
"""Original RW allocation/free ABI and bounded kext producer candidates.

Read-only KC/normalized image. O(B+I+256R+chain work) time/source space.
No heap, synchronization, provider, crypto, native target or IDB execution.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,selected,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from resolve_kernel_collection_interfaces import commands
TABLE=0xfffffe000846c420;POOL=0xfffffe00084716e0
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def state_index(s):return s^((((s+0xa0)^0xb025e4d5)+0x4fda12ff)&0xffffffff)
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e)
 fs=[function(k,e,a)for a in[0xfffffe000a508d7c,0xfffffe000a508d84,0xfffffe000a50d088,0xfffffe000a5302e4]]
 for f in fs:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 kernels=[k.function(a)for a in[0xfffffe000c4bb6e4,0xfffffe000c4bb780,0xfffffe000bd06180,0xfffffe000bd062b8,0xfffffe000bcfefc8,0xfffffe000bd7a4b8,0xfffffe000bd03ad0]]
 specs=[('resolved_allocator',0xfffffe00079171c0,0xfffffe0007919bb0,0xca,0x996,TABLE,0,0xfffffe000a508d7c),('same_modifier_internal_helper',qword(POOL+0x308),qword(POOL+0x420),0x0d,0xa36,TABLE,0,0xfffffe000a560468),('early_table_base',0xfffffe000791d3b0,0xfffffe0007920e10,0x3b,-0x3f,POOL,-8,TABLE),('resolved_free',0xfffffe0007920c10,0xfffffe00079170c0,0xaa,0x97b,TABLE,0,0xfffffe000a508d84)];rules=[]
 for label,l,r,key,add,base,bias,target in specs:
  b=selected(l,r,key,add,base=base,bias=bias);assert int(b['target'],16)==target;b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 bindings=[]
 for name,w,stub,slot in[('IORWLockAlloc',0xfffffe000a508d7c,0xfffffe000a69f104,0xfffffe000847c3b0),('IORWLockFree',0xfffffe000a508d84,0xfffffe000a69f114,0xfffffe000847c3b8)]:
  p=pointer(k,slot);syms=k.symbols([int(p['target'],16)])[p['target']];assert '_'+name in[x['name']for x in syms];bindings.append({'name':name,'wrapper':span(k,w,w+8),'stub':span(k,stub,stub+16),'original_pointer':p,'exact_symbols':syms})
 view=0xfffffe0007e42bd8;raw=k.read(view,64);nameptr=pointer(k,view+16);sigptr=pointer(k,view+32);name=k.read(int(nameptr['target'],16),64).split(b'\0')[0];assert name==b'site.lck_rw_old_t';flags,size=struct.unpack_from('<2I',raw,40);assert flags==0x6a and size==16
 desc={'address':hex(view),'bytes64_hex':raw.hex(),'site_name_pointer':nameptr,'site_name_bytes_hex':(name+b'\0').hex(),'site_name':name.decode(),'signature_pointer':sigptr,'signature_first16_hex':k.read(int(sigptr['target'],16),16).hex(),'flags_word_at40':flags,'size_word_at44':size,'initial_runtime_links_first16_hex':raw[:16].hex()}
 spans=[dict(span(k,a,z),label=label)for label,a,z in[('allocator_call_and_return',0xfffffe000a530fc4,0xfffffe000a531058),('early_call',0xfffffe000a50d1c0,0xfffffe000a50d258),('shared_store_candidate',0xfffffe000a56d3c0,0xfffffe000a56d3fc),('free_and_cell_clear',0xfffffe000a579364,0xfffffe000a5793c0)]]
 census=[];scan_words=0
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19 or IMAGE.data[at+8:at+24].split(b'\0')[0]!=b'__TEXT_EXEC':continue
  va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24);scan_words=n//4
  for j,(word,)in enumerate(struct.iter_unpack('<I',IMAGE.data[off:off+n//4*4])):
   if word&0xffe0001f!=0xd2800011 or(word>>5)&0xffff not in[0x9f59,0x9d3a]:continue
   a=va+j*4;ix=bisect.bisect_right(catalog,a)-1;census.append({'modifier_PC':hex(a),'call_PC':hex(a+4),'modifier16':hex((word>>5)&0xffff),'bytes8_hex':IMAGE.read(a,8).hex(),'following_instruction':[{'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a+4,4),a+4)],'enclosing_compiler_start':hex(catalog[ix]),'enclosing_compiler_end':hex(catalog[ix+1]),'resolution':'native_allocator'if a+4==0xfffffe000a531028 else'internal_helper'if a+4==0xfffffe000a50d254 else'native_free'if a+4==0xfffffe000a5793b8 else'unresolved_candidate'})
 assert len(census)==11
 n=(POOL-TABLE)//8;states=[]
 for s in range(n):
  ix=state_index(s)
  if not 0<=ix<n:continue
  target=qword(TABLE+8*ix)
  if not 0xfffffe000a502000<=target<0xfffffe000a69f000:continue
  ins=list(CS.disasm(IMAGE.read(target,20),target))
  if any(i.mnemonic in['str','stur','stp','mov']and(i.op_str.startswith(('x0,','w0,'))or i.mnemonic=='mov'and i.op_str.endswith(', x0'))for i in ins):states.append({'state32':s,'index32':ix,'target':hex(target)})
 assert len(states)==64 and {r['target']for r in states}=={'0xfffffe000a56d3c0'}
 data={'attribute_default':{'address':'0xfffffe0007e63610','bytes16_hex':k.read(0xfffffe0007e63610,16).hex()},'initial_header_constant':{'address':'0xfffffe000700dd08','bytes8_hex':k.read(0xfffffe000700dd08,8).hex()},'IOKit_group_cell':{'address':'0xfffffe000cb52628','bytes8_hex':k.read(0xfffffe000cb52628,8).hex(),'exact_symbols':k.symbols([0xfffffe000cb52628])['0xfffffe000cb52628']}}
 h=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IOLocks.h');lines=h.read_text().splitlines(keepends=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','sample_lock_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'kernel_functions':kernels,'bank_rules':rules,'original_bindings':bindings,'typed_site':desc,'data':data,'spans':spans,'literal_modifier_census':{'scope':'All aligned MOVZ X17,imm16 at shift0 in file-backed __TEXT_EXEC for two modifiers; excludes other constructions/registers and does not identify callees by modifier.','words_scanned':scan_words,'rows':census},'allocation_store_candidates':{'enumerated_state_domain':[0,n],'filter':'nonnull return branch in range; code target; first five instructions use X0 in STR/STUR/STP/MOV or MOV from X0','states':states,'original_target_pointer':pointer(k,TABLE+8*0x8b4),'destination_X20_provenance_proved':False,'cached_cell_association_proved':False},'SDK_header':{'path':str(h),'sha256':sha(h),'first_line':238,'last_line':254,'text':''.join(lines[237:254])},'native_target_executed':False,'native_lock_lifetime_proved':False,'cached_cell_publication_proved':False,'full_goal_complete':False};(ROOT/'rw_lifecycle_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kext_functions':len(fs),'kernel_functions':len(kernels),'banks':len(rules),'modifier_candidates':len(census),'store_candidate_states':len(states)}),flush=True)
if __name__=='__main__':main()
