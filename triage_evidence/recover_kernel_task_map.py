#!/usr/bin/env python3
"""Original named task/map accessors, replacement and bounded writer/caller scan.
O(instruction words+candidate windows) time; O(captured bytes+metadata) space.
Syntactic scan excludes arbitrary indirect calls and signature constructions.
"""
import json,struct
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
FUNCTIONS=[0xfffffe000bd41ac4,0xfffffe000bd7e658,0xfffffe000bd7e9c4,0xfffffe000bcdd350,0xfffffe000bd7e78c,0xfffffe000bdd0208]
def span(k,a,n):return {'start':hex(a),'bytes_hex':k.read(a,n).hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(k.read(a,n),a)]}
def recover():
 im=Image();k=im.k;functions=[k.function(a)for a in FUNCTIONS];names=k.symbols([0xfffffe000bd41ac4,0xfffffe000bd7e658]);assert any(x['name']=='_current_task'for x in names['0xfffffe000bd41ac4'])and any(x['name']=='_get_task_map'for x in names['0xfffffe000bd7e658'])
 words=0;candidates=[];calls=[];seen=set()
 for e in k.entries:
  for s in e['sections']:
   key=(s['address'],s['size'])
   if key in seen or not s['flags']&0x80000400:continue
   seen.add(key);raw=k.read(s['address'],s['size']&~3);words+=len(raw)//4
   for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
    a=s['address']+4*j
    if w&0xffffffe0==0xf2ebdf00:
     ins=list(k.cs.disasm(k.read(a,64),a))
     if any(i.mnemonic=='pacda'for i in ins):candidates.append({'entry':e['name'],'MOVK':hex(a),'review':span(k,a-20,96)})
    if w&0xfc000000==0x94000000:
     imm=w&0x3ffffff;imm-=(imm>>25)<<26
     if(a+(imm<<2))&((1<<64)-1)==0xfffffe000bd7e78c:calls.append({'entry':e['name'],'call':hex(a),'review':span(k,a-24,64)})
 assert len(candidates)==7 and len(calls)==1 and calls[0]['call']=='0xfffffe000c29edb4'
 roles={0xfffffe000bd41acc:('b','#0xfffffe000bd7e9c4'),0xfffffe000bd7e65c:('ldr','x16, [x0, #0x28]!'),0xfffffe000bd7e668:('movk','x17, #0x5ef8, lsl #48'),0xfffffe000bcdd3a0:('ldr','x16, [x23, #0x428]'),0xfffffe000bd7e888:('str','x17, [x9]'),0xfffffe000bd7e8d0:('str','x17, [x1, #0x428]'),0xfffffe000bd7e8e8:('bl','#0xfffffe000be63ea0'),0xfffffe000bd7e938:('mov','x0, x22'),0xfffffe000bdd0230:('str','w8, [x19, #0xb0]'),0xfffffe000bdd0234:('str','xzr, [x19, #0xb8]'),0xfffffe000c29edb8:('str','x0, [x19, #0x2f8]')};checked=[]
 for a,(m,o)in roles.items():
  i=next(k.cs.disasm(k.read(a,4),a));assert(i.mnemonic,i.op_str)==(m,o);checked.append({'pc':hex(a),'mnemonic':m,'operands':o,'bytes_hex':i.bytes.hex()})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_native_reader.py','kernel_copyin_policy_source.json','kernel_copyin_policy_checks.json']},'kernel_sha256':k.sha256,'functions':functions,'exact_symbols':names,'instruction_words_scanned':words,'signing_candidates':candidates,'direct_replacement_calls':calls,'exact_instruction_roles':checked,'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'kernel_task_map_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'functions':len(r['functions']),'instructions':sum(len(f['instructions'])for f in r['functions']),'scan_words':r['instruction_words_scanned'],'signing_candidates':len(r['signing_candidates']),'direct_calls':len(r['direct_replacement_calls']),'roles':len(r['exact_instruction_roles'])}))
