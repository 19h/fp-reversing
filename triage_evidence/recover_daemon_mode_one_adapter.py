#!/usr/bin/env python3
"""Original 48 B wrapper,protected adapter/core and return-frame contracts.
O(source bytes+fixups+256*bank roles+recaptures),no target execution or IDB edits.
"""
import json
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,CS,block,selected,h,FLAGS,binding
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_adapter'
SCOPE='Mode1 object/local32 -> private48 B request -> adapterd03348/corecf0194;aligned address cookie,decoded mode4923,size32 predicate,budget/stack delta and immediate-rejection return. The32 B processing body,complete budget history,native owner/PAC/transport and daemon-kext exchange remain unproved.'
BLOCKS={'mode_one':0x1005b0494,'setup':0x10090151c,'entry':0x100729920,'wrapper':0x1009bb3b0,'relay':0x10068b47c,'caller_return':0x100911fe0,'adapter':0x100d03348,'core':0x100cf0194,'reject':0x100d7cc50,'accepted':0x100d5dfc8}
SPECS=[('seed',0x101031da0,0x100e99900,0x9a,0x486,POOL,0xffffffff9b6579d5),('wrapper_adapter',0x100e99a00,0x100f4e390,0x6d,0xcd48,TABLE,0),('adapter_controllerA',0x100e99a00,0x100f4e390,0x6d,0xeb7,POOL,0xffffffff8b42b121),('adapter_controllerB',0x100fc4130,0x101031ea0,0x4e,-0x6b,POOL,0xffffffffec9e1772),('adapter_LCG',0x101031da0,0x100e99900,0xa,0x481,POOL,0xffffffff9b6579d5),('adapter_dispatch',0x100fc4130,0x101031ea0,0xa3,0x8a8,POOL,0xffffffffd0c4d1ee),('adapter_core',0x101031da0,0x100e99900,0x86,0xcde4,TABLE,0),('core_controllerA',0x100e99a00,0x100f4e390,0x9c,0xe4d,POOL,0xffffffffcc0a8c25),('core_controllerB',0x100e99a00,0x100f4e390,0x78,-0xd,POOL,0xffffffffec9e1772),('core_fill',0x100e99a00,0x100f4e390,0xd7,0xcc0f,TABLE,0),('core_dispatch',0x100fc4130,0x101031ea0,0xbb,0x85f,POOL,0xffffffffd0c4d1ee)]
def capture(a,z):
 raw=IMAGE.read(a,z-a);ii=list(CS.disasm(raw,a));assert len(raw)==len(ii)*4
 return {'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']in('braa','retab');fs[n]=f
 fs['guard_failure']=capture(0x100d7cc94,0x100d7cc98)
 banks=[];slots={TABLE+8*j for j in [0x2486,0x24b2,0x15db,0x9d05,0x9d0d,0x6358,0x8ed9,0x4923]};slots.update([0x1010b1e18,0x1010b1e28,0x1010b1d00]);roots=[]
 for n,l,r,key,add,base,bias in SPECS:
  b=selected(l,r,key,add,base,bias);left=IMAGE.read(l,256);right=IMAGE.read(r,256);v=[j^right[left[j]^key]for j in range(256)];assert len(set(v))==1;b.update(role=n,left_bytes=left.hex(),right_bytes=right.hex(),key_u8=key,results_256=v);banks.append(b);slots.add(int(b['slot'],16))
 for off,bias in [(0x29c8,0xffffffffaa591739),(0x4c18,0xffffffff8af86dcd),(0x2b50,0xfffffffff02ce87e),(0x30f8,-0xd45667),(0x1658,0xffffffffa6e7fab5),(0x26a0,0xffffffff9d07c0b2)]:
  a=POOL+off;v=(FIXUPS[a]['target']+bias)&((1<<64)-1);slots.add(a);roots.append({'slot':hex(a),'bias':hex(bias&((1<<64)-1)),'decoded_root':hex(v),'fixup':FIXUPS[a]})
 branches=[]
 for n,ixs in [('mode_one',[0x24b2]),('setup',[0x2486]),('entry',[0x9d05,0x9d0d]),('wrapper',[0x6358]),('core',[0x8ed9,0x4923]),('caller_return',[0xa1da,0xb9a])]:
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix in ixs:
   slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and((word>>32)&65535)==mod and not((word>>48)&7);slots.add(slot);branches.append({'fragment':n,'index':hex(ix),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 calls=[]
 for pc,slot in [(0x1009bb540,TABLE+8*0xce18),(0x100d03580,TABLE+8*0xce3c),(0x100cf042c,int(next(b['slot']for b in banks if b['role']=='core_fill'),16))]:
  ii=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ii[0].mnemonic=='mov'and ii[1].mnemonic=='blraa';mod=int(ii[0].op_str.split('#')[1],0);word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and((word>>32)&65535)==mod and not((word>>48)&7);slots.add(slot);calls.append({'site':hex(pc),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 assertions=[]
 patterns=[('adapter','stp','x22, x21, [sp, #-0x30]!'),('adapter','add','x29, sp, #0x20'),('adapter','sub','sp, sp, #0x10'),('adapter','sub','x16, x21, #0x90'),('adapter','sub','sp, x29, #0x20'),('adapter','ldp','x22, x21, [sp], #0x30'),('adapter','retab',''),('core','stp','x28, x27, [sp, #-0x60]!'),('core','add','x29, sp, #0x50'),('core','sub','sp, sp, #1, lsl #12'),('core','sub','sp, sp, #0x1b0'),('core','mov','w9, #0x11b0'),('core','mov','w2, #0x128'),('core','add','x0, sp, #0x768'),('reject','b.ne','#0x100d7cc94'),('reject','add','sp, sp, #1, lsl #12'),('reject','add','sp, sp, #0x1b0'),('reject','ldp','x28, x27, [sp], #0x60'),('reject','retab',''),('guard_failure','bl','#0x100e2aad0')]
 for n,m,op in patterns:
  hits=[i for i in fs[n]['instructions']if i['mnemonic']==m and i['operands']==op];assert len(hits)==1,(n,m,op);assertions.append({'fragment':n,**hits[0]})
 rec=[]
 for fn in ['daemon_outer_first_key_source.json','daemon_constructor_bank_origins_source.json']:
  obj=json.loads(read(ROOT/fn))
  def walk(o,path=''):
   if isinstance(o,dict):
    raw=o.get('bytes',o.get('bytes_hex'));a=o.get('start')
    if isinstance(raw,str)and isinstance(a,str)and a.startswith('0x'):
     bb=bytes.fromhex(raw);assert IMAGE.read(int(a,16),len(bb))==bb;rec.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
    for k,v in o.items():walk(v,path+'/'+k)
   elif isinstance(o,list):
    for j,v in enumerate(o):walk(v,path+'/'+str(j))
  walk(obj)
 deps=['daemon_outer_first_key_source.json','daemon_constructor_bank_origins_source.json','validate_daemon_reader_outer_lifecycle.py','validate_daemon_existing_scalar_reader.py','validate_daemon_reader_container_origins.py','validate_daemon_list_output.py','daemon_receive_fixups.txt']
 ptr=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)]
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'bank_roles':len(banks),'bank_inputs_checked':256*len(banks),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(branches),'resolved_call_sites':len(calls),'structural_instruction_assertions':len(assertions),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'banks':banks,'structural_assertions':assertions,'bank_roots':roots,'branches':branches,'calls':calls,'pointer_records':ptr,'original_fixup_checks':{'authenticated_and_rebases':verify_original_fixups(slots-{0x1010b1e18}),'unauthenticated_guard_binding':binding(0x1010b1e18)},'prior_recaptures':rec,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
