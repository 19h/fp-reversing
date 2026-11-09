#!/usr/bin/env python3
"""Original-source allocation,default state and reader context admission."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,sha,h,FLAGS,selected
from recover_daemon_context_input_producers import scan
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_container_origins'
SCOPE='Conditional16 B pair allocation/default state/empty output and separate112 B allocation prefix;shared reader-context admission and register provenance. Normal allocation return/save semantics and file-backed banks are premises. No complete container/112 B object type,native owners/callers/PAC/endpoint or daemon-kext pairing proof.'
BLOCKS={'caller16':0x1004e1f94,'alloc16':0x100495808,'zero16':0x1005b078c,'loop16':0x1004ddaec,'empty16':0x1005588b4,'success16':0x1007f6f54,'publish16':0x10058816c,'return16':0x1005b95e8,'clear16':0x10079768c,'admission':0x10054984c,'context':0x1004d3e04,'alloc112':0x1006d679c,'fail112':0x100707484}
EDGES={'caller16':[0x3884],'alloc16':[0xc4dd,0xc4e0],'zero16':[0x3599],'loop16':[0xb350,0xb358],'empty16':[0x3298],'success16':[0x751d],'publish16':[0x7613],'clear16':[0x751d],'admission':[0x50e4,0x50e6],'context':[0x4a8d],'alloc112':[0x1e10,0x1e17]}
CALLS={'alloc16':0x1004958d0,'alloc112':0x1006d6804};LEFT=0x100fc4130;RIGHT=0x101031ea0
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f
 raw=IMAGE.read(0x100939f64,0x30);fs['init112']={'start':'0x100939f64','end':'0x100939f94','bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,0x100939f64)],'scope':'12-instruction prefix only;later helper/caller behavior is excluded.'}
 edges=[];indices={0x3884,0x3f27,0xfd4,0xcc0d,0xb9a}
 for n,ixs in EDGES.items():
  f=fs[n];mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in ixs:
   a=TABLE+8*ix;w=int.from_bytes(IMAGE.read(a,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);indices.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(a),'target':hex(FIXUPS[a]['target']),'IA_diversity':hex(mod)})
 bank=selected(LEFT,RIGHT,0x4e,0xcb0e,TABLE,0);l,r=IMAGE.read(LEFT,256),IMAGE.read(RIGHT,256);v=[i^r[l[i]^0x4e]for i in range(256)];assert v==[255]*256 and bank['target']=='libSystem/_malloc'and bank['slot']=='0x10109ff58';bank.update(left_bytes=l.hex(),right_bytes=r.hex(),results_256=v,key_u8=0x4e,additive_u32=0xcb0e,frame_left_cell='0x968',frame_right_cell='0x960')
 for ix,div in[(0xb9a,0xbcd2),(0xfd4,0xecaa)]:
  w=int.from_bytes(IMAGE.read(TABLE+8*ix,8),'little');assert w>>63 and((w>>32)&65535)==div and not((w>>48)&7)
 census=scan([{'input':n,'offset_bytes':o,'extent_bytes':8}for n,o in [('CTX_COMPARE',0x5e50),('HEAD_SOURCE',0x7d98),('CTX_N19',0x6368),('OUT_N19',0x8398)]]);assert len(census['candidates'])==5
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;controls={}
 for n,f in fs.items():
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));cc=[{'site':hex(i.address),'mnemonic':i.mnemonic}for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc','hvc','smc')];assert not any('sp'in{i.reg_name(x)for x in i.regs_access()[1]}for i in ii)
  if n=='init112':assert not cc
  elif n in CALLS:assert cc==[{'site':hex(CALLS[n]),'mnemonic':'blraa'},{'site':f['instructions'][-1]['ea'],'mnemonic':'braa'}]
  else:assert len(cc)==1 and cc[0]['mnemonic']=='braa'
  controls[n]=cc
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)];deps=['daemon_reader_value_consumers_source.json','daemon_reader_value_consumers_checks.json','daemon_constructor_bank_origins_source.json','daemon_constructor_bank_origins_checks.json','recover_daemon_context_input_producers.py','validate_daemon_reader_value_consumers.py','daemon_receive_fixups.txt'];counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'partial_prefixes':1,'allocation_call_boundaries':len(CALLS),'bank_inputs_checked':256,'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'writer_candidates':len(census['candidates']),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'call_boundaries':{n:hex(a)for n,a in CALLS.items()},'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'allocation_bank':bank,'writer_census':census,'control_ledger':controls,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
