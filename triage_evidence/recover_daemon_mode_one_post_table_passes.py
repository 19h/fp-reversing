#!/usr/bin/env python3
"""Original post-table size fork,two source passes and shared initializer."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_post_table_passes'
SCOPE='Selected mode1 post-table size gate,two additional32-byte source reads and shared initializer. Static source/SMT only;no whole-operation,output,native PAC or daemon-kext exchange proof.'
ENTRIES={'gate':0x100daee68,'setup':0x100bd6bbc,'first':0x100d77c1c,'advance':0x100d77860,'between':0x100d64a00,'second':0x100bf2de0,'handoff':0x100dac01c,'initializer':0x100dda7d8,'relabel_seed':0x100d17960}
CUTS={'size_decode':(0x100cf0430,0x100cf04b4),'size_save':(0x100d5e010,0x100d5e014),'source_save':(0x100d5e38c,0x100d5e390)}
EDGES=[('gate',0xa0c1),('gate',0xa0cc),('setup',0x663b),('first',0x8980),('first',0x89a3),('advance',0x663b),('between',0x87c8),('second',0x87c8),('second',0x87c6),('handoff',0x8ad6),('initializer',0x6284)]
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={};writes={};corrections=[];edges=[];slots=set();stores=[];rec=[]
 for n,a in ENTRIES.items():fs[n]=block(a,0x3000)
 for n,(a,b)in CUTS.items():
  bb=IMAGE.read(a,b-a);ii=list(dc.disasm(bb,a));assert len(ii)*4==len(bb);fs[n]={'start':hex(a),'end':hex(b),'bytes':bb.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 for n,f in fs.items():
  bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);ww=set()
  for i in dc.disasm(bb,int(f['start'],16)):
   rr={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in rr if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    rr-=bad
   ww.update(rr)
   if i.mnemonic.startswith('str'):stores.append({'fragment':n,'site':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
  assert 'sp'not in ww;writes[n]=sorted(ww)
  if n in ENTRIES:assert f['instructions'][-1]['mnemonic']=='braa'
 assert all(not any(i['mnemonic'].startswith('str')for i in fs[n]['instructions'])for n in['first','second','advance'])
 for n,ix in EDGES:
  f=fs[n];mod=int(f['instructions'][-2]['operands'].split('#')[1],0);slot=TABLE+ix*8;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7);slots.add(slot)
  edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 spstores={};indirect={}
 for name in['daemon_mode_one_digit_maps_source.json','daemon_mode_one_source_passes_source.json','daemon_mode_one_scatter_source.json','daemon_mode_one_inverse_tables_source.json','daemon_mode_one_carry_table_source.json']:
  old=json.loads(read(ROOT/name))
  for n,f in old['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'artifact':name,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
   for i in f['instructions']:
    if not i['mnemonic'].startswith('str'):continue
    m=re.search(r'\[sp, #([^\]]+)\]',i['operands'])
    if m:
     off=int(m[1],0);width=1 if i['mnemonic']=='strb'else 4 if i['operands'].startswith('w')else 8;spstores[i['ea']]={'site':i['ea'],'frame_offset':off,'width_bytes':width}
     touched=set(range(off,off+width));protected=set(range(0x750,0x754))|set(range(0x458,0x460))
     if touched&protected:assert i['ea']in['0x100d5e010','0x100d5e38c']
    else:
     assert i['mnemonic']=='strb';indirect[i['ea']]={'site':i['ea'],'operands':i['operands'],'width_bytes':1,'address_contract':'Prior source-certified scratch domain T+[0,962].'}
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'new_routine_instructions':sum(len(fs[n]['instructions'])for n in ENTRIES if n!='relabel_seed'),'pointer_records':len(slots),'branch_slot_modifier_matches':len(edges),'SP_writes':0,'comparison_operand_role_corrections':len(corrections),'loop_store_instructions':0,'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'original_pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'source_store_sites':stores,'prior_recaptures':rec,'prior_frame_stores':list(spstores.values()),'prior_indirect_byte_stores':list(indirect.values()),'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_digit_maps_source.json','daemon_mode_one_digit_maps_checks.json','daemon_mode_one_source_passes_source.json','daemon_mode_one_source_passes_checks.json','daemon_mode_one_adapter_source.json','daemon_mode_one_adapter_checks.json','daemon_mode_one_scatter_source.json','daemon_mode_one_inverse_tables_source.json','daemon_mode_one_carry_table_source.json','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
