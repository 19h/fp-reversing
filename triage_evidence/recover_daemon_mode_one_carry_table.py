#!/usr/bin/env python3
"""Recover the second mode1 table producer and its original-byte lineage."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_carry_table'
SCOPE='Selected mode1 local nibble-sum/carry table construction. Static source and finite algebra only; caller output,whole return,native PAC and daemon-kext exchange remain unknown.'
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 old=json.loads(read(ROOT/'daemon_mode_one_inverse_tables_source.json'))
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={'carry':block(0x100c18e20,0x2000)}
 for n,a,b in [('shuffle_seed',0x100dbfc3c,0x100dbfc54),('shuffle_exit',0x100dc0220,0x100dc02a4),('sum_writer',0x100c07254,0x100c07398)]:
  bb=IMAGE.read(a,b-a);ii=list(dc.disasm(bb,a));assert len(ii)*4==len(bb)
  fs[n]={'start':hex(a),'end':hex(b),'bytes':bb.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 writes={};corrections=[]
 for n,f in fs.items():
  bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);ww=set()
  for i in dc.disasm(bb,int(f['start'],16)):
   regs={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f
    bad={r for r in regs if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    regs-=bad
   ww.update(regs)
  writes[n]=sorted(ww);assert 'sp'not in ww
 assert not({'w4','x4','w8','x8'}&set(writes['sum_writer']))
 # W23 and X21 have no further writes after their recorded shuffle producers.
 sh=old['fragments']['second_shuffle']['instructions']
 assert [i['ea']for i in sh if i['operands'].split(',')[0]in('w23','x23')]==['0x100dbfc50']
 assert [i['ea']for i in sh if i['operands'].split(',')[0]in('w21','x21')]==['0x100dbfd64']
 for f in old['fragments'].values():assert IMAGE.read(int(f['start'],16),len(bytes.fromhex(f['bytes'])))==bytes.fromhex(f['bytes'])
 edges=[];slots=set()
 for ix in[0xc25d,0xc262]:
  slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==0x4177 and not(word>>48&7)
  edges.append({'index':hex(ix),'slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]});slots.add(slot)
 op=old['data_roots'][2];assert IMAGE.read(int(op['target'],16),op['size_bytes'])==bytes.fromhex(op['bytes']);slots.add(int(op['slot'],16))
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'new_routine_instructions':len(fs['carry']['instructions']),'new_routine_bytes':len(bytes.fromhex(fs['carry']['bytes'])),'pointer_records':len(slots),'branch_slot_modifier_matches':len(edges),'data_bytes':op['size_bytes'],'SP_writes':0,'comparison_operand_role_corrections':len(corrections),'prior_source_ranges_recaptured':len(old['fragments']),'prior_source_bytes_recaptured':sum(len(bytes.fromhex(f['bytes']))for f in old['fragments'].values())}
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'operation_data':op,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'lineage':{'W23_producer':'0x100dbfc50','X21_producer':'0x100dbfd64','W4_W8_preserved_by_sum_writer':True},'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_inverse_tables_source.json','daemon_mode_one_inverse_tables_checks.json','recover_daemon_mode_one_inverse_tables.py','validate_daemon_mode_one_inverse_tables.py','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
