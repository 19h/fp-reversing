#!/usr/bin/env python3
"""Original post-extension setup,64-round consumer,state update and continuation gate."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_word_rounds'
SCOPE='Selected post-extension setup,64-round consumption of two private word streams and a fixed image-word bank,20 frame-state stores and the next signed continuation gate. Static source/control/address ABI;other byte-access bounds/value equations,complete algorithm,caller publication and native daemon-kext exchange remain unknown.'
BLOCKS={'setup':0x100c5917c,'round':0x100d53ba4,'state_update':0x100b2ab1c,'gate':0x100cad378}
CUTS={'bank_roots':(0x100d5dfc8,0x100d5dfd4),'cell_root':(0x100cf038c,0x100cf0390)}
EDGE_SPECS=[('predecessor',0xb8d9,0x100c5917c,0x4a5b),('setup',0x9033,0x100d53ba4,0xf68f),('round',0x9033,0x100d53ba4,0xf68f),('round',0x9043,0x100b2ab1c,0xf68f),('state_update',0xab26,0x100cad378,0xe7b9),('gate',0x2ac4,0x100dc9674,0xb560),('gate',0x2aca,0x100cec684,0xb560)]
DEPS=['daemon_mode_one_word_schedule_source.json','daemon_mode_one_word_schedule_checks.json','daemon_mode_one_inverse_tables_source.json','daemon_mode_one_inverse_tables_checks.json','daemon_mode_one_state_materialization_source.json','daemon_mode_one_state_materialization_checks.json','daemon_mode_one_source_absorption_checks.json','daemon_mode_one_plane_consumer_checks.json','daemon_mode_one_lookup_roles_checks.json','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={name:block(a,0x10000)for name,a in BLOCKS.items()}
 for name,(a,b)in CUTS.items():
  raw=IMAGE.read(a,b-a);fs[name]={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(raw,a)]}
 corrections=[];writes={};adrps=[]
 for name,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);assert len(raw)==4*len(f['instructions']);rr=set()
  for i in dc.disasm(raw,int(f['start'],16)):
   ww={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    ww-=bad
   if i.mnemonic=='adrp':
    word=int.from_bytes(i.bytes,'little');assert word&0x9f000000==0x90000000;imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm;target=(i.address&~4095)+(imm<<12);assert target==int(i.op_str.split('#')[1],0);adrps.append({'site':hex(i.address),'decoded_page_target':hex(target),'bytes':i.bytes.hex()})
   rr.update(ww)
  writes[name]=sorted(rr);assert 'sp'not in rr
  controls=[i['mnemonic']for i in f['instructions']if i['mnemonic']in['b','br','bl','blr','braa','brab','blraa','blrab','svc','hvc','smc','ret','retab']or i['mnemonic'].startswith(('b.','cb','tb'))];assert controls==(['braa']if name in BLOCKS else[])
 edges=[];slots=set()
 for name,index,target,modifier in EDGE_SPECS:
  slot=TABLE+8*index;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==modifier and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot)
  if name!='predecessor':assert int(fs[name]['instructions'][-2]['operands'].split('#')[1],0)==modifier
  edges.append({'fragment':name,'index':hex(index),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(modifier),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 banks=[]
 for role,a,n in[('left_byte_bank',0x100e99a00,256),('right_byte_bank',0x100f4e390,256),('word_bank',0x100f4aaf0,768)]:
  raw=IMAGE.read(a,n);banks.append({'role':role,'address':hex(a),'size_bytes':n,'bytes':raw.hex(),'sha256':h(raw)})
 left,right=[bytes.fromhex(v['bytes'])for v in banks[:2]];selectors=[v^right[left[v]^0xd7]for v in range(256)];assert set(selectors)=={0x8c}
 slot=POOL+8*(0x458+0x8c);fix=FIXUPS[slot];assert fix['kind']=='rebase'and(fix['target']+0xffffffffd090d602)&((1<<64)-1)==0x100f4aaf0;slots.add(slot)
 pointer={'slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':fix,'bias_u64':'0xffffffffd090d602','resolved_target':'0x100f4aaf0'}
 rec=[]
 for name in[DEPS[0],DEPS[2],DEPS[4]]:
  old=json.loads(read(ROOT/name))
  for label,f in old['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':name,'fragment':label,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'data_ranges':len(banks),'data_bytes':sum(v['size_bytes']for v in banks),'bank_selector_cases':256,'SP_writes':0,'ADRP_decodes_checked':len(adrps),'comparison_role_corrections':len(corrections),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'data_banks':banks,'selector_results256':selectors,'word_bank_pointer':pointer,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'ADRP_decode_checks':adrps,'comparison_role_corrections':corrections,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
