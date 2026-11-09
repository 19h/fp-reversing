#!/usr/bin/env python3
"""Original inverse/reseed/shuffle/table bytes and fixed lookup provenance."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_inverse_tables'
SCOPE='Selected LEN32 mode1 continuation:inverse and reset tables,second-bank shuffle,fixed cyclic16 operation and local256-entry table construction. Source certificates do not establish native owners/PAC,whole return,budget history or daemon-kext exchange.'
BLOCKS={'seed':0x100ca09c4,'inverse':0x100dd165c,'reset':0x100c97370,'second_shuffle':0x100dbfc3c,'table':0x100c07254,'first_shuffle':0x100ca047c}
CUTS={'left_root':(0x100cf0260,0x100cf0270),'right_root':(0x100cf027c,0x100cf028c),'frame_roots':(0x100d5dfc8,0x100d5dfd4),'frame_counter':(0x100cf038c,0x100cf0390)}
EDGES={'seed':[0x8a66],'inverse':[0x8a66,0x8a68],'reset':[0x6d9c,0x6dcb],'second_shuffle':[0x8d87],'table':[0x8d87,0xc7f3],'first_shuffle':[0x8a66]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={};edges=[];slots=set();writes={};corrections=[]
 for n,a in BLOCKS.items():
  f=block(a,0x3000);assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 for n,(a,b)in CUTS.items():
  bb=IMAGE.read(a,b-a);ii=list(dc.disasm(bb,a));assert len(ii)*4==len(bb);fs[n]={'start':hex(a),'end':hex(b),'bytes':bb.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 for n,f in fs.items():
  bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);rr=set()
  for i in dc.disasm(bb,int(f['start'],16)):
   ww={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic in('cmp','tst'):
    word=int.from_bytes(i.bytes,'little');assert word&31==31 and word&(1<<29)
    if i.mnemonic=='cmp':assert word&0x6000001f==0x6000001f
    removed={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if removed:corrections.append({'site':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'reported_GPR_writes':sorted(removed),'architectural_GPR_writes':[]})
    ww-=removed
   rr.update(ww)
  writes[n]=sorted(rr);assert 'sp'not in rr
  controls=[i['mnemonic']for i in f['instructions']if i['mnemonic']in('b','br','bl','blr','braa','brab','blraa','blrab','svc','hvc','smc','ret','retab')or i['mnemonic'].startswith(('b.','cb','tb'))];assert controls==(['braa']if n in BLOCKS else[])
 roots=[]
 for role,off,bias,target,size in [('left',0x1658,0xffffffffa6e7fab5,0x100e99a00,256),('right',0x26a0,0xffffffff9d07c0b2,0x100f4e390,256),('operation',8*(0xd89+0xd0),0xffffffff8e873ed9,0x100f715a0,944)]:
  slot=POOL+off;f=FIXUPS[slot];assert f['kind']=='rebase'and(f['target']+bias)&((1<<64)-1)==target;slots.add(slot);bb=IMAGE.read(target,size);roots.append({'role':role,'slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':f,'bias_u64':hex(bias),'target':hex(target),'size_bytes':size,'bytes':bb.hex(),'sha256':h(bb)})
 left,right=(bytes.fromhex(r['bytes'])for r in roots[:2]);values=[j^right[left[j]^0x6d]for j in range(256)];assert set(values)=={0xd0}
 rec=[]
 for file in['daemon_mode_one_scatter_source.json','daemon_mode_one_source_passes_source.json']:
  old=json.loads(read(ROOT/file))
  for n,f in old['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'artifact':file,'fragment':n,'start':f['start'],'bytes_checked':len(bb),'sha256':h(bb)})
 unique={i['ea']for f in fs.values()for i in f['instructions']};counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'distinct_source_instruction_sites':len(unique),'pointer_records':len(slots),'branch_slot_modifier_matches':len(edges),'data_ranges':len(roots),'data_bytes':sum(q['size_bytes']for q in roots),'bank_inputs_checked':len(values),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'SP_writes':0,'comparison_operand_role_corrections':len(corrections),'second_shuffle_byte_store_sites':sum(i['mnemonic']=='strb'for i in fs['second_shuffle']['instructions'])}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'data_roots':roots,'operation_bank_results256':values,'original_fixup_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'Capstone_version':capstone.__version__,'prior_recaptures':rec,'IDA_memory_lookup':{'status':'unavailable','tool':'list_databases','database_queried':False,'facts_used':False,'reason':'No authenticated bridge worker was reachable;original file evidence supplies the semantics.'},'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_scatter_source.json','daemon_mode_one_scatter_checks.json','daemon_mode_one_source_passes_source.json','daemon_mode_one_source_passes_checks.json','validate_daemon_list_output.py','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
