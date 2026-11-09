#!/usr/bin/env python3
"""Post-round phase handoff,re-entry,workspace and private-request field consumers."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,h,FLAGS,binding
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_phase_handoff'
SCOPE='Post-round equality gate,16-word repacking,internal phase-bit re-entry,32-word finalization workspace and C0/LOCAL-dependent private-request suffixes. Conditional source/ABI results;later phase-one reachability,record codec/output semantics,complete budget history and native daemon-kext pairing remain unknown.'
BLOCKS={'equal_gate':0x100cec684,'repack':0x100db4af0,'phase_gate':0x100c4c834,'reentry':0x100bdba34,'repeat_mix':0x100d41af4,'shared_spills':0x100bf3160,'workspace':0x100d9d804,'cell_null':0x100cbddd0,'cell_present':0x100a76520}
CUTS={'save_request':(0x100cf037c,0x100cf0380),'reject_prefix':(0x100d7cc50,0x100d7cc6c)}
EDGES={'equal_gate':[(0x32ff,0x100c8df0c),(0x56a0,0x100db4af0)],'repack':[(0x30fa,0x100c4c834)],'phase_gate':[(0x6284,0x100bdba34),(0x8aaf,0x100d9d804)],'reentry':[(0x4cf9,0x100dab3d0),(0x4cdb,0x100d41af4)],'repeat_mix':[(0x17d8,0x100bf3160)],'shared_spills':[(0x3146,0x100c9d2b8)],'workspace':[(0x7a8c,0x100a76520),(0x7acf,0x100cbddd0)],'cell_null':[(0x4923,0x100d7cc50),(0x4928,0x100c57884)],'cell_present':[(0xac4c,0x100bda488)]}
DEPS=['daemon_mode_one_word_rounds_source.json','daemon_mode_one_word_rounds_checks.json','daemon_mode_one_bank_combine_source.json','daemon_mode_one_bank_combine_checks.json','daemon_mode_one_word_mix_source.json','daemon_mode_one_word_mix_checks.json','daemon_mode_one_state_materialization_checks.json','daemon_mode_one_source_absorption_checks.json','daemon_mode_one_plane_consumer_checks.json','daemon_mode_one_word_schedule_checks.json','daemon_mode_one_adapter_source.json','daemon_mode_one_adapter_checks.json','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={n:block(a,0x10000)for n,a in BLOCKS.items()}
 for n,(a,b)in CUTS.items():
  raw=IMAGE.read(a,b-a);fs[n]={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(raw,a)]}
 writes={};corrections=[];adrps=[];unscaled=[]
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);rr=set();assert len(raw)==4*len(f['instructions'])
  for i in dc.disasm(raw,int(f['start'],16)):
   ww={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    ww-=bad
   if i.mnemonic=='adrp':
    word=int.from_bytes(i.bytes,'little');assert word&0x9f000000==0x90000000;imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm;target=(i.address&~4095)+(imm<<12);assert target==int(i.op_str.split('#')[1],0);adrps.append({'site':hex(i.address),'target':hex(target),'bytes':i.bytes.hex()})
   if i.mnemonic in['stur','ldur']:
    word=int.from_bytes(i.bytes,'little');imm=(word>>12)&511;imm=imm-512 if imm&256 else imm;assert imm==int(i.op_str.split('#')[-1].rstrip(']'),0);unscaled.append({'site':hex(i.address),'mnemonic':i.mnemonic,'immediate_s9':imm,'bytes':i.bytes.hex()})
   rr.update(ww)
  assert 'sp'not in rr;writes[n]=sorted(rr);controls=[i['mnemonic']for i in f['instructions']if i['mnemonic']in['b','br','bl','blr','braa','brab','blraa','blrab','svc','hvc','smc','ret','retab']or i['mnemonic'].startswith(('b.','cb','tb'))];assert controls==(['braa']if n in BLOCKS else[])
 edges=[];slots=set()
 for n,rows in EDGES.items():
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 roots=[]
 for slot,bias,target in[(0x1010a4328,0xffffffffaa591739,0x100fc4130),(0x1010a6578,0xffffffff8af86dcd,0x101031ea0)]:
  fix=FIXUPS[slot];assert fix['kind']=='rebase'and(fix['target']+bias)&((1<<64)-1)==target;slots.add(slot);raw=IMAGE.read(target,256);roots.append({'slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':fix,'bias_u64':hex(bias),'target':hex(target),'size_bytes':256,'bytes':raw.hex(),'sha256':h(raw)})
 slots.add(0x1010b1e18);rec=[]
 for file in[DEPS[0],DEPS[2],DEPS[4],DEPS[10]]:
  old=json.loads(read(ROOT/file))
  for label,f in old['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':file,'fragment':label,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'data_ranges':2,'data_bytes':512,'ADRP_decodes_checked':len(adrps),'unscaled_immediates_checked':len(unscaled),'SP_writes':0,'comparison_role_corrections':len(corrections),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'codec_roots':roots,'pointer_checks':{'authenticated_and_rebases':verify_original_fixups(slots-{0x1010b1e18}),'unauthenticated_guard_binding':binding(0x1010b1e18)},'register_write_sets':writes,'comparison_role_corrections':corrections,'ADRP_decode_checks':adrps,'unscaled_immediate_checks':unscaled,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
