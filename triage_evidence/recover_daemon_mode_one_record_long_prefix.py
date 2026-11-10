#!/usr/bin/env python3
"""Recapture the long-record seed,four-round prefix body and exit handoff."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_record_long_prefix'
SCOPE='Conditional long-record64-byte prefix:full seed/body/exit source SSA,four finite counter states,all record/plane addresses,original-source U/V update identities,address-only V-mask functions,private frame effects and authenticated exit. Canonical-mask identity,compact state/algorithm,native traversal,output and daemon-kext pairing remain unknown.'
BLOCKS={'seed':0x100c9148c,'loop':0x100c1206c,'exit':0x100dad2c4}
EDGES={'seed':[(0x67f0,0x100c1206c)],'loop':[(0x84f9,0x100c1206c),(0x84ef,0x100dad2c4)],'exit':[(0x8d10,0x100b8ed9c)]}
DEPS=['daemon_mode_one_record_long_planes_source.json','daemon_mode_one_record_long_planes_checks.json','daemon_mode_one_record_input_planes_source.json','daemon_mode_one_record_input_planes_checks.json','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={n:block(a,0x30000)for n,a in BLOCKS.items()}
 writes={};corrections=[];bitfields=[];pairs=[];liveins={};eons=[];load_pairs=[]
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);rr=set();seen=set();live=[];assert len(raw)==4*len(f['instructions'])
  for i in dc.disasm(raw,int(f['start'],16)):
   rd,wr=i.regs_access();ww={i.reg_name(r)for r in wr}
   for r in rd:
    name=i.reg_name(r)
    if re.fullmatch('[xw][0-9]+',name)and name[1:]not in seen and name not in{v['register']for v in live}:live.append({'register':name,'first_read':hex(i.address)})
   word=int.from_bytes(i.bytes,'little')
   if i.mnemonic in ['bfi','bfxil','ubfx','ubfiz']:
    sf=word>>31;w=64 if sf else 32;assert(word>>22)&1==sf
    assert word&0x7f800000==(0x53000000 if i.mnemonic in['ubfx','ubfiz']else 0x33000000)
    immr=(word>>16)&63;imms=(word>>10)&63;assert immr<w and imms<w
    args=[v.strip()for v in i.op_str.split(',')];lsb=int(args[2][1:],0);count=int(args[3][1:],0)
    assert int(args[0][1:])==word&31 and int(args[1][1:])==(word>>5)&31
    assert(lsb,count)==(((w-immr)%w,imms+1)if i.mnemonic in['bfi','ubfiz']else(immr,imms-immr+1))
    bitfields.append({'site':hex(i.address),'mnemonic':i.mnemonic,'word_bits':w,'immr':immr,'imms':imms,'source_lsb':lsb,'source_count':count,'bytes':i.bytes.hex()})
   if i.mnemonic=='eon':
    assert word&0x7f200000==0x4a200000 and word>>31==1
    args=[v.strip()for v in i.op_str.split(',')];assert args[:3]==['x'+str(word&31),'x'+str((word>>5)&31),'x'+str((word>>16)&31)]
    assert(word>>22)&3==3 and(word>>10)&63==61 and args[3]=='ror #61'
    eons.append({'site':hex(i.address),'bytes':i.bytes.hex(),'word_bits':64,'shift':'ROR61','operation':'Rn XOR NOT(ROR64(Rm,61))'})
   if i.mnemonic=='ldp':
    assert word&0xffc00000==0x29400000 and(word>>5)&31==31
    imm=(word>>15)&127;off=(imm-128 if imm&64 else imm)*4
    args=[int(v)for v in re.findall(r'\bw([0-9]+)\b',i.op_str)];assert args==[word&31,(word>>10)&31]and off==0x14
    load_pairs.append({'site':hex(i.address),'bytes':i.bytes.hex(),'frame_offsets':[off,off+4],'registers':args})
   if i.mnemonic=='stp':
    assert word&0xffc00000==0x29000000 and(word>>5)&31==31
    imm=(word>>15)&127;off=(imm-128 if imm&64 else imm)*4
    args=[int(v)for v in re.findall(r'\bw([0-9]+)\b',i.op_str)];assert args==[word&31,(word>>10)&31]
    assert i.op_str.endswith('[sp, #'+hex(off)+']')
    pairs.append({'site':hex(i.address),'frame_offsets':[off,off+4],'registers':args,'scaled_signed_imm7':imm,'bytes':i.bytes.hex()})
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    ww-=bad
   seen.update(r[1:]for r in ww if re.fullmatch("[xw][0-9]+",r));rr.update(ww)
  assert 'sp'not in rr;writes[n]=sorted(rr);liveins[n]=live;controls=[i['mnemonic']for i in f['instructions']if i['mnemonic']in ['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or i['mnemonic'].startswith(('b.','cb','tb'))];assert controls==(['braa']if n in BLOCKS else [])
 edges=[];slots=set()
 for n,rows in EDGES.items():
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 rec=[]
 for name in [DEPS[0],DEPS[2]]:
  for label,f in json.loads(read(ROOT/name))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':name,'fragment':label,'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'SP_writes':0,'comparison_role_corrections':len(corrections),'bitfield_decodes_checked':len(bitfields),'pair_store_decodes_checked':len(pairs),'EON_decodes_checked':len(eons),'pair_load_decodes_checked':len(load_pairs),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'live_in_GPR_read_sites':liveins,'comparison_role_corrections':corrections,'bitfield_decode_checks':bitfields,'pair_store_decode_checks':pairs,'EON_decode_checks':eons,'pair_load_decode_checks':load_pairs,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
