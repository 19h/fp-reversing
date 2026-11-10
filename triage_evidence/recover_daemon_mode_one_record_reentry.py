#!/usr/bin/env python3
"""Recapture shifted record absorption and the parameterized re-entry interfaces."""
import json,re,capstone
from validate_daemon_list_output import split
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_record_reentry'
SCOPE='Parameterized position-aware re-entry:original modular COUNT threshold,complete short-remainder address/codec/loop contract,four16-byte full-prefix steps,64-byte biased progress and conditional control/address cycle composition. Counter-wrap behavior is retained as abstract evidence;native acceptance/owners/traversal,decoded state and daemon-kext output pairing remain unknown.'
BLOCKS={'initializer':0x100c88438,'short':0x100c4a194,'short_seed':0x100c65bdc,'short_loop':0x100dc10d4,'prefix_seed':0x100c9148c,'prefix_loop':0x100c1206c,'prefix_exit':0x100dad2c4}
CUTS={}
EDGES={'initializer':[(0xb1fc,0x100c4a194),(0xb217,0x100c9148c)],'short':[(0x3c0d,0x100c74750),(0x782c,0x100c65bdc)],'short_seed':[(0xa1ce,0x100dc10d4)],'short_loop':[(0xa1ce,0x100dc10d4),(0x3c0d,0x100c74750)],'prefix_seed':[(0x67f0,0x100c1206c)],'prefix_loop':[(0x84f9,0x100c1206c),(0x84ef,0x100dad2c4)],'prefix_exit':[(0x8d10,0x100b8ed9c)]}
LINEAGE=['rounds','long_planes','input_planes','long_prefix','word_gather','word_extension']
DEPS=['daemon_mode_one_record_'+n+'_'+k+'.json'for n in LINEAGE for k in ['source','checks']]+['daemon_mode_one_record_codecs_checks.json','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={n:block(a,0x30000)for n,a in BLOCKS.items()}
 for n,(a,b)in CUTS.items():
  raw=IMAGE.read(a,b-a);fs[n]={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(raw,a)]}
 writes={};corrections=[];bitfields=[];pairs=[];liveins={};eons=[];load_pairs=[];adrps=[]
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
   if i.mnemonic=='adrp':
    word=int.from_bytes(i.bytes,'little');assert word&0x9f000000==0x90000000;imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm;target=(i.address&~4095)+(imm<<12);assert target==int(i.op_str.split('#')[1],0);adrps.append({'site':hex(i.address),'target':hex(target),'bytes':i.bytes.hex()})
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
 for name in ['daemon_mode_one_record_'+n+'_source.json'for n in LINEAGE]:
  for label,f in json.loads(read(ROOT/name))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':name,'fragment':label,'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'SP_writes':0,'comparison_role_corrections':len(corrections),'bitfield_decodes_checked':len(bitfields),'pair_store_decodes_checked':len(pairs),'EON_decodes_checked':len(eons),'pair_load_decodes_checked':len(load_pairs),'ADRP_decodes_checked':len(adrps),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 operand_live={}
 for name,f in fs.items():
  seen=set();live=[]
  for i in f['instructions']:
   p=split(i['operands']);m=i['mnemonic'];reads=p if m in['str','strb','cmp','braa']else p[1:]+([p[0]]if m in['movk','bfi','bfxil']else[])
   for op in reads:
    for reg in re.findall(r'\b[wx][0-9]+\b',op):
     if reg[1:]not in seen and reg not in{v['register']for v in live}:live.append({'register':reg,'first_read':i['ea']})
   if m not in['str','strb','cmp','braa']:assert p[0]!='sp';seen.add(p[0][1:])
  operand_live[name]=live
 return {'operand_based_GPR_first_reads':operand_live,'ADRP_decode_checks':adrps,'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'live_in_GPR_read_sites':liveins,'comparison_role_corrections':corrections,'bitfield_decode_checks':bitfields,'pair_store_decode_checks':pairs,'EON_decode_checks':eons,'pair_load_decode_checks':load_pairs,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
