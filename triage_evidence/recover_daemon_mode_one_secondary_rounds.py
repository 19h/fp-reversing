#!/usr/bin/env python3
"""Recapture secondary setup,round consumer,state update and scalar gate."""
import collections,json,re,capstone
from validate_daemon_list_output import split
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_secondary_rounds'
SCOPE='Conditional secondary setup,64-round word/table consumer,state update and flag-zero scalar gate. Exact control/address contracts and scalar producer sites;complete round arithmetic,native state ownership/output and daemon-kext pairing remain unknown.'
BLOCKS={'setup':0x100c2c25c,'round':0x100b18194,'update':0x100c52828,'gate':0x100b50474}
EDGES={'setup':[(0xa9d0,0x100b18194)],'round':[(0xa9d0,0x100b18194),(0xa9df,0x100c52828)],'update':[(0xaa1c,0x100b50474),(0xaa31,0x100d183e8)],'gate':[(0x66f1,0x100c583b0),(0x6703,0x100d183e8)]}
FIELDS=[0x4b8,0x4c4,0x4c8,0x4cc,0x4d0,0x4d4,0x4d8,0x4e4,0x4e8,0x4ec,0x4f0,0x4f4,0x504,0x508,0x50c,0x510]
LINEAGE=['daemon_mode_one_secondary_word_extension','daemon_mode_one_secondary_word_import','daemon_mode_one_parity_state_adapters','daemon_mode_one_inverse_tables']
DEPS=[n+'_'+k+'.json'for n in LINEAGE for k in['source','checks']]+['daemon_receive_fixups.txt']
LEFT=0x100e99a00;RIGHT=0x100f4e390;ROM=0x10101d700

def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()};liveins={};counts={};isa=[];cmps=[]
 for name,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);ii=list(dc.disasm(raw,int(f['start'],16)));assert len(raw)==len(ii)*4
  seen=set();live=[];control=[]
  for i in ii:
   p=split(i.op_str);m=i.mnemonic;w=int.from_bytes(i.bytes,'little');rd,ww=i.regs_access();writes={i.reg_name(r)for r in ww};assert 'sp'not in writes
   if m in['cmp','tst']:
    bad=sorted(r for r in writes if re.fullmatch('[wx][0-9]+',r))
    if bad:cmps.append({'site':hex(i.address),'Capstone_GPR_writes':bad,'architectural_GPR_writes':[]})
   args=p if m in['str','strb','cmp','tst','braa']else p[1:]+([p[0]]if m in['movk','bfi','bfxil']else[])
   for arg in args:
    for r in re.findall(r'\b[wx][0-9]+\b',arg):
     if r[1:]not in seen and r not in{v['register']for v in live}:live.append({'register':r,'first_read':hex(i.address)})
   if m not in['str','strb','cmp','tst','braa']:seen.add(p[0][1:])
   if m in['bfi','bfxil','ubfx','ubfiz']:
    sf=w>>31;width=64 if sf else 32;assert(w>>22)&1==sf and w&0x7f800000==(0x53000000 if m in['ubfx','ubfiz']else 0x33000000)
    r=(w>>16)&63;s=(w>>10)&63;l,n=int(p[2][1:],0),int(p[3][1:],0);assert r<width and s<width
    assert(l,n)==(((width-r)%width,s+1)if m in['bfi','ubfiz']else(r,s-r+1));assert[int(v[1:])for v in p[:2]]==[w&31,(w>>5)&31]
    isa.append({'site':hex(i.address),'kind':m,'width_bits':width,'immr':r,'imms':s,'source_lsb':l,'source_count':n,'bytes':i.bytes.hex()})
   if m in['udiv','umull']:
    assert w&0xffe0fc00=={'udiv':0x1ac00800,'umull':0x9ba07c00}[m]and[int(v[1:])for v in p]==[w&31,(w>>5)&31,(w>>16)&31];isa.append({'site':hex(i.address),'kind':m,'bytes':i.bytes.hex(),'operands':i.op_str})
   if m=='adrp':
    assert w&0x9f000000==0x90000000;imm=((w>>5&0x7ffff)<<2)|(w>>29&3);imm=imm-(1<<21)if imm&(1<<20)else imm;target=(i.address&~4095)+(imm<<12);assert int(p[1][1:],0)==target and int(p[0][1:])==w&31;isa.append({'site':hex(i.address),'kind':m,'page_target':hex(target),'bytes':i.bytes.hex()})
   if m=='extr':
    sf=w>>31;assert w&0x7fa00000==0x13800000 and(w>>22)&1==sf;assert[int(v[1:])for v in p[:3]]==[w&31,(w>>5)&31,(w>>16)&31]and int(p[3][1:],0)==(w>>10)&63;isa.append({'site':hex(i.address),'kind':m,'width_bits':64 if sf else 32,'bytes':i.bytes.hex()})
   if m in['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or m.startswith(('b.','cb','tb')):control.append(m)
  assert control==['braa'];liveins[name]=live;counts[name]=dict(collections.Counter(i['mnemonic']for i in f['instructions']))
  assert all(re.fullmatch(r'w(?:[0-9]+|zr), \[sp, #0x[0-9a-f]+\]',i['operands'])for i in f['instructions']if i['mnemonic'].startswith('st'))
 edges=[];slots=set()
 for name,rows in EDGES.items():
  modifier=int(fs[name]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;raw=IMAGE.read(slot,8);w=int.from_bytes(raw,'little');assert FIXUPS[slot]['target']==target and w>>63 and(w>>32)&65535==modifier and not(w>>48&7)
   slots.add(slot);edges.append({'fragment':name,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(modifier),'raw_bytes':raw.hex(),'fixup':FIXUPS[slot]})
 banks={n:{'address':hex(a),'size_bytes':sz,'bytes':IMAGE.read(a,sz).hex(),'sha256':h(IMAGE.read(a,sz))}for n,a,sz in[('left',LEFT,256),('right',RIGHT,256),('word_bank',ROM,768)]}
 slot=POOL+8*(0x819+0xb6);pointer=FIXUPS[slot];assert(pointer['target']+0xffffffffa7323e09)&((1<<64)-1)==ROM;slots.add(slot)
 pool={'index':'0x8cf','slot':hex(slot),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':pointer,'u64_bias':'0xffffffffa7323e09','resolved_root':hex(ROM)}
 rec=[]
 for n in LINEAGE:
  for label,f in json.loads(read(ROOT/(n+'_source.json')))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':n+'_source.json','fragment':label,'bytes_checked':len(raw),'sha256':h(raw)})
 old=json.loads(read(ROOT/'daemon_mode_one_parity_state_adapters_checks.json'))['semantics']['source_models'];producers=[]
 for path in['odd','even']:
  stores=old[path]['frame_writes']+old[path+'_setup']['frame_writes']
  for off in FIELDS:
   rows=[r for r in stores if r['frame_offset']==off];assert rows;r=rows[-1];assert r['width_bits']==32;pc=int(r['site'],16);raw=IMAGE.read(pc,4);i=list(dc.disasm(raw,pc));assert len(i)==1 and i[0].mnemonic=='str'and i[0].op_str.endswith('[sp, #'+hex(off)+']')
   producers.append({'path':path,'frame_offset':hex(off),'last_store':r['site'],'bytes':raw.hex(),'source_value':r['value'],'inherited_source_model':path+'_setup','reaching_definition_scope':'Selected parity adapter and common setup;continuity across intervening computed writes uses prior address contracts.'})
 frontier=[]
 for ix,target in[(0x66f1,0x100c583b0),(0x6703,0x100d183e8)]:
  f=block(target,0x30000);raw=bytes.fromhex(f['bytes']);frontier.append({'slot':hex(ix),'start':f['start'],'end':f['end'],'source_instructions':len(f['instructions']),'source_bytes':len(raw),'sha256':h(raw),'mnemonic_census':dict(collections.Counter(i['mnemonic']for i in f['instructions'])),'full_body_translated':False})
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'operand_based_GPR_first_reads':liveins,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'coded_word_bank_pointer':pool,'original_banks':banks,'ISA_decode_checks':isa,'comparison_role_corrections':cmps,'mnemonic_census':counts,'scalar_producer_ledger':producers,'prior_recaptures':rec,'frontier_census':frontier,'dependencies':{n:sha(ROOT/n)for n in DEPS},'Capstone_version':capstone.__version__,'new_IDA_access':False,'verified_source_counts':{'source_ranges':4,'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_bindings':len(edges),'pointer_records':len(slots),'original_bank_bytes':1280,'scalar_producer_rows':len(producers),'ISA_decodes_checked':len(isa),'comparison_role_corrections':len(cmps),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec),'SP_writes':0},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
