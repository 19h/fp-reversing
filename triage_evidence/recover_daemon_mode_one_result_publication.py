#!/usr/bin/env python3
"""Recapture terminal state materialization,private-view serialization and LOCAL result stores."""
import collections,json,re,struct,capstone
from validate_daemon_list_output import split
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,POOL,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
from resolve_kernel_collection_interfaces import commands
P='daemon_mode_one_result_publication'
SCOPE='Source-bound terminal state materialization,two private32-byte encodings,LOCAL32-byte output/REQUEST result store,and flag0-to-flag1 even-phase control bridge. Whole algorithm,native execution,buffer ownership/extent/alias policy and daemon-kext transport remain unknown.'
BLOCKS={'materialize':0x100d183e8,'views':0x100c86898,'local':0x100bf6f60,'dispatch':0x100b6fe00,'even':0x100be0eac,'setup':0x100d74e68,'skip':0x100dc4288}
CUTS={'status':(0x100d7cc50,0x100d7cc58)}
EDGES={'materialize':[(0xb55a,0x100c86898),(0xb578,0x100bf6f60)],'views':[(0x40d0,0x100b6fe00)],'local':[(0x6012,0x100d7cc50)],'dispatch':[(0xc83d,0x100be0eac)],'even':[(0x255c,0x100d74e68)],'setup':[(0x9654,0x100dc4288)],'skip':[(0x34d0,0x100c62f48)]}
LINEAGE=['daemon_mode_one_secondary_rounds','daemon_mode_one_secondary_reentry','daemon_mode_one_even_view_import','daemon_mode_one_parity_state_adapters','daemon_mode_one_record_checkpoint']
DEPS=[n+'_'+k+'.json'for n in LINEAGE for k in['source','checks']]+['daemon_receive_fixups.txt']

def logical_mask(word):
 n=(word>>22)&1;r=(word>>16)&63;s=(word>>10)&63;length=(n*64+(~s&63)).bit_length()-1;assert length>=1
 size=1<<length;levels=size-1;ones=s&levels;rot=r&levels;assert ones!=levels
 element=(1<<(ones+1))-1;element=((element>>rot)|(element<<(size-rot)))&levels_mask(size)
 return sum(element<<j for j in range(0,32,size))

def levels_mask(size):return(1<<size)-1

def guard_record():
 data=SOURCE.read_bytes();a=next(o for o,c,n in commands(data,0)if c==0x80000034);fo,sz=struct.unpack_from('<II',data,a+8)
 version,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',data,fo);assert(version,fmt,symfmt)==(0,2,0)
 slot=0x1010b1e18;raw=IMAGE.read(slot,8);word=int.from_bytes(raw,'little');assert word>>63==0 and(word>>62)&1==1 and(word>>24)&255==0 and(word>>32)&0x7ffff==0
 ordinal=word&0xffffff;assert ordinal<count;iw,addend=struct.unpack_from('<Ii',data,fo+imports+ordinal*8);assert addend==0;start=fo+symbols+(iw>>9);name=data[start:data.index(0,start)].decode();assert name=='___stack_chk_guard'and FIXUPS[slot]['target']=='libSystem/'+name
 return {'slot':hex(slot),'raw_bytes':raw.hex(),'authenticated':False,'bind':True,'import_ordinal':ordinal,'library_ordinal':iw&255,'import_name':name,'pointer_addend':0,'import_addend':addend,'fixup':FIXUPS[slot],'original_import_table_checked':True,'chain_membership_provenance':'Retained dyld_info fixup walk;format12 and raw import fields independently checked.'}

def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()}
 for n,(a,b)in CUTS.items():
  raw=IMAGE.read(a,b-a);fs[n]={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(raw,a)]}
 liveins={};counts={};isa=[];cmps=[]
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
   if m=='lsr'and not p[-1].startswith('#'):
    width=64 if w>>31 else 32;assert w&0x7fe0fc00==0x1ac02400 and[int(v[1:])for v in p]==[w&31,(w>>5)&31,(w>>16)&31]
    isa.append({'site':hex(i.address),'kind':'register_lsr','width_bits':width,'shift_count_mask':width-1,'bytes':i.bytes.hex()})
   if m=='eon':
    width=64 if w>>31 else 32;shift=(w>>10)&63;kind=(w>>22)&3;assert w&0x7f200000==0x4a200000 and kind==0 and shift<width
    assert[int(v[1:])for v in p[:3]]==[w&31,(w>>5)&31,(w>>16)&31];assert(len(p)==3 and shift==0)or(len(p)==4 and p[3]=='lsl #'+str(shift))
    isa.append({'site':hex(i.address),'kind':'eon','width_bits':width,'shift_kind':'lsl','shift_bits':shift,'bytes':i.bytes.hex(),'operation':'Rn XOR NOT(shifted Rm),complement after shift'})
   if m=='tst':
    assert w>>31==0 and w&0x7f80001f==0x7200001f and(w>>5)&31==int(p[0][1:]);mask=logical_mask(w);assert mask==int(p[1][1:],0)==0x40000;isa.append({'site':hex(i.address),'kind':'tst_immediate','width_bits':32,'mask':hex(mask),'bytes':i.bytes.hex(),'GPR_writes':[]})
   if m=='adrp':
    assert w&0x9f000000==0x90000000;imm=((w>>5&0x7ffff)<<2)|(w>>29&3);imm=imm-(1<<21)if imm&(1<<20)else imm;target=(i.address&~4095)+(imm<<12);assert int(p[1][1:],0)==target and int(p[0][1:])==w&31;isa.append({'site':hex(i.address),'kind':m,'page_target':hex(target),'bytes':i.bytes.hex()})
   if m=='extr':
    sf=w>>31;assert w&0x7fa00000==0x13800000 and(w>>22)&1==sf;assert[int(v[1:])for v in p[:3]]==[w&31,(w>>5)&31,(w>>16)&31]and int(p[3][1:],0)==(w>>10)&63;isa.append({'site':hex(i.address),'kind':m,'width_bits':64 if sf else 32,'bytes':i.bytes.hex()})
   if m in['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or m.startswith(('b.','cb','tb')):control.append(m)
  assert control==(['braa']if name in BLOCKS else[]);liveins[name]=live;counts[name]=dict(collections.Counter(i['mnemonic']for i in f['instructions']))
 edges=[];slots=set()
 for name,rows in EDGES.items():
  modifier=int(fs[name]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;raw=IMAGE.read(slot,8);w=int.from_bytes(raw,'little');assert FIXUPS[slot]['target']==target and w>>63 and(w>>32)&65535==modifier and not(w>>48&7)
   slots.add(slot);edges.append({'fragment':name,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(modifier),'raw_bytes':raw.hex(),'fixup':FIXUPS[slot]})
 slots.add(0x1010b1e18);assert FIXUPS[0x1010b1e18]['target']=='libSystem/___stack_chk_guard'
 rec=[]
 for n in LINEAGE:
  for label,f in json.loads(read(ROOT/(n+'_source.json')))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':n+'_source.json','fragment':label,'bytes_checked':len(raw),'sha256':h(raw)})
 f=block(CUTS['status'][0],0x400);raw=bytes.fromhex(f['bytes']);frontier=[{'start':f['start'],'end':f['end'],'source_instructions':len(f['instructions']),'source_bytes':len(raw),'sha256':h(raw),'mnemonic_census':dict(collections.Counter(i['mnemonic']for i in f['instructions'])),'prefix_translated_instructions':2,'whole_canary_and_RETAB_semantics_proved':False}]
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'operand_based_GPR_first_reads':liveins,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots-{0x1010b1e18}), 'stack_guard_reference':guard_record(),'ISA_decode_checks':isa,'comparison_role_corrections':cmps,'mnemonic_census':counts,'prior_recaptures':rec,'frontier_census':frontier,'dependencies':{n:sha(ROOT/n)for n in DEPS},'Capstone_version':capstone.__version__,'new_IDA_access':False,'verified_source_counts':{'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_bindings':len(edges),'pointer_records':len(slots),'ISA_decodes_checked':len(isa),'comparison_role_corrections':len(cmps),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec),'frontier_ranges_hashed':1,'frontier_bytes_hashed':sum(r['source_bytes']for r in frontier),'SP_writes':0},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
