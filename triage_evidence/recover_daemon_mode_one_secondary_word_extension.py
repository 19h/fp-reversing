#!/usr/bin/env python3
"""Recapture secondary word extension,source sigma components and exit prefix."""
import json,re,collections,capstone
from validate_daemon_list_output import split
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_secondary_word_extension'
SCOPE='Conditional48-step secondary word expansion:word/frame/control contracts,all69 primary-byte bounds,four exact SHA-2 small-sigma components and one state-parametric additive stream dependence. Numeric table validity,full decoded four-stream recurrence,native arrival/owners/output,whole algorithm and daemon-kext pairing remain unknown.'
BLOCKS={'loop':0x100c503c8}
CUTS={'after':(0x100c2c25c,0x100c2c278)}
EDGES={'loop':[(0x1ef1,0x100c503c8),(0xa529,0x100c2c25c)]}
LINEAGE=['daemon_mode_one_secondary_word_import','daemon_mode_one_record_word_extension']
PDF='daemon_mode_one_record_word_extension_fips180-4.pdf'
DEPS=[n+'_'+k+'.json'for n in LINEAGE for k in ['source','checks']]+[PDF,'daemon_receive_fixups.txt']

def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 assert sha(ROOT/PDF)=='0455b406d89648d20cbde375561e19c245b9815e894164c2670772e3d54deb82'and(ROOT/PDF).stat().st_size==833315
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()}
 for n,(a,b)in CUTS.items():
  raw=IMAGE.read(a,b-a);fs[n]={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(raw,a)]}
 whole_exit=block(CUTS['after'][0],0x30000);assert whole_exit['instructions'][:7]==fs['after']['instructions'];exit_census={'start':whole_exit['start'],'end':whole_exit['end'],'source_instructions':len(whole_exit['instructions']),'source_bytes':len(bytes.fromhex(whole_exit['bytes'])),'sha256':h(bytes.fromhex(whole_exit['bytes'])),'captured_prefix_instructions':7,'full_body_translated':False}
 writes={};liveins={};bitfields=[];umulls=[];shifts=[];comparisons=[];memory={};opcounts={};divisions=[];eons=[];tests=[];cnegs=[]
 for name,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);ii=list(dc.disasm(raw,int(f['start'],16)));assert len(raw)==4*len(ii)
  seen=set();live=[];wr=set();control=[]
  for i in ii:
   m=i.mnemonic;p=split(i.op_str);word=int.from_bytes(i.bytes,'little');rd,ww=i.regs_access();ww={i.reg_name(r)for r in ww}
   if m in['cmp','tst']:
    bad={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if bad:comparisons.append({'site':hex(i.address),'mnemonic':m,'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    ww-=bad
   wr.update(ww)
   args=p if m in['str','strb','cmp','tst','braa']else p[1:]+([p[0]]if m in['movk','bfi','bfxil']else[])
   for op in args:
    for r in re.findall(r'\b[wx][0-9]+\b',op):
     if r[1:]not in seen and r not in{v['register']for v in live}:live.append({'register':r,'first_read':hex(i.address)})
   if m not in['str','strb','cmp','tst','braa']:seen.add(p[0][1:])
   if m in['bfi','bfxil','ubfx','ubfiz']:
    sf=word>>31;width=64 if sf else 32;assert(word>>22)&1==sf
    assert word&0x7f800000==(0x53000000 if m in['ubfx','ubfiz']else 0x33000000)
    r=(word>>16)&63;s=(word>>10)&63;assert r<width and s<width
    l,n=int(p[2][1:],0),int(p[3][1:],0);assert(l,n)==(((width-r)%width,s+1)if m in['bfi','ubfiz']else(r,s-r+1))
    assert int(p[0][1:])==word&31 and int(p[1][1:])==(word>>5)&31
    bitfields.append({'site':hex(i.address),'mnemonic':m,'width_bits':width,'immr':r,'imms':s,'source_lsb':l,'source_count':n,'bytes':i.bytes.hex()})
   if m=='eon':
    assert word&0xff200000==0x4a200000 and(word>>22)&3==0 and(word>>10)&63==0 and len(p)==3 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];eons.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'operation':'Rn XOR NOT(Rm);no shift'})
   if m=='tst':
    assert word>>31==0 and word&0x7f20001f==0x6a00001f and(word>>5)&31==23 and(word>>16)&31==4 and(word>>10)&63==0;tests.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'operation':'NE iff (W23 AND W4)!=0;no GPR write'})
   if m=='cneg':
    assert word&0xffe00c00==0x5a800400 and word&31==(word>>5)&31==(word>>16)&31==23 and(word>>12)&15==0 and p==['w23','w23','ne'];cnegs.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'encoded_CSNEG_condition':'EQ','alias_condition':'NE'})
   if m=='udiv':
    assert word&0xffe0fc00==0x1ac00800 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];divisions.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'operands':i.op_str})
   if m=='umull':
    assert word&0xffe0fc00==0x9ba07c00 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];umulls.append({'site':hex(i.address),'bytes':i.bytes.hex(),'operands':i.op_str})
   if m=='lsr'and not p[-1].startswith('#'):
    assert word&0xffe0fc00==0x1ac02400 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];shifts.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'shift_count_mask':31})
   if m in['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or m.startswith(('b.','cb','tb')):control.append(m)
  assert 'sp'not in wr and control==(['braa']if name in BLOCKS else[]);writes[name]=sorted(wr);liveins[name]=live;memory[name]=[i for i in f['instructions']if i['mnemonic'].startswith(('ld','st'))];opcounts[name]=dict(collections.Counter(i['mnemonic']for i in f['instructions']))
 edges=[];slots=set()
 for name,rows in EDGES.items():
  modifier=int(fs[name]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');actual=FIXUPS[slot]['target'];assert w>>63 and(w>>32)&65535==modifier and not(w>>48&7)
   if target is not None:assert actual==target
   else:assert isinstance(actual,int)
   slots.add(slot);edges.append({'fragment':name,'index':hex(ix),'slot':hex(slot),'target':hex(actual),'IA_diversity':hex(modifier),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 rec=[]
 for n in LINEAGE:
  for label,f in json.loads(read(ROOT/(n+'_source.json')))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':n+'_source.json','fragment':label,'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'exit_block_full_instructions':exit_census['source_instructions'],'exit_block_untranslated_instructions':exit_census['source_instructions']-7,'exit_block_bytes_hashed':exit_census['source_bytes'],'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'SP_writes':0,'EON_decodes_checked':len(eons),'TST_decodes_checked':len(tests),'CNEG_decodes_checked':len(cnegs),'UDIV_decodes_checked':len(divisions),'UMULL_decodes_checked':len(umulls),'bitfield_decodes_checked':len(bitfields),'register_shift_decodes_checked':len(shifts),'comparison_role_corrections':len(comparisons),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'operand_based_GPR_first_reads':liveins,'EON_decode_checks':eons,'TST_decode_checks':tests,'CNEG_decode_checks':cnegs,'UDIV_decode_checks':divisions,'UMULL_decode_checks':umulls,'bitfield_decode_checks':bitfields,'register_shift_decode_checks':shifts,'comparison_role_corrections':comparisons,'memory_instructions':memory,'mnemonic_census':opcounts,'prior_recaptures':rec,'exit_block_census':exit_census,'new_IDA_access':False,'prior_IDA_snapshot_reference':'daemon_mode_one_secondary_word_import_source.json','standard_reference':{'publication':'NIST FIPS180-4,August2015','url':'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf','DOI':'10.6028/NIST.FIPS.180-4','local_copy':PDF,'sha256':sha(ROOT/PDF),'size_bytes':833315,'sigma_section':'4.1.2,equations4.6 and4.7','schedule_section':'6.2.2'},'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
