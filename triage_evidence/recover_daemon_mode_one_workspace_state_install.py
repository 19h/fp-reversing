#!/usr/bin/env python3
"""Recapture two workspace traversals,adapter and private state-plane install."""
import json,re,collections,capstone
from validate_daemon_list_output import split
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_workspace_state_install'
SCOPE='Two74-word workspace traversals and128-byte private state install;Q/I cells are repurposed while800 arithmetic/codec cells survive. Full source,address/control contracts and saved-slot epochs only;algorithm identity,native ownership/output and daemon-kext pairing remain unknown.'
BLOCKS={'first':0x100d845e0,'second':0x100d9c40c,'adapter':0x100cc80a8,'install':0x100b57924}
EDGES={'first':[(0x3489,0x100d845e0),(0x34a3,0x100d9c40c)],'second':[(0x9d34,0x100cc80a8),(0x9d55,0x100b57924)],'adapter':[(0x34a3,0x100d9c40c)],'install':[(0x40d0,None)]}
LINEAGE=['daemon_mode_one_nibble_operation_suite','daemon_mode_one_workspace_passes']
DEPS=[n+'_'+k+'.json'for n in LINEAGE for k in ['source','checks']]+['daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()};writes={};liveins={};bitfields=[];shifts=[];comparisons=[];memory={};opcounts={}
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
   if m=='lsr'and not p[-1].startswith('#'):
    assert word&0xffe0fc00==0x1ac02400 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];shifts.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'shift_count_mask':31})
   if m in['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or m.startswith(('b.','cb','tb')):control.append(m)
  assert 'sp'not in wr and control==['braa'];writes[name]=sorted(wr);liveins[name]=live;memory[name]=[i for i in f['instructions']if i['mnemonic'].startswith(('ld','st'))];opcounts[name]=dict(collections.Counter(i['mnemonic']for i in f['instructions']))
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
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'SP_writes':0,'bitfield_decodes_checked':len(bitfields),'register_shift_decodes_checked':len(shifts),'comparison_role_corrections':len(comparisons),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'operand_based_GPR_first_reads':liveins,'bitfield_decode_checks':bitfields,'register_shift_decode_checks':shifts,'comparison_role_corrections':comparisons,'memory_instructions':memory,'mnemonic_census':opcounts,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
