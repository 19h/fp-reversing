#!/usr/bin/env python3
"""Recapture secondary word import and its post-import handoff."""
import json,re,collections,capstone
from validate_daemon_list_output import split
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_secondary_word_import'
SCOPE='Four-step secondary word import and post-import handoff;source/control/address contracts with arbitrary plane bytes and unconstrained other GPRs under the inherited private ABI. Word-value transforms,post-mutation codec validity,native ownership/output,algorithm identity and daemon-kext pairing remain unknown.'
BLOCKS={'import_words':0x100d524a8,'post_import':0x100d85430}
EDGES={'import_words':[(0x1f73,0x100d524a8),(0x1f61,0x100d85430)],'post_import':[(0x1ef1,0x100c503c8)]}
LINEAGE=['daemon_mode_one_word_xor_plane_refresh','daemon_mode_one_parity_state_adapters']
DEPS=[n+'_'+k+'.json'for n in LINEAGE for k in ['source','checks']]+['daemon_receive_fixups.txt']
def ida_snapshot():
 # Historical read-only MCP observation,not a live IDB query on replay.
 samples=[('0x100d524a8','ef3b07b9e34b07b9e27d041b487c0153497c0c11eccb46b92a09cc1a087da79b'),('0x100ce305c','09f50f51aa0c9b52ca9db8720a020a4a4a01094aab3d90524b99b1720b020b0a'),('0x100b0c100','faab03f90f008052faaf43f95f030039f63f2f394b008052ebb32c396b008052')]
 rows=[]
 for address,value in samples:
  raw=bytes.fromhex(value);assert IMAGE.read(int(address,16),len(raw))==raw;rows.append({'address':address,'bytes_hex':value,'bytes_checked':len(raw),'matches_pinned_reference':True})
 return {'observation_date_UTC':'2026-11-10','database_id':'70f8437872acecf1b3e9068fcca2ec291ae676c59c3cce134703bad2e934062e','input_sha256':'4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7','imagebase':'0x100000000','processor':'ARM','bitness':64,'file_type':'Fat Mach-O file, 2. ARM64e-pauth0','recorded_input_path_available_on_analyst_filesystem':False,'full_container_slice_equivalence_verified':False,'spot_byte_matches':rows,'spot_bytes_checked':96,'knowledge_stats_fact_count':9,'unfiltered_recall_count':7,'unfiltered_recall_truncated':False,'filtered_recall_counts':{'padding':0,'SHA':0,'mode_at_0x100d524a8':0},'returned_ARM64e_protocol_fact_ids':[6,7,8,9],'returned_architecture_mismatched_fact_ids':[2,3,4],'semantic_memory_claims_imported':0,'recall_is_exhaustive':False,'full_5884_byte_comparison_completed':False,'full_byte_batch_observation':'MCP tools/call timed out after300 s;backend completion unknown;no full comparison result.','subsequent_file_probe_observation':'IDA Assist unavailable:matching authenticated bridge worker unavailable;no file/slice hash result.','read_only_tools_only':True,'explicit_target_execution_or_emulation_requested':False,'IDB_mutated':False,'automatic_disassembly_model_diagnostics_used_as_semantic_proof':False,'snapshot_replay_scope':'Pinned-file bytes rechecked;MCP metadata and recall observations are recorded observations,not freshly repeated by this script.'}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={n:block(a,0x30000)for n,a in BLOCKS.items()};writes={};liveins={};bitfields=[];umulls=[];shifts=[];comparisons=[];memory={};opcounts={};divisions=[]
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
   if m=='udiv':
    assert word&0xffe0fc00==0x1ac00800 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];divisions.append({'site':hex(i.address),'bytes':i.bytes.hex(),'width_bits':32,'operands':i.op_str})
   if m=='umull':
    assert word&0xffe0fc00==0x9ba07c00 and[int(v[1:])for v in p]==[word&31,(word>>5)&31,(word>>16)&31];umulls.append({'site':hex(i.address),'bytes':i.bytes.hex(),'operands':i.op_str})
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
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'SP_writes':0,'UDIV_decodes_checked':len(divisions),'UMULL_decodes_checked':len(umulls),'bitfield_decodes_checked':len(bitfields),'register_shift_decodes_checked':len(shifts),'comparison_role_corrections':len(comparisons),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'operand_based_GPR_first_reads':liveins,'UDIV_decode_checks':divisions,'UMULL_decode_checks':umulls,'bitfield_decode_checks':bitfields,'register_shift_decode_checks':shifts,'comparison_role_corrections':comparisons,'memory_instructions':memory,'mnemonic_census':opcounts,'prior_recaptures':rec,'IDA_read_only_context_consulted':True,'IDA_observation_snapshot':ida_snapshot(),'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
