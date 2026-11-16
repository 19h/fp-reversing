#!/usr/bin/env python3
"""Versioned SPTM input publication and nested storage/CPU initialization.
O(collection + scanned words + seeds*512 + source + fixups) time/space.
The last compiler start is bounded by its file-backed boot segment end.
"""
import bisect,json,struct
from hashlib import sha256
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_MEM,ARM64_OP_IMM
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_mapping_context as C
P='kernel_sptm_boot_inputs';BOOT=0xfffffe000c662920;BOOT_END=0xfffffe000c662b04
POOL=0xfffffe000be71258;DT=0xfffffe000be71450;CPU_CALLER=0xfffffe000be780f8;BOOT_CALLER=0xfffffe000c66054c
GLOBALS=C.CONV_GLOBALS;GLOBAL_BYTES=0x108;MEMSIZE=C.B.MEMSIZE;TOPOBASE=0xfffffe0007ef8260
FUNCTIONS=[BOOT,BOOT_CALLER,POOL,DT,CPU_CALLER,*C.FUNCTIONS]
SCOPE='Original versioned SPTM boot-record publication, original shared/pool allocation and CPU tail call nested inside the complete pmap context initializer, original converters and selected mapping consumers. Original topology pointer is a chained fixup. Exact private state joins preserve declared root/table/backing/DT/opaque-return inputs. Native boot record origin, allocation ownership, SPTM receiver effects, complete gateway and matched daemon transaction remain unknown.'
FALSE=C.FALSE+['native_boot_record_origin_established','native_shared_backing_ownership_established']

def locate(k,sections):
 k.cs.detail=True;targets={C.BOOTROOT,C.SHARED,C.TOPOLOGY,*range(GLOBALS,GLOBALS+GLOBAL_BYTES,8)};pages={a&~4095 for a in targets}
 refs={};seeds=words=0;branches=[];widths={'x':8,'w':4,'q':16,'d':8,'s':4,'b':1,'h':2}
 for sec in sections:
  a=int(sec['address'],16);raw=k.read(a,sec['bytes_scanned']);assert sha256(raw).hexdigest()==sec['sha256'];words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   pc=a+4*j
   if w&0x7c000000==0x14000000:
    imm=w&0x3ffffff;imm-=((imm>>25)&1)<<26;target=(pc+(imm<<2))&((1<<64)-1)
    if target in [BOOT,BOOT_CALLER,POOL,DT,C.CPUINIT]:branches.append({'pc':hex(pc),'target':hex(target),'kind':'BL' if w>>31 else 'B','entry':sec['entry']})
   if w&0x9f000000!=0x90000000:continue
   imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);imm-=((imm>>20)&1)<<21
   if ((pc&~4095)+(imm<<12))&((1<<64)-1) not in pages:continue
   seeds+=1;regs={}
   for i in k.cs.disasm(raw[j*4:min(len(raw),j*4+2048)],pc):
    m=i.mnemonic;o=i.operands;new={};name=lambda r:'x'+i.reg_name(r)[1:] if i.reg_name(r).startswith('w') else i.reg_name(r)
    if m=='adrp':new[name(o[0].reg)]=o[1].imm&((1<<64)-1)
    if m in ['add','sub'] and len(o)==3 and o[2].type==ARM64_OP_IMM and name(o[1].reg) in regs:
     new[name(o[0].reg)]=(regs[name(o[1].reg)]+(1 if m=='add' else -1)*(o[2].imm<<o[2].shift.value))&((1<<(32 if i.reg_name(o[0].reg).startswith('w') else 64))-1)
    if m=='mov' and len(o)>1 and o[1].type==ARM64_OP_REG and name(o[1].reg) in regs:new[name(o[0].reg)]=regs[name(o[1].reg)]&((1<<(32 if i.reg_name(o[0].reg).startswith('w') else 64))-1)
    allowed=m in ['ldr','ldur','str','stur','ldrb','strb','ldrh','strh','sturh','ldp','stp','ldpsw','ldrsw']
    if allowed:
     size=1 if m.endswith('b') else 2 if m.endswith('h') else 8 if m=='ldpsw' else 4 if m=='ldrsw' else widths.get(i.reg_name(o[0].reg)[0],0)*(2 if m in ['ldp','stp'] else 1)
     for op in o:
      if op.type!=ARM64_OP_MEM or name(op.mem.base) not in regs or op.mem.index:continue
      at=(regs[name(op.mem.base)]+op.mem.disp)&((1<<64)-1);hits=sorted(t for t in targets if at<=t<at+size)
      if hits:refs[i.address,at]={'pc':hex(i.address),'access_address':hex(at),'access_bytes':size,'target_words':list(map(hex,hits)),
       'instruction':m+' '+i.op_str,'bytes_hex':i.bytes.hex(),'entry':sec['entry']}
    for reg in i.regs_access()[1]:regs.pop(name(reg),None)
    if m in ['bl','blr','blraa']:
     for q in [*range(19),30]:regs.pop('x'+str(q),None)
    regs.update(new)
    if m in ['ret','retab']:break
 return {'sections':sections,'aligned_words_scanned':words,'ADRP_seeds':seeds,'maximum_window_instructions':512,
  'targets':sorted(map(hex,targets)),'references':sorted(refs.values(),key=lambda r:int(r['pc'],16)),'direct_B_BL_calls':branches,
  'scope':'Candidate-only fallthrough ADRP/immediate ADD-SUB/MOV locator, including pair-access footprints and after branches; register writes/caller-clobbered constants killed. Indexed/distant/other encodings and path feasibility remain unclosed. Direct B/BL scan covers the recorded executable sections only.'}

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[];opaque=[]
 bootseg=next(s for s in k.kernel['segments'] if s['name']=='__TEXT_BOOT_EXEC');assert k.starts[-1]==BOOT and bootseg['address']+bootseg['file_size']==BOOT_END
 old=json.loads(read(ROOT/(C.P+'_checks.json')));matched=0
 for a in FUNCTIONS:
  j=bisect.bisect_right(k.starts,a)-1;assert k.starts[j]==a;b=BOOT_END if a==BOOT else k.starts[j+1];raw=k.read(a,b-a);ii=[]
  for at in range(a,b,4):
   word=k.read(at,4);decoded=list(k.cs.disasm(word,at));assert len(decoded)<=1
   ii.append({'ea':hex(at),'mnemonic':decoded[0].mnemonic if decoded else '.word','operands':decoded[0].op_str if decoded else hex(int.from_bytes(word,'little'))})
   if not decoded:opaque.append({'pc':hex(at),'bytes_hex':word.hex(),'word_u32':hex(int.from_bytes(word,'little'))})
  f={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':ii}
  prior=next((g for g in old['functions'] if g['start']==hex(a)),None)
  if prior is not None:assert f==prior;matched+=1
  functions.append(f)
 sections=json.loads(read(ROOT/'kernel_zone_prefill_callers_checks.json'))['direct_branch_scan']['sections'];scan=locate(k,sections)
 stores=[r for r in scan['references'] if r['instruction'].startswith('st')];rootstores=[r for r in stores if hex(C.BOOTROOT) in r['target_words']]
 assert any(r['pc']=='0xfffffe000be713f4' for r in stores) and not rootstores
 topology=im.pointer(C.TOPOLOGY);assert topology['target']==hex(TOPOBASE)
 strings=[]
 for a in [0xfffffe00070ea7fc,0xfffffe0007061c9c,0xfffffe0007061ce0,0xfffffe0007061d2e]:
  raw=k.read(a,256).split(bytes(1))[0];strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw.decode('ascii')})
 counts={'captured_functions':len(functions),'captured_words':sum(len(f['instructions']) for f in functions),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),
  'matched_prior_functions':matched,'undecoded_words_preserved':len(opaque),'sections_rehashed':len(sections),'aligned_words_scanned':scan['aligned_words_scanned'],
  'ADRP_seeds':scan['ADRP_seeds'],'candidate_references':len(scan['references']),'candidate_store_sites':len(stores),'boot_root_candidate_stores':len(rootstores),'direct_B_BL_calls':len(scan['direct_B_BL_calls'])}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in [C.P+'_checks.json','kernel_zone_prefill_callers_checks.json','kernel_native_reader.py','kernel_vm_mig_tools.py']},
  'functions':functions,'undecoded_words':opaque,'boot_boundary':{'compiler_start':hex(BOOT),'last_compiler_start':True,'file_backed_segment_end':hex(BOOT_END),
   'segment':{k:(hex(v) if isinstance(v,int) else v) for k,v in bootseg.items()},'last_instruction_PC':hex(BOOT_END-4),'last_instruction':'ret',
   'scope':'Last compiler start lacks a following function-start record; the file-backed boot segment ends immediately after its second RET. All direct internal successors are checked independently.'},
  'candidate_reference_scan':scan,'topology_fixup':topology,'topology_first_three_records_hex':k.read(TOPOBASE,3*136).hex(),
  'original_boot_root_bytes_hex':k.read(C.BOOTROOT,8).hex(),'original_interface_globals_hex':k.read(GLOBALS,GLOBAL_BYTES).hex(),
  'strings':strings,'exact_symbols':k.symbols([*FUNCTIONS,TOPOBASE,C.TOPOLOGY,C.SHARED,0xfffffe000c662324,0xfffffe000c662110]),'verified_counts':counts,
  'conditional_kernel_sptm_boot_inputs_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
