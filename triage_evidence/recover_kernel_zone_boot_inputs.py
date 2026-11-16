#!/usr/bin/env python3
"""Original ARM/SPTM memory and CPU-number input producers.
O(collection + scanned words + seeds*512 + source) time/space. The bounded
fallthrough address locator generates candidates, not all native references.
"""
import json,struct
from hashlib import sha256
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_MEM,ARM64_OP_IMM
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_magazine_bootstrap as M
P='kernel_zone_boot_inputs';ARM=0xfffffe000be7400c;TOPOLOGY=0xfffffe000be83068;GETTER=0xfffffe000be843d0
SANE=0xfffffe000cb29cb0;MAXMEM=0xfffffe000cb5bb90;MEMSIZE=0xfffffe000cb2fb68
PHYS=0xfffffe0007f36958;AVAILABLE=0xfffffe0007e6da98;EARLY=0xfffffe0007ef8228
CPUCOUNT=0xfffffe0007ef8bec;CPUMAX=CPUCOUNT+4;FUNCTIONS=[ARM,TOPOLOGY,GETTER,M.POLICY]
SPANS={'memory_prefix':(ARM,0xfffffe000be740c0),'sane_publication':(0xfffffe000be752a4,0xfffffe000be752c8),
 'cpu_publication':(0xfffffe000be832fc,0xfffffe000be83338),'getter':(GETTER,GETTER+16),
 'cpu_base':(0xfffffe000be831a0,0xfffffe000be831a8),'policy_count':(0xfffffe000c631fb8,0xfffffe000c631fcc),
 'policy_high_word':(0xfffffe000c63218c,0xfffffe000c632198)}
SCOPE='Original memory-parameter prefix, positive sane-size publication, logical CPU descriptor/count/maximum publication and exported getter. Source proofs and independent private source-cut cases qualify the inputs consumed by the retained capacity policy. Complete ARM/SPTM/topology execution, native inputs/units/boot order, active CPU count, allocator backing/ownership and daemon transaction pairing remain unknown.'
FALSE=M.FALSE+['complete_ARM_or_topology_function_executed','native_boot_argument_control_established','native_active_CPU_count_established']

def locate(k):
 k.cs.detail=True;refs={};windows=[];seeds=words=0
 sections=json.loads(read(ROOT/'kernel_zone_prefill_callers_checks.json'))['direct_branch_scan']['sections']
 targets={SANE,SANE+4,CPUCOUNT,CPUMAX};pages={a&~4095 for a in targets}
 for sec in sections:
  a=int(sec['address'],16);raw=k.read(a,sec['bytes_scanned']);assert sha256(raw).hexdigest()==sec['sha256'];words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x9f000000!=0x90000000:continue
   pc=a+4*j;imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);imm-=((imm>>20)&1)<<21
   if ((pc&~4095)+(imm<<12))&((1<<64)-1) not in pages:continue
   seeds+=1;regs={};hits=[];ii=list(k.cs.disasm(raw[j*4:min(len(raw),j*4+2048)],pc))
   for i in ii:
    m=i.mnemonic;o=i.operands;new={};name=lambda r:'x'+i.reg_name(r)[1:] if i.reg_name(r).startswith('w') else i.reg_name(r)
    if m=='adrp':new[name(o[0].reg)]=o[1].imm&((1<<64)-1)
    if m in ['add','sub'] and len(o)==3 and o[2].type==ARM64_OP_IMM and name(o[1].reg) in regs:
     value=regs[name(o[1].reg)]+(1 if m=='add' else -1)*(o[2].imm<<o[2].shift.value)
     new[name(o[0].reg)]=value&((1<<(32 if i.reg_name(o[0].reg).startswith('w') else 64))-1)
    if m=='mov' and o[1].type==ARM64_OP_REG and name(o[1].reg) in regs:new[name(o[0].reg)]=regs[name(o[1].reg)]&((1<<(32 if i.reg_name(o[0].reg).startswith('w') else 64))-1)
    for op in o:
     if op.type!=ARM64_OP_MEM or name(op.mem.base) not in regs or op.mem.index:continue
     at=(regs[name(op.mem.base)]+op.mem.disp)&((1<<64)-1)
     if at in targets:
      row={'pc':hex(i.address),'address':hex(at),'instruction':m+' '+i.op_str,'bytes_hex':i.bytes.hex(),'entry':sec['entry']}
      refs[(i.address,at)]=row;hits.append(hex(i.address))
    for reg in i.regs_access()[1]:regs.pop(name(reg),None)
    if m in ['bl','blr','blraa']:
     for q in [*range(19),30]:regs.pop('x'+str(q),None)
    regs.update(new)
    if m in ['ret','retab']:break
   if hits:windows.append({'seed_PC':hex(pc),'decoded_window_instructions':len(ii),'candidate_PCs':sorted(set(hits))})
 return {'sections':sections,'aligned_words_scanned':words,'ADRP_seed_count':seeds,'maximum_window_instructions':512,
  'references':list(sorted(refs.values(),key=lambda r:(int(r['pc'],16),int(r['address'],16)))),'candidate_windows':windows,
  'scope':'Candidate-only source fallthrough, including after branches; literal ADRP, immediate ADD/SUB and register MOV constants; aliases killed on writes, volatile constants killed on calls, nonvolatile ABI assumed. Indexed/distant/other encodings and path feasibility are not exhausted.'}

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[k.function(a) for a in FUNCTIONS];old=json.loads(read(ROOT/'kernel_zone_boot_order_checks.json'))
 assert functions[-1]==next(f for f in old['functions'] if f['start']==hex(M.POLICY))
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 strings=[]
 for a in [0xfffffe00070de859,0xfffffe000706412a,0xfffffe00070ea8de,0xfffffe00070ea8e4,0xfffffe00070ea8ea,0xfffffe00070621f9,0xfffffe0007062748]:
  raw=k.read(a,200).split(bytes(1))[0]+bytes(1);strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 scan=locate(k);stores=[r for r in scan['references'] if r['instruction'].startswith('str')]
 assert any(r['pc']=='0xfffffe000be752c4' and r['address']==hex(SANE) for r in stores)
 assert any(r['pc']=='0xfffffe000be83334' and r['address']==hex(CPUMAX) for r in stores)
 counts={'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
  'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':1,'source_blocks':len(spans),
  'block_instructions':sum(len(s['instructions']) for s in spans),'sections_rehashed':len(scan['sections']),
  'aligned_words_scanned':scan['aligned_words_scanned'],'ADRP_seeds':scan['ADRP_seed_count'],'candidate_references':len(scan['references']),
  'candidate_store_sites':len(stores)}
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','kernel_zone_boot_order_checks.json',
   'kernel_zone_prefill_callers_checks.json','audit_kernel_magazine_bootstrap.py','probe_kernel_vm_mig.py','replay_kernel_magazine_bootstrap.py']},
  'functions':functions,'spans':spans,'strings':strings,'candidate_reference_scan':scan,
  'exact_symbols':k.symbols([*FUNCTIONS,SANE,MAXMEM,MEMSIZE,PHYS,AVAILABLE,EARLY,CPUCOUNT,CPUMAX]),
  'file_globals':[{'address':hex(a),'bytes_hex':k.read(a,n).hex()} for a,n in [(SANE,8),(MAXMEM,8),(MEMSIZE,8),(PHYS,8),(AVAILABLE,8),(EARLY,8),(CPUCOUNT,8)]],
  'verified_counts':counts,'conditional_kernel_zone_boot_inputs_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
