#!/usr/bin/env python3
"""Static descriptor-array and typed caller ABI certificate; no target execution."""
import copy,json,subprocess
from recover_daemon_constructor_callers import ROOT,P,SCOPE,FLAGS,IMAGE,CS,FIXUPS,TABLE,BLOCKS,sha,h,build
from validate_daemon_constructor_inputs import SSA as ParentSSA,bv,split
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   if int(i['ea'],16)>=end:break
   if i['mnemonic']=='mvn':
    p=split(i['operands']);self.put(p[0],'(bvnot '+self.get(p[1])+')');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},int(i['ea'],16)+4)
  return self
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in['K','BASE','REC','C','CELL','CONT','TABLE','FN','PTR','B','STATUS']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in['INDEX','COUNT','KIND','QUAL','FILTER','HE','V','E','Q','IX'])+'(declare-fun T () (_ BitVec 16))\n'
def z32(s):return'((_ zero_extend 32) '+s+')'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(tt):return'(assert (or '+' '.join(tt)+'))'
def solve(n,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20)
 assert r.returncode==0 and not r.stderr and r.stdout.strip()=='unsat',(n,r.stdout,r.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
def make(s,n,a,z,r,loads=None,ns='v_'):
 ii=[i for i in s['fragments'][n]['instructions']if a<=int(i['ea'],16)<z];ll=dict(loads or{});dd=[]
 for i in ii:
  if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh')and i['ea']not in ll:
   bits=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;n0=ns+'L'+str(len(dd));dd.append('(declare-fun '+n0+' () (_ BitVec '+str(bits)+'))');ll[i['ea']]=(n0,bits)
 rr={j:'Z'+str(j)for j in range(31)};rr.update(r);g=SSA(rr,ll,namespace=ns).run({'instructions':ii},z);g.declarations='\n'.join(dd)+'\n';return g
def prefix(*gs):return''.join(g.declarations+g.prefix()for g in gs)
def verify(s):
 assert s['static_scope']==SCOPE and s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in s['fragments'].values():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256'];assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 for e in s['branch_edges']:
  ii=s['fragments'][e['fragment']]['instructions'];assert e['source_modifier_u16']==int(ii[-2]['operands'].split('#')[1],0)
  for r in e['selected_slots']:assert((int.from_bytes(IMAGE.read(int(r['slot'],16),8),'little')>>32)&65535)==e['source_modifier_u16']
 for row in s['pointer_records']:assert FIXUPS[int(row['slot'],16)]==row['fixup']and IMAGE.read(int(row['slot'],16),8).hex()==row['raw_bytes']
 assert len(s['modifier_census']['candidates'])==len(s['modifier_census']['original_modifier_collisions'])==8
 for row in s['modifier_census']['candidates']:assert row['target_proved_by_modifier_alone']is False
 assert len(s['retained_profiles'])==12
 for p in s['retained_profiles']:
  assert not p['native_evidence']and p['total_constructor_entries']==5 and p['array_constructor_entries']==2 and p['other_constructor_entries']==3
  assert p['counts']['u64_root']==p['counts']['generic_root']==0 and p['counts']['record']==2 and p['counts']['filter']==4
  assert len(p['array_episodes'])==2
  assert[e['filters']for e in p['array_episodes']]==[2,2]and[e['selected_record_dispatches']for e in p['array_episodes']]==[2,0]and[e['constructor_entries']for e in p['array_episodes']]==[2,0]
  for e in p['array_episodes']:assert all(q['authentication']=='bypassed in private synthetic model'for q in e['events'])
 return True

def proofs(s):
 pp=[];tr={}
 def add(n,gs,tt,scope,extra=''):
  gs=gs if isinstance(gs,list)else[gs];pp.append(solve(n,prefix(*gs)+extra+mismatch(tt),scope));tr[n]=[g.record()for g in gs]
 def read(g,pc):return next(r for r in g.reads if r['site']==pc)
 def at(ix):return'(bvadd TABLE '+bv(ix*8)+')'
 def target(g,pc,cond,a,b):return neq(read(g,pc)['address'],'(ite '+cond+' '+at(a)+' '+at(b)+')')
 ent=make(s,'entry',0x1008cadf0,0x1008cae5c,{8:bv(0x6cf4),9:z32('COUNT'),11:'BASE',13:z32('IX'),14:'CELL',15:z32('FILTER'),'sp':'K'},{'0x1008cae0c':('C',64),'0x1008cae18':('TABLE',64),'0x1008cae1c':('CONT',64)},'e_')
 ex=[(0x3fa0,'C',64),(0x6d40,'CONT',64),(0x1cbc,'FILTER',32),(0x4af8,'BASE',64),(0x2c6c,'COUNT',32)];tt=[];assert len(ent.stores)==5
 for st,(off,val,width)in zip(ent.stores,ex):assert st['width_bits']==width;tt.extend([neq(st['address'],'(bvadd K '+bv(off)+')'),neq(st['value'],val)])
 tt.extend([neq(read(ent,'0x1008cae0c')['address'],'CELL'),neq(ent.get('w10'),'#x00000000'),neq(ent.get('w12'),'#x00002c7c'),neq(ent.get('w6'),'#x74c29d88'),neq(ent.get('x13'),'CONT'),target(ent,'0x1008cae4c','(= BASE #x0000000000000000)',0xba95,0x845e)])
 add('array_entry_snapshot_null_base_and_initial_index',ent,tt,'Selected phase6cf4; borrowed collection-pointer cell is read before array-base guard. NULL base selects direct relay with invalid marker; nonnull base initializes index0 and loop phase. Physical owners/continuation validity remain premises.')
 filt=make(s,'filter',0x100864934,0x10086497c,{10:z32('INDEX'),13:bv(0x2c4e),'sp':'K'},{'0x10086493c':('BASE',64),'0x100864948':('QUAL',32),'0x10086494c':('FILTER',32),'0x100864970':('TABLE',64)},'f_')
 recaddr='(bvadd BASE (bvmul '+z32('INDEX')+' #x0000000000000028))'
 add('array_stride_and_qualifier_partition',filt,[neq(read(filt,'0x100864948')['address'],'(bvadd '+recaddr+' #x0000000000000024)'),neq(read(filt,'0x10086494c')['address'],'(bvadd K #x0000000000001cbc)'),neq(filt.get('x8'),z32('INDEX')),neq(filt.get('x9'),'BASE'),neq(filt.get('w11'),'#x0000845e'),target(filt,'0x100864974','(= QUAL FILTER)',0xa2a0,0x2c4e)],'All u32 indices and arbitrary base/qualifier values;40 B stride and +36 filter. Address equations are modular, not native readable-extent proof.')
 rec=make(s,'record',0x1009c4088,0x1009c40b4,{8:z32('INDEX'),9:'BASE',13:bv(0x2c4e),'sp':'K'},{'0x1009c40a4':('KIND',32),'0x1009c40a8':('TABLE',64)},'r_')
 add('selected_record_pointer_kind_and_dispatch',rec,[neq(rec.get('x10'),recaddr),neq(read(rec,'0x1009c40a4')['address'],'(bvadd '+recaddr+' #x000000000000001c)'),neq(rec.get('w12'),'#x00003428'),neq(read(rec,'0x1009c40ac')['address'],at(0x316a))],'Exact selected descriptor and kind32 load; callee uses record pointer and supplied kind/phase, not a wire discriminator.')
 kp=make(s,'kind_partition',0x100708898,0x1007088ec,{12:bv(0x3428),11:z32('KIND'),'sp':'K'},{'0x1007088e0':('TABLE',64)},'k_')
 add('kind_signed_lower_partition',kp,[target(kp,'0x1007088e4','(bvslt KIND #x372c9ea1)',0x3435,0x3428),neq(kp.get('w9'),'#x372c9ea0'),neq(kp.get('w8'),'#x0000824e')],'All u32 kind codes; source signed threshold and preserved outputs. Target load overwrites X12; the span callee reinitializes W12 before use.')
 sc=make(s,'scalar_class',0x10089e028,0x10089e06c,{8:bv(0x824e),11:z32('KIND'),'sp':'K'},{'0x10089e060':('TABLE',64)},'c_')
 uk=make(s,'u32_kind',0x1009e175c,0x1009e179c,{9:bv(0x556c),11:z32('KIND'),'sp':'K'},{'0x1009e1788':('TABLE',64)},'u_')
 add('scalar_kind_range_and_u32_exact_gate',[sc,uk],[target(sc,'0x10089e064','(bvslt KIND #x372c9ea2)',0x825d,0x824e),neq(sc.get('w9'),'#x0000556c'),target(uk,'0x1009e178c','(= KIND #x372c9ea2)',0x9750,0x556c),neq(uk.get('w8'),'#x00002f82'),neq(uk.get('w6'),'#x74c29d8f')],'Source predicates compose with lower partition to admit exactly372c9ea1/u64 or372c9ea2/u32; unknown scalar-kind path retains raw marker, not public error name.')
 sk=make(s,'span_kind',0x10068fb08,0x10068fb6c,{9:bv(0x372c9ea0),11:z32('KIND'),'sp':'K'},{'0x10068fb58':('TABLE',64)},'sk_')
 add('span_exact_kind_gate',sk,[target(sk,'0x10068fb5c','(= KIND #x372c9ea0)',0xa56e,0x2c7c),neq(sk.get('w12'),'#x00009fdc'),neq(sk.get('w8'),'#x00002f82'),neq(sk.get('w6'),'#x74c29d8f')],'All-u32 equality idiom; W12 is reinitialized from W9, independent of incoming target-register contents. Only exact span kind is accepted on this side.')
 accepted='(or (and (bvslt KIND #x372c9ea1) (= KIND #x372c9ea0)) (and (not (bvslt KIND #x372c9ea1)) (bvslt KIND #x372c9ea2)) (and (not (bvslt KIND #x372c9ea1)) (not (bvslt KIND #x372c9ea2)) (= KIND #x372c9ea2)))'
 pp.append(solve('all_u32_private_kind_membership',mismatch([neq(accepted,'(or (= KIND #x372c9ea0) (= KIND #x372c9ea1) (= KIND #x372c9ea2))')]),'Composition of source-proved signed partitions; exact all-u32 kind membership only, separate qualifier/owner/constructor admission prerequisites.'))
 sg=make(s,'span_guard',0x1009123b4,0x100912434,{12:bv(0x9fdc),10:'REC','sp':'K'},{'0x1009123cc':('PTR',64),'0x100912428':('TABLE',64)},'sp_')
 add('span_pointer_null_skip_and_parameter_phase',sg,[neq(read(sg,'0x1009123cc')['address'],'(bvadd REC #x0000000000000010)'),target(sg,'0x10091242c','(distinct PTR #x0000000000000000)',0x9fee,0x9fdc),neq(sg.get('w9'),'#x0000148c'),neq(sg.get('w11'),'#x0000845e')],'All u64 stored pointers; final constant cancels phase845e and the exact guard is pointer!=0. NULL selects record skip; pointer validity and extent are separate.')
 up=make(s,'u32_params',0x1009d452c,0x1009d4560,{9:bv(0x556c),10:'REC','sp':'K'},{'0x1009d453c':('HE',32),'0x1009d4540':('V',32),'0x1009d4544':('C',64),'0x1009d4554':('TABLE',64)},'up_')
 add('u32_descriptor_fields_and_adapter_phase',up,[neq(read(up,'0x1009d453c')['address'],'(bvadd REC #x0000000000000018)'),neq(read(up,'0x1009d4540')['address'],'(bvadd REC #x0000000000000008)'),neq(up.get('w19'),'HE'),neq(up.get('w10'),'V'),neq(up.get('x0'),'C'),neq(up.get('w20'),'#x000001be'),neq(up.get('w21'),'#x000047f4'),neq(read(up,'0x1009d4558')['address'],at(0x18a5))],'Descriptor raw identifier/value32 come from +24/+8. Actual adapter target index is source-derived; frame+3fa0 provides collection.')
 sp=make(s,'span_params',0x1009312bc,0x100931358,{9:bv(0x148c),10:'REC','sp':'K'},{'0x1009312cc':('HE',32),'0x1009312d0':('PTR',64),'0x100931314':('E',32),'0x100931318':('C',64),'0x10093134c':('TABLE',64)},'spr_')
 add('span_descriptor_pointer_identity_and_fields',sp,[neq(read(sp,'0x1009312cc')['address'],'(bvadd REC #x0000000000000018)'),neq(read(sp,'0x1009312d0')['address'],'(bvadd REC #x0000000000000010)'),neq(read(sp,'0x100931314')['address'],'(bvadd REC #x0000000000000020)'),neq(sp.get('x20'),'PTR'),neq(sp.get('w21'),'E'),neq(sp.get('w19'),'HE'),neq(sp.get('x0'),'C'),neq(sp.get('w11'),'#x0000a337'),neq(read(sp,'0x100931350')['address'],at(0x2a01))],'All-u64 span transform is identity, not assumed pointer encryption. Encoded constructor extent E is read at+32; owner validity is independent of the source null predicate.')
 ua=make(s,'u32_adapter',0x100752360,0x1007523a8,{0:'C',19:z32('HE'),10:z32('V'),20:bv(0x1be),21:bv(0x47f4),'sp':'K'},{'0x100752368':('TABLE',64),'0x10075236c':('CONT',64)},'ua_')
 add('u32_adapter_outer_continuation_and_null_collection',ua,[neq(ua.stores[0]['address'],'(bvadd K #x0000000000003598)'),neq(ua.stores[0]['value'],'CONT'),neq(read(ua,'0x10075236c')['address'],at(0x1be)),target(ua,'0x100752398','(= C #x0000000000000000)',0x47f4,0x482e),neq(ua.get('w8'),'#x00006cf4'),neq(ua.get('w6'),'#x74c29d88'),neq(ua.get('w19'),'HE'),neq(ua.get('w10'),'V')],'Valid saved frame/table; NULL collection bypasses constructor via typed return. Parent selector1be is resolved before inner continuation222 replaces W11.')
 sa=make(s,'span_adapter',0x100894dac,0x100894df8,{0:'C',9:bv(0x148c),11:bv(0xa337),19:z32('HE'),20:'PTR',21:z32('E'),'sp':'K'},{'0x100894dbc':('TABLE',64),'0x100894dc0':('CONT',64)},'sa_')
 add('span_adapter_outer_continuation_and_null_collection',sa,[neq(sa.stores[0]['address'],'(bvadd K #x0000000000002a78)'),neq(sa.stores[0]['value'],'CONT'),neq(read(sa,'0x100894dc0')['address'],at(0x148c)),target(sa,'0x100894de8','(= C #x0000000000000000)',0xa34b,0xa337),neq(sa.get('w8'),'#x00006cf4'),neq(sa.get('w6'),'#x74c29d88'),neq(sa.get('x20'),'PTR'),neq(sa.get('w21'),'E')],'Selected span phase; saves the distinct parent continuation before constructor continuation1ee. NULL collection and NULL span-pointer skip are separate predicates.')
 ur=make(s,'u32_root',0x100828290,0x1008282cc,{8:bv(0x6cf4),0:'C',19:z32('HE'),10:z32('V'),'sp':'K'},{'0x1008282a4':('TABLE',64)},'ur_')
 sr=make(s,'span_root',0x10069d718,0x10069d74c,{8:bv(0x6cf4),0:'C',19:z32('HE'),20:'PTR',21:z32('E'),'sp':'K'},{'0x10069d724':('TABLE',64)},'sr_')
 add('u32_span_roots_and_common_entry',[ur,sr],[neq(read(ur,'0x1008282a8')['address'],at(0x5eb2)),neq(ur.get('w11'),'#x00000222'),neq(ur.get('w9'),'#x000086b4'),neq(ur.get('w21'),'#x8b3dc655'),neq(ur.get('w10'),'V'),neq(ur.get('x0'),'C'),neq(ur.get('w19'),'HE'),neq(ur.get('x12'),bv(0x2c220a381b62f9ab)),neq(ur.get('x20'),bv(0)),neq(read(sr,'0x10069d728')['address'],at(0x5eb2)),neq(sr.get('w11'),'#x000001ee'),neq(sr.get('w9'),'#x00004118'),neq(sr.get('w21'),'E'),neq(sr.get('x20'),'PTR'),neq(sr.get('x0'),'C'),neq(sr.get('w19'),'HE'),neq(sr.get('w10'),'#x8b3dc651'),neq(sr.get('x12'),bv(0x2c220a381b62f9ab))],'Source target5eb2 is common constructor700d80, IA2c67; selected internal types and encoded extents, not a PAC-only name inference.')
 ug=make(s,'u64_gate',0x100941ef4,0x100941f3c,{9:bv(0x556c),10:'REC','sp':'K'},{'0x100941f00':('C',64),'0x100941f28':('TABLE',64)},'ug_')
 add('u64_array_collection_gate',ug,[target(ug,'0x100941f2c','(= C #x0000000000000000)',0x556c,0x5570),neq(ug.get('w8'),'#x00002f82'),neq(ug.get('w6'),'#x74c29d88'),neq(ug.get('x10'),'REC')],'Kind-range membership supplies u64 mode; this gate checks collection pointer only, retaining raw invalid marker for NULL.')
 dr=make(s,'u64_root',0x1006b74e8,0x1006b7530,{9:bv(0x556c),10:'REC',0:'C','sp':'K'},{'0x1006b74fc':('B',64),'0x1006b7500':('HE',32),'0x1006b7510':('TABLE',64)},'dr_')
 add('u64_descriptor_root_full_operand_and_entry',dr,[neq(read(dr,'0x1006b74fc')['address'],'REC'),neq(read(dr,'0x1006b7500')['address'],'(bvadd REC #x0000000000000018)'),neq(read(dr,'0x1006b7514')['address'],at(0x5eb2)),neq(dr.get('x12'),'B'),neq(dr.get('x0'),'C'),neq(dr.get('w19'),'HE'),neq(dr.get('w11'),'#x0000022e'),neq(dr.get('w8'),'#x00006cf4'),neq(dr.get('w9'),'#x00009546'),neq(dr.get('w21'),'#x8b3dc659'),neq(dr.get('w10'),'#x8b3dc651'),neq(dr.get('x20'),bv(0))],'Full-u64 raw operand from record+0; fixed u64 type and8 B extent, default unused value32/span fields, direct constructor return22e. No retained occurrence is claimed.')
 gr=make(s,'generic_root',0x10097b9b0,0x10097b9dc,{8:bv(0x6cf4),19:z32('HE'),9:'((_ zero_extend 48) T)',21:z32('E'),'sp':'K'},{'0x10097b9b4':('C',64),'0x10097b9b8':('V',32),'0x10097b9bc':('B',64),'0x10097b9c0':('PTR',64),'0x10097b9d0':('TABLE',64)},'gr_')
 add('generic_constructor_root_frame_operands',gr,[neq(read(gr,'0x10097b9d4')['address'],at(0x5eb2)),neq(gr.get('w11'),'#x00000228'),neq(gr.get('x0'),'C'),neq(gr.get('w10'),'V'),neq(gr.get('x12'),'B'),neq(gr.get('x20'),'PTR'),neq(gr.get('w19'),'HE'),neq(gr.get('w21'),'E'),neq(gr.get('w9'),'((_ zero_extend 16) T)'),neq(read(gr,'0x10097b9b4')['address'],'(bvadd K #x0000000000002ff8)'),neq(read(gr,'0x10097b9b8')['address'],'(bvadd K #x0000000000001a74)'),neq(read(gr,'0x10097b9bc')['address'],'(bvadd K #x0000000000007768)'),neq(read(gr,'0x10097b9c0')['address'],'(bvadd K #x00000000000031f0)')],'Additional source-proved caller: C/frame2ff8,V/1a74,B/7768,span/31f0 and incoming HE/T/E. Upstream production and reachability remain unproved.')
 uret=make(s,'u32_return',0x100781e0c,0x100781e1c,{6:'STATUS','sp':'K'},{'0x100781e0c':('CONT',64),'0x100781e10':(bv(0x6cf4),64)},'urt_')
 sret=make(s,'span_return',0x1006d8264,0x1006d826c,{6:'STATUS','sp':'K'},{'0x1006d8264':('CONT',64)},'srt_')
 add('typed_outer_continuation_reload_and_status',[uret,sret],[neq(read(uret,'0x100781e0c')['address'],'(bvadd K #x0000000000003598)'),neq(uret.get('x8'),'CONT'),neq(uret.get('x21'),bv(0x6cf4)),neq(uret.get('x6'),'STATUS'),neq(read(sret,'0x1006d8264')['address'],'(bvadd K #x0000000000002a78)'),neq(sret.get('x8'),'CONT'),neq(sret.get('x6'),'STATUS')],'Inner constructor returns222/1ee and outer saved continuations are distinct. Raw full64 status survives local relay instructions; native frame preservation remains a premise.')
 status_gates=[]
 for n,a,z,phasepc,tpc,bpc,yes,no in [('u32_status',0x10072d2cc,0x10072d318,'0x10072d2d0','0x10072d30c','0x10072d310',0x2c4e,0x2c7c),('span_status',0x100882c94,0x100882cdc,'0x100882c98','0x100882cd0','0x100882cd4',0x2c4e,0x2c7c),('u64_status',0x100712d84,0x100712de8,'0x100712d8c','0x100712ddc','0x100712de0',0x7c6a,0x556c)]:
  g=make(s,n,a,z,{6:'STATUS','sp':'K'},{phasepc:(bv(0x6cf4),64),tpc:('TABLE',64)},n+'_');status_gates.append(g)
  add(n+'_exact_success_partition',g,[target(g,bpc,'(= ((_ extract 31 0) STATUS) #x8b3dc651)',yes,no),neq(g.get('w8'),'#x00002f82'),neq(g.get('w11'),'#x0000845e'),neq(g.get('x6'),'STATUS')],'Every raw X6 value; exact low32 success advances, other values select common completion. No public error-name or native return behavior is assigned.')
 adv=make(s,'advance',0x10084dce0,0x10084dd18,{11:bv(0x845e),6:'STATUS','sp':'K'},{'0x10084dcf8':('INDEX',32),'0x10084dd08':('COUNT',32),'0x10084dd0c':('TABLE',64)},'ad_')
 add('selected_or_skipped_record_increment',adv,[neq(adv.get('w10'),'(bvadd INDEX #x00000001)'),neq(adv.get('w9'),'COUNT'),neq(adv.get('w12'),'#x00002c7c'),neq(read(adv,'0x10084dd10')['address'],at(0x845e))],'All u32 indices/counts; source increment is modular. Nonwrapping progress requires the separately proved in-range loop invariant.')
 nxt=make(s,'next',0x10082e028,0x10082e07c,{12:bv(0x2c7c),10:z32('INDEX'),9:z32('COUNT'),'sp':'K'},{'0x10082e068':('TABLE',64)},'nx_')
 assert len(nxt.stores)==1 and nxt.stores[0]['width_bits']==32
 add('loop_index_store_unsigned_count_gate_and_success',nxt,[neq(nxt.stores[0]['address'],'(bvadd K #x0000000000002bf4)'),neq(nxt.stores[0]['value'],'INDEX'),target(nxt,'0x10082e06c','(bvugt COUNT INDEX)',0x5524,0x2c7c),neq(nxt.get('w13'),'#x00002c4e'),neq(nxt.get('w8'),'#x00002f82'),neq(nxt.get('w6'),'#x8b3dc651')],'All u32 indices/counts, including count0; the 64-bit carry expression is exactly unsigned COUNT>INDEX. Own source instructions publish success before final completion.')
 pp.append(solve('in_range_loop_increment_no_wrap',mismatch(['(and (bvult INDEX COUNT) (not (bvult INDEX (bvadd INDEX #x00000001))))','(and (bvult INDEX COUNT) (bvugt (bvadd INDEX #x00000001) COUNT))']),'All u32 INDEX/COUNT. With initial index0 and source COUNT>INDEX gate, each visited record advances without wrap and at most COUNT records are examined, unless constructor failure completes earlier.'))
 comp=make(s,'complete',0x100757d2c,0x100757d3c,{8:bv(0x2f82),6:'STATUS','sp':'K'},{'0x100757d2c':('CONT',64),'0x100757d30':('TABLE',64)},'co_')
 relay=make(s,'relay',0x100692834,0x100692838,{13:'CONT',6:'STATUS','sp':'K'},ns='re_')
 add('shared_array_completion_and_raw_status',[comp,relay],[neq(read(comp,'0x100757d2c')['address'],'(bvadd K #x0000000000006d40)'),neq(comp.get('x13'),'CONT'),neq(read(comp,'0x100757d34')['address'],at(0x2f82)),neq(comp.get('x6'),'STATUS'),neq(relay.get('x13'),'CONT'),neq(relay.get('x17'),bv(0x7d32)),neq(relay.get('x6'),'STATUS')],'Common completion is used for success/end and errors; saved outer continuation and full raw X6 are transferred. It is not intrinsically a failure-only block or public C return.')
 gen=make(s,'generic_status',0x10084d5d0,0x10084d628,{6:'STATUS','sp':'K'},{'0x10084d5d4':(bv(0x6cf4),64),'0x10084d61c':('TABLE',64)},'ge_')
 add('generic_caller_status_frontiers',gen,[target(gen,'0x10084d620','(= ((_ extract 31 0) STATUS) #x8b3dc651)',0x8784,0x1a25),neq(gen.get('w8'),'#x00000b9e'),neq(gen.get('x6'),'STATUS')],'Additional generic caller reaches distinct success/error frontiers; full generic cursor/cleanup workflow is not proved.')
 err=make(s,'generic_error',0x1008f045c,0x1008f0490,{8:bv(0xb9e),6:'STATUS','sp':'K'},{'0x1008f046c':('C',64),'0x1008f0474':('TABLE',64)},'er_')
 assert len(err.stores)==2
 add('generic_error_status_and_collection_cell_relay',err,[neq(err.stores[0]['address'],'(bvadd K #x000000000000850c)'),neq(err.stores[0]['value'],'((_ extract 31 0) STATUS)'),neq(err.stores[1]['address'],'(bvadd K #x0000000000001548)'),neq(err.stores[1]['value'],'C'),neq(err.get('x19'),'(bvadd K #x0000000000001548)'),neq(err.get('w24'),'#x00006cf4'),neq(read(err,'0x1008f0480')['address'],at(0x3ad1))],'Failure-side local u32 marker and collection-pointer-cell relay only; the next helper body/native effects and public result remain unproved.')
 cf=make(s,'caller_first',0x100703a30,0x100703a54,{8:bv(0x6cf4),19:'CELL',9:z32('COUNT'),11:'BASE','sp':'K'},{'0x100703a44':('TABLE',64)},'cf_')
 cs=make(s,'caller_second',0x1008f05f0,0x1008f0624,{13:bv(0x8b),'sp':'K'},{'0x1008f05f8':('CELL',64),'0x1008f05fc':('BASE',64),'0x1008f0604':('COUNT',32),'0x1008f0614':('TABLE',64)},'cs_')
 add('two_frozen_array_caller_argument_interfaces',[cf,cs],[neq(cf.get('x14'),'(bvadd CELL #x0000000000000008)'),neq(cf.get('w13'),'#x00000099'),neq(cf.get('w15'),'#x00000002'),neq(read(cf,'0x100703a48')['address'],at(0x25eb)),neq(cs.get('x14'),'CELL'),neq(cs.get('x11'),'BASE'),neq(cs.get('w9'),'COUNT'),neq(cs.get('w13'),'#x0000008b'),neq(cs.get('w15'),'#x00000001'),neq(cs.get('w8'),'#x00006cf4'),neq(read(cs,'0x1008f0618')['address'],at(0x25eb))],'First caller supplies pointer cell object+8 and filter2; second supplies pointer-cell address/frame3950,base3430,count8dd0,filter1. Owner roots and native producer history remain unproved.')
 for n,a,z,phasepc,tpc,bpc,yes in [('outer_first',0x1009a9e00,0x1009a9e44,'0x1009a9e1c','0x1009a9e34','0x1009a9e38',0x8314),('outer_second',0x10088f390,0x10088f3c8,'0x10088f3ac','0x10088f3b8','0x10088f3bc',0x58aa)]:
  g=make(s,n,a,z,{6:'STATUS','sp':'K'},{phasepc:(bv(0x6cf4),64),tpc:('TABLE',64)},n+'_')
  add(n+'_status_consumer',g,[target(g,bpc,'(= ((_ extract 31 0) STATUS) #x8b3dc651)',yes,0x1c9),neq(g.get('x21'),bv(0x6cf4)),neq(g.get('x6'),'STATUS')],'Observed array return destination and exact raw-success consumer; downstream API emission and native result remain distinct. First success reaches the second array caller, not all source states.')
 return pp,tr

def alterations(s):
 ops=[('branch_modifier',lambda t:t['branch_edges'][0].__setitem__('source_modifier_u16',0)),('source_byte',lambda t:t['fragments']['span_guard'].__setitem__('bytes','00'+t['fragments']['span_guard']['bytes'][2:])),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('modifier_names_target',lambda t:t['modifier_census']['candidates'][0].__setitem__('target_proved_by_modifier_alone',True)),('u64_as_observed',lambda t:t['retained_profiles'][0]['counts'].__setitem__('u64_root',1)),('generic_as_observed',lambda t:t['retained_profiles'][0]['counts'].__setitem__('generic_root',1)),('selected_count',lambda t:t['retained_profiles'][0].__setitem__('array_constructor_entries',5)),('episode_filter',lambda t:t['retained_profiles'][0]['array_episodes'][0].__setitem__('filters',1)),('episode_selection',lambda t:t['retained_profiles'][0]['array_episodes'][1].__setitem__('constructor_entries',1)),('native_relabel',lambda t:t['retained_profiles'][0].__setitem__('native_evidence',True))]
 aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:aa.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return aa

def semantic_rejections(s):
 g=make(s,'span_guard',0x1009123b4,0x100912434,{12:bv(0x9fdc),10:'REC','sp':'K'},{'0x1009123cc':('PTR',64),'0x100912428':('TABLE',64)},'reject_')
 address=next(r['address']for r in g.reads if r['site']=='0x10091242c');actual='(= '+address+' (bvadd TABLE '+bv(0x9fee*8)+'))';wrong='(distinct PTR #x000000000000845e)';query='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+prefix(g)+mismatch([neq(actual,wrong)])+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=query,text=True,capture_output=True,timeout=20);assert r.returncode==0 and not r.stderr and r.stdout.strip()=='sat'
 return[{'name':'nonzero_845e_sentinel_interpretation','query':query,'result':'sat','interpretation_rejected':True,'correct_predicate':'PTR!=0','scope':'Pure source-expression counterexample to the provisional nonzero-sentinel interpretation; no target input or fault is executed. Phase845e cancels against the final constant.'}]

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s);sem=semantic_rejections(s);sites=[pc for gs in tr.values()for g in gs for pc in g['source_sites']];expected=[i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']!='braa'];assert sorted(sites)==sorted(expected)and len(sites)==len(set(sites));counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'translated_instruction_instances':sum(len(g['source_sites'])for gs in tr.values()for g in gs),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa),'rejected_semantic_interpretations':len(sem)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'semantic_rejections':sem,'all_nonterminal_source_instructions_covered_once':True,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
