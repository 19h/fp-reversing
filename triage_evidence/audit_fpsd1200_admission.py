#!/usr/bin/env python3
"""Independent event replay and byte/control oracles for protected admission.

Does not import the admission producer. Frozen image/fixup loader is shared;
PAC control, import replay, checkpoints and terminal comparisons are separate.
O(C*(B+F+K)+R) time; O(B+F+R) transient space; SMT cost separate. No native API.
"""
import hashlib,json,struct
import unicorn as uc
from unicorn import arm64_const as A
import z3
from daemon_rpc502_probe import Probe as Loader,STACK,HALT
from daemon_receive_tools import IMAGE,SOURCE,CS,ROOT,FIXUPS,TABLE,qword,verify_original_fixups
from daemon_import_bindings import binding
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:hashlib.sha256(b).hexdigest();PRIVATE=0x73000000


class Replay(Loader):
    def __init__(self,row):
        super().__init__();self.row=row;self.index=0;self.ei=0;self.pi=0;self.ci=0;self.bi=0;self.pending_copy=None;self.finished=False
        self.bank_bases={int(r['base'],16)for r in row['byte_bank_reads']}
        self.import_events=[e for e in row['events']if e['kind']=='import_fixture']
        self.point_addresses={int(p['pc'],16)for p in row['points']}
        self.u.mem_write(STACK,b'\xa5'*0x80000);self.u.mem_map(PRIVATE,0x10000)
        self.u.mem_write(STACK+0x1000,bytes.fromhex(row['initial_request128']));self.u.mem_write(STACK+0x6000,bytes(range(128)))
        for a,v in zip([0x1010b8078,0x1010c4670],row['fixture'].get('states',[0,0])):self.u.mem_write(a,struct.pack('<Q',v))
        for name,val in [('CoreFoundation/_kCFAllocatorDefault',0),('CoreFoundation/_kCFAllocatorNull',PRIVATE+0x1000)]:self.u.mem_write(self.import_addresses[name],struct.pack('<Q',val))
        self.setreg(0,STACK+0x1000);self.setreg(1,STACK+0x2000);self.setreg(30,HALT)
        self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)

    def read_hook(self,u,access,address,width,value,data):
        if width==1:
            for b in self.bank_bases:
                if b<=address<b+256:
                    actual={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'base':hex(b),'index':address-b,'value':u.mem_read(address,1)[0]}
                    assert actual==self.row['byte_bank_reads'][self.bi];self.bi+=1;break

    def hook(self,u,pc,n,data):
        if self.pending_copy is not None and pc==self.pending_copy['return_pc']:
            c=self.pending_copy;assert bytes(u.mem_read(c['destination'],32)).hex()==c['destination_after_hex'];self.pending_copy=None;self.ci+=1
        if pc==0x10046f89c:
            c=self.row['copies'][self.ci]
            assert [self.reg(j)for j in range(3)]==[c['source'],c['destination'],c['size_B']]and self.reg(30)==c['return_pc']
            assert bytes(u.mem_read(self.reg(0),32)).hex()==c['source_hex'];self.pending_copy=c
        if pc==HALT:
            assert self.row['stop_reason']=='returned_to_fixture'and self.reg(0)==1;self.finished=True;u.emu_stop();return
        if pc in self.imports:
            e=self.import_events[self.ei];self.ei+=1
            assert e['name']==self.imports[pc]and e['site']==hex(self.reg(30)-4)and e['args']==[hex(self.reg(j))for j in range(8)]
            if 'audit32'in e:assert bytes(u.mem_read(self.reg(1),32)).hex()==e['audit32']
            if 'literal'in e:assert bytes(u.mem_read(self.reg(1),128)).split(b'\0')[0].decode()==e['literal']
            if 'error_cell_before'in e and e['error_cell_before']is not None:assert bytes(u.mem_read(self.reg(2),8)).hex()==e['error_cell_before']
            if 'text32'in e:assert bytes(u.mem_read(self.reg(0),32)).hex()==e['text32']
            if 'modeled_error_object'in e:u.mem_write(self.reg(2),struct.pack('<Q',int(e['modeled_error_object'],16)))
            if 'modeled_output32'in e:u.mem_write(self.reg(2),struct.pack('<I',int(e['modeled_output32'],16)))
            if 'modeled_bytes'in e:u.mem_write(self.reg(1),bytes.fromhex(e['modeled_bytes']))
            if 'modeled_end_pointer'in e:u.mem_write(self.reg(1),struct.pack('<Q',int(e['modeled_end_pointer'],16)))
            if 'result'not in e and e['name']!='libSystem/___chkstk_darwin':
                assert self.row['stop_reason']=='unmodeled_import_boundary'and self.index==len(self.row['visited']);self.finished=True;u.emu_stop();return
            if 'result'in e:self.setreg(0,int(e['result'],16))
            u.reg_write(A.UC_ARM64_REG_PC,self.reg(30));return
        assert self.index<len(self.row['visited'])and self.row['visited'][self.index]==hex(pc)
        self.index+=1
        raw=IMAGE.read(pc,4);assert bytes(u.mem_read(pc,4))==raw;i=next(CS.disasm(raw,pc))
        if pc in self.point_addresses:
            p=self.row['points'][self.pi];self.pi+=1
            assert p['pc']==hex(pc)and p['sp']==hex(u.reg_read(A.UC_ARM64_REG_SP))and p['regs']==[hex(self.reg(j))for j in range(29)]and p['nzcv']==hex(u.reg_read(A.UC_ARM64_REG_NZCV))
            if pc==0x10065ffd8:self.carrier=self.reg(0);self.delta=self.reg(1)
            if 'carrier28'in p:assert bytes(u.mem_read(self.carrier,28)).hex()==p['carrier28']and bytes(u.mem_read(self.delta,8)).hex()==p['delta8']
            if 'adapter_scratch8'in p:assert bytes(u.mem_read(self.reg(20),8)).hex()==p['adapter_scratch8']
            if 'helper_record24'in p:assert bytes(u.mem_read(u.reg_read(A.UC_ARM64_REG_X29)-0xa8,24)).hex()==p['helper_record24']
        m=i.mnemonic
        if m in ['pacibsp','paciasp','autibsp','autiasp','xpaclri','bti']:u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif m in ['retab','retaa']:u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
        elif m in ['braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz']:
            rn=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(rn)
            if m.startswith('blr'):self.setreg(30,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
        else:assert m not in ['svc','hvc','smc','brk']and not m.startswith(('pac','aut','xpac'))

    def run_replay(self):
        self.u.emu_start(0x100004b80,0,count=18001)
        assert self.finished and self.index==len(self.row['visited'])and self.ei==len(self.import_events)and self.pi==len(self.row['points'])and self.ci==len(self.row['copies'])and self.pending_copy is None and self.bi==len(self.row['byte_bank_reads'])
        assert bytes(self.u.mem_read(STACK+0x2000,212)).hex()==self.row['reply212']
        assert bytes(self.u.mem_read(self.carrier,28)).hex()==self.row['carrier28_final']and bytes(self.u.mem_read(self.delta,8)).hex()==self.row['delta8_final']
        assert SHA(bytes(self.u.mem_read(STACK,0x80000)))==self.row['final_stack_sha256']and SHA(bytes(self.u.mem_read(PRIVATE,0x10000)))==self.row['final_private_sha256']
        return self.index,self.ei,self.pi


def audit():
    e=json.loads(read(ROOT/'fpsd1200_admission_checks.json'))
    assert SHA(SOURCE.read_bytes())==e['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert SHA((ROOT/'recover_fpsd1200_admission.py').read_bytes())==e['generator_sha256']
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h,n
    ins={}
    for r in e['spans']:
        a,z=int(r['start'],16),int(r['end'],16);b=IMAGE.read(a,z-a)
        assert b.hex()==r['bytes_hex']and SHA(b)==r['sha256']
        actual=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]
        assert actual==r['instructions'];ins.update({int(i['ea'],16):i for i in actual})
    for a,m,o in [(0x100576604,'cmp','w1, w9'),(0x1004d0654,'cmp','x19, #0'),
      (0x1000ed948,'cmp','w0, w8, uxtb'),(0x1000b7a3c,'mov','w2, #0xa'),
      (0x100127894,'ldrb','w9, [x9]'),(0x100054a0c,'str','w0, [x9]'),
      (0x10055515c,'cmp','w0, w8, uxtb'),(0x100660238,'ubfiz','x8, x8, #4, #0x10')]:
        assert(ins[a]['mnemonic'],ins[a]['operands'])==(m,o),(hex(a),ins.get(a))
    for p in e['proofs'].values():
        s=z3.Solver();s.set(timeout=15000);s.from_string(p['query']);assert s.check()==z3.unsat and p['result']=='unsat'
    assert len(e['proofs'])==8 and len(e['negative_controls'])==2
    for p in e['negative_controls'].values():
        s=z3.Solver();s.set(timeout=15000);s.from_string(p['query']);assert s.check()==z3.sat and p['result']=='sat'
    accesses={int(a,16)for r in e['profiles']for a in r['fixup_reads']};binds={a for a in accesses if FIXUPS[a]['kind'].endswith('bind')}
    assert verify_original_fixups(sorted(accesses-binds))=={k:v for k,v in e['fixups'].items()if k!='bindings'}
    assert [binding(a)for a in sorted(binds)]==e['fixups']['bindings']
    pairs=0
    for p in e['byte_bank_proofs']:
        l,r,k=(int(p[n],16)for n in ['left','right','key']);left,right=IMAGE.read(l,256),IMAGE.read(r,256)
        vals={x^right[left[x]^k]for x in range(256)}
        assert vals=={int(p['constant'],16)}and p['inputs_checked']==256;pairs+=p['observed_uses']
    assert pairs==e['byte_bank_pairs']and sum(len(r['byte_bank_reads'])for r in e['profiles'])==pairs*2+len(e['unpaired_byte_bank_reads'])
    visits=imports=points=copies=denied=frontiers=0
    labels={r['fixture']['label']:r for r in e['profiles']}
    expected_frontiers={'numeric_one','numeric_zero','numeric_minus_one','numeric_two','value_is_string','string_zero','fallback_boolean_true','zero_audit_numeric','client_field2_extent756','string_wide_value','string_empty'}
    for r in e['profiles']:
        f=r['fixture'];token=f.get('audit32',bytes(range(32)).hex());req=bytes.fromhex(r['initial_request128'])
        assert req[84:116].hex()==token and not r['input_ool_reads']
        ev=[p for p in r['events']if p['kind']=='import_fixture']
        for p in ev:
            if 'audit32'in p:assert p['audit32']==token
        for c in r['copies']:
            assert c['size_B']==32 and c['source_hex']==c['destination_after_hex']==token;copies+=1
        at={p['pc']:p for p in r['points']}
        assert int(at['0x1005283ac']['regs'][1],16)==0xad952088 and int(at['0x1004d0640']['regs'][8],16)==0x19a3
        assert int(at['0x10052ddd0']['consumer_phase32'],16)&0xd9==0x48
        first_marker=bytes.fromhex(at['0x10052ddd0']['helper_record24'])[16]
        assert at['0x10052ddd0']['helper_key_prefix32']=='0x72696166'
        first_target=int(at['0x10052de54']['regs'][8],16)
        assert first_target==(0x1004de208 if first_marker==0x7e else 0x100581dd0)
        if f['label']in expected_frontiers:
            assert r['stop_reason']=='unmodeled_import_boundary'and not r['reply_completed']and r['reply_status_u32']is None
            assert ev[-1]['name']=='libbsm/_audit_token_to_au32'and ev[-1]['site']=='0x100581f2c'
            args=[int(a,16)for a in ev[-1]['args']];assert args[1:6]==[0]*5 and args[6]and args[7]==0
            frontiers+=1
        else:
            assert r['reply_completed']and r['reply_size_B']==36 and r['reply_status_u32']==0xffff5bbb
            assert r['delta8_final']=='00'*8 and bytes.fromhex(r['carrier28_final'])[24:28].hex()=='ea9dc274'
            before,after=at['0x10066022c'],at['0x100660230'];seed=int(before['regs'][21],16)
            assert int.from_bytes(bytes.fromhex(before['adapter_scratch8']),'little')==(seed-224)&((1<<64)-1)
            assert int.from_bytes(bytes.fromhex(after['adapter_scratch8']),'little')==seed
            assert ev[-1]['name']=='libSystem/_mig_deallocate';denied+=1
        v,i,p=Replay(r).run_replay();visits+=v;imports+=i;points+=p
    assert len(labels)==27 and frontiers==11 and denied==16
    return {'profiles':27,'returned_error_replies':denied,'audit_PID_boundaries':frontiers,'source_visits':visits,
      'import_events':imports,'GP_SP_NZCV_checkpoints':points,'original_copy_calls':copies,
      'terminal_stack_private_bytes_checked':27*(0x80000+0x10000),'queries_unsat':8,'controls_sat':2,
      'bank_identities':len(e['byte_bank_proofs']),'bank_inputs':256*len(e['byte_bank_proofs']),
      'bank_pair_uses':pairs,'unpaired_byte_bank_reads':len(e['unpaired_byte_bank_reads']),'all_checks_pass':True}


if __name__=='__main__':print(json.dumps(audit()))
