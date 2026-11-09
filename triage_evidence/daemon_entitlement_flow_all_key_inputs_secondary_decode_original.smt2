; benchmark generated from python API
(set-info :status unknown)
(declare-fun ent_flow_key_input32 () (_ BitVec 32))
(declare-fun ent_flow_raw_control32 () (_ BitVec 32))
(assert
 (let ((?x694 (concat (_ bv0 32) (bvxor ent_flow_raw_control32 (bvmul (_ bv834057011 32) ent_flow_key_input32)))))
(and (distinct ((_ extract 31 0) ?x694) (bvxor ent_flow_raw_control32 (bvmul ent_flow_key_input32 (_ bv834057011 32)))) true)))
(check-sat)
