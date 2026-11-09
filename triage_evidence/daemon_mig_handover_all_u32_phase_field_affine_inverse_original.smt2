; benchmark generated from python API
(set-info :status unknown)
(declare-fun handover_input0_32 () (_ BitVec 32))
(declare-fun handover_computed_key32 () (_ BitVec 32))
(assert
 (let ((?x227 (bvadd (bvmul handover_input0_32 (_ bv303893401 32)) handover_computed_key32)))
(and (distinct (bvmul (bvsub ?x227 handover_computed_key32) (_ bv2915375273 32)) handover_input0_32) true)))
(check-sat)
