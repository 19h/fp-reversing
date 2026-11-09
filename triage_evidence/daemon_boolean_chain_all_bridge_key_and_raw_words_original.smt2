; benchmark generated from python API
(set-info :status unknown)
(declare-fun bool_chain_key_input32 () (_ BitVec 32))
(declare-fun bool_chain_raw32 () (_ BitVec 32))
(assert
 (let ((?x53 (concat (_ bv0 32) (bvxor bool_chain_raw32 (bvmul (_ bv2207351123 32) bool_chain_key_input32)))))
(and (distinct ((_ extract 31 0) ?x53) (bvxor bool_chain_raw32 (bvmul bool_chain_key_input32 (_ bv2207351123 32)))) true)))
(check-sat)
