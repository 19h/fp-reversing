; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_descriptor_count32 () (_ BitVec 32))
(assert
 (let ((?x82 (concat ((_ extract 27 0) rs_descriptor_count32) (_ bv0 4))))
(not (= ?x82 (bvmul (_ bv16 32) rs_descriptor_count32)))))
(check-sat)
