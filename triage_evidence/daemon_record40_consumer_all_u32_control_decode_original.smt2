; benchmark generated from python API
(set-info :status unknown)
(declare-fun record40_key_input32 () (_ BitVec 32))
(declare-fun record40_raw32 () (_ BitVec 32))
(assert
 (let ((?x80 (concat (_ bv0 32) (bvadd record40_raw32 (bvmul (_ bv1803966767 32) record40_key_input32)))))
(and (distinct ((_ extract 31 0) ?x80) (bvadd record40_raw32 (bvmul record40_key_input32 (_ bv1803966767 32)))) true)))
(check-sat)
