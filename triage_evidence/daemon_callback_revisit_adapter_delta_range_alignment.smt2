; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(declare-fun callback_temp64 () (_ BitVec 64))
(assert
 (let ((?x96 (bvadd ((_ extract 15 0) callback_temp64) (bvmul (_ bv65535 16) ((_ extract 15 0) callback_state64)))))
(not (bvule (concat ?x96 (_ bv0 4)) (_ bv1048560 20)))))
(check-sat)
