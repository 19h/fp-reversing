; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_counter64 () (_ BitVec 64))
(declare-fun producer_cursor64 () (_ BitVec 64))
(assert
 (let ((?x383 (bvadd ((_ extract 15 0) producer_cursor64) (bvmul (_ bv65535 16) ((_ extract 15 0) producer_counter64)))))
(not (bvule (concat ?x383 (_ bv0 4)) (_ bv1048560 20)))))
(check-sat)
