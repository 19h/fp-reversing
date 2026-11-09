; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(declare-fun callback_temp64 () (_ BitVec 64))
(assert
 (let ((?x74 ((_ zero_extend 32) (bvand ((_ extract 31 0) (bvsub callback_temp64 callback_state64)) (_ bv65535 32)))))
(let ((?x65 (bvshl ?x74 (_ bv4 64))))
(and true (or (bvugt ?x65 (_ bv1048560 64)) (and (distinct (bvand ?x65 (_ bv15 64)) (_ bv0 64)) true))))))
(check-sat)
