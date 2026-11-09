; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_counter64 () (_ BitVec 64))
(declare-fun producer_cursor64 () (_ BitVec 64))
(assert
 (let ((?x360 (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub producer_cursor64 producer_counter64))) (_ bv4 64))))
(and true (or (bvugt ?x360 (_ bv1048560 64)) (and (distinct (bvand ?x360 (_ bv15 64)) (_ bv0 64)) true)))))
(check-sat)
