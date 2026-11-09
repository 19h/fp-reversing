; benchmark generated from python API
(set-info :status unknown)
(declare-fun old_state32 () (_ BitVec 32))
(declare-fun new_state32 () (_ BitVec 32))
(assert
 (let ((?x37 ((_ zero_extend 32) (bvand (bvshl (bvsub new_state32 old_state32) (_ bv4 32)) (_ bv1048560 32)))))
(let ((?x41 (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub new_state32 old_state32))) (_ bv4 64))))
(or (and (distinct ?x37 ?x41) true) (and (distinct (bvand ?x37 (_ bv15 64)) (_ bv0 64)) true) (bvugt ?x37 (_ bv1048560 64))))))
(check-sat)
