; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_N32 () (_ BitVec 32))
(declare-fun registry_i32 () (_ BitVec 32))
(assert
 (let (($x284 (bvugt (bvadd (bvshl ((_ zero_extend 32) registry_i32) (_ bv4 64)) (_ bv16 64)) (bvshl ((_ zero_extend 32) registry_N32) (_ bv4 64)))))
(and (bvult registry_i32 registry_N32) $x284)))
(check-sat)
