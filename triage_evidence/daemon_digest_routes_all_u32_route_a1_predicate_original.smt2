; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_value32 () (_ BitVec 32))
(declare-fun routes_phase32 () (_ BitVec 32))
(assert
 (let ((?x125 (bvxor routes_phase32 (bvmul (_ bv212 32) (concat (_ bv0 31) ((_ extract 0 0) routes_value32))))))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x125)) (bvxor routes_phase32 (bvmul (bvand routes_value32 (_ bv1 32)) (_ bv212 32)))) true)))
(check-sat)
