; benchmark generated from python API
(set-info :status unknown)
(declare-fun raw_result_status32 () (_ BitVec 32))
(assert
 (let ((?x382 (ite (= raw_result_status32 (_ bv1582700617 32)) (_ bv908 32) (_ bv936 32))))
(let ((?x217 (bvor ((_ extract 31 31) (bvadd (_ bv2712266679 32) raw_result_status32)) ((_ extract 31 31) (bvadd (_ bv1582700617 32) (bvmul (_ bv4294967295 32) raw_result_status32))))))
(let ((?x360 (bvmul (_ bv36 32) (concat (_ bv0 31) ?x217))))
(let ((?x310 (bvnot ((_ extract 3 2) ?x360))))
(let ((?x333 ((_ extract 6 4) ?x360)))
(let ((?x337 (bvnot ((_ extract 9 7) ?x360))))
(let ((?x342 ((_ extract 31 10) ?x360)))
(let ((?x367 (concat ?x342 ?x337 ?x333 ?x310 (_ bv0 2))))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x367)) ?x382) true))))))))))
(check-sat)
