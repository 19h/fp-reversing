; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_pointer64 () (_ BitVec 64))
(declare-fun ctxlock_result32 () (_ BitVec 32))
(assert
 (let (($x170 (= ctxlock_pointer64 (_ bv0 64))))
(let ((?x241 (ite $x170 (_ bv1 32) (_ bv0 32))))
(let ((?x244 (bvxor ctxlock_result32 ?x241)))
(let ((?x237 ((_ extract 31 0) (concat (_ bv0 63) (bvxor ((_ extract 0 0) ctxlock_result32) (ite $x170 (_ bv1 1) (_ bv0 1)))))))
(and true (and (distinct ?x237 (bvand ?x244 (_ bv1 32))) true)))))))
(check-sat)
