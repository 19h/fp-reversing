; benchmark generated from python API
(set-info :status unknown)
(declare-fun window_selection64 () (_ BitVec 64))
(declare-fun window_selection_high32 () (_ BitVec 32))
(assert
 (let ((?x4385 (bvand window_selection64 (_ bv14815232 64))))
(let ((?x4391 (bvxor window_selection64 (bvshl ((_ zero_extend 32) window_selection_high32) (_ bv32 64)))))
(and true (and (distinct (bvand ?x4391 (_ bv14815232 64)) ?x4385) true)))))
(check-sat)
