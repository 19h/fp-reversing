; benchmark generated from python API
(set-info :status unknown)
(declare-fun window_selection64 () (_ BitVec 64))
(assert
 (let ((?x4385 (bvand window_selection64 (_ bv14815232 64))))
(and true (and (distinct (bvand (bvand window_selection64 (_ bv14817176 64)) (_ bv18446744073709547520 64)) ?x4385) true))))
(check-sat)
