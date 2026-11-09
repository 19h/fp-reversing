; benchmark generated from python API
(set-info :status unknown)
(declare-fun result32 () (_ BitVec 32))
(assert
 (and (distinct (bvsub (bvadd result32 (_ bv833486950 32)) (bvand (bvshl result32 (_ bv1 32)) (_ bv1666973900 32))) (bvxor result32 (_ bv833486950 32))) true))
(check-sat)
