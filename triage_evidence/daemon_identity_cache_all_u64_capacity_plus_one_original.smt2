; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_return64 () (_ BitVec 64))
(assert
 (and (distinct (bvadd (_ bv1 64) identity_return64) (bvadd identity_return64 (_ bv1 64))) true))
(check-sat)
