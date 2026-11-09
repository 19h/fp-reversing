; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_A64 () (_ BitVec 64))
(assert
 (and (distinct (bvadd (_ bv256 64) identity_A64) (bvadd identity_A64 (_ bv256 64))) true))
(check-sat)
