(set-logic QF_BV)
(declare-fun o () (_ BitVec 64))
(define-fun encoded () (_ BitVec 64)
 (bvadd (bvxor o #xfd5ff337f77dd6ba) #x7fee7ffee9daef60
  (bvand (bvshl o #x0000000000000001) #xfabfe66feefbad74)))
(assert (not (= encoded (bvadd o #x7d4e7336e158c61a))))
(check-sat)
