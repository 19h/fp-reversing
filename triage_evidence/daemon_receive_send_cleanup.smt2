(set-logic QF_BV)
(declare-fun x () (_ BitVec 32))
(define-fun folded () (_ BitVec 32)
 (bvadd (bvxor x #xdffd7e7e) #x1002817f
   (bvand (bvshl x #x00000001) #xbffafcfc)))
(assert (not (= (bvule folded #x00000001)
 (or (= x #x10000003) (= x #x10000004)))))
(check-sat)
