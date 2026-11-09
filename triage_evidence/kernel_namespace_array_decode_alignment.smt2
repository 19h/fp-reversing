(set-logic QF_BV)
(declare-fun token () (_ BitVec 64))
(define-fun small () Bool (= (bvand token #x0000400000000000) #x0000000000000000))
(define-fun addr () (_ BitVec 64) (ite small
 (bvor (bvand token #xffffffffffffc000) #x0000400000000000)
 (bvand token #xffffffffffffffe0)))
(define-fun size () (_ BitVec 64) (ite small
 (bvshl (bvand token #x0000000000003fff) #x000000000000000e)
 (bvshl (bvor (bvand token #x0000000000000010) #x0000000000000020) (bvand token #x000000000000000f))))
(assert (not (and (= (bvand addr #x000000000000001f) #x0000000000000000)
 (bvule size #x000000000fffc000))))
(check-sat)
