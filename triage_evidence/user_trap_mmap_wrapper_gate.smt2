(set-logic QF_BV)
(declare-fun n () (_ BitVec 64))
(declare-fun f () (_ BitVec 32))
(define-fun native () Bool
 (ite (not (= (bvand f #x00000002) #x00000000))
      (not (= n #x0000000000000000))
      (and (not (= n #x0000000000000000)) (not (= (bvand f #x00000001) #x00000000)))))
(assert (not (= native (and (not (= n #x0000000000000000)) (not (= (bvand f #x00000003) #x00000000))))))
(check-sat)
