(set-logic QF_BV)
(declare-fun status () (_ BitVec 32))
(define-fun folded () (_ BitVec 32)
  (bvadd (bvxor status #xfbefb35f) #x359fffb3
    (bvand (bvshl status #x00000001) #xf7df66be)))
(assert (not (= (= folded #x318fb312) (= status #x00000000))))
(check-sat)
