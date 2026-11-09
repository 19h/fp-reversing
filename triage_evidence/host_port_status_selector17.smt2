(set-logic QF_BV)
(declare-fun status () (_ BitVec 32))
(define-fun folded () (_ BitVec 32)
  (bvadd (bvxor status #x71cff3bf) #xbfbfbf53
    (bvand (bvshl status #x00000001) #xe39fe77e)))
(assert (not (= (= folded #x318fb312) (= status #x00000000))))
(check-sat)
