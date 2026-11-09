(set-logic QF_BV)
(declare-fun p () (_ BitVec 64))
(assert (not (= (bvadd p #x000000007ed8f1f2 #xffffffff81270e0e) p)))
(check-sat)
