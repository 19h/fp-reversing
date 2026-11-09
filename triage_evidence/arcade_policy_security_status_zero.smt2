(set-logic QF_BV)
(declare-fun s () (_ BitVec 32))
(assert (not (= (= (bvxor s #x662255dd) #x662255dd) (= s #x00000000))))
(check-sat)
