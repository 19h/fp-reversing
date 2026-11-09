(set-logic QF_BV)
(declare-fun s () (_ BitVec 32))
(assert (not (= (= (bvxor s #x8b3dc651) #x8b3dc651) (= s #x00000000))))
(check-sat)
