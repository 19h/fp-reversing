(set-logic QF_BV)
(declare-fun p () (_ BitVec 64))
(assert (not (= (bvadd (bvxor p #xffdcefdcfbfbf6a5) #x002310230404095b (bvand (bvshl p #x0000000000000001) #xffb9dfb9f7f7ed4a)) p)))
(check-sat)
