(set-logic QF_BV)
(declare-fun s () (_ BitVec 32)) (declare-fun p () (_ BitVec 32))
(assert (not (= (= (bvsub (bvadd s (bvxor p #x58a30122)) (bvand (bvshl p #x00000001) #x4eb9fdba)) #x58a30122) (= s p))))
(check-sat)
