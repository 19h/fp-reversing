(set-logic QF_BV)
(declare-fun s () (_ BitVec 64))
(assert (or
 (not (= (bvadd s #x000000007bed81d2 #xffffffff84127e2e) s))
 (not (= (bvadd s #x000000004677e24f #xffffffffb9881db1) s))))
(check-sat)
