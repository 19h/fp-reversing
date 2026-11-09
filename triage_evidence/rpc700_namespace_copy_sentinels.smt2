(set-option :timeout 60000)
(declare-fun p () (_ BitVec 64))
(assert (not (= (bvult (bvadd p #x0000000000000001) #x0000000000000002) (or (= p #x0000000000000000) (= p #xffffffffffffffff)))))
(check-sat)
