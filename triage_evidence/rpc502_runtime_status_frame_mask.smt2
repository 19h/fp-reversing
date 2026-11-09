(set-logic QF_BV)
(declare-fun p () (_ BitVec 64))
(define-fun caller () (_ BitVec 64)
 (bvmul (bvxor (bvsub #xfffffffffffffffe
 (bvadd (bvor p #x7ff9dd26253164cc) (bvor (bvnot p) #x800622d9dace9b33)))
 #x2e351d0119674812) #x0000000044a8b7e9))
(assert (not (= caller (bvmul (bvxor p #xae333fd8c3a9d321) #x0000000044a8b7e9))))
(check-sat)
