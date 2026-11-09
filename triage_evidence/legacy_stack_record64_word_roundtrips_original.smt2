; benchmark generated from python API
(set-info :status unknown)
(declare-fun arg32 () (_ BitVec 32))
(declare-fun key32 () (_ BitVec 32))
(assert
 (or (and (distinct (bvsub (bvadd key32 arg32) key32) arg32) true) (and (distinct (bvadd (bvsub arg32 key32) key32) arg32) true) (and (distinct (bvxor (bvxor key32 arg32) key32) arg32) true)))
(check-sat)
