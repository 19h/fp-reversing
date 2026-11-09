; benchmark generated from python API
(set-info :status unknown)
(declare-fun input64 () (_ BitVec 64))
(assert
 (let ((?x11 (bvnot ((_ extract 0 0) input64))))
(let ((?x9 ((_ extract 31 1) input64)))
(let ((?x12 (concat ?x9 ?x11)))
(and (distinct (bvxor ((_ extract 31 0) input64) (_ bv1 32)) ?x12) true)))))
(check-sat)
