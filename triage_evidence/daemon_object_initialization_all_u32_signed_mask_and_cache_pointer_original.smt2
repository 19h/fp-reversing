; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_mask32 () (_ BitVec 32))
(assert
 (let ((?x60 ((_ extract 31 31) init_mask32)))
(let ((?x59 (concat ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 ?x60 init_mask32)))
(and true (or (and (distinct ?x59 ((_ sign_extend 32) init_mask32)) true) (and (distinct (_ bv446676795392 64) (_ bv446676795392 64)) true))))))
(check-sat)
