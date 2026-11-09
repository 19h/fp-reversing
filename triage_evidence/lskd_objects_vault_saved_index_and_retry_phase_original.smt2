; benchmark generated from python API
(set-info :status unknown)
(declare-fun objects_saved_index32 () (_ BitVec 32))
(assert
 (let ((?x10 ((_ zero_extend 32) objects_saved_index32)))
(let (($x173 (and (distinct ?x10 ?x10) true)))
(or $x173 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv150 32))) (_ bv150 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1777 32))) (_ bv1777 32)) true)))))
(check-sat)
