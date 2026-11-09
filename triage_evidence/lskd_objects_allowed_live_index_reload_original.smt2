; benchmark generated from python API
(set-info :status unknown)
(declare-fun objects_saved_index32 () (_ BitVec 32))
(assert
 (let (($x164 (and (distinct (_ bv18446741874859907896 64) (_ bv18446741874859907896 64)) true)))
(let ((?x10 ((_ zero_extend 32) objects_saved_index32)))
(let (($x173 (and (distinct ?x10 ?x10) true)))
(or $x173 $x164)))))
(check-sat)
