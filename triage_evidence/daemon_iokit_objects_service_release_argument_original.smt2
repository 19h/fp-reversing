; benchmark generated from python API
(set-info :status unknown)
(declare-fun service32 () (_ BitVec 32))
(assert
 (let ((?x110 ((_ zero_extend 32) service32)))
(let ((?x141 (concat (_ bv0 32) service32)))
(let (($x124 (and (distinct ?x141 ?x110) true)))
(or $x124 (and (distinct (_ bv48766 64) (_ bv48766 64)) true))))))
(check-sat)
