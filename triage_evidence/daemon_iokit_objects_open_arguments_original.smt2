; benchmark generated from python API
(set-info :status unknown)
(declare-fun service32 () (_ BitVec 32))
(declare-fun owning_task32 () (_ BitVec 32))
(assert
 (let (($x126 (and (distinct (_ bv4312490884 64) (_ bv4312490884 64)) true)))
(let ((?x110 ((_ zero_extend 32) service32)))
(let ((?x141 (concat (_ bv0 32) service32)))
(let (($x124 (and (distinct ?x141 ?x110) true)))
(let ((?x140 ((_ zero_extend 32) owning_task32)))
(let (($x115 (and (distinct ?x140 ?x140) true)))
(or (and (distinct ?x110 ?x110) true) $x115 (and (distinct ((_ zero_extend 32) (_ bv0 32)) (_ bv0 64)) true) $x126 $x124 $x126 (and (distinct (_ bv59435 64) (_ bv59435 64)) true)))))))))
(check-sat)
