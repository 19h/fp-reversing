; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_value32 () (_ BitVec 32))
(declare-fun routes_context64 () (_ BitVec 64))
(declare-fun routes_A64 () (_ BitVec 64))
(assert
 (let ((?x108 (concat (_ bv0 32) routes_value32)))
(let (($x387 (and (distinct ?x108 ((_ zero_extend 32) routes_value32)) true)))
(let (($x54 (and (distinct routes_context64 routes_context64) true)))
(let (($x308 (and (distinct routes_A64 routes_A64) true)))
(or $x308 $x54 $x387))))))
(check-sat)
