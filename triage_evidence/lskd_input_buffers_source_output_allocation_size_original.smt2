; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_capacity32 () (_ BitVec 32))
(assert
 (let ((?x47 ((_ zero_extend 32) output_capacity32)))
(let (($x64 (and (distinct ?x47 ?x47) true)))
(or $x64 $x64))))
(check-sat)
