; benchmark generated from python API
(set-info :status unknown)
(declare-fun saved_input_length32 () (_ BitVec 32))
(declare-fun output_sized_region64 () (_ BitVec 64))
(assert
 (let ((?x53 ((_ zero_extend 32) saved_input_length32)))
(let ((?x94 (concat (_ bv0 32) saved_input_length32)))
(let (($x34 (and (distinct output_sized_region64 output_sized_region64) true)))
(or $x34 (and (distinct ((_ zero_extend 32) (_ bv28 32)) (_ bv28 64)) true) (and (distinct ?x94 ?x53) true))))))
(check-sat)
