; benchmark generated from python API
(set-info :status unknown)
(declare-fun saved_input_length32 () (_ BitVec 32))
(declare-fun output_sized_region64 () (_ BitVec 64))
(assert
 (let (($x62 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) saved_input_length32)) saved_input_length32) true)))
(let (($x34 (and (distinct output_sized_region64 output_sized_region64) true)))
(or $x34 $x62))))
(check-sat)
