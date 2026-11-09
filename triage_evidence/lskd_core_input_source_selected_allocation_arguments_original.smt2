; benchmark generated from python API
(set-info :status unknown)
(declare-fun core_typed_pointer64 () (_ BitVec 64))
(declare-fun core_shape_length32 () (_ BitVec 32))
(assert
 (let ((?x35 ((_ zero_extend 32) core_shape_length32)))
(let (($x8 (and (distinct ?x35 ?x35) true)))
(or $x8 $x8 (and (distinct core_typed_pointer64 core_typed_pointer64) true)))))
(check-sat)
