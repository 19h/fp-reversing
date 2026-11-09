; benchmark generated from python API
(set-info :status unknown)
(declare-fun saved_phase32 () (_ BitVec 32))
(declare-fun input_sized_region64 () (_ BitVec 64))
(assert
 (let (($x12 (and (distinct input_sized_region64 input_sized_region64) true)))
(or $x12 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1203 32))) (_ bv1203 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv700 32))) (_ bv700 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv3208434912 32))) (_ bv3208434912 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) saved_phase32)) saved_phase32) true))))
(check-sat)
