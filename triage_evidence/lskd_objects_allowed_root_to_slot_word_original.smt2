; benchmark generated from python API
(set-info :status unknown)
(declare-fun objects_saved_index32 () (_ BitVec 32))
(declare-fun objects_slot_word64 () (_ BitVec 64))
(declare-fun objects_vector_pointer64 () (_ BitVec 64))
(assert
 (let ((?x219 (bvadd (bvmul ((_ zero_extend 32) (bvand objects_saved_index32 (_ bv1023 32))) (_ bv8 64)) (_ bv8 64))))
(or (and (distinct objects_vector_pointer64 objects_vector_pointer64) true) (and (distinct objects_slot_word64 objects_slot_word64) true) (bvugt ?x219 (_ bv8192 64)))))
(check-sat)
