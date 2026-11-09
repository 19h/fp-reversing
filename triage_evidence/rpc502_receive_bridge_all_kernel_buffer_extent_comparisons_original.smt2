; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_descriptor_extent32 () (_ BitVec 32))
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(assert
 (and (distinct (= (bvsub ((_ zero_extend 32) rb_descriptor_extent32) rb_copy_extent64) (_ bv0 64)) (= rb_copy_extent64 ((_ zero_extend 32) rb_descriptor_extent32))) true))
(check-sat)
