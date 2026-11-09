; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_descriptor_extent32 () (_ BitVec 32))
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(assert
 (let (($x310 (= (= (concat (_ bv0 32) rb_descriptor_extent32) rb_copy_extent64) (= rb_copy_extent64 (concat (_ bv0 32) rb_descriptor_extent32)))))
(not $x310)))
(check-sat)
