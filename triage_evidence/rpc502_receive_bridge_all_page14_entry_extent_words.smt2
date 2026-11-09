; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_descriptor_extent32 () (_ BitVec 32))
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(assert
 (let ((?x113 (concat ((_ extract 63 14) (bvadd (_ bv16383 64) (concat (_ bv0 32) rb_descriptor_extent32))) (_ bv0 14))))
(let (($x773 (or (not (= ((_ extract 63 32) rb_copy_extent64) (_ bv0 32))) (bvule rb_descriptor_extent32 ((_ extract 31 0) rb_copy_extent64)))))
(let (($x308 (and $x773 (or (not (bvule ?x113 rb_copy_extent64)) (= rb_copy_extent64 ?x113)))))
(not (= $x308 (and $x773 (bvule rb_copy_extent64 ?x113))))))))
(check-sat)
