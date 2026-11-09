; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(assert
 (let (($x22 (and (distinct rb_copy_extent64 rb_copy_extent64) true)))
(or $x22 (and (distinct ((_ extract 31 0) (_ bv1 64)) (_ bv1 32)) true))))
(check-sat)
