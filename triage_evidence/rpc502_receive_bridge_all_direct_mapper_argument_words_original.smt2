; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(declare-fun rb_copy64 () (_ BitVec 64))
(declare-fun rb_map64 () (_ BitVec 64))
(assert
 (let (($x22 (and (distinct rb_copy_extent64 rb_copy_extent64) true)))
(or (and (distinct rb_map64 rb_map64) true) (and (distinct (_ bv433792675744 64) (_ bv433792675744 64)) true) (and (distinct rb_copy64 rb_copy64) true) $x22 (and (distinct (_ bv1 64) (_ bv1 64)) true))))
(check-sat)
