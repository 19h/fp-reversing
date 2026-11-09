; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_copy_extent64 () (_ BitVec 64))
(declare-fun rb_mapped_address64 () (_ BitVec 64))
(assert
 (or (and (distinct rb_mapped_address64 rb_mapped_address64) true) (and (distinct ((_ extract 31 0) rb_copy_extent64) ((_ extract 31 0) rb_copy_extent64)) true)))
(check-sat)
