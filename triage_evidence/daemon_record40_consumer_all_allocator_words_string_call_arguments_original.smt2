; benchmark generated from python API
(set-info :status unknown)
(declare-fun record40_contents_deallocator_ref64 () (_ BitVec 64))
(declare-fun record40_allocator_ref64 () (_ BitVec 64))
(assert
 (let (($x99 (and (distinct record40_contents_deallocator_ref64 record40_contents_deallocator_ref64) true)))
(or (and (distinct record40_allocator_ref64 record40_allocator_ref64) true) (and (distinct (_ bv446676972016 64) (_ bv446676972016 64)) true) (and (distinct ((_ extract 31 0) (_ bv1536 64)) (_ bv1536 32)) true) $x99 (and (distinct (_ bv2080385536 64) (_ bv2080385536 64)) true) (and (distinct (_ bv54385 64) (_ bv54385 64)) true))))
(check-sat)
