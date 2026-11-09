; benchmark generated from python API
(set-info :status unknown)
(declare-fun record40_argument_SP64 () (_ BitVec 64))
(declare-fun record40_allocator_argument64 () (_ BitVec 64))
(assert
 (let (($x517 (and (distinct (bvadd (_ bv80 64) record40_argument_SP64) (bvadd record40_argument_SP64 (_ bv80 64))) true)))
(or (and (distinct record40_allocator_argument64 record40_allocator_argument64) true) $x517 (and (distinct (_ bv10884 64) (_ bv10884 64)) true))))
(check-sat)
