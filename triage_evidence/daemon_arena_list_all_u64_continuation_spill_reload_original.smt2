; benchmark generated from python API
(set-info :status unknown)
(declare-fun arena_continuation_pointer64 () (_ BitVec 64))
(assert
 (let (($x57 (and (distinct arena_continuation_pointer64 arena_continuation_pointer64) true)))
(or $x57 (and (distinct (_ bv29461 64) (_ bv29461 64)) true) $x57)))
(check-sat)
