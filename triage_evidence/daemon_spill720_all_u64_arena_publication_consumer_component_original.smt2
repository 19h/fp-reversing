; benchmark generated from python API
(set-info :status unknown)
(declare-fun arena_published_pointer64 () (_ BitVec 64))
(assert
 (let (($x761 (and (distinct arena_published_pointer64 arena_published_pointer64) true)))
(or $x761 $x761 $x761)))
(check-sat)
