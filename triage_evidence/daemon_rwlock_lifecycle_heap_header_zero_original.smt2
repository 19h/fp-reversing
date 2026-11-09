; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_heap64 () (_ BitVec 64))
(assert
 (let (($x190 (and (distinct ((_ extract 15 0) (_ bv0 32)) (_ bv0 16)) true)))
(let (($x210 (and (distinct rw_heap64 rw_heap64) true)))
(or $x210 $x190 $x190 $x190 $x190))))
(check-sat)
