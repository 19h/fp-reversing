; benchmark generated from python API
(set-info :status unknown)
(declare-fun continuation_limit64 () (_ BitVec 64))
(declare-fun continuation_scratch64 () (_ BitVec 64))
(assert
 (let (($x279 (and (distinct continuation_limit64 continuation_limit64) true)))
(let (($x247 (and (distinct (bvadd (_ bv128 64) continuation_scratch64) (bvadd continuation_scratch64 (_ bv128 64))) true)))
(or $x247 $x279))))
(check-sat)
