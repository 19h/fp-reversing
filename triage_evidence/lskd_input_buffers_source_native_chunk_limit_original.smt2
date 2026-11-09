; benchmark generated from python API
(set-info :status unknown)
(declare-fun native_random_remaining32 () (_ BitVec 32))
(assert
 (let ((?x124 ((_ zero_extend 32) native_random_remaining32)))
(let (($x113 (bvult ?x124 (_ bv256 64))))
(let ((?x100 (ite $x113 ?x124 (_ bv256 64))))
(and (distinct (ite $x113 ?x124 ((_ zero_extend 32) (_ bv256 32))) ?x100) true)))))
(check-sat)
