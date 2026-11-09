; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (let (($x257 (= (ite (= ((_ extract 15 8) fallback_version32) (_ bv0 8)) (_ bv0 32) (_ bv1 32)) (bvadd (_ bv3311664678 32) (ite (= ((_ extract 15 8) fallback_version32) (_ bv0 8)) (_ bv983302618 32) (_ bv983302619 32))))))
(let (($x697 (not $x257)))
(let (($x996 (= ((_ extract 23 16) fallback_version32) (_ bv30 8))))
(let ((?x503 ((_ extract 31 24) fallback_version32)))
(let (($x796 (= ?x503 (_ bv46 8))))
(and $x796 $x996 $x697)))))))
(check-sat)
