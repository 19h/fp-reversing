; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (let (($x252 (= ((_ extract 15 8) fallback_version32) (_ bv0 8))))
(let (($x647 (not (= ((_ extract 31 30) fallback_version32) (_ bv0 2)))))
(let ((?x126 (ite (or $x647 (bvule (_ bv11806 14) ((_ extract 29 16) fallback_version32))) (ite (and (= ((_ extract 31 16) fallback_version32) (_ bv11806 16)) $x252) (_ bv983302618 32) (_ bv983302619 32)) (_ bv983302617 32))))
(let ((?x33 (ite (= ((_ extract 23 16) fallback_version32) (_ bv30 8)) (bvadd (_ bv983302618 32) (ite $x252 (_ bv0 32) (_ bv1 32))) (_ bv983302617 32))))
(let (($x597 (= ((_ extract 23 21) fallback_version32) (_ bv0 3))))
(let (($x428 (not $x597)))
(let ((?x1153 (ite (= ((_ extract 31 24) fallback_version32) (_ bv46 8)) (ite (or $x428 (= ((_ extract 20 16) fallback_version32) (_ bv31 5))) (_ bv983302619 32) ?x33) (_ bv983302617 32))))
(let (($x587 (= (ite (or $x647 (bvule (_ bv47 6) ((_ extract 29 24) fallback_version32))) (_ bv983302619 32) ?x1153) ?x126)))
(not $x587))))))))))
(check-sat)
