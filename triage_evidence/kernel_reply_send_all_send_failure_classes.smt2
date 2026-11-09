; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_send_status32 () (_ BitVec 32))
(assert
 (let (($x83 (= rs_send_status32 (_ bv268435469 32))))
(let (($x61 (= rs_send_status32 (_ bv268435459 32))))
(let (($x122 (or $x61 (= rs_send_status32 (_ bv268435460 32)) (= rs_send_status32 (_ bv268435463 32)) $x83)))
(let ((?x137 (bvshl (_ bv1 32) (concat (_ bv0 27) (bvadd (_ bv29 5) ((_ extract 4 0) rs_send_status32))))))
(let (($x1701 (and (= ((_ extract 1 0) ?x137) (_ bv0 2)) (= ((_ extract 4 4) ?x137) (_ bv0 1)) (= ((_ extract 10 10) ?x137) (_ bv0 1)))))
(let (($x1665 (= ((_ extract 31 29) rs_send_status32) (_ bv0 3))))
(let (($x1710 (or (bvule (_ bv268435469 29) ((_ extract 28 0) rs_send_status32)) (and $x1665 (bvule ((_ extract 28 0) rs_send_status32) (_ bv268435458 29))) (not $x1665))))
(not (= (and (or (not $x1710) $x83) (not $x1701)) $x122))))))))))
(check-sat)
