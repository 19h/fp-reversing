; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_send_status32 () (_ BitVec 32))
(assert
 (let (($x83 (= rs_send_status32 (_ bv268435469 32))))
(let (($x61 (= rs_send_status32 (_ bv268435459 32))))
(let (($x122 (or $x61 (= rs_send_status32 (_ bv268435460 32)) (= rs_send_status32 (_ bv268435463 32)) $x83)))
(let ((?x137 (bvshl (_ bv1 32) (concat (_ bv0 27) (bvadd (_ bv29 5) ((_ extract 4 0) rs_send_status32))))))
(let (($x115 (= (bvsub ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4026531837 32) rs_send_status32))) (_ bv10 32)) (_ bv0 32))))
(let (($x54 (not (bvuge ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4026531837 32) rs_send_status32))) (_ bv10 32)))))
(let (($x134 (and (or $x54 $x115) (not (= (bvand ((_ extract 31 0) (concat (_ bv0 32) ?x137)) ((_ extract 31 0) (_ bv1043 64))) (_ bv0 32))))))
(and (distinct $x134 $x122) true)))))))))
(check-sat)
