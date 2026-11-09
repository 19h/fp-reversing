; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_remaining64 () (_ BitVec 64))
(assert
 (let (($x708 (or (bvugt (bvsub destruct_remaining64 (_ bv1 64)) (_ bv871 64)) (bvugt destruct_remaining64 (_ bv872 64)))))
(let (($x1393 (bvule destruct_remaining64 (_ bv872 64))))
(let (($x719 (bvuge destruct_remaining64 (_ bv1 64))))
(and (and $x719 $x1393) $x708)))))
(check-sat)
