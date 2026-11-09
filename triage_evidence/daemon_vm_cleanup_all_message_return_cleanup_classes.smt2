; benchmark generated from python API
(set-info :status unknown)
(declare-fun vmclean_trap_status32 () (_ BitVec 32))
(assert
 (let (($x398 (= vmclean_trap_status32 (_ bv268435472 32))))
(let (($x32 (= vmclean_trap_status32 (_ bv268435459 32))))
(let (($x428 (or (= vmclean_trap_status32 (_ bv268435458 32)) $x32 $x398)))
(let ((?x433 (bvshl (_ bv1 32) (concat (_ bv0 27) (bvadd (_ bv30 5) ((_ extract 4 0) vmclean_trap_status32))))))
(let ((?x420 ((_ extract 14 14) ?x433)))
(let (($x1485 (= ((_ extract 31 29) vmclean_trap_status32) (_ bv0 3))))
(let (($x1463 (or (and $x1485 (bvule ((_ extract 28 0) vmclean_trap_status32) (_ bv268435457 29))) (bvule (_ bv268435472 29) ((_ extract 28 0) vmclean_trap_status32)) (not $x1485))))
(let (($x1568 (or (not (or (not $x1463) $x398)) (and (= ((_ extract 1 0) ?x433) (_ bv0 2)) (= ?x420 (_ bv0 1))))))
(= $x1568 $x428))))))))))
(check-sat)
