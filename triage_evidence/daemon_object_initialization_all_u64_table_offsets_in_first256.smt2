; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_address64 () (_ BitVec 64))
(assert
 (let ((?x100 (bvadd (_ bv18446743627032756224 64) (concat (_ bv1744831232 56) (bvadd (_ bv56 8) (concat ((_ extract 7 3) init_address64) (_ bv0 3)))))))
(let (($x386 (and (= ((_ extract 63 8) ?x100) (_ bv0 56)) (bvule (bvadd (_ bv56 8) (concat ((_ extract 7 3) init_address64) (_ bv0 3))) (_ bv248 8)))))
(not $x386))))
(check-sat)
