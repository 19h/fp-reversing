; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_address64 () (_ BitVec 64))
(assert
 (let ((?x123 (concat ((_ extract 7 3) init_address64) (_ bv0 3))))
(let ((?x124 (bvadd (_ bv56 8) ?x123)))
(let ((?x109 (concat (_ bv1744831232 56) ?x124)))
(let (($x775 (= ?x109 (bvadd (_ bv446676795392 64) (concat (_ bv0 56) (bvadd (_ bv56 8) ((_ extract 7 0) init_address64)))))))
(let (($x56 (= ((_ extract 2 0) init_address64) (_ bv0 3))))
(and $x56 (not $x775))))))))
(check-sat)
