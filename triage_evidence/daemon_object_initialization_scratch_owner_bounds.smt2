; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_counter64 () (_ BitVec 64))
(assert
 (let (($x3014 (= ((_ extract 63 6) init_counter64) (_ bv0 58))))
(let (($x4908 (not (and $x3014 (bvule ((_ extract 5 0) init_counter64) (_ bv47 6))))))
(and (not (or (not $x3014) (bvule (_ bv48 6) ((_ extract 5 0) init_counter64)))) $x4908))))
(check-sat)
