; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_output64 () (_ BitVec 64))
(declare-fun callback_length16 () (_ BitVec 16))
(assert
 (let (($x353 (and (not (= callback_output64 (_ bv0 64))) (not (= callback_length16 (_ bv0 16))))))
(= $x353 (or (= callback_length16 (_ bv0 16)) (= callback_output64 (_ bv0 64))))))
(check-sat)
