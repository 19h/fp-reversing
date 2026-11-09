; benchmark generated from python API
(set-info :status unknown)
(declare-fun caller_phase32 () (_ BitVec 32))
(assert
 (let (($x171 (= caller_phase32 (_ bv26205 32))))
(xor (= (bvsub caller_phase32 (_ bv3801 32)) (_ bv22404 32)) $x171)))
(check-sat)
