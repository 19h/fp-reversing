; benchmark generated from python API
(set-info :status unknown)
(declare-fun caller_phase32 () (_ BitVec 32))
(assert
 (let (($x26 (= caller_phase32 (_ bv17512 32))))
(xor (= (bvadd caller_phase32 (_ bv4892 32)) (_ bv22404 32)) $x26)))
(check-sat)
