; benchmark generated from python API
(set-info :status unknown)
(declare-fun head_nested_phase32 () (_ BitVec 32))
(assert
 (let (($x448 (= head_nested_phase32 (_ bv20345 32))))
(xor (= (bvadd head_nested_phase32 (_ bv7547 32)) (_ bv27892 32)) $x448)))
(check-sat)
