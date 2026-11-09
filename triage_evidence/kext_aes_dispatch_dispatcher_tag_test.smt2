; benchmark generated from python API
(set-info :status unknown)
(declare-fun decoded_tag32 () (_ BitVec 32))
(assert
 (let (($x55 (= decoded_tag32 (_ bv39041526 32))))
(and (distinct (= (bvadd decoded_tag32 (_ bv3788151235 32)) (_ bv3827192761 32)) $x55) true)))
(check-sat)
