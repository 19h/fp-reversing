; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_mode32 () (_ BitVec 32))
(assert
 (let (($x27 (not (= ((_ extract 31 3) (bvadd (_ bv4294951156 32) registry_mode32)) (_ bv258 29)))))
(let (($x36 (= registry_mode32 (_ bv18204 32))))
(and $x36 $x27))))
(check-sat)
