; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_mode32 () (_ BitVec 32))
(assert
 (let ((?x19 ((_ extract 31 0) (concat (_ bv0 32) ((_ extract 31 3) (bvadd (_ bv4294951156 32) registry_mode32)) (_ bv7 3)))))
(let (($x36 (= registry_mode32 (_ bv18204 32))))
(and $x36 (and (distinct ?x19 (_ bv2071 32)) true)))))
(check-sat)
