; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_mode32 () (_ BitVec 32))
(assert
 (let ((?x19 ((_ extract 31 0) (concat (_ bv0 32) ((_ extract 31 3) (bvadd (_ bv4294951156 32) registry_mode32)) (_ bv7 3)))))
(and true (and (distinct ?x19 (bvor (bvsub registry_mode32 (_ bv16140 32)) (_ bv7 32))) true))))
(check-sat)
