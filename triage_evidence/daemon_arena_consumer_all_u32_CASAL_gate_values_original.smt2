; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_gate32 () (_ BitVec 32))
(assert
 (let ((?x19 (ite (= consumer_gate32 (_ bv23958 32)) (_ bv693487 32) consumer_gate32)))
(let ((?x65 (ite (= consumer_gate32 ((_ extract 31 0) (_ bv23958 64))) ((_ extract 31 0) (_ bv693487 64)) consumer_gate32)))
(or (and (distinct ((_ extract 31 0) (concat (_ bv0 32) consumer_gate32)) consumer_gate32) true) (and (distinct ?x65 ?x19) true)))))
(check-sat)
