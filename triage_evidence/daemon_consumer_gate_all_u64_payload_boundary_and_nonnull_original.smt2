; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_saved_continuation64 () (_ BitVec 64))
(assert
 (let ((?x91 (ite (= gate_saved_continuation64 (_ bv0 64)) (_ bv0 32) (_ bv1 32))))
(let ((?x103 (bvadd (_ bv18446744073709551592 64) gate_saved_continuation64)))
(or (and (distinct ?x103 (bvsub gate_saved_continuation64 (_ bv24 64))) true) (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x91)) ?x91) true)))))
(check-sat)
