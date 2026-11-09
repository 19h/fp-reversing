; benchmark generated from python API
(set-info :status unknown)
(declare-fun gate_encoded_pointer64 () (_ BitVec 64))
(assert
 (let ((?x128 (bvadd (_ bv18446744073583553657 64) gate_encoded_pointer64)))
(and (distinct ?x128 (bvsub gate_encoded_pointer64 (_ bv125997959 64))) true)))
(check-sat)
