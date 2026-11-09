; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_limit16 () (_ BitVec 16))
(declare-fun qs_count16 () (_ BitVec 16))
(assert
 (let ((?x30 ((_ extract 31 0) (concat (_ bv0 48) qs_limit16))))
(and (distinct (bvuge ((_ extract 31 0) (concat (_ bv0 48) qs_count16)) ?x30) (bvuge qs_count16 qs_limit16)) true)))
(check-sat)
