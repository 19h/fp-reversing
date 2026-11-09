; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_count16 () (_ BitVec 16))
(assert
 (let ((?x9 ((_ extract 15 0) ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv1 32) (concat (_ bv0 16) qs_count16)))))))
(and (distinct ?x9 (bvadd qs_count16 (_ bv1 16))) true)))
(check-sat)
