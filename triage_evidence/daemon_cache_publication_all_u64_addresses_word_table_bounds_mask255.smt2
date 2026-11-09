; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_address64 () (_ BitVec 64))
(assert
 (let ((?x4002 (concat (_ bv1 1) ((_ extract 6 6) publication_address64) (_ bv1 1) ((_ extract 4 3) publication_address64) (_ bv7 3))))
(let ((?x3997 (concat ((_ extract 7 7) publication_address64) (_ bv1 1) ((_ extract 5 5) publication_address64) (_ bv25 5))))
(not (bvule (concat ((_ extract 7 3) (bvadd (_ bv58 8) ?x3997 ?x4002)) (_ bv0 3)) (_ bv248 8))))))
(check-sat)
