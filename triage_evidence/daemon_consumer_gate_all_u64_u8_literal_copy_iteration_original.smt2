; benchmark generated from python API
(set-info :status unknown)
(declare-fun literal_index64 () (_ BitVec 64))
(declare-fun literal_byte8 () (_ BitVec 8))
(assert
 (let (($x270 (and (distinct ((_ extract 7 0) ((_ extract 31 0) (concat (_ bv0 56) literal_byte8))) literal_byte8) true)))
(or $x270 (and (distinct (bvadd (_ bv1 64) literal_index64) (bvadd literal_index64 (_ bv1 64))) true))))
(check-sat)
