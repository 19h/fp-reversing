; benchmark generated from python API
(set-info :status unknown)
(declare-fun decoder_entry_W28 () (_ BitVec 32))
(assert
 (let ((?x98 (bvadd (_ bv4294966794 32) decoder_entry_W28)))
(let ((?x212 ((_ extract 2 2) ?x98)))
(not (= ?x212 ((_ extract 2 2) (bvadd (_ bv2 3) ((_ extract 2 0) decoder_entry_W28))))))))
(check-sat)
