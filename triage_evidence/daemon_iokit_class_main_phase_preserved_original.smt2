; benchmark generated from python API
(set-info :status unknown)
(declare-fun decoder_entry_W28 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) decoder_entry_W28)) decoder_entry_W28) true))
(check-sat)
