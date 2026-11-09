; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_base_decoded_aux32 () (_ BitVec 32))
(assert
 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) output_base_decoded_aux32)) output_base_decoded_aux32) true))
(check-sat)
