(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun token_biased_word32 () (_ BitVec 32))
(declare-fun address_key_word32 () (_ BitVec 32))
(assert
 (let ((?x186 (bvxor (bvxor token_biased_word32 address_key_word32) address_key_word32)))
(and (distinct ?x186 token_biased_word32) true)))
(check-sat)
