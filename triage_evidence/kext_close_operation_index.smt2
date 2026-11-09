(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun address_key_word32 () (_ BitVec 32))
(assert
 (and (distinct (bvsub (bvadd address_key_word32 (_ bv3096 32)) address_key_word32) (_ bv3096 32)) true))
(check-sat)
