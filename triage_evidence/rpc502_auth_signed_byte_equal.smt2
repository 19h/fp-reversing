(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun encoded_byte8 () (_ BitVec 8))
(declare-fun plaintext_byte8 () (_ BitVec 8))
(assert
 (let ((?x67 ((_ extract 7 0) (bvxor ((_ sign_extend 24) plaintext_byte8) ((_ zero_extend 24) encoded_byte8)))))
(let (($x69 (= ?x67 (_ bv129 8))))
(and (distinct $x69 (= plaintext_byte8 (bvxor encoded_byte8 (_ bv129 8)))) true))))
(check-sat)
