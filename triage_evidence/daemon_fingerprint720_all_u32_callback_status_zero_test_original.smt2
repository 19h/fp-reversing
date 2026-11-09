; benchmark generated from python API
(set-info :status unknown)
(declare-fun fingerprint_digest_state32 () (_ BitVec 32))
(assert
 (let (($x340 (= fingerprint_digest_state32 (_ bv0 32))))
(let ((?x182 (bvsub fingerprint_digest_state32 (bvand (bvshl fingerprint_digest_state32 (_ bv1 32)) (_ bv377195682 32)))))
(let (($x183 (= ?x182 (_ bv0 32))))
(and true (and (distinct $x183 $x340) true))))))
(check-sat)
