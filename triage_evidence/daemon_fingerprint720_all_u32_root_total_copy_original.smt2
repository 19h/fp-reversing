; benchmark generated from python API
(set-info :status unknown)
(declare-fun fingerprint_encoded_total32 () (_ BitVec 32))
(assert
 (let (($x30 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) fingerprint_encoded_total32)) fingerprint_encoded_total32) true)))
(and true (or $x30 (and (distinct (_ bv446677450752 64) (_ bv446677450752 64)) true)))))
(check-sat)
