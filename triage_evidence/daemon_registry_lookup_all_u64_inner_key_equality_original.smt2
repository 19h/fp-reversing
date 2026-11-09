; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_encoded_key64 () (_ BitVec 64))
(declare-fun registry_payload_key64 () (_ BitVec 64))
(assert
 (let (($x178 (= registry_payload_key64 registry_encoded_key64)))
(and true (and (distinct $x178 $x178) true))))
(check-sat)
