; benchmark generated from python API
(set-info :status unknown)
(declare-fun registry_payload_key64 () (_ BitVec 64))
(declare-fun registry_encoded_key64 () (_ BitVec 64))
(assert
 (let (($x580 (= registry_encoded_key64 registry_payload_key64)))
(let (($x579 (= (bvxor registry_encoded_key64 (_ bv16409013220067847612 64)) (bvxor registry_payload_key64 (_ bv16409013220067847612 64)))))
(and true (and (distinct $x579 $x580) true)))))
(check-sat)
