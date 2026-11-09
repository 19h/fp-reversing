; benchmark generated from python API
(set-info :status unknown)
(declare-fun client_obj_context_encoded_length32 () (_ BitVec 32))
(declare-fun client_obj_pointer64 () (_ BitVec 64))
(assert
 (let (($x356 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) client_obj_context_encoded_length32)) client_obj_context_encoded_length32) true)))
(let (($x26 (and (distinct client_obj_pointer64 client_obj_pointer64) true)))
(or $x26 $x356 (and (distinct (_ bv0 64) (_ bv0 64)) true) (and (distinct ((_ extract 31 0) (_ bv2336081489 64)) (_ bv2336081489 32)) true) (and (distinct (_ bv3180115522970909099 64) (_ bv3180115522970909099 64)) true) (and (distinct ((_ extract 31 0) (_ bv42539 64)) (_ bv42539 32)) true)))))
(check-sat)
