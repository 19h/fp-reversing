; benchmark generated from python API
(set-info :status unknown)
(declare-fun client_obj_encoded_length32 () (_ BitVec 32))
(declare-fun client_obj_cursor64 () (_ BitVec 64))
(assert
 (let ((?x412 ((_ zero_extend 32) (bvxor client_obj_encoded_length32 (_ bv2336081489 32)))))
(let ((?x587 (bvadd (_ bv6 64) client_obj_cursor64)))
(let ((?x364 (bvsub ?x412 client_obj_cursor64)))
(let (($x450 (bvugt ?x364 (_ bv9 64))))
(let (($x372 (bvugt ?x412 client_obj_cursor64)))
(or (and (distinct ?x587 (bvadd client_obj_cursor64 (_ bv6 64))) true) (and $x372 $x450 (not (bvult ?x587 ?x412))))))))))
(check-sat)
