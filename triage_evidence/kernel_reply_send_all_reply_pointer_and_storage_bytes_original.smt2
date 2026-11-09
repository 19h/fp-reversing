; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_storage_byte8 () (_ BitVec 8))
(declare-fun rs_reply_pointer64 () (_ BitVec 64))
(assert
 (let (($x21 (= (bvsub ((_ extract 31 0) (concat (_ bv0 62) ((_ extract 7 6) rs_storage_byte8))) (_ bv1 32)) (_ bv0 32))))
(let ((?x25 ((_ extract 31 0) (concat (_ bv0 62) ((_ extract 7 6) rs_storage_byte8)))))
(let (($x12 (and (distinct rs_reply_pointer64 rs_reply_pointer64) true)))
(or $x12 (and (distinct ?x25 (bvlshr ((_ zero_extend 24) rs_storage_byte8) (_ bv6 32))) true) (and (distinct $x21 (= (bvlshr rs_storage_byte8 (_ bv6 8)) (_ bv1 8))) true))))))
(check-sat)
