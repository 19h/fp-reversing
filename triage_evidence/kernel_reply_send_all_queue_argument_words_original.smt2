; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_wait64 () (_ BitVec 64))
(declare-fun rs_options64 () (_ BitVec 64))
(declare-fun rs_reply_pointer64 () (_ BitVec 64))
(declare-fun rs_destination64 () (_ BitVec 64))
(assert
 (let (($x12 (and (distinct rs_reply_pointer64 rs_reply_pointer64) true)))
(let (($x65 (and (distinct (bvadd (_ bv40 64) rs_destination64) (bvadd rs_destination64 (_ bv40 64))) true)))
(or $x65 $x12 (and (distinct rs_options64 rs_options64) true) (and (distinct rs_wait64 rs_wait64) true)))))
(check-sat)
