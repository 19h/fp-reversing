; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_reply_pointer64 () (_ BitVec 64))
(declare-fun rs_header_pointer64 () (_ BitVec 64))
(assert
 (let ((?x70 ((_ extract 47 0) rs_reply_pointer64)))
(let ((?x73 (bvadd (_ bv232 48) ?x70)))
(let ((?x98 (concat (_ bv10397 16) ?x73)))
(let (($x79 (and (distinct ?x98 (bvor (bvand (bvadd rs_reply_pointer64 (_ bv232 64)) (_ bv281474976710655 64)) (_ bv2926495332860690432 64))) true)))
(let (($x58 (and (distinct rs_header_pointer64 rs_header_pointer64) true)))
(let (($x57 (and (distinct (bvadd (_ bv64 64) rs_reply_pointer64) (bvadd rs_reply_pointer64 (_ bv64 64))) true)))
(or $x57 $x58 $x79))))))))
(check-sat)
