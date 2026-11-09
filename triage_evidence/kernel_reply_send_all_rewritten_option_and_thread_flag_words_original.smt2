; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_thread_flags16 () (_ BitVec 16))
(declare-fun rs_options64 () (_ BitVec 64))
(assert
 (let ((?x1663 ((_ extract 9 0) rs_thread_flags16)))
(let ((?x1666 ((_ extract 15 11) rs_thread_flags16)))
(let (($x1593 (and (distinct ((_ extract 15 0) ((_ extract 31 0) (concat (_ bv0 48) ?x1666 (_ bv0 1) ?x1663))) (bvand rs_thread_flags16 (_ bv64511 16))) true)))
(let ((?x1641 ((_ extract 3 0) rs_options64)))
(let ((?x1601 ((_ extract 15 5) rs_options64)))
(let ((?x1643 ((_ extract 63 17) rs_options64)))
(let ((?x1588 (concat ?x1643 (_ bv0 1) ?x1601 (_ bv1 1) ?x1641)))
(or (and (distinct ?x1588 (bvor (bvand rs_options64 (_ bv18446744073709486079 64)) (_ bv16 64))) true) $x1593)))))))))
(check-sat)
