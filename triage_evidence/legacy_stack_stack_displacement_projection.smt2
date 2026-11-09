; benchmark generated from python API
(set-info :status unknown)
(declare-fun old_state32 () (_ BitVec 32))
(declare-fun new_state32 () (_ BitVec 32))
(assert
 (let ((?x162 ((_ extract 15 0) old_state32)))
(let ((?x166 (bvmul (_ bv65535 16) ?x162)))
(let ((?x158 ((_ extract 15 0) new_state32)))
(let ((?x168 (bvadd ?x158 ?x166)))
(let (($x876 (bvule (concat ?x168 (_ bv0 4)) (_ bv1048560 20))))
(not $x876)))))))
(check-sat)
