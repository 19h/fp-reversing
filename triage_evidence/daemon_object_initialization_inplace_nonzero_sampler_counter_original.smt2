; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_phase32 () (_ BitVec 32))
(declare-fun init_candidate32 () (_ BitVec 32))
(declare-fun init_cursor32 () (_ BitVec 32))
(declare-fun init_offset64 () (_ BitVec 64))
(assert
 (let (($x1256 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv8 32) init_phase32))) (bvadd init_phase32 (_ bv8 32))) true)))
(let ((?x1712 ((_ extract 7 0) init_candidate32)))
(let (($x1988 (and (distinct ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) init_candidate32))) ?x1712) true)))
(let ((?x1263 (bvadd init_cursor32 (bvmul (_ bv4294967295 32) (ite (= ?x1712 (_ bv0 8)) (_ bv0 32) (_ bv1 32))))))
(let (($x1808 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x1263)) (bvsub init_cursor32 (ite (= ?x1712 (_ bv0 8)) (_ bv0 32) (_ bv1 32)))) true)))
(and (bvult init_offset64 (_ bv587 64)) (or $x1808 $x1988 $x1256))))))))
(check-sat)
