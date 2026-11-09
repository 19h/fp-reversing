; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_second_B32 () (_ BitVec 32))
(declare-fun consumer_second_A32 () (_ BitVec 32))
(declare-fun consumer_payload64 () (_ BitVec 64))
(declare-fun consumer_second_phase32 () (_ BitVec 32))
(assert
 (let ((?x53 (bvadd (_ bv4294921508 32) consumer_second_A32 consumer_second_B32)))
(let (($x28 (= consumer_payload64 (_ bv0 64))))
(let ((?x43 (bvadd (_ bv2519 32) consumer_second_phase32)))
(let ((?x85 (bvxor ?x43 (ite $x28 ?x53 (_ bv0 32)))))
(let ((?x47 (bvxor ?x43 (bvmul ?x53 (ite $x28 (_ bv1 32) (_ bv0 32))))))
(not (= ?x47 ?x85))))))))
(check-sat)
