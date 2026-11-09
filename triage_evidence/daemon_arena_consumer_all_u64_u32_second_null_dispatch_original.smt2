; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_second_B32 () (_ BitVec 32))
(declare-fun consumer_second_A32 () (_ BitVec 32))
(declare-fun consumer_payload64 () (_ BitVec 64))
(declare-fun consumer_second_phase32 () (_ BitVec 32))
(assert
 (let (($x28 (= consumer_payload64 (_ bv0 64))))
(let ((?x46 (ite $x28 (bvsub (bvadd consumer_second_A32 consumer_second_B32) (_ bv45788 32)) (_ bv0 32))))
(let ((?x21 (ite $x28 (_ bv1 32) (_ bv0 32))))
(let ((?x53 (bvadd (_ bv4294921508 32) consumer_second_A32 consumer_second_B32)))
(let ((?x43 (bvadd (_ bv2519 32) consumer_second_phase32)))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvxor ?x43 (bvmul ?x53 ?x21)))) (bvxor (bvadd consumer_second_phase32 (_ bv2519 32)) ?x46)) true)))))))
(check-sat)
