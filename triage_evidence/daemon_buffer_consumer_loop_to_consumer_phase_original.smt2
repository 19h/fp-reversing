; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_frame64 () (_ BitVec 64))
(declare-fun consumer_record64 () (_ BitVec 64))
(assert
 (let (($x26 (and (= (bvand consumer_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge consumer_frame64 (_ bv429496729600 64)) (bvule consumer_frame64 (_ bv429496792096 64)) (= consumer_record64 (bvadd consumer_frame64 (_ bv2808 64))))))
(and $x26 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv3054907823 32))) (_ bv3054907823 32)) true))))
(check-sat)
