; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_frame64 () (_ BitVec 64))
(declare-fun consumer_record64 () (_ BitVec 64))
(assert
 (let (($x26 (and (= (bvand consumer_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge consumer_frame64 (_ bv429496729600 64)) (bvule consumer_frame64 (_ bv429496792096 64)) (= consumer_record64 (bvadd consumer_frame64 (_ bv2808 64))))))
(and $x26 (or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv2325448032 32))) (_ bv2325448032 32)) true) (and (distinct (_ bv4312564328 64) (_ bv4312564328 64)) true)))))
(check-sat)
