; benchmark generated from python API
(set-info :status unknown)
(declare-fun packet_base64 () (_ BitVec 64))
(assert
 (or (and (distinct (bvadd (_ bv28 64) packet_base64) (bvadd packet_base64 (_ bv28 64))) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv4 32))) (_ bv4 32)) true)))
(check-sat)
