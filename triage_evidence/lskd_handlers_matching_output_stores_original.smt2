; benchmark generated from python API
(set-info :status unknown)
(declare-fun cursor32 () (_ BitVec 32))
(declare-fun packet_base64 () (_ BitVec 64))
(declare-fun wire_length16 () (_ BitVec 16))
(assert
 (let (($x1271 (and (distinct (bvadd packet_base64 (concat (_ bv0 32) (bvadd (_ bv4 32) cursor32))) (bvadd packet_base64 ((_ zero_extend 32) (bvadd cursor32 (_ bv4 32))))) true)))
(let (($x1259 (and (distinct ((_ extract 15 0) ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 16) wire_length16)))) wire_length16) true)))
(or $x1259 $x1271))))
(check-sat)
