; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_text_index32 () (_ BitVec 32))
(assert
 (let (($x1245 (and (distinct (bvadd (_ bv4294971480 64) (concat (_ bv0 49) ((_ extract 14 0) init_text_index32))) (bvadd (_ bv4294971480 64) ((_ zero_extend 32) (bvand init_text_index32 (_ bv32767 32))))) true)))
(and true $x1245)))
(check-sat)
