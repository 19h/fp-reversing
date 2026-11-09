; benchmark generated from python API
(set-info :status unknown)
(declare-fun rd_current_space64 () (_ BitVec 64))
(declare-fun rd_port_receiver_space64 () (_ BitVec 64))
(assert
 (let (($x40 (= rd_port_receiver_space64 rd_current_space64)))
(and (distinct (= (bvsub rd_port_receiver_space64 rd_current_space64) (_ bv0 64)) $x40) true)))
(check-sat)
