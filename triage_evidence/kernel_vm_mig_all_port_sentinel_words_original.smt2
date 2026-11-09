; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_output_body64 () (_ BitVec 64))
(declare-fun kmig_port_object64 () (_ BitVec 64))
(assert
 (let (($x45 (and (and (distinct kmig_port_object64 (_ bv0 64)) true) (and (distinct kmig_port_object64 (_ bv18446744073709551615 64)) true))))
(or (and (distinct (bvuge (bvadd (_ bv1 64) kmig_port_object64) (_ bv2 64)) $x45) true) (and (distinct kmig_output_body64 kmig_output_body64) true))))
(check-sat)
