; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_context64 () (_ BitVec 64))
(declare-fun conventions_A64 () (_ BitVec 64))
(assert
 (let (($x31 (and (distinct (_ bv4311981808 64) (_ bv4311981808 64)) true)))
(let (($x58 (and (distinct conventions_context64 conventions_context64) true)))
(or (and (distinct (bvadd (_ bv568 64) conventions_A64) (bvadd conventions_A64 (_ bv568 64))) true) $x58 (and (distinct ((_ extract 31 0) (_ bv450309926 64)) (_ bv450309926 32)) true) (and (distinct ((_ extract 31 0) (_ bv39216 64)) (_ bv39216 32)) true) (and (distinct ((_ extract 31 0) (_ bv2909 64)) (_ bv2909 32)) true) (and (distinct (_ bv4305496784 64) (_ bv4305496784 64)) true) $x31))))
(check-sat)
