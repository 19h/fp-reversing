; benchmark generated from python API
(set-info :status unknown)
(declare-fun rs_destination_counter32 () (_ BitVec 32))
(assert
 (let (($x1657 (and (distinct (bvadd rs_destination_counter32 ((_ extract 31 0) (_ bv4294967295 64))) (bvsub rs_destination_counter32 (_ bv1 32))) true)))
(let (($x1631 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) rs_destination_counter32)) rs_destination_counter32) true)))
(or (and (distinct (_ bv433791770628 64) (_ bv433791770628 64)) true) $x1631 $x1657))))
(check-sat)
