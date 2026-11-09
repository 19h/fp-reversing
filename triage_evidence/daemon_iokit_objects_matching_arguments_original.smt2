; benchmark generated from python API
(set-info :status unknown)
(declare-fun objects_frame64 () (_ BitVec 64))
(declare-fun matching_dictionary64 () (_ BitVec 64))
(declare-fun main_port32 () (_ BitVec 32))
(assert
 (let (($x16 (and (distinct matching_dictionary64 matching_dictionary64) true)))
(or (and (distinct ((_ zero_extend 32) main_port32) ((_ zero_extend 32) main_port32)) true) $x16 (and (distinct (bvadd (_ bv104 64) objects_frame64) (bvadd objects_frame64 (_ bv104 64))) true) (and (distinct (_ bv40999 64) (_ bv40999 64)) true))))
(check-sat)
