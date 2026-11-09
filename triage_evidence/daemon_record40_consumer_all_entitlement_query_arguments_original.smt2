; benchmark generated from python API
(set-info :status unknown)
(declare-fun record40_task_ref64 () (_ BitVec 64))
(declare-fun record40_frame_pointer64 () (_ BitVec 64))
(declare-fun record40_name_ref64 () (_ BitVec 64))
(assert
 (let (($x752 (and (distinct record40_task_ref64 record40_task_ref64) true)))
(let ((?x771 (bvadd (_ bv18446744073709551520 64) record40_frame_pointer64)))
(or $x752 (and (distinct record40_name_ref64 record40_name_ref64) true) (and (distinct ?x771 (bvsub record40_frame_pointer64 (_ bv96 64))) true) (and (distinct (_ bv65182 64) (_ bv65182 64)) true) $x752))))
(check-sat)
