; benchmark generated from python API
(set-info :status unknown)
(declare-fun ent_flow_frame64 () (_ BitVec 64))
(declare-fun ent_flow_audit_argument64 () (_ BitVec 64))
(assert
 (let (($x412 (and (distinct (_ bv0 64) (_ bv0 64)) true)))
(let (($x55 (and (distinct (bvadd (_ bv23900 64) ent_flow_frame64) (bvadd ent_flow_frame64 (_ bv23900 64))) true)))
(or (and (distinct ent_flow_audit_argument64 ent_flow_audit_argument64) true) $x55 (and (distinct (_ bv56405 64) (_ bv56405 64)) true) $x412 $x412 $x412 $x412 $x412 $x412 $x412))))
(check-sat)
