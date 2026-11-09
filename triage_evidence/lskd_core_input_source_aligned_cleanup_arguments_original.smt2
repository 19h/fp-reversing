; benchmark generated from python API
(set-info :status unknown)
(declare-fun core_workspace_pointer64 () (_ BitVec 64))
(assert
 (or (and (distinct core_workspace_pointer64 core_workspace_pointer64) true) (and (distinct ((_ zero_extend 32) (_ bv16384 32)) (_ bv16384 64)) true)))
(check-sat)
