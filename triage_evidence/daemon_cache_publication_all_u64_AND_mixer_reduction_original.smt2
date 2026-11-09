; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_mba64 () (_ BitVec 64))
(assert
 (let ((?x57 (bvadd (bvsub publication_mba64 (bvand (bvshl publication_mba64 (_ bv1 64)) (_ bv980765719290952102 64))) (_ bv490382859645476051 64))))
(let (($x1436 (and (distinct ?x57 (bvadd (bvsub (bvxor publication_mba64 (_ bv490382859645476051 64)) (_ bv490382859645476051 64)) (_ bv490382859645476051 64))) true)))
(and true $x1436))))
(check-sat)
