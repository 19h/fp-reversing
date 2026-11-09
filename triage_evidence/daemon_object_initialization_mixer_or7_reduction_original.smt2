; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_mba64 () (_ BitVec 64))
(assert
 (let (($x1854 (and (distinct (bvadd (bvsub (bvor (bvshl init_mba64 (_ bv1 64)) (_ bv3304390235164884592 64)) init_mba64) (_ bv7571176919272333512 64)) (bvadd (bvadd (bvxor init_mba64 (_ bv1652195117582442296 64)) (_ bv1652195117582442296 64)) (_ bv7571176919272333512 64))) true)))
(and true $x1854)))
(check-sat)
