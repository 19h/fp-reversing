; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_mba64 () (_ BitVec 64))
(assert
 (let ((?x65 (bvadd (bvsub (bvor (bvshl publication_mba64 (_ bv1 64)) (_ bv6502258558015995404 64)) publication_mba64) (_ bv15195614794701553914 64))))
(let (($x60 (and (distinct ?x65 (bvadd (bvadd (bvxor publication_mba64 (_ bv3251129279007997702 64)) (_ bv3251129279007997702 64)) (_ bv15195614794701553914 64))) true)))
(and true $x60))))
(check-sat)
