; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (and (distinct (ite (bvuge (bvlshr fallback_version32 (_ bv16 32)) (_ bv11806 32)) (_ bv3298203640 32) (_ bv3298203632 32)) (ite (bvuge fallback_version32 (_ bv773718016 32)) (_ bv3298203640 32) (_ bv3298203632 32))) true))
(check-sat)
