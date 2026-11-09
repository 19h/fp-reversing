; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_cursor64 () (_ BitVec 64))
(declare-fun handoff_result64 () (_ BitVec 64))
(assert
 (let ((?x374 (bvshl ((_ zero_extend 48) ((_ extract 15 0) (bvsub handoff_result64 handoff_cursor64))) (_ bv4 64))))
(let ((?x404 ((_ extract 15 0) handoff_cursor64)))
(let ((?x407 (bvmul (_ bv65535 16) ?x404)))
(let ((?x400 ((_ extract 15 0) handoff_result64)))
(let ((?x408 (bvadd ?x400 ?x407)))
(let ((?x422 (concat (_ bv0 44) ?x408 (_ bv0 4))))
(and true (and (distinct ?x422 ?x374) true)))))))))
(check-sat)
