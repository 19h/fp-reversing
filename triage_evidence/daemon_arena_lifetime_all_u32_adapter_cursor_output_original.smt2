; benchmark generated from python API
(set-info :status unknown)
(declare-fun lifetime_cursor_before32 () (_ BitVec 32))
(declare-fun lifetime_cursor_now32 () (_ BitVec 32))
(assert
 (let ((?x47 ((_ zero_extend 32) (bvand (bvsub lifetime_cursor_now32 lifetime_cursor_before32) (_ bv65535 32)))))
(let ((?x66 ((_ extract 15 0) lifetime_cursor_before32)))
(let ((?x69 (bvmul (_ bv65535 16) ?x66)))
(let ((?x62 ((_ extract 15 0) lifetime_cursor_now32)))
(let ((?x70 (bvadd ?x62 ?x69)))
(let ((?x85 (concat (_ bv0 44) ?x70 (_ bv0 4))))
(and (distinct ?x85 (bvshl ?x47 (_ bv4 64))) true))))))))
(check-sat)
