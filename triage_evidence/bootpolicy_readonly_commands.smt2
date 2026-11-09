(set-logic QF_BV)
(declare-fun c () (_ BitVec 32))
(define-fun delta () (_ BitVec 32) (bvsub c #x0000000b))
(define-fun shifted () (_ BitVec 64) (bvshl #x0000000000000001
 ((_ zero_extend 32) (bvand delta #x0000003f))))
(define-fun native () Bool (or (= c #x0000004c) (= c #x0000005a)
 (and (bvule delta #x0000003c) (not (= (bvand shifted #x1b1f88048800207f) #x0000000000000000)))))
(assert (not (= native (or (= c #x0000000b) (= c #x0000000c) (= c #x0000000d) (= c #x0000000e) (= c #x0000000f) (= c #x00000010) (= c #x00000011) (= c #x00000018) (= c #x00000026) (= c #x0000002a) (= c #x0000002d) (= c #x00000036) (= c #x0000003a) (= c #x0000003b) (= c #x0000003c) (= c #x0000003d) (= c #x0000003e) (= c #x0000003f) (= c #x00000043) (= c #x00000044) (= c #x00000046) (= c #x00000047) (= c #x0000004c) (= c #x0000005a)))))
(check-sat)
