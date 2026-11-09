; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_daemon_reply_pointer64 () (_ BitVec 64))
(assert
 (let (($x763 (and (distinct (bvadd (_ bv380 64) rb_daemon_reply_pointer64) (bvadd rb_daemon_reply_pointer64 (_ bv380 64))) true)))
(let (($x496 (and (distinct (bvadd (_ bv376 64) rb_daemon_reply_pointer64) (bvadd rb_daemon_reply_pointer64 (_ bv376 64))) true)))
(let (($x498 (and (distinct (bvadd (_ bv204 64) rb_daemon_reply_pointer64) (bvadd rb_daemon_reply_pointer64 (_ bv204 64))) true)))
(or $x498 $x496 $x763)))))
(check-sat)
