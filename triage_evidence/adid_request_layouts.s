	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_analyst_getpath                ; -- Begin function analyst_getpath
	.p2align	2
_analyst_getpath:                       ; @analyst_getpath
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #32
	stp	x29, x30, [sp, #16]             ; 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	str	x1, [sp]
	mov	w1, #50                         ; =0x32
	bl	_fcntl
	ldp	x29, x30, [sp, #16]             ; 16-byte Folded Reload
	add	sp, sp, #32
	retab
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_lock_open              ; -- Begin function analyst_lock_open
	.p2align	2
_analyst_lock_open:                     ; @analyst_lock_open
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #32
	stp	x29, x30, [sp, #16]             ; 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	mov	w8, #438                        ; =0x1b6
	str	x8, [sp]
	mov	w1, #513                        ; =0x201
	movk	w1, #256, lsl #16
	bl	_open
	ldp	x29, x30, [sp, #16]             ; 16-byte Folded Reload
	add	sp, sp, #32
	retab
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_mode                   ; -- Begin function analyst_mode
	.p2align	2
_analyst_mode:                          ; @analyst_mode
	.cfi_startproc
; %bb.0:
	mov	w1, #438                        ; =0x1b6
	b	_fchmod
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_lock                   ; -- Begin function analyst_lock
	.p2align	2
_analyst_lock:                          ; @analyst_lock
	.cfi_startproc
; %bb.0:
	mov	w1, #1                          ; =0x1
	mov	x2, #0                          ; =0x0
	b	_lockf
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
