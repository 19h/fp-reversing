	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_notification_abi               ; -- Begin function notification_abi
	.p2align	2
_notification_abi:                      ; @notification_abi
	.cfi_startproc
; %bb.0:
	pacibsp
	stp	x22, x21, [sp, #-48]!           ; 16-byte Folded Spill
	stp	x20, x19, [sp, #16]             ; 16-byte Folded Spill
	stp	x29, x30, [sp, #32]             ; 16-byte Folded Spill
	add	x29, sp, #32
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	.cfi_offset w19, -24
	.cfi_offset w20, -32
	.cfi_offset w21, -40
	.cfi_offset w22, -48
	mov	x19, x2
	mov	x20, x1
	mov	x21, x0
	bl	_notify_register_check
	mov	x22, x0
	ldr	w0, [x20]
	mov	x1, x19
	bl	_notify_check
	orr	w22, w0, w22
	ldr	w0, [x20]
	bl	_notify_cancel
	mov	x19, x0
	mov	x0, x21
	bl	_notify_post
	orr	w8, w19, w0
	orr	w0, w22, w8
	ldp	x29, x30, [sp, #32]             ; 16-byte Folded Reload
	ldp	x20, x19, [sp, #16]             ; 16-byte Folded Reload
	ldp	x22, x21, [sp], #48             ; 16-byte Folded Reload
	retab
	.cfi_endproc
                                        ; -- End function
	.globl	_notification_clock             ; -- Begin function notification_clock
	.p2align	2
_notification_clock:                    ; @notification_clock
	.cfi_startproc
; %bb.0:
	pacibsp
	stp	x20, x19, [sp, #-32]!           ; 16-byte Folded Spill
	stp	x29, x30, [sp, #16]             ; 16-byte Folded Spill
	add	x29, sp, #16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	.cfi_offset w19, -24
	.cfi_offset w20, -32
	mov	x19, x0
	mov	x0, x1
	bl	_atexit
	mov	x20, x0
	mov	x0, x19
	mov	x1, #0                          ; =0x0
	bl	_gettimeofday
	orr	w0, w0, w20
	ldp	x29, x30, [sp, #16]             ; 16-byte Folded Reload
	ldp	x20, x19, [sp], #32             ; 16-byte Folded Reload
	retab
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
