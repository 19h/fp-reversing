	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_local_status                   ; -- Begin function local_status
	.p2align	2
_local_status:                          ; @local_status
	.cfi_startproc
; %bb.0:
	and	w8, w0, #0xff
	and	w9, w1, #0xff
	cmp	w9, #81
	ccmp	w8, #0, #0, eq
	mov	w8, #40330                      ; =0x9d8a
	movk	w8, #29890, lsl #16
	mov	w9, #50769                      ; =0xc651
	movk	w9, #35645, lsl #16
	csel	w0, w9, w8, eq
	ret
	.cfi_endproc
                                        ; -- End function
	.globl	_signature_size                 ; -- Begin function signature_size
	.p2align	2
_signature_size:                        ; @signature_size
	.cfi_startproc
; %bb.0:
	mov	w8, #50769                      ; =0xc651
	movk	w8, #35645, lsl #16
	eor	w0, w0, w8
	ret
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
