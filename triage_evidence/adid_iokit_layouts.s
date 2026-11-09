	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_analyst_main                   ; -- Begin function analyst_main
	.p2align	2
_analyst_main:                          ; @analyst_main
	.cfi_startproc
; %bb.0:
	mov	x1, x0
	mov	w0, #0                          ; =0x0
	b	_IOMainPort
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_open                   ; -- Begin function analyst_open
	.p2align	2
_analyst_open:                          ; @analyst_open
	.cfi_startproc
; %bb.0:
	mov	x3, x2
	mov	w2, #0                          ; =0x0
	b	_IOServiceOpen
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_indirect               ; -- Begin function analyst_indirect
	.p2align	2
_analyst_indirect:                      ; @analyst_indirect
	.cfi_startproc
; %bb.0:
	mov	x5, x2
	mov	x2, x1
	mov	w1, #26                         ; =0x1a
	mov	w3, #16                         ; =0x10
	mov	x4, x2
	b	_IOConnectCallStructMethod
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_direct                 ; -- Begin function analyst_direct
	.p2align	2
_analyst_direct:                        ; @analyst_direct
	.cfi_startproc
; %bb.0:
	mov	x5, x2
	mov	x2, x1
	mov	w1, #26                         ; =0x1a
	mov	w3, #96                         ; =0x60
	mov	x4, x2
	b	_IOConnectCallStructMethod
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
