	.build_version macos, 27, 2	sdk_version 27, 2
	.ptrauth_abi_version 0
	.ptrauth_abi_version 0
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_analyst_host_uuid              ; -- Begin function analyst_host_uuid
	.p2align	2
_analyst_host_uuid:                     ; @analyst_host_uuid
	.cfi_startproc
; %bb.0:
	b	_gethostuuid
	.cfi_endproc
                                        ; -- End function
	.globl	_analyst_truncate               ; -- Begin function analyst_truncate
	.p2align	2
_analyst_truncate:                      ; @analyst_truncate
	.cfi_startproc
; %bb.0:
	b	_ftruncate
	.cfi_endproc
                                        ; -- End function
.subsections_via_symbols
