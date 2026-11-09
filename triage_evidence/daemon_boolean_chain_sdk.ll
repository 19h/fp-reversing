; ModuleID = '/Users/___/dev/dylex/extracted/triage_evidence/daemon_boolean_chain_sdk.c'
source_filename = "/Users/___/dev/dylex/extracted/triage_evidence/daemon_boolean_chain_sdk.c"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64e-apple-macosx11.0.0"

; Function Attrs: mustprogress nofree norecurse nosync nounwind ssp willreturn memory(argmem: read) uwtable(sync)
define i32 @read_bridge_status(ptr noundef readonly captures(none) %0) local_unnamed_addr #0 {
  %2 = getelementptr inbounds nuw i8, ptr %0, i64 8, !annotation !9
  %3 = load i32, ptr %2, align 8, !tbaa !10
  %4 = xor i32 %3, -1958885807
  ret i32 %4
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind ssp willreturn memory(argmem: read) uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }

!llvm.module.flags = !{!0, !1, !2, !5, !6, !7}
!llvm.ident = !{!8}

!0 = !{i32 2, !"SDK Version", [2 x i32] [i32 27, i32 2]}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 6, !"ptrauth.abi-version", !3}
!3 = !{!4}
!4 = !{i32 0, i1 false}
!5 = !{i32 8, !"PIC Level", i32 2}
!6 = !{i32 7, !"uwtable", i32 1}
!7 = !{i32 7, !"frame-pointer", i32 1}
!8 = !{!"Apple clang version 21.0.0 (clang-2100.3.34.2)"}
!9 = !{!"cpa-safe"}
!10 = !{!11, !15, i64 8}
!11 = !{!"client_bits_record", !12, i64 0, !15, i64 8, !15, i64 12, !16, i64 16}
!12 = !{!"any pointer", !13, i64 0}
!13 = !{!"omnipotent char", !14, i64 0}
!14 = !{!"Simple C/C++ TBAA"}
!15 = !{!"int", !13, i64 0}
!16 = !{!"p1 int", !12, i64 0}
