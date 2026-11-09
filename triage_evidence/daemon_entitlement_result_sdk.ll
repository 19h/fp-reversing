; ModuleID = '/Users/___/dev/dylex/extracted/triage_evidence/daemon_entitlement_result_sdk.c'
source_filename = "/Users/___/dev/dylex/extracted/triage_evidence/daemon_entitlement_result_sdk.c"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64e-apple-macosx11.0.0"

; Function Attrs: nounwind ssp uwtable(sync)
define zeroext i8 @entitlement_boolean(ptr noundef %0) local_unnamed_addr #0 {
  %2 = tail call i64 @CFGetTypeID(ptr noundef %0) #2
  %3 = tail call i64 @CFBooleanGetTypeID() #2
  %4 = icmp eq i64 %2, %3
  br i1 %4, label %5, label %7

5:                                                ; preds = %1
  %6 = tail call zeroext i8 @CFBooleanGetValue(ptr noundef %0) #2
  br label %7

7:                                                ; preds = %1, %5
  %8 = phi i8 [ %6, %5 ], [ 0, %1 ]
  ret i8 %8
}

declare i64 @CFGetTypeID(ptr noundef) local_unnamed_addr #1

declare i64 @CFBooleanGetTypeID() local_unnamed_addr #1

declare zeroext i8 @CFBooleanGetValue(ptr noundef) local_unnamed_addr #1

attributes #0 = { nounwind ssp uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #1 = { "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #2 = { nounwind }

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
