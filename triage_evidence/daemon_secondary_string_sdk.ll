; ModuleID = '/Users/___/dev/dylex/extracted/triage_evidence/daemon_secondary_string_sdk.c'
source_filename = "/Users/___/dev/dylex/extracted/triage_evidence/daemon_secondary_string_sdk.c"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64e-apple-macosx11.0.0"

; Function Attrs: mustprogress nofree norecurse nounwind ssp willreturn uwtable(sync)
define i64 @decimal_parse(ptr noundef %0, ptr noundef captures(none) %1) local_unnamed_addr #0 {
  %3 = tail call i64 @strtol(ptr noundef %0, ptr noundef %1, i32 noundef 10)
  ret i64 %3
}

; Function Attrs: mustprogress nocallback nofree nounwind willreturn
declare i64 @strtol(ptr noundef readonly, ptr noundef captures(none), i32 noundef) local_unnamed_addr #1

; Function Attrs: nounwind ssp uwtable(sync)
define zeroext i8 @ascii_convert(ptr noundef %0, ptr noundef %1) local_unnamed_addr #2 {
  %3 = tail call zeroext i8 @CFStringGetCString(ptr noundef %0, ptr noundef %1, i64 noundef 32, i32 noundef 1536) #4
  ret i8 %3
}

declare zeroext i8 @CFStringGetCString(ptr noundef, ptr noundef, i64 noundef, i32 noundef) local_unnamed_addr #3

attributes #0 = { mustprogress nofree norecurse nounwind ssp willreturn uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #1 = { mustprogress nocallback nofree nounwind willreturn "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #2 = { nounwind ssp uwtable(sync) "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #3 = { "checked-pointer-arith"="compatible" "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+altnzcv,+bti,+ccdp,+ccidx,+ccpp,+complxnum,+crc,+dit,+dotprod,+flagm,+fp-armv8,+fp16fml,+fptoint,+fullfp16,+jsconv,+lse,+neon,+pauth,+perfmon,+predres,+ras,+rcpc,+rdm,+sb,+sha2,+sha3,+specrestrict,+ssbs,+v8.1a,+v8.2a,+v8.3a,+v8.4a,+v8.5a,+v8a" }
attributes #4 = { nounwind }

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
