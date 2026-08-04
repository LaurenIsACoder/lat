# WI-231 Step4 writer 接线白盒测试报告

## Summary

- worktree: `/home/loongson/work/code/latu-worktrees/kzt-step4-wi230-wi231-integrated-20260709094322`
- branch: `lauren/kzt-step4-wi230-wi231-integrated-20260709094322`
- 代码验证范围: `20dec00bac069e77a07d30a6d43a24ce34882f17..d7401373939651a8c51b841d32457eafda5744a1`
- 报告修正说明: 本文件随后随报告修正 commit 更新，因此不把报告自身 commit 写作固定 HEAD。
- 测试目标: `kzt-rela-immediate-candidate` 与 13 个 KZT 单测目标
- 结论: `git diff --check`、debug build、13 个 KZT 单测、`latxbuild/build-release.sh` 均通过。
- 集成说明: 当前测试已经调用真实生产 helper `kzt_rela_immediate_jump_slot_try_write()`，不是平行模拟 Step4 contract。该 helper 再调用 Step3 writer/guard，覆盖 approved writer success、planner 非批准、writer fail-open、`GLOB_DAT`/非目标/lazy skip writer。

## Checklist

- [x] 测试证据包含 command。
- [x] 测试证据包含 summary。
- [x] 测试证据包含 stdout/raw output。
- [x] 测试证据包含 exit_code。
- [x] 测试点直接覆盖 WI-230/WI-231 writer 接线验收，不只复用 Step3 writer 通用单测。
- [x] 测试调用真实生产 helper `kzt_rela_immediate_jump_slot_try_write()`。
- [x] 生产接线仍通过 Step3 guard/writer，不直接写 slot。
- [x] 未 push，未创建远端 PR。

## Commands

```sh
cd /home/loongson/work/code/latu-worktrees/kzt-step4-wi230-wi231-integrated-20260709094322
git diff --check
ninja -C build64-dbg
meson test -C build64-dbg --print-errorlogs -v \
  kzt-guest-registry \
  kzt-guest-registry-concurrency \
  kzt-guest-link-map-reader \
  kzt-guest-dynamic-parser \
  kzt-guest-dynamic-snapshot \
  kzt-guest-dynamic-diagnostics \
  kzt-observation-adapter \
  kzt-registry-diagnostics-gate \
  kzt-patch-planner \
  kzt-runtime-got-plt-candidate \
  kzt-rela-immediate-candidate \
  kzt-patch-spike-guard \
  kzt-patch-spike-writer
latxbuild/build-release.sh
```

## Exit Codes

```text
git diff --check: 0
ninja -C build64-dbg: 0
meson test -C build64-dbg 13 KZT tests: 0
latxbuild/build-release.sh: 0
```

## Raw Output Highlights

```text
[113/132] Compiling C object libqemu-x86_64-linux-user.fa.p/target_i386_latx_context_box64context.c.o
[119/132] Compiling C object libqemu-x86_64-linux-user.fa.p/target_i386_latx_context_elfloader.c.o
[132/132] Linking target latx-x86_64
```

```text
WI231_TC tc=approved-writer-success-skips-legacy plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=0 skip_legacy=1 result=APPLIED failure=NONE reads=2 writer_writes=1 final=0x7200004560
WI231_TC tc=planner-unsupported-keeps-legacy plan_status=1 plan_reason=0 decision=UNSUPPORTED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-rejected-keeps-legacy plan_status=1 plan_reason=0 decision=REJECTED writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=lazy-deferred-keeps-legacy plan_status=0 plan_reason=3 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=planner-fail-open-keeps-legacy plan_status=2 plan_reason=6 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300003333
WI231_TC tc=writer-expected-mismatch-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=EXPECTED_MISMATCH reads=1 writer_writes=0 final=0x7300004444
WI231_TC tc=writer-write-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=WRITE_FAILED reads=1 writer_writes=1 final=0x7300004444
WI231_TC tc=writer-verify-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=VERIFY_FAILED reads=2 writer_writes=2 final=0x7300004444
WI231_TC tc=writer-rollback-fail-fail-open plan_status=1 plan_reason=0 decision=APPROVED writer_called=1 legacy_writes=1 skip_legacy=0 result=FAIL_OPEN failure=ROLLBACK_FAILED reads=2 writer_writes=2 final=0x7300004444
WI231_TC tc=non-target-relocation-skips-writer plan_status=0 plan_reason=2 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
WI231_TC tc=glob-dat-skips-writer plan_status=0 plan_reason=2 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
WI231_TC tc=lazy-deferred-skips-writer plan_status=0 plan_reason=3 decision=(none) writer_called=0 legacy_writes=1 skip_legacy=0 result=DISABLED failure=NONE reads=0 writer_writes=0 final=0x7300005555
```

```text
Ok:                 13
Fail:               0
[67/67] Linking target latx-i386
[132/132] Linking target latx-x86_64
```

## Coverage Mapping

- approved writer success: `approved-writer-success-skips-legacy` 验证 writer 调用、legacy 跳过、最终值为 bridge。
- planner 非批准或 fail-open: `planner-unsupported-keeps-legacy`、`planner-rejected-keeps-legacy`、`planner-fail-open-keeps-legacy` 验证 writer 不调用且 legacy 保持。
- writer fail-open: `writer-expected-mismatch-fail-open`、`writer-write-fail-fail-open`、`writer-verify-fail-fail-open`、`writer-rollback-fail-fail-open` 验证失败时继续 legacy。
- 非目标范围: `non-target-relocation-skips-writer`、`glob-dat-skips-writer`、`lazy-deferred-skips-writer` 验证本阶段不接管 `GLOB_DAT`、非目标 relocation 和 lazy deferred。
- 生产生命周期: `ninja -C build64-dbg` 和 `latxbuild/build-release.sh` 编译 `box64context.c`、`elfloader.c` 和 KZT helper，确认 guard 挂到 `box64context_t` 的生产接线可编译。
