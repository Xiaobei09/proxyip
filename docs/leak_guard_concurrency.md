# Leak Guard 并发行为说明

## 现象

在连续 md 提交场景下，GitHub Actions 的 `concurrency.cancel-in-progress: true`
会中断上一轮 Leak guard；最终以最后一轮的结果为准，不是泄漏证据丢失。

## 解读规则

- `cancelled`：被新提交 supersede，应看同队列 newer run。
- `failure`：需要定位日志；本仓额外做 push 前 `pcb/tests_pipeline.test_checks_bundle` 与
  `test_commit_data` 定点回归。
- 门禁数字来自 act 执行日志实时派生，避免硬编码漂移。

## 私有源泄露扫描

```bash
grep -RInE '<PRIVATE_SOURCE_IDENTIFIER_PATTERN>' --exclude-dir=.git --exclude-dir=data/raw --exclude-dir=data/diff --exclude-dir=.opencode .
```

结果必须为空。
