# 缓存与多出口标记契约（公开）

## 可用 IP 缓存（pool_cache）

- 仅在当前池跌破上一公布规模 × 0.9 时启用补回。
- 候选仅来自 `node_seen.json` 中最近 7 天实测存活的键。
- 单轮补回上限默认 <= 1000，所有补回键必须通过存活/出口校验。
- 候选源缺失或坏结构时静默跳过，不阻断下载链。

## 出口多源标记（build_exit_cc_set_map）

- `exit_ccs` 保存全部独立出口观测，`multi_region_exit=true` 时标记 >=2 个互斥出口国。
- 建议至少聚合 10 个出口观测源；可复用现有 reputations/external checks 的观测。
- 入口/出口不同地区单独标记，不能仅靠单源成功判定。
- 缺失出口观测的 IP 不能写成 " exporters == importers"，必须标 pending/reorg.

## 可用性
- CN 分运营商数据 >24h 清除。
- 三网可用读数目标均衡，仅认实测 reachable，不回退 CN 副本（R838 删除多线）。
- RTT 低于出口地理下限或异常过大的 CN 延迟剔除。
