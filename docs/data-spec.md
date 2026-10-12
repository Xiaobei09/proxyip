CN 分运营商趋势，每行一快照 `{ts, cn_reachable, cn_by_isp}`；`cn_by_isp` 为
`{运营商: {sampled, reachable, cn_wide, min_ms, median_ms}}`（无读数时为 `{}`）。
`cn_wide`（R393）为 CN 口径可达（各运营商相同），`reachable`/`sampled` 为逐运营商实测。保留最近 8 天。