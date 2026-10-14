# 可用性校验流程（Availability Validation）

## 链路总览

1. ip 源抓取：`pcb/scripts/download_proxies.py`
2. 存活 + 出口：`pcb/scripts/validate_proxies.py`、`pcb/scripts/external_check.py`
3. 出口家族/多出口：`exit_family.json`
4. 大陆可达与分运营商：`china_check.py`、`china_engine.py`
5. 缓存：`pool_cache.py`（7 天，单轮 ≤ 1000）
6. 质量与 good/premium：`quality_*.py`、`build_good.py`

## 具体端点

- 出口 IP：`http://httpbin.org/get`、`https://api.ipify.org?format=json`、Cloudflare `cf-ray`、`ip-api.com/json`
- 分运营商 RTT 异常下限：境内 1ms / 港澳 5ms / 台 8ms / 日韩 12ms / 东南亚 25ms / 其他 40ms。
- 分运营商数据超过 1 天清除（`CN_ISP_TTL_SEC=86400`）。
- ≥10 个出口源对比，多出口打 `multi_region_exit=true`。

## 超时

- 网络 ≤ 30s；脚本 ≤ 5min；测试 ≤ 5min；git ≤ 60s。
