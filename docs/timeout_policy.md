# 超时与降级策略（Timeout & Degradation）

- 网络请求 ≤ 30s
- 单脚本 ≤ 5min
- unittest ≤ 5min
- git/gh ≤ 60s
- 每轮总预算 ≤ 15min
- CI 跟踪：push 后查询一次状态即返回；未完成记“CI 进行中”，下轮重试
- 任一子任务卡住：跳过并记录待处理，其余任务继续
