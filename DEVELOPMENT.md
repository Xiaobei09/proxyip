# 开发规范

## 提交流程

**修改完代码后必须提交并推送，不允许仅本地修改不推送。**

```bash
git add -A
git commit -m "<type>: <description>"
git push
```

### 提交信息格式

- `feat:` 新功能
- `fix:` 修复
- `fix(ci):` CI 修复
- `chore:` 维护性变更
- `docs:` 文档变更
- `refactor:` 重构
- `test:` 测试

### 提交检查清单

1. 运行测试：`python -m unittest discover -s tests -v`
2. 检查代码风格
3. 确认无敏感信息泄露
4. 提交并推送

## CI 并发策略

- `update-proxies.yml`：`cancel-in-progress: true`（主更新优先）
- 下游 workflow：`cancel-in-progress: false`（保护已完成的检测结果）

## 代码规范

- 零第三方依赖，仅标准库
- Python 3.11+
- 使用 `asyncio` 进行异步操作
- 幂等设计：重复运行不产生副作用
- Token 追加前先 `has_token` 判重

## 数据规范

- 格式：`ip:port#<emoji><CC>→<exit>-<latency>ms-<speed>MB/s[-tokens]`
- 排序：`all.txt` 按延迟升序，`*_ltd.txt` 按速度降序
- 去重：同一 `ip:port` 全局唯一
