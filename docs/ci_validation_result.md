# CI 验证结果记录

- 最新 Leak guard run `38522725656`（public b466fefa + PCB `7fb5c88`）结论：**success**.
- 门禁：commit format 与 private-source leak guard PASS.
- 关键回归：
  - `TestLoopCommitFormat.test_loop_commits_never_touch_data_or_noise_r107` 157.215s OK
  - `TestWorkflowConcurrency.test_cancel_policy` OK
- 公共仓 workflow `leak-guard.yml` 的 cancel-in-progress 保持 `true`（Do not weaken tests）.
- 后续轮次继续 targeted tests，更新此文件可作为 CI evidence 附录。

## R521（2026-10-15）CI 健康复测：R517 根因修复确认 + 残留瞬时漂移定位与修复

- **R517 根因修复确认有效**：此前 5 个工作流（Update proxy list / Quality
  check / Annotate / Exit family / China check）同因全红的单一根因
  （`pcb/scripts/suite_size.py` 缺 `--help`，被 `test_cli_health` 判红）已消失；
  干净提交上 `Update proxy list` run `38651080667`（head `e91d84132`）转绿。
- **残留红单定位**：`Update proxy list` run `38673336666` 与 `Quality check`
  run `38674115902`（同一 head `cb5b7e251`）连红，红因是
  `data/valid/countries/` 的**孤儿国家目录**——`countries/HR/`（仅 `rep*`
  家族）与 `countries/SC/`（仅 `cn*`/`ltd*`）存在但**无 `all.txt`**；另有
  1 个端点出现在 `all.txt` 而未进任何 `countries/*/all.txt`。三例同源
  （`test_no_orphan_dirs` / `test_sum_equals_all_txt` /
  `test_published_exit_annotations_are_faithful`）。
- **引入点**：quality-check 链提交 `36d00508e`（00:47Z）删除了
  `countries/HR/all.txt`（及 `cn*`/`ltd*`）却保留了 `rep*` 分支文件 ⇒ 目录
  缺 `all.txt`。
- **自愈**：后续链约 03:10 将目录整树清理；`origin/main` 新 tip `7be86f1be`
  已 **0 孤儿**（79 国目录）。
- **架构说明（有意为之、测试锁定）**：`Run tests` 先于重型网络步
  （`R254`/`R325` 成本决策）；`tests_pipeline/test_commit_data.py` 双向锁定
  「fail-fast 步不得加 `always()`、heal 步必须 `always()`」。故漂移提交所在
  那一轮自身无法自愈，由后续链（`always()` heal）收敛。
- **修复（R521）**：`pcb/scripts/annotate_classify.py` 的 `reconcile_views`
  在 `backfill`（master 权威重建有效出口国 `all.txt`）之后，**无条件清理**仍缺
  `all.txt` 的 `countries/<cc>/` 孤儿目录——与 `pcb/scripts/reorg_country.py`
  的 `_prune_orphan_country_dirs` 同口径、同卫生契约（只扫 `countries/`、只认
  两字母目录名）；`backfill=False` 的 download 扁平树不受影响。回归锁入
  `tests_pipeline/test_annotate.py::TestReconcileViews`。
- 目标测试（change-where-run-where）：`test_annotate` 54 OK、`test_quality`
  289 OK、`test_reorg` 29 OK、`test_download` 147 OK、`test_cli_health` 13 OK、
  `test_suite_size` 1 OK。
- 复测命令：`gh run list --workflow='Update proxy list'`；
  `git ls-tree -r --name-only origin/main data/valid/countries` 核对孤儿。
