"""commit_data.sh 必须把 job 的删除产物也写进提交。

``find -newer .jobstart`` 只按 mtime 找"改/增"，删掉的文件没有 mtime；
若不从基线快照单独推算删除，pipeline（validate/quality/annotate）对
countries/sets/ports 越界视图与 rep/verified 残留的清理永远进不了提交，
死代视图会一直留在发布树。同时删除不得被 align_foreign 用 checkout -f
救回，他人中途更新（外来漂移）仍须对齐 origin 而不是回滚。
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "commit_data.sh"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


class TestCommitData(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name) / "work"
        self.work.mkdir(parents=True, exist_ok=True)
        self.origin = Path(self.tmp.name) / "origin.git"
        _git(self.work, "init", "-b", "main")
        _git(self.work, "config", "user.name", "t")
        _git(self.work, "config", "user.email", "t@local")
        _git(self.work, "config", "push.default", "simple")
        _git(self.work, "init", "--bare", str(self.origin))
        _git(self.work, "remote", "add", "origin", str(self.origin))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _initial_commit(self, files: dict[str, str]) -> None:
        for rel, content in files.items():
            p = self.work / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        _git(self.work, "add", "-A")
        self.assertEqual(
            _git(self.work, "commit", "-q", "-m", "init").returncode, 0
        )
        self.assertEqual(
            _git(self.work, "push", "-u", "origin", "main").returncode, 0
        )

    def _run_job(
        self, msg: str, marker_mtime: float = 1_577_836_800.0
    ) -> subprocess.CompletedProcess:
        """模拟一次 CI job：touch .jobstart（早于脚本写盘）后提交数据。"""
        marker = self.work / ".jobstart"
        marker.touch()
        import os

        os.utime(marker, (marker_mtime, marker_mtime))
        return subprocess.run(
            ["bash", str(SCRIPT), msg],
            cwd=str(self.work),
            capture_output=True,
            text=True,
            timeout=180,
        )

    def _head_has(self, rel: str) -> bool:
        return (
            _git(self.work, "cat-file", "-e", f"HEAD:{rel}").returncode == 0
        )

    def _head_content(self, rel: str) -> str:
        return _git(self.work, "show", f"HEAD:{rel}").stdout

    def test_deletion_is_committed_and_modification_kept(self):
        self._initial_commit(
            {
                "data/valid/keep.txt": "keep-v0\n",
                "data/valid/stale.txt": "stale-v0\n",
            }
        )
        (self.work / "data/valid").joinpath("keep.txt").write_text(
            "keep-v1\n", encoding="utf-8"
        )
        (self.work / "data/valid").joinpath("stale.txt").unlink()

        proc = self._run_job("test job")
        self.assertEqual(proc.returncode, 0, proc.stderr)

        self.assertEqual(
            _git(self.work, "log", "-1", "--format=%s").stdout.strip(),
            "test job",
        )
        self.assertEqual(self._head_content("data/valid/keep.txt"), "keep-v1\n")
        self.assertFalse(
            self._head_has("data/valid/stale.txt"),
            "job 删除的文件必须进入提交（此前 find -newer 漏掉删除）",
        )

    def test_delete_only_job_still_commits(self):
        self._initial_commit({"data/valid/gone.txt": "gone-v0\n"})
        (self.work / "data/valid").joinpath("gone.txt").unlink()

        proc = self._run_job("delete-only")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            _git(self.work, "log", "-1", "--format=%s").stdout.strip(),
            "delete-only",
        )
        self.assertFalse(
            self._head_has("data/valid/gone.txt"),
            "纯删除 job 也必须产出提交",
        )

    def test_foreign_drift_is_restored_not_rolled_back(self):
        initial = {
            "data/valid/keep.txt": "keep-v0\n",
            "data/quality/other.json": '{"v": 0}\n',
        }
        self._initial_commit(initial)
        # job 改动 keep；other.json 是陈旧 checkout 副本（内容不同但 mtime 早
        # 于 marker），必须对齐 origin 而非把新数据回滚成旧副本。
        (self.work / "data/valid").joinpath("keep.txt").write_text(
            "keep-v1\n", encoding="utf-8"
        )
        foreign = self.work / "data/quality" / "other.json"
        foreign.write_text('{"v": 999}\n', encoding="utf-8")
        import os

        os.utime(foreign, (1_577_836_800.0, 1_577_836_800.0))

        proc = self._run_job("drift")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            _git(self.work, "log", "-1", "--format=%s").stdout.strip(), "drift"
        )
        self.assertEqual(self._head_content("data/valid/keep.txt"), "keep-v1\n")
        self.assertEqual(
            self._head_content("data/quality/other.json"), '{"v": 0}\n'
        )
        self.assertEqual(
            (self.work / "data/quality/other.json").read_text(encoding="utf-8"),
            '{"v": 0}\n',
            "外来漂移应 checkout -f 对齐 origin，不得保留陈旧副本",
        )

    def test_excl_paths_are_never_staged(self):
        self._initial_commit(
            {
                "data/raw/gone.txt": "raw-v0\n",
                "data/valid/keep.txt": "keep-v0\n",
            }
        )
        (self.work / "data/raw").joinpath("gone.txt").unlink()
        (self.work / "data/valid").joinpath("keep.txt").write_text(
            "keep-v1\n", encoding="utf-8"
        )

        proc = self._run_job("excl")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self._head_content("data/valid/keep.txt"), "keep-v1\n"
        )
        self.assertTrue(
            self._head_has("data/raw/gone.txt"),
            "data/raw 归档不在删除/新增追踪范围，HEAD 必须保留旧稿",
        )


if __name__ == "__main__":
    unittest.main()