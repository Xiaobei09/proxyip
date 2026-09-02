import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from annotate_classify import reconcile_ports


class TestReconcilePorts(unittest.TestCase):
    """``reconcile_ports`` 须把 ``ports/*.txt`` 行集约束到 ``all.txt``。

    历史轮次遗留的非 CF 端口/离场节点一旦不在 ``all.txt``，就在每轮
    注解时剔除；``all.txt`` 内节点必须原样保留。
    """

    def _tree(self, all_lines, port85, port443):
        d = Path(tempfile.mkdtemp())
        valid = d / "valid"
        valid.mkdir(parents=True)
        ports = valid / "ports"
        ports.mkdir(parents=True)
        (valid / "all.txt").write_text("\n".join(all_lines) + "\n", encoding="utf-8")
        (ports / "85.txt").write_text("\n".join(port85) + "\n", encoding="utf-8")
        (ports / "443.txt").write_text("\n".join(port443) + "\n", encoding="utf-8")
        return d, valid

    def test_removes_phantom_lines_only(self):
        d, valid = self._tree(
            all_lines=[
                "1.1.1.1:443#US",
                "2.2.2.2:443#US",
                "3.3.3.3:85#US",
            ],
            port85=["3.3.3.3:85#US", "9.9.9.9:85#US"],
            port443=["1.1.1.1:443#US", "2.2.2.2:443#US", "8.8.8.8:443#US"],
        )
        removed = reconcile_ports(valid)
        self.assertEqual(removed, 2)
        self.assertEqual(
            (valid / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US\n2.2.2.2:443#US\n",
        )
        self.assertEqual(
            (valid / "ports" / "85.txt").read_text(encoding="utf-8"),
            "3.3.3.3:85#US\n",
        )
        self.assertEqual(
            (valid / "all.txt").read_text(encoding="utf-8").splitlines(),
            ["1.1.1.1:443#US", "2.2.2.2:443#US", "3.3.3.3:85#US"],
        )

    def test_key_compare_ignores_note_differences(self):
        d, valid = self._tree(
            all_lines=["1.1.1.1:443#US-old"],
            port85=[],
            port443=["1.1.1.1:443#US-new"],
        )
        self.assertEqual(reconcile_ports(valid), 0)
        self.assertEqual(
            (valid / "ports" / "443.txt").read_text(encoding="utf-8"),
            "1.1.1.1:443#US-new\n",
        )

    def test_empty_all_returns_zero(self):
        d, valid = self._tree(all_lines=[], port85=["9.9.9.9:85#US"], port443=[])
        self.assertEqual(reconcile_ports(valid), 0)


if __name__ == "__main__":
    unittest.main()