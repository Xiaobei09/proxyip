"""Tests for generate_fingerprint.py."""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import generate_fingerprint as gf


class TestFingerprint(unittest.TestCase):
    def test_deterministic_with_seed(self):
        a = gf.fingerprint(random.Random(42))
        b = gf.fingerprint(random.Random(42))
        self.assertEqual(a, b)
        c = gf.fingerprint(random.Random(43))
        self.assertNotEqual(a, c)

    def test_internal_consistency(self):
        for seed in range(20):
            fp = gf.fingerprint(random.Random(seed))
            with self.subTest(seed=seed):
                self.assertIn(fp["os"], gf.UAS)
                self.assertIn(fp["userAgent"], gf.UAS[fp["os"]])
                self.assertEqual(fp["platform"], gf.PLATFORM[fp["os"]])
                self.assertIn((fp["screen"]["width"], fp["screen"]["height"]), gf.SCREENS[fp["os"]])
                self.assertIn(fp["language"], [loc[0] for loc in gf.LANGS[fp["os"]]])
                self.assertIn(fp["timezone"], gf.TIMEZONES[fp["os"]])
                self.assertIn(fp["screen"]["devicePixelRatio"], gf.DPR[fp["os"]])
                self.assertIn(fp["hardwareConcurrency"], gf.CONCURRENCY[fp["os"]])
                self.assertIn(fp["deviceMemory"], gf.MEMORY[fp["os"]])
                self.assertIn(
                    (fp["webgl"]["renderer"], fp["webgl"]["vendor"]), gf.WEBGL[fp["os"]]
                )

    def test_canvas_hash_stable_per_profile(self):
        fp = gf.fingerprint(random.Random(7))
        self.assertEqual(len(fp["canvasHash"]), 16)
        self.assertTrue(fp["canvasHash"].isalnum())


if __name__ == "__main__":
    unittest.main()
