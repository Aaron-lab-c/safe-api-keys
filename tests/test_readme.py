"""README code blocks stay identical to examples/ and the quick start runs (§13.6, §21)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import readme_examples  # noqa: E402


def test_readme_blocks_match_examples():
    assert readme_examples.check((ROOT / "README.md").read_text(encoding="utf-8")) == []


def test_readme_quick_start_runs(capsys):
    assert readme_examples.run_blocks((ROOT / "README.md").read_text(encoding="utf-8")) >= 1
    assert capsys.readouterr().out.startswith("sk_test_")
