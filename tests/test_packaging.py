"""
Packaging checks: the distribution must ship every first-party module its code imports.
"""

import ast
import runpy
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def setup_kwargs(monkeypatch_module):
    setuptools = pytest.importorskip("setuptools")
    captured = {}
    monkeypatch_module.setattr(
        setuptools, "setup", lambda **kwargs: captured.update(kwargs)
    )
    monkeypatch_module.chdir(REPO_ROOT)
    runpy.run_path(str(REPO_ROOT / "setup.py"), run_name="__main__")
    return captured


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def _first_party_top_level_imports(package_dirs):
    first_party = {p.stem for p in REPO_ROOT.glob("*.py")} | {
        p.parent.name for p in REPO_ROOT.glob("*/__init__.py")
    }
    found = set()
    for package in package_dirs:
        for path in (REPO_ROOT / package).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    found.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    found.update(alias.name.split(".")[0] for alias in node.names)
    return found & first_party


def test_distribution_ships_imported_first_party_modules(setup_kwargs):
    shipped = {pkg.split(".")[0] for pkg in setup_kwargs["packages"]}
    shipped |= set(setup_kwargs.get("py_modules", []))

    imported = _first_party_top_level_imports(["analysis_engine", "cli", "generator"])

    assert imported - shipped == set()


def test_database_layer_imports_with_declared_dependencies():
    """SQLAlchemy 2.1 no longer installs greenlet, which the async engine needs."""
    from analysis_engine import pipeline

    assert pipeline.DATABASE_AVAILABLE is True
