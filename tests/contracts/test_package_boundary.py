"""Public package boundary: no host imports or implicit migration authority."""

import ast
import importlib
from pathlib import Path

import pytest
import bravo_security
from bravo_security.contracts.commands import ContractError
from bravo_security.migrations import MIGRATIONS, migration_sql


def test_source_imports_do_not_depend_on_sova_or_demo():
    root = Path(bravo_security.__file__).parent
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names = (
                [node.module]
                if isinstance(node, ast.ImportFrom)
                else (
                    [x.name for x in node.names] if isinstance(node, ast.Import) else []
                )
            )
            assert all(
                n is None or n.split(".")[0] not in {"sova", "demo", "platform"}
                for n in names
            ), path


def test_all_public_modules_import_without_a_host_runtime():
    root = Path(bravo_security.__file__).parent
    for path in root.rglob("*.py"):
        suffix = path.relative_to(root).with_suffix("").parts
        name = "bravo_security." + ".".join(
            suffix[:-1] if suffix[-1] == "__init__" else suffix
        )
        importlib.import_module(name.rstrip("."))


def test_migrations_are_explicit_security_owned_resources():
    assert len(MIGRATIONS) == 6
    for name in MIGRATIONS:
        text = migration_sql(name)
        assert "sova_control" in text
        assert "ALTER TABLE sova_control.operations" not in text
        assert "CREATE TABLE IF NOT EXISTS sova_control.operations" not in text
    for name in (
        "../pyproject.toml",
        "postgres_security_response_v1.sql",
        "missing.sql",
    ):
        with pytest.raises(ContractError):
            migration_sql(name)
