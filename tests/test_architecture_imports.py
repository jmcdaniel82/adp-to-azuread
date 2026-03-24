import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
FACADE_MODULES = {
    "app.adp.workers",
    "app.adp_client",
    "app.ldap_client",
    "app.department_resolution",
}
FACADE_FILES = {
    APP_ROOT / "adp" / "workers.py",
    APP_ROOT / "adp_client.py",
    APP_ROOT / "ldap_client.py",
    APP_ROOT / "department_resolution.py",
}


def _iter_python_files() -> list[Path]:
    return sorted(path for path in APP_ROOT.rglob("*.py") if path not in FACADE_FILES)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            if node.level == 0:
                imported.add(node.module)
            elif node.level == 1:
                imported.add(f"app.{node.module}")
            elif node.level == 2:
                parent = path.relative_to(APP_ROOT).with_suffix("").parts[:-1]
                if parent:
                    imported.add(f"app.{'.'.join(parent[:-1])}.{node.module}".strip("."))
    return imported


def test_internal_modules_do_not_depend_on_compatibility_facades():
    offenders: list[str] = []
    for path in _iter_python_files():
        imports = _imported_modules(path)
        facade_hits = sorted(FACADE_MODULES.intersection(imports))
        if facade_hits:
            offenders.append(f"{path.relative_to(REPO_ROOT)} -> {', '.join(facade_hits)}")
    assert offenders == []
