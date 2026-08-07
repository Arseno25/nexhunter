"""Install-recipe table and command building (cli/installer.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.cli import installer as I


def test_recipe_for_known_and_unknown():
    assert I.recipe_for("nmap") is not None
    assert I.recipe_for("definitely-not-a-tool") is None


def test_command_shapes_per_method():
    assert I.command_for(I.Recipe(I.APT, "nmap")) == ["sudo", "apt-get", "install", "-y", "nmap"]
    assert I.command_for(I.Recipe(I.GO, "example.com/x@latest")) == ["go", "install", "-v", "example.com/x@latest"]
    assert I.command_for(I.Recipe(I.PIPX, "semgrep")) == ["pipx", "install", "semgrep"]


def test_unknown_method_rejected():
    import pytest

    with pytest.raises(ValueError):
        I.command_for(I.Recipe("brew", "nmap"))


def test_command_str_roundtrip():
    assert I.command_str(I.Recipe(I.PIPX, "awscli")) == "pipx install awscli"


def test_recipe_targets_never_contain_shell_metacharacters():
    """Targets are a fixed table; guard against a typo introducing an injection."""
    bad = set(";|&`$><\n")
    for binary, recipe in I.INSTALL_RECIPES.items():
        assert not (bad & set(recipe.target)), f"{binary} target has a shell metacharacter"
        assert recipe.method in (I.APT, I.GO, I.PIPX), f"{binary} has unknown method {recipe.method}"


def test_method_available_uses_path(monkeypatch):
    monkeypatch.setattr(I.shutil, "which", lambda name: "/usr/bin/" + name if name == "go" else None)
    assert I.method_available(I.GO) is True
    assert I.method_available(I.APT) is False  # looks up apt-get, not present here
