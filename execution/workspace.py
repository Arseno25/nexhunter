"""Per-execution workspaces.

Every execution gets its own directory under the engagement it belongs to:

    NEXHUNTER_DATA_DIR/engagements/<engagement_id>/executions/<execution_id>/

Nothing a tool or an AI client names is allowed to resolve outside that
directory. There is deliberately no general file-manager API: artifacts are
reachable only by name, only within one execution's workspace.
"""

import os
import re
from pathlib import Path
from typing import List, Optional

# Identifiers become directory names, so they are restricted to characters that
# cannot traverse, escape, or collide case-insensitively on Windows.
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Artifact names are a single path component; no separators, no dot-dot.
_SAFE_ARTIFACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

DEFAULT_MAX_ARTIFACT_BYTES = 50 * 1024 * 1024


class WorkspaceError(Exception):
    """A workspace path was unsafe or could not be prepared."""


def data_dir() -> Path:
    """Root data directory, from NEXHUNTER_DATA_DIR or a local default."""
    configured = os.environ.get("NEXHUNTER_DATA_DIR", "").strip()
    return Path(configured).expanduser() if configured else Path.cwd() / "nexhunter_data"


def _check_id(value: str, kind: str) -> str:
    if not value or not _SAFE_ID.match(value):
        raise WorkspaceError(f"unsafe {kind}: {value!r}")
    return value


class Workspace:
    """An isolated directory for one execution's artifacts."""

    def __init__(self, root: Path, engagement_id: str, execution_id: str):
        self.engagement_id = engagement_id
        self.execution_id = execution_id
        self.root = root

    @classmethod
    def create(
        cls,
        engagement_id: str,
        execution_id: str,
        base_dir: Optional[Path] = None,
    ) -> "Workspace":
        """Create (or reuse) the workspace for one execution."""
        engagement_id = _check_id(engagement_id, "engagement id")
        execution_id = _check_id(execution_id, "execution id")

        base = (base_dir or data_dir()).resolve()
        root = base / "engagements" / engagement_id / "executions" / execution_id

        # Confirm the composed path really is under the base before creating it.
        resolved_parent = root.parent
        root.mkdir(parents=True, exist_ok=True)
        root = root.resolve()
        if not cls._is_within(root, base):
            raise WorkspaceError(f"workspace escaped the data directory: {root}")
        del resolved_parent

        return cls(root=root, engagement_id=engagement_id, execution_id=execution_id)

    @staticmethod
    def _is_within(candidate: Path, parent: Path) -> bool:
        """True when candidate is parent or lives inside it, symlinks resolved."""
        try:
            candidate.relative_to(parent)
            return True
        except ValueError:
            return False

    def artifact_path(self, name: str) -> Path:
        """Resolve an artifact name inside this workspace.

        Rejects traversal, absolute paths, nested paths, null bytes, and
        symlinks that point back out of the workspace.
        """
        if not name or "\x00" in name:
            raise WorkspaceError("artifact name is empty or contains a null byte")
        if not _SAFE_ARTIFACT.match(name):
            raise WorkspaceError(f"unsafe artifact name: {name!r}")

        candidate = self.root / name

        # Resolve symlinks before comparing; a symlink placed by a tool must not
        # be able to point at /etc/shadow and be served as an artifact.
        resolved = candidate.resolve() if candidate.exists() else (self.root.resolve() / name)
        if not self._is_within(resolved, self.root.resolve()):
            raise WorkspaceError(f"artifact escapes the workspace: {name!r}")
        return resolved

    def list_artifacts(self, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> List[dict]:
        """List regular files directly inside this workspace."""
        if not self.root.exists():
            return []
        artifacts = []
        for entry in sorted(self.root.iterdir()):
            if entry.is_symlink() or not entry.is_file():
                continue
            size = entry.stat().st_size
            artifacts.append({
                "name": entry.name,
                "bytes": size,
                "oversized": size > max_bytes,
            })
        return artifacts

    def read_artifact(self, name: str, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> str:
        """Read an artifact, truncating at max_bytes."""
        path = self.artifact_path(name)
        if not path.is_file():
            raise WorkspaceError(f"no such artifact: {name!r}")
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(max_bytes)

    def __repr__(self) -> str:
        return f"Workspace({self.engagement_id}/{self.execution_id})"
