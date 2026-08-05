"""Persistent, concurrency-safe engagement storage.

Engagements are the authorization record, so they are written to disk rather
than held in memory: a restart must not silently widen or drop the scope an
operator configured.

Storage is one JSON file per engagement under DATA_DIR/engagements/<id>/. That
is the same directory an execution's workspace lives in, which keeps everything
about one engagement in one place.
"""

import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from nexhunter.execution.workspace import data_dir
from nexhunter.security.engagement import (
    Engagement,
    EngagementScope,
    RiskLevel,
    TargetValidator,
)

# Engagement ids become directory names, so they are restricted to characters
# that cannot traverse or collide.
_VALID_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

VALID_STATUSES = ("active", "paused", "completed", "cancelled")

METADATA_FILENAME = "engagement.json"


class EngagementError(Exception):
    """An engagement could not be created, loaded, or validated."""


@dataclass
class ValidationResult:
    """Outcome of validating an engagement definition."""

    ok: bool
    errors: List[str]

    def raise_if_invalid(self) -> None:
        if not self.ok:
            raise EngagementError("; ".join(self.errors))


def _parse_datetime(value, field: str) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise EngagementError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from exc
    # Stored naive in UTC so comparisons stay consistent across the codebase.
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def engagement_to_dict(engagement: Engagement) -> dict:
    """Serialize an engagement to its stored/API form."""
    return {
        "id": engagement.id,
        "name": engagement.name,
        "status": engagement.status,
        "starts_at": engagement.starts_at.isoformat(),
        "expires_at": engagement.expires_at.isoformat(),
        "active": engagement.is_active(),
        "expired": engagement.is_expired(),
        "scope": {
            "allowed_targets": list(engagement.scope.allowed_targets),
            "denied_targets": list(engagement.scope.denied_targets),
            "allowed_ports": list(engagement.scope.allowed_ports),
            "allowed_protocols": list(engagement.scope.allowed_protocols),
            "allowed_risk_levels": [r.value for r in engagement.scope.allowed_risk_levels],
        },
    }


def engagement_from_dict(data: dict) -> Engagement:
    """Build an engagement from its stored/API form.

    Raises EngagementError on anything malformed. Nothing is defaulted that
    would widen scope: a missing allow-list stays empty, which authorizes
    nothing.
    """
    if not isinstance(data, dict):
        raise EngagementError("engagement must be a JSON object")

    engagement_id = str(data.get("id", "")).strip()
    if not _VALID_ID.match(engagement_id):
        raise EngagementError(
            f"invalid engagement id {engagement_id!r}: use letters, digits, dot, dash, underscore"
        )

    status = str(data.get("status", "active")).strip().lower()
    if status not in VALID_STATUSES:
        raise EngagementError(f"invalid status {status!r}: expected one of {', '.join(VALID_STATUSES)}")

    scope_raw = data.get("scope") or {}
    if not isinstance(scope_raw, dict):
        raise EngagementError("scope must be a JSON object")

    risk_levels = []
    for value in scope_raw.get("allowed_risk_levels", ["passive"]):
        try:
            risk_levels.append(RiskLevel(str(value)))
        except ValueError as exc:
            raise EngagementError(f"invalid risk level {value!r}") from exc

    # Destructive risk is never granted through this path. Enabling it takes an
    # explicit feature flag and an approval record, not a line in a scope file.
    if RiskLevel.DESTRUCTIVE in risk_levels:
        raise EngagementError("destructive risk cannot be granted by an engagement definition")

    scope = EngagementScope(
        allowed_targets=[str(t).strip() for t in scope_raw.get("allowed_targets", []) if str(t).strip()],
        denied_targets=[str(t).strip() for t in scope_raw.get("denied_targets", []) if str(t).strip()],
        allowed_ports=[str(p).strip() for p in scope_raw.get("allowed_ports", []) if str(p).strip()],
        allowed_protocols=[str(p).strip() for p in scope_raw.get("allowed_protocols", []) if str(p).strip()],
        allowed_risk_levels=risk_levels or [RiskLevel.PASSIVE],
    )

    now = datetime.utcnow()
    starts_at = _parse_datetime(data.get("starts_at", now.isoformat()), "starts_at")
    expires_at = _parse_datetime(
        data.get("expires_at", (now + timedelta(days=30)).isoformat()), "expires_at"
    )
    if expires_at <= starts_at:
        raise EngagementError("expires_at must be after starts_at")

    return Engagement(
        id=engagement_id,
        name=str(data.get("name") or engagement_id),
        status=status,
        scope=scope,
        starts_at=starts_at,
        expires_at=expires_at,
    )


def validate(engagement: Engagement) -> ValidationResult:
    """Check an engagement is usable before anything relies on it."""
    errors: List[str] = []

    if not engagement.scope.allowed_targets:
        errors.append("allowed_targets is empty, so every execution would be denied")

    ok, scope_errors = TargetValidator.validate_scope_config(engagement.scope)
    if not ok:
        errors.extend(scope_errors)

    if engagement.expires_at <= engagement.starts_at:
        errors.append("expires_at must be after starts_at")

    return ValidationResult(ok=not errors, errors=errors)


class EngagementStore:
    """Thread-safe, file-backed engagement storage."""

    def __init__(self, base_dir: Optional[Path] = None):
        self._lock = threading.RLock()
        self._base = Path(base_dir) if base_dir else data_dir()
        self._cache: Dict[str, Engagement] = {}
        self._loaded = False

    @property
    def root(self) -> Path:
        return self._base / "engagements"

    def _path_for(self, engagement_id: str) -> Path:
        if not _VALID_ID.match(engagement_id):
            raise EngagementError(f"invalid engagement id: {engagement_id!r}")
        return self.root / engagement_id / METADATA_FILENAME

    def _load_all_locked(self) -> None:
        """Read every stored engagement. Caller holds the lock."""
        self._cache.clear()
        if not self.root.is_dir():
            self._loaded = True
            return

        for entry in sorted(self.root.iterdir()):
            metadata = entry / METADATA_FILENAME
            if not entry.is_dir() or not metadata.is_file():
                continue
            try:
                data = json.loads(metadata.read_text(encoding="utf-8"))
                engagement = engagement_from_dict(data)
            except (OSError, ValueError, EngagementError):
                # A corrupt engagement file must not authorize anything, and
                # must not take down the whole store either. It is skipped;
                # `doctor` and the API surface the gap.
                continue
            self._cache[engagement.id] = engagement
        self._loaded = True

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load_all_locked()

    def reload(self) -> None:
        """Re-read from disk, discarding the cache."""
        with self._lock:
            self._load_all_locked()

    def create(self, data: dict, overwrite: bool = False) -> Engagement:
        """Validate and persist a new engagement."""
        engagement = engagement_from_dict(data)
        validate(engagement).raise_if_invalid()

        with self._lock:
            self._ensure_loaded()
            path = self._path_for(engagement.id)
            if path.exists() and not overwrite:
                raise EngagementError(f"engagement already exists: {engagement.id}")

            path.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temporary file and replace, so a crash mid-write
            # cannot leave a half-parsed scope in place.
            temporary = path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(engagement_to_dict(engagement), indent=2), encoding="utf-8"
            )
            temporary.replace(path)

            self._cache[engagement.id] = engagement
            return engagement

    def get(self, engagement_id: str) -> Optional[Engagement]:
        """Look up one engagement, or None."""
        if not engagement_id or not _VALID_ID.match(engagement_id):
            return None
        with self._lock:
            self._ensure_loaded()
            return self._cache.get(engagement_id)

    def list(self, active_only: bool = False) -> List[Engagement]:
        """List engagements, newest start first."""
        with self._lock:
            self._ensure_loaded()
            engagements = list(self._cache.values())
        if active_only:
            engagements = [e for e in engagements if e.is_active()]
        return sorted(engagements, key=lambda e: e.starts_at, reverse=True)

    def set_status(self, engagement_id: str, status: str) -> Engagement:
        """Change an engagement's status (pause, complete, cancel, resume)."""
        status = status.strip().lower()
        if status not in VALID_STATUSES:
            raise EngagementError(f"invalid status {status!r}")

        with self._lock:
            existing = self.get(engagement_id)
            if existing is None:
                raise EngagementError(f"no such engagement: {engagement_id}")
            payload = engagement_to_dict(existing)
            payload["status"] = status
            return self.create(payload, overwrite=True)

    def default_engagement(self) -> Optional[Engagement]:
        """The single active engagement, when there is exactly one.

        Used only to resolve a request that names no engagement. Ambiguity is
        not guessed at: with two active engagements the caller must say which.
        """
        active = [e for e in self.list() if e.is_active()]
        return active[0] if len(active) == 1 else None

    def __len__(self) -> int:
        with self._lock:
            self._ensure_loaded()
            return len(self._cache)
