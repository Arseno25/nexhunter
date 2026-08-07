"""Chain of custody: a tamper-evident, hash-linked audit trail per finding.

Every review-state change (created, re-observed by a tool, gated, checked
against the pre-submission checklist, promoted, reported) appends one link.
Each link's hash covers the event, its data, its timestamp, and the
previous link's hash -- altering or deleting a past link breaks every hash
after it. This does not prevent tampering (anyone with the data file can
rewrite the whole chain); it makes an *undetected* rewrite impossible,
which is what a custody trail is for: proving the record wasn't quietly
edited after the fact, not physically stopping the edit.

append() never mutates the list it's given -- it returns chain + [new_link],
so a caller holding a reference to the old list never observes a partial
update, the same discipline FindingStore already applies to Finding itself.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class CustodyLink:
    seq: int
    event: str
    data: dict[str, Any]
    timestamp: str
    prev_hash: str
    link_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "event": self.event,
            "data": self.data,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "link_hash": self.link_hash,
        }


def _compute_hash(seq: int, event: str, data: dict, timestamp: str, prev_hash: str) -> str:
    material = json.dumps(
        {"seq": seq, "event": event, "data": data, "timestamp": timestamp, "prev_hash": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def append(chain: list[dict], event: str, data: dict[str, Any] | None = None) -> list[dict]:
    """Append one tamper-evident link. Returns a new list; never mutates `chain`."""
    data = data or {}
    seq = len(chain)
    prev_hash = chain[-1]["link_hash"] if chain else GENESIS_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    link = CustodyLink(
        seq=seq,
        event=event,
        data=data,
        timestamp=timestamp,
        prev_hash=prev_hash,
        link_hash=_compute_hash(seq, event, data, timestamp, prev_hash),
    )
    return [*chain, link.to_dict()]


def verify(chain: list[dict]) -> tuple[bool, str | None]:
    """Recompute every link's hash and check the chain is intact.

    Returns (True, None) when every link's stored hash matches what its
    (seq, event, data, timestamp, prev_hash) actually hashes to, and every
    link's prev_hash matches the previous link's link_hash. Returns
    (False, reason) naming the first broken link otherwise.
    """
    prev_hash = GENESIS_HASH
    for i, raw in enumerate(chain):
        if raw.get("seq") != i:
            return False, f"link {i}: out-of-order sequence number {raw.get('seq')!r}"
        if raw.get("prev_hash") != prev_hash:
            return False, f"link {i}: prev_hash does not match the preceding link"
        try:
            expected = _compute_hash(raw["seq"], raw["event"], raw.get("data") or {}, raw["timestamp"], raw["prev_hash"])
        except KeyError as exc:
            return False, f"link {i}: missing field {exc}"
        if raw.get("link_hash") != expected:
            return False, f"link {i}: hash mismatch -- this link's data was altered after being written"
        prev_hash = raw["link_hash"]
    return True, None


__all__ = ["GENESIS_HASH", "CustodyLink", "append", "verify"]
