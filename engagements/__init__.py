"""nexhunter.engagements - Authorized assessment records.

An engagement is the record of what you are permitted to test, for how long.
Every active execution belongs to one; without it there is nothing to check a
target against, so there is nothing to authorize.
"""

from nexhunter.engagements.store import EngagementStore, EngagementError

__all__ = ["EngagementStore", "EngagementError"]
