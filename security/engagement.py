"""Engagement scope model and target validation."""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple
from enum import Enum


class RiskLevel(Enum):
    """Tool risk classification."""
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class TargetType(Enum):
    """Target classification."""
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR4 = "cidr4"
    CIDR6 = "cidr6"
    URL = "url"
    PORT = "port"


@dataclass(frozen=True)
class EngagementScope:
    """Scope constraints for an engagement."""

    allowed_targets: List[str] = field(default_factory=list)
    denied_targets: List[str] = field(default_factory=list)
    allowed_ports: List[str] = field(default_factory=list)
    allowed_protocols: List[str] = field(default_factory=list)
    allowed_risk_levels: List[RiskLevel] = field(default_factory=lambda: [RiskLevel.PASSIVE, RiskLevel.ACTIVE])


@dataclass(frozen=True)
class Engagement:
    """Security engagement with scope and constraints."""

    id: str
    name: str
    status: str  # active, paused, completed, cancelled
    scope: EngagementScope
    starts_at: datetime
    expires_at: datetime

    def is_active(self, now: Optional[datetime] = None) -> bool:
        """Check if engagement is currently active."""
        if self.status != "active":
            return False
        now = now or datetime.utcnow()
        return self.starts_at <= now <= self.expires_at

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check if engagement has expired."""
        now = now or datetime.utcnow()
        return now > self.expires_at


class TargetValidator:
    """Validate targets against engagement scope."""

    # Cloud metadata endpoints to block
    METADATA_IPS = {
        ipaddress.IPv4Address("169.254.169.254"),  # AWS, Azure, GCP
        ipaddress.IPv4Address("169.254.169.253"),  # Azure
    }

    # Private/reserved IP ranges
    RESERVED_RANGES = [
        ipaddress.IPv4Network("0.0.0.0/8"),
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("127.0.0.0/8"),  # loopback
        ipaddress.IPv4Network("169.254.0.0/16"),  # link-local
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
        ipaddress.IPv4Network("224.0.0.0/4"),  # multicast
        ipaddress.IPv4Network("240.0.0.0/4"),  # reserved
        ipaddress.IPv4Network("255.255.255.255/32"),  # broadcast
    ]

    @staticmethod
    def is_reserved_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
        """Check if IP is in reserved ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)

            # IPv4 checks
            if isinstance(ip, ipaddress.IPv4Address):
                if ip in TargetValidator.METADATA_IPS:
                    return True, "Cloud metadata endpoint"

                for reserved in TargetValidator.RESERVED_RANGES:
                    if ip in reserved:
                        return True, f"Reserved range: {reserved}"

            # IPv6 loopback
            if isinstance(ip, ipaddress.IPv6Address) and ip.is_loopback:
                return True, "IPv6 loopback"

            return False, None
        except ValueError:
            return False, None

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Validate hostname format."""
        if not hostname or len(hostname) > 253:
            return False

        # Allow wildcard subdomains
        if hostname.startswith("*."):
            hostname = hostname[2:]

        # Hostname validation regex
        pattern = r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)$"
        return bool(re.match(pattern, hostname))

    @staticmethod
    def is_valid_cidr(cidr_str: str) -> bool:
        """Validate CIDR notation."""
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_port(port_str: str) -> bool:
        """Validate port number or range."""
        try:
            parts = port_str.split("-")
            if len(parts) == 1:
                port = int(parts[0])
                return 1 <= port <= 65535
            elif len(parts) == 2:
                start = int(parts[0])
                end = int(parts[1])
                return 1 <= start <= end <= 65535
            return False
        except ValueError:
            return False

    @classmethod
    def validate_target(
        cls,
        target: str,
        engagement: Optional[Engagement] = None,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate if target is allowed in engagement scope.

        Returns: (is_allowed, reason)
        """
        if not engagement:
            return True, None

        # Check engagement is active
        if not engagement.is_active(now):
            return False, "Engagement is not active"

        # Denied targets always take precedence
        if cls._matches_any_pattern(target, engagement.scope.denied_targets):
            return False, "Target is in denied list"

        # Check allowed targets
        if engagement.scope.allowed_targets:
            if not cls._matches_any_pattern(target, engagement.scope.allowed_targets):
                return False, "Target is not in allowed list"

        # Check for reserved IPs
        try:
            # Try to parse as IP
            is_reserved, reason = cls.is_reserved_ip(target)
            if is_reserved:
                # Allow if explicitly in allowed_targets
                if not cls._matches_any_pattern(target, engagement.scope.allowed_targets):
                    return False, reason or "Reserved IP address"
        except (ValueError, ipaddress.AddressValueError):
            pass  # Not an IP, continue with hostname validation

        return True, None

    @staticmethod
    def _matches_any_pattern(target: str, patterns: List[str]) -> bool:
        """Check if target matches any pattern (supports wildcards)."""
        target_lower = target.lower()

        for pattern in patterns:
            pattern_lower = pattern.lower()

            # Exact match
            if pattern_lower == target_lower:
                return True

            # Wildcard subdomain match (*.example.com matches sub.example.com)
            if pattern_lower.startswith("*."):
                domain_part = pattern_lower[2:]
                if target_lower.endswith(domain_part) and "." in target_lower:
                    # Ensure it's a subdomain, not partial domain match
                    prefix = target_lower[: -len(domain_part) - 1]
                    if "." not in prefix:  # Only one level of subdomain
                        return True

            # CIDR match
            if "/" in pattern_lower:
                try:
                    network = ipaddress.ip_network(pattern_lower, strict=False)
                    ip = ipaddress.ip_address(target_lower)
                    if ip in network:
                        return True
                except ValueError:
                    pass

        return False

    @classmethod
    def validate_scope_config(cls, scope: EngagementScope) -> Tuple[bool, List[str]]:
        """Validate scope configuration for validity."""
        errors = []

        for target in scope.allowed_targets:
            if not cls._is_valid_target_pattern(target):
                errors.append(f"Invalid target pattern: {target}")

        for target in scope.denied_targets:
            if not cls._is_valid_target_pattern(target):
                errors.append(f"Invalid denied target pattern: {target}")

        for port in scope.allowed_ports:
            if not cls.is_valid_port(port):
                errors.append(f"Invalid port specification: {port}")

        return len(errors) == 0, errors

    @staticmethod
    def _is_valid_target_pattern(target: str) -> bool:
        """Check if target pattern is valid."""
        # Wildcard domain
        if target.startswith("*."):
            return TargetValidator.is_valid_hostname(target)

        # CIDR
        if "/" in target:
            return TargetValidator.is_valid_cidr(target)

        # IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        # Hostname
        return TargetValidator.is_valid_hostname(target)


class ScopeEnforcer:
    """Enforce engagement scope constraints."""

    def __init__(self, validator: TargetValidator = None):
        """Initialize with optional custom validator."""
        self.validator = validator or TargetValidator()

    def check_execution(
        self,
        engagement: Engagement,
        target: str,
        risk_level: RiskLevel,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if execution is allowed under engagement scope.

        Returns: (is_allowed, reason)
        """
        # Check engagement active
        if not engagement.is_active():
            return False, "Engagement is not active"

        # Check target allowed
        is_allowed, reason = self.validator.validate_target(target, engagement)
        if not is_allowed:
            return False, reason

        # Check risk level allowed
        if risk_level not in engagement.scope.allowed_risk_levels:
            return False, f"Risk level {risk_level.value} not allowed in this engagement"

        return True, None

    def check_execution_or_raise(
        self,
        engagement: Engagement,
        target: str,
        risk_level: RiskLevel,
    ) -> None:
        """Check execution, raise if denied."""
        is_allowed, reason = self.check_execution(engagement, target, risk_level)
        if not is_allowed:
            raise PermissionError(f"Execution denied: {reason}")
