"""Engagement scope model and target validation."""

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Sequence, Tuple
from enum import Enum


def _dns_resolve(host: str) -> List[ipaddress._BaseAddress]:
    """Resolve a hostname to every address it points at.

    Raises OSError when resolution fails; callers must treat that as a denial
    (a name we cannot resolve is a name whose scope we cannot verify).
    """
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return list({ipaddress.ip_address(info[4][0]) for info in infos})


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

    # Cloud metadata endpoints. Blocked unconditionally: reaching one of these
    # from inside a target's network is SSRF, never a legitimate scan target.
    METADATA_IPS = {
        ipaddress.ip_address("169.254.169.254"),  # AWS, Azure, GCP, OpenStack
        ipaddress.ip_address("169.254.169.253"),  # Azure secondary
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS over IPv6
    }

    # Hostnames that front a metadata service.
    METADATA_HOSTS = {
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }

    # Injectable so tests (and offline runs) do not depend on real DNS.
    resolver: Callable[[str], List[ipaddress._BaseAddress]] = staticmethod(_dns_resolve)

    @staticmethod
    def _normalize_ip(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
        """Unwrap IPv4-mapped IPv6 (::ffff:169.254.169.254) to its IPv4 form.

        Without this, an attacker reaches a blocked IPv4 address by writing it
        in IPv6 notation.
        """
        mapped = getattr(ip, "ipv4_mapped", None)
        return mapped or ip

    @classmethod
    def is_metadata_ip(cls, ip_str: str) -> bool:
        """Check if an address is a known cloud metadata endpoint."""
        try:
            ip = cls._normalize_ip(ipaddress.ip_address(str(ip_str)))
        except ValueError:
            return False
        return ip in cls.METADATA_IPS

    @classmethod
    def is_reserved_ip(cls, ip_str: str) -> Tuple[bool, Optional[str]]:
        """Check if an address is loopback, private, or otherwise not routable.

        Uses the stdlib classification so IPv6 (link-local, unique-local,
        IPv4-mapped) is covered as thoroughly as IPv4.
        """
        try:
            ip = cls._normalize_ip(ipaddress.ip_address(str(ip_str)))
        except ValueError:
            return False, None

        if ip in cls.METADATA_IPS:
            return True, "Cloud metadata endpoint"
        for flag, reason in (
            ("is_loopback", "Loopback address"),
            ("is_link_local", "Link-local address"),
            ("is_multicast", "Multicast address"),
            ("is_unspecified", "Unspecified address"),
            ("is_private", "Private address"),
            ("is_reserved", "Reserved address"),
        ):
            if getattr(ip, flag, False):
                return True, reason
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

        Fails closed: anything this function cannot positively verify against an
        active engagement is denied.

        Returns: (is_allowed, reason)
        """
        # No engagement means no authorization to scan anything.
        if not engagement:
            return False, "No engagement context; scope cannot be verified"

        if not engagement.is_active(now):
            return False, "Engagement is not active"

        allowed = engagement.scope.allowed_targets
        denied = engagement.scope.denied_targets

        # An empty allow-list authorizes nothing, it does not authorize everything.
        if not allowed:
            return False, "Engagement has an empty allowed-target list"

        host = cls._extract_host(target)
        if not host:
            return False, "Target could not be parsed into a host"

        # Denied entries always win over allowed entries.
        if cls._matches_any_pattern(host, denied):
            return False, "Target is in denied list"

        if not cls._matches_any_pattern(host, allowed):
            return False, "Target is not in allowed list"

        if host.lower() in cls.METADATA_HOSTS:
            return False, "Cloud metadata endpoint"

        # A host named only by wildcard is authorized by name, not by address.
        named_literally = cls._is_literal_allow(host, allowed)

        addresses, resolve_error = cls._target_addresses(host)
        if resolve_error:
            return False, resolve_error

        # Check every address the name actually points at. This is what stops
        # DNS rebinding and hostnames aimed at internal or metadata addresses.
        for ip in addresses:
            if cls.is_metadata_ip(str(ip)):
                return False, f"Cloud metadata endpoint ({ip})"
            if cls._matches_any_pattern(str(ip), denied):
                return False, f"Resolved address {ip} is in denied list"

            is_reserved, reason = cls.is_reserved_ip(str(ip))
            if not is_reserved:
                continue

            # Non-routable space needs explicit authorization: either an
            # address-shaped scope entry covering this exact address, or the
            # host named literally. A wildcard domain must never be enough --
            # otherwise *.example.com silently reaches RFC1918 or link-local.
            if named_literally or cls._address_explicitly_allowed(ip, allowed):
                continue
            return False, f"{reason or 'Reserved address'} ({ip})"

        return True, None

    @classmethod
    def _address_explicitly_allowed(cls, ip, allowed: Sequence[str]) -> bool:
        """True when an IP/CIDR entry in the scope covers this address.

        Only address-shaped entries count; a wildcard hostname never authorizes
        an address it merely happens to resolve to.
        """
        for pattern in allowed:
            candidate = (pattern or "").strip().lower()
            if not candidate or candidate.startswith("*."):
                continue
            try:
                if "/" in candidate:
                    network = ipaddress.ip_network(candidate, strict=False)
                else:
                    network = ipaddress.ip_network(f"{candidate}/{ipaddress.ip_address(candidate).max_prefixlen}")
            except ValueError:
                continue  # hostname entry, not an address
            if ip.version == network.version and ip in network:
                return True
        return False

    @staticmethod
    def _extract_host(target: str) -> str:
        """Reduce a URL or host:port target to its bare host."""
        host = (target or "").strip()
        if not host:
            return ""
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split("?", 1)[0]
        if host.startswith("["):  # [2001:db8::1]:443
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:  # host:port, never bare IPv6
            host = host.split(":", 1)[0]
        return host.rstrip(".").lower()

    @classmethod
    def _is_literal_allow(cls, host: str, allowed: Sequence[str]) -> bool:
        """True when the engagement names this host exactly.

        Deliberately excludes wildcard and CIDR matches so that widening the
        scope cannot quietly authorize reserved address space.
        """
        return host.lower() in {cls._extract_host(p) for p in allowed}

    @classmethod
    def _target_addresses(cls, host: str) -> Tuple[List[ipaddress._BaseAddress], Optional[str]]:
        """Return every address a target resolves to, or a denial reason."""
        try:
            return [cls._normalize_ip(ipaddress.ip_address(host))], None
        except ValueError:
            pass  # Not a literal address; resolve it.

        try:
            addresses = [cls._normalize_ip(ip) for ip in cls.resolver(host)]
        except OSError as exc:
            return [], f"DNS resolution failed for {host}: {exc}"

        if not addresses:
            return [], f"DNS resolution returned no addresses for {host}"
        return addresses, None

    @staticmethod
    def _matches_any_pattern(target: str, patterns: Sequence[str]) -> bool:
        """Check if target matches any pattern (supports wildcards and CIDRs)."""
        target_lower = (target or "").strip().rstrip(".").lower()
        if not target_lower:
            return False

        for pattern in patterns:
            pattern_lower = (pattern or "").strip().rstrip(".").lower()
            if not pattern_lower:
                continue

            # Exact match
            if pattern_lower == target_lower:
                return True

            # Wildcard subdomain match: *.example.com covers sub.example.com.
            # The leading dot is required -- a bare suffix test would also match
            # evil-example.com, which is a different domain entirely.
            if pattern_lower.startswith("*."):
                suffix = pattern_lower[2:]
                if not suffix:
                    continue
                if target_lower.endswith("." + suffix):
                    label = target_lower[: -(len(suffix) + 1)]
                    if label and "." not in label:  # single label deep
                        return True

            # CIDR match
            if "/" in pattern_lower:
                try:
                    network = ipaddress.ip_network(pattern_lower, strict=False)
                except ValueError:
                    continue
                try:
                    ip = TargetValidator._normalize_ip(ipaddress.ip_address(target_lower))
                except ValueError:
                    continue
                if ip.version == network.version and ip in network:
                    return True

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
