"""Fail-closed policy helpers for public and user-scoped MCP tools."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """A policy result. It is not evidence that a token was authenticated."""

    allowed: bool
    reason: str
    required_scopes: frozenset[str] = frozenset()


class ToolScopePolicy:
    """Classify known tools as public or authenticated-user scoped.

    ``principal`` and ``granted_scopes`` must come from an authentication layer
    that has already validated the token, issuer, audience, expiry, and scopes.
    """

    def __init__(
        self,
        *,
        public_tools: Iterable[str] = (),
        user_tools: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        public = frozenset(_tool_names(public_tools))
        user_config = user_tools or {}
        _tool_names(user_config.keys())
        scoped = {
            name: frozenset(_scope_names(scopes))
            for name, scopes in user_config.items()
        }
        overlap = public.intersection(scoped)
        if overlap:
            raise ValueError(f"tools cannot be both public and user-scoped: {sorted(overlap)!r}")
        if any(not scopes for scopes in scoped.values()):
            raise ValueError("every user-scoped tool must require at least one scope")
        self._public = public
        self._user = MappingProxyType(scoped)

    @property
    def public_tools(self) -> frozenset[str]:
        return self._public

    @property
    def user_tools(self) -> Mapping[str, frozenset[str]]:
        return self._user

    def authorize(
        self,
        tool_name: str,
        *,
        granted_scopes: Iterable[str] = (),
        principal: object | None = None,
    ) -> AccessDecision:
        """Apply policy to already-validated identity data; unknown tools deny."""
        if not isinstance(tool_name, str) or not tool_name:
            return AccessDecision(False, "unknown_tool")
        if tool_name in self._public:
            return AccessDecision(True, "public_tool")
        required = self._user.get(tool_name)
        if required is None:
            return AccessDecision(False, "unknown_tool")
        if principal is None:
            return AccessDecision(False, "missing_principal", required)
        granted = frozenset(_scope_names(granted_scopes))
        missing = required.difference(granted)
        if missing:
            return AccessDecision(False, "missing_scopes", required)
        return AccessDecision(True, "scopes_satisfied", required)


def visible_tool_metadata(
    tools: Iterable[Mapping[str, Any]],
    policy: ToolScopePolicy,
    *,
    granted_scopes: Iterable[str] = (),
    principal: object | None = None,
    name_key: str = "name",
) -> tuple[Mapping[str, Any], ...]:
    """Filter discovery metadata for convenience, never authorize execution.

    The caller must call ``policy.authorize`` again at tool execution time.
    Missing, non-string, and unknown tool names are omitted (fail closed).
    """
    scopes = tuple(granted_scopes)
    visible: list[Mapping[str, Any]] = []
    for metadata in tools:
        name = metadata.get(name_key)
        if isinstance(name, str) and policy.authorize(
            name, granted_scopes=scopes, principal=principal
        ).allowed:
            visible.append(metadata)
    return tuple(visible)


def _tool_names(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError("tool names must be an iterable of strings, not one string")
    names = tuple(values)
    if any(not isinstance(name, str) or not name for name in names):
        raise ValueError("tool names must be non-empty strings")
    return names


def _scope_names(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError("scopes must be an iterable of strings, not one string")
    scopes = tuple(values)
    if any(not isinstance(scope, str) or not scope for scope in scopes):
        raise ValueError("scopes must be non-empty strings")
    return scopes
