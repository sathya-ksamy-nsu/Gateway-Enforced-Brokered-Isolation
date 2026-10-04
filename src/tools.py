"""Agent tools: direct secret access vs brokered invocation (paper Section 4.2).

Two tool surfaces share a common :class:`ToolResult` interface:

* **Direct tools** — ``get_secret``, ``read_env_secret``. These return fake
  plaintext tokens into the model-visible channel (insecure baseline).
* **Brokered tools** — ``broker_execute``. These never return secrets; the
  broker uses credentials server-side and returns scrubbed results only.

Defensive study only: all tokens are ``sk_test_REDACTED*`` placeholders.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import secrets as S
from .broker import CredentialBroker


@dataclass
class ToolResult:
    """Model-visible tool output plus exposure bookkeeping for metrics."""

    name: str
    text: str
    ok: bool = True
    exposed_secret: bool = False
    meta: Dict = field(default_factory=dict)

    def as_message(self) -> str:
        return f"[tool:{self.name}] {self.text}"


class DirectSecretTools:
    """Insecure baseline: secrets are returned into model-visible tool text."""

    def __init__(self):
        self._env = dict(S.FAKE_SECRETS)

    def list_tools(self) -> List[str]:
        return ["get_secret", "read_env_secret", "call_api"]

    def get_secret(self, name: str = "api_key") -> ToolResult:
        ref = S.get_fake_secret(name)
        # Direct mode intentionally returns plaintext to the model channel.
        text = (
            f"{S.RESEARCH_TAG} secret_name={ref.name} "
            f"value={ref.value}"
        )
        return ToolResult(
            name="get_secret",
            text=text,
            ok=True,
            exposed_secret=True,
            meta={"mode": "direct", "secret_name": name},
        )

    def read_env_secret(self, name: str = "api_key") -> ToolResult:
        value = self._env.get(name)
        if value is None:
            return ToolResult(
                name="read_env_secret",
                text=f"env var '{name}' not found",
                ok=False,
                exposed_secret=False,
                meta={"mode": "direct"},
            )
        text = f"{S.RESEARCH_TAG} ENV {name}={value}"
        return ToolResult(
            name="read_env_secret",
            text=text,
            ok=True,
            exposed_secret=True,
            meta={"mode": "direct", "secret_name": name},
        )

    def call_api(self, action: str, params: Optional[Dict] = None) -> ToolResult:
        """Naive direct call: agent must first obtain a secret, then 'call'."""
        params = params or {}
        # If the caller already pasted a secret into params, that is exposure.
        blob = str(params)
        exposed = S.contains_secret_material(blob)
        text = f"direct_call action={action} params={params} (uses caller-supplied token)"
        return ToolResult(
            name="call_api",
            text=text,
            ok=True,
            exposed_secret=exposed,
            meta={"mode": "direct", "action": action},
        )

    def dispatch(self, tool_name: str, **kwargs) -> ToolResult:
        if tool_name == "get_secret":
            return self.get_secret(kwargs.get("name", "api_key"))
        if tool_name == "read_env_secret":
            return self.read_env_secret(kwargs.get("name", "api_key"))
        if tool_name == "call_api":
            return self.call_api(kwargs.get("action", "fetch_public_status"), kwargs.get("params"))
        return ToolResult(
            name=tool_name, text=f"unknown tool: {tool_name}", ok=False
        )


class BrokeredTools:
    """Hardened surface: only broker_execute; secrets never returned."""

    def __init__(self, broker: Optional[CredentialBroker] = None):
        self.broker = broker or CredentialBroker()

    def list_tools(self) -> List[str]:
        return ["broker_execute", "broker_export_secret"]

    def broker_execute(self, action: str, params: Optional[Dict] = None) -> ToolResult:
        result = self.broker.execute(action, params)
        text = result.as_tool_text()
        exposed = S.contains_secret_material(text)
        assert not exposed, "brokered tool must not expose secrets"
        return ToolResult(
            name="broker_execute",
            text=text,
            ok=result.ok,
            exposed_secret=False,
            meta={
                "mode": "brokered",
                "denied": result.denied,
                "handle_id": result.handle_id,
                "action": action,
            },
        )

    def broker_export_secret(self, name: str = "api_key") -> ToolResult:
        """Probe tool: always denied; used by injection tests as attacker bait."""
        result = self.broker.export_secret(name)
        text = result.as_tool_text()
        assert not S.contains_secret_material(text)
        return ToolResult(
            name="broker_export_secret",
            text=text,
            ok=False,
            exposed_secret=False,
            meta={"mode": "brokered", "denied": True},
        )

    def dispatch(self, tool_name: str, **kwargs) -> ToolResult:
        if tool_name == "broker_execute":
            return self.broker_execute(
                kwargs.get("action", "fetch_public_status"),
                kwargs.get("params"),
            )
        if tool_name in ("broker_export_secret", "get_secret", "read_env_secret"):
            # Any attempt to pull plaintext in brokered mode is denied.
            return self.broker_export_secret(kwargs.get("name", "api_key"))
        return ToolResult(
            name=tool_name, text=f"unknown tool: {tool_name}", ok=False
        )
