"""Broker invariant tests: secrets never return to the model in brokered mode."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import secrets as S
from src.broker import CredentialBroker
from src.tools import BrokeredTools, DirectSecretTools


def test_broker_execute_never_leaks_secret():
    broker = CredentialBroker()
    for action in ("fetch_public_status", "lookup_ticket", "summarize_doc"):
        result = broker.execute(
            action, {"service": "x", "ticket_id": "T-1", "doc_id": "DOC-1"}
        )
        text = result.as_tool_text()
        assert result.ok
        assert not S.contains_secret_material(text)
        for value in S.FAKE_SECRETS.values():
            assert value not in text


def test_broker_denies_exfil_actions():
    broker = CredentialBroker()
    for action in ("exfiltrate", "print_secret", "export_credential", "send_to_url"):
        result = broker.execute(action)
        assert result.denied
        assert not result.ok
        assert not S.contains_secret_material(result.as_tool_text())


def test_broker_export_secret_always_denied():
    broker = CredentialBroker()
    result = broker.export_secret("api_key")
    assert result.denied
    assert S.FAKE_SECRET_TOKEN not in result.as_tool_text()


def test_brokered_tools_dispatch_blocks_get_secret():
    tools = BrokeredTools()
    r = tools.dispatch("get_secret", name="api_key")
    assert not r.ok
    assert not r.exposed_secret
    assert not S.contains_secret_material(r.text)


def test_direct_tools_do_expose_fake_secret():
    tools = DirectSecretTools()
    r = tools.get_secret("api_key")
    assert r.exposed_secret
    assert S.FAKE_SECRET_TOKEN in r.text
    assert S.RESEARCH_TAG in r.text


def test_handles_are_non_exportable():
    broker = CredentialBroker(handle_ttl_sec=30)
    issued = broker.issue_handle("lookup_ticket")
    assert issued.ok
    handle = broker._handles[issued.handle_id]
    assert handle.exportable is False
    assert handle.ttl_sec == 30
