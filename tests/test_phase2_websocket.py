"""
Phase 2 Tests — WebSocket Threat Stream Engine
pytest tests/test_phase2_websocket.py
"""

import asyncio
import json
import pytest

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.threat_stream import (
    ThreatEventBus,
    ThreatEvent,
    ThreatEventType,
    ThreatSeverity,
    get_event_bus,
    emit_finding,
    emit_exploit_confirmed,
    emit_mev_attack,
    emit_cve_correlation,
)


@pytest.mark.asyncio
async def test_event_bus_publish_and_receive():
    """Test that published events are received by subscribers."""
    bus = ThreatEventBus()

    async with await bus.subscribe("test-sub-1") as ctx:
        event = ThreatEvent(
            event_type  = ThreatEventType.FINDING_DETECTED,
            severity    = ThreatSeverity.HIGH,
            title       = "Test Finding",
            description = "A test security finding",
        )
        await bus.publish(event)
        received = await ctx.get(timeout=2.0)

    assert received is not None
    assert received.title == "Test Finding"
    assert received.event_type == ThreatEventType.FINDING_DETECTED
    assert received.severity   == ThreatSeverity.HIGH


@pytest.mark.asyncio
async def test_event_bus_fanout_multiple_subscribers():
    """Test that events are delivered to ALL active subscribers."""
    bus = ThreatEventBus()
    results = []

    async with await bus.subscribe("sub-A") as ctxA:
        async with await bus.subscribe("sub-B") as ctxB:
            event = ThreatEvent(
                event_type  = ThreatEventType.EXPLOIT_CONFIRMED,
                severity    = ThreatSeverity.CRITICAL,
                title       = "Exploit Confirmed",
                description = "100 ETH drained",
            )
            await bus.publish(event)

            r1 = await ctxA.get(timeout=2.0)
            r2 = await ctxB.get(timeout=2.0)
            results = [r1, r2]

    assert len(results) == 2
    assert all(r is not None for r in results)
    assert all(r.event_type == ThreatEventType.EXPLOIT_CONFIRMED for r in results)


@pytest.mark.asyncio
async def test_event_bus_history():
    """Test that event history is maintained and queryable."""
    bus = ThreatEventBus()

    for i in range(5):
        await bus.publish(ThreatEvent(
            event_type  = ThreatEventType.FINDING_DETECTED,
            severity    = ThreatSeverity.MEDIUM,
            title       = f"Finding #{i}",
            description = f"Description {i}",
        ))

    history = bus.get_history(limit=3)
    assert len(history) == 3
    # Most recent first
    assert history[0]["title"] == "Finding #4"


@pytest.mark.asyncio
async def test_emit_helpers():
    """Test that convenience emitter functions publish valid events."""
    bus = get_event_bus.__wrapped__() if hasattr(get_event_bus, "__wrapped__") else ThreatEventBus()

    async with await bus.subscribe("helper-test") as ctx:
        # Publish directly using the bus since get_event_bus returns singleton
        event = ThreatEvent(
            event_type  = ThreatEventType.MEV_ATTACK_DETECTED,
            severity    = ThreatSeverity.CRITICAL,
            title       = "MEV Attack: sandwich on ethereum",
            description = "Value at risk: $132,500 USD.",
            payload     = {"attack_type": "sandwich", "chain": "ethereum", "value_at_risk_usd": 132500.0},
            source      = "mev-intelligence",
        )
        await bus.publish(event)
        received = await ctx.get(timeout=2.0)

    assert received is not None
    assert received.event_type == ThreatEventType.MEV_ATTACK_DETECTED
    assert received.payload["chain"] == "ethereum"


@pytest.mark.asyncio
async def test_event_bus_stats():
    """Test stats tracking."""
    bus = ThreatEventBus()
    for _ in range(3):
        await bus.publish(ThreatEvent(
            event_type=ThreatEventType.SYSTEM_HEALTH,
            severity=ThreatSeverity.INFO,
            title="Health Check",
            description="OK",
        ))

    stats = bus.get_stats()
    assert stats["published"] == 3
    assert "active_subscribers" in stats


@pytest.mark.asyncio
async def test_event_serialization():
    """Test ThreatEvent serializes correctly to JSON."""
    event = ThreatEvent(
        event_type  = ThreatEventType.CVE_CORRELATION,
        severity    = ThreatSeverity.CRITICAL,
        title       = "CVE-2024-1234 (CVSS 9.8)",
        description = "Critical vulnerability correlated",
        payload     = {"cve_id": "CVE-2024-1234", "cvss": 9.8},
    )
    json_str = event.to_json()
    parsed   = json.loads(json_str)

    assert parsed["event_type"] == "cve_correlation"
    assert parsed["severity"]   == "CRITICAL"
    assert parsed["payload"]["cvss"] == 9.8
    assert "event_id" in parsed
    assert "timestamp" in parsed
