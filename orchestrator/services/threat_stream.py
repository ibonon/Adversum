"""
Adversum Real-Time Threat Stream Engine
========================================
Async event bus that pushes security events to WebSocket subscribers.
Supports multi-channel subscription: findings, exploits, patches, intel, mev.

Architecture:
    EventBus (singleton) ──► WebSocket connections (fan-out)
                          ──► Redis pub/sub (optional, for multi-process)
                          ──► In-memory queue (default, single-process)
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("adversum.threat_stream")


# ---------------------------------------------------------------------------
# Event Types
# ---------------------------------------------------------------------------

class ThreatEventType(str, Enum):
    FINDING_DETECTED    = "finding_detected"
    EXPLOIT_CONFIRMED   = "exploit_confirmed"
    PATCH_GENERATED     = "patch_generated"
    PR_OPENED           = "pr_opened"
    MEV_ATTACK_DETECTED = "mev_attack_detected"
    THREAT_MODEL_READY  = "threat_model_ready"
    COMPLIANCE_REPORT   = "compliance_report"
    CVE_CORRELATION     = "cve_correlation"
    AUDIT_STARTED       = "audit_started"
    AUDIT_COMPLETED     = "audit_completed"
    SYSTEM_HEALTH       = "system_health"


class ThreatSeverity(str, Enum):
    CRITICAL  = "CRITICAL"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    LOW       = "LOW"
    INFO      = "INFO"


@dataclass
class ThreatEvent:
    """Canonical event object pushed to all subscribers."""
    event_type:  ThreatEventType
    severity:    ThreatSeverity
    title:       str
    description: str
    payload:     Dict[str, Any] = field(default_factory=dict)
    source:      str            = "adversum-core"
    event_id:    str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   str            = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_json(self) -> str:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["severity"]   = self.severity.value
        return json.dumps(d)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["severity"]   = self.severity.value
        return d


# ---------------------------------------------------------------------------
# Event Bus (singleton)
# ---------------------------------------------------------------------------

class ThreatEventBus:
    """
    In-process async event bus with WebSocket fan-out support.
    
    Usage:
        bus = get_event_bus()
        await bus.publish(ThreatEvent(...))
        
        # In WebSocket handler:
        async with bus.subscribe() as queue:
            event = await queue.get()
    """

    def __init__(self, max_queue_size: int = 500):
        self._subscribers: Dict[str, asyncio.Queue] = {}
        self._history: List[ThreatEvent] = []
        self._max_history = 200
        self._max_queue_size = max_queue_size
        self._lock = asyncio.Lock()
        self._stats = {"published": 0, "dropped": 0, "subscribers_peak": 0}

    # ── Publish ────────────────────────────────────────────────────────────

    async def publish(self, event: ThreatEvent) -> None:
        """Broadcast event to all active subscribers."""
        async with self._lock:
            # Keep rolling history
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history.pop(0)

            self._stats["published"] += 1
            peak = self._stats["subscribers_peak"]
            self._stats["subscribers_peak"] = max(peak, len(self._subscribers))

            dead_subs: List[str] = []
            for sub_id, queue in self._subscribers.items():
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    self._stats["dropped"] += 1
                    logger.warning("Queue full for subscriber %s — event dropped", sub_id)
                except Exception as exc:
                    logger.error("Error publishing to %s: %s", sub_id, exc)
                    dead_subs.append(sub_id)

            for sub_id in dead_subs:
                self._subscribers.pop(sub_id, None)

        logger.debug("Published [%s] %s to %d subscribers",
                     event.event_type, event.title, len(self._subscribers))

    # ── Subscribe / Unsubscribe ────────────────────────────────────────────

    async def subscribe(self, sub_id: Optional[str] = None) -> "SubscriberContext":
        if sub_id is None:
            sub_id = str(uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue_size)
        async with self._lock:
            self._subscribers[sub_id] = queue
        logger.info("New subscriber: %s (total=%d)", sub_id, len(self._subscribers))
        return SubscriberContext(bus=self, sub_id=sub_id, queue=queue)

    async def unsubscribe(self, sub_id: str) -> None:
        async with self._lock:
            self._subscribers.pop(sub_id, None)
        logger.info("Unsubscribed: %s (remaining=%d)", sub_id, len(self._subscribers))

    # ── History & Stats ────────────────────────────────────────────────────

    def get_history(self, limit: int = 50, severity: Optional[str] = None) -> List[dict]:
        events = list(reversed(self._history))
        if severity:
            events = [e for e in events if e.severity.value == severity.upper()]
        return [e.to_dict() for e in events[:limit]]

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "active_subscribers": len(self._subscribers),
            "history_size": len(self._history),
        }

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


class SubscriberContext:
    """Context manager for safe subscription lifecycle."""

    def __init__(self, bus: ThreatEventBus, sub_id: str, queue: asyncio.Queue):
        self.bus    = bus
        self.sub_id = sub_id
        self.queue  = queue

    async def __aenter__(self) -> "SubscriberContext":
        return self

    async def __aexit__(self, *_) -> None:
        await self.bus.unsubscribe(self.sub_id)

    async def get(self, timeout: float = 30.0) -> Optional[ThreatEvent]:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_bus_instance: Optional[ThreatEventBus] = None


def get_event_bus() -> ThreatEventBus:
    global _bus_instance
    if _bus_instance is None:
        _bus_instance = ThreatEventBus()
    return _bus_instance


# ---------------------------------------------------------------------------
# Helper publishers (convenience API)
# ---------------------------------------------------------------------------

async def emit_finding(
    rule_id: str,
    description: str,
    severity: str = "HIGH",
    payload: Optional[dict] = None,
) -> None:
    bus = get_event_bus()
    await bus.publish(ThreatEvent(
        event_type  = ThreatEventType.FINDING_DETECTED,
        severity    = ThreatSeverity(severity),
        title       = f"Finding: {rule_id}",
        description = description,
        payload     = payload or {},
        source      = "sast-core",
    ))


async def emit_exploit_confirmed(
    contract: str,
    vector: str,
    eth_drained: float,
    poe_hash: str,
    payload: Optional[dict] = None,
) -> None:
    bus = get_event_bus()
    await bus.publish(ThreatEvent(
        event_type  = ThreatEventType.EXPLOIT_CONFIRMED,
        severity    = ThreatSeverity.CRITICAL,
        title       = f"EXPLOIT CONFIRMED: {vector} on {contract[:10]}...",
        description = f"Live Fork PoE confirmed {eth_drained:.4f} ETH drained. Hash: {poe_hash[:16]}...",
        payload     = payload or {"contract": contract, "vector": vector, "eth_drained": eth_drained},
        source      = "live-fork-engine",
    ))


async def emit_patch_generated(
    rule_id: str,
    pr_url: str,
    gas_saved_pct: float,
    payload: Optional[dict] = None,
) -> None:
    bus = get_event_bus()
    await bus.publish(ThreatEvent(
        event_type  = ThreatEventType.PATCH_GENERATED,
        severity    = ThreatSeverity.INFO,
        title       = f"Patch Generated: {rule_id}",
        description = f"Self-Healing Bot generated patch. Gas saved: {gas_saved_pct:.1f}%. PR: {pr_url}",
        payload     = payload or {"rule_id": rule_id, "pr_url": pr_url, "gas_saved_pct": gas_saved_pct},
        source      = "self-healing-bot",
    ))


async def emit_mev_attack(
    attack_type: str,
    chain: str,
    value_at_risk_usd: float,
    tx_hash: str,
    payload: Optional[dict] = None,
) -> None:
    bus = get_event_bus()
    await bus.publish(ThreatEvent(
        event_type  = ThreatEventType.MEV_ATTACK_DETECTED,
        severity    = ThreatSeverity.CRITICAL,
        title       = f"MEV Attack: {attack_type} on {chain}",
        description = f"Value at risk: ${value_at_risk_usd:,.0f} USD. Tx: {tx_hash[:16]}...",
        payload     = payload or {
            "attack_type": attack_type,
            "chain": chain,
            "value_at_risk_usd": value_at_risk_usd,
            "tx_hash": tx_hash,
        },
        source      = "mev-intelligence",
    ))


async def emit_cve_correlation(
    cve_id: str,
    cvss_score: float,
    affected_component: str,
    payload: Optional[dict] = None,
) -> None:
    bus = get_event_bus()
    sev = ThreatSeverity.CRITICAL if cvss_score >= 9.0 else (
        ThreatSeverity.HIGH if cvss_score >= 7.0 else ThreatSeverity.MEDIUM
    )
    await bus.publish(ThreatEvent(
        event_type  = ThreatEventType.CVE_CORRELATION,
        severity    = sev,
        title       = f"CVE Correlation: {cve_id} (CVSS {cvss_score})",
        description = f"Live Tavily correlation matched {cve_id} to {affected_component}",
        payload     = payload or {"cve_id": cve_id, "cvss_score": cvss_score, "component": affected_component},
        source      = "threat-intel",
    ))
