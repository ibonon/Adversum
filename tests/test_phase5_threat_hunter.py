"""
Phase 5 Tests — Autonomous Threat Hunter Daemon & Heuristics
"""
import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modules.threat_hunter.heuristics import BytecodeHeuristicsEngine, HunterFinding
from modules.threat_hunter.daemon import ThreatHuntingDaemon, HunterStatus


class TestBytecodeHeuristics:
    def test_clean_bytecode_returns_empty(self):
        engine = BytecodeHeuristicsEngine()
        clean = "608060405234801561001057600080fd5b50"
        findings = engine.analyze_bytecode(clean, "0x123", 100, "0xabc")
        assert len(findings) == 0

    def test_detects_delegatecall(self):
        engine = BytecodeHeuristicsEngine()
        code = "60806040f43d6000"
        findings = engine.analyze_bytecode(code, "0xProxyContract", 100, "0xabc")
        assert len(findings) == 1
        assert findings[0].detector_id == "HUNT-001"
        assert findings[0].severity == "HIGH"

    def test_detects_selfdestruct(self):
        engine = BytecodeHeuristicsEngine()
        code = "60806040ff"
        findings = engine.analyze_bytecode(code, "0xDestructContract", 100, "0xabc")
        assert len(findings) == 1
        assert findings[0].detector_id == "HUNT-002"
        assert findings[0].severity == "CRITICAL"

    def test_detects_tx_origin(self):
        engine = BytecodeHeuristicsEngine()
        code = "6080326000"
        findings = engine.analyze_bytecode(code, "0xOriginContract", 100, "0xabc")
        assert len(findings) == 1
        assert findings[0].detector_id == "HUNT-003"


class MockEventBus:
    def __init__(self):
        self.published = []

    async def publish(self, event):
        self.published.append(event)


class TestThreatHuntingDaemon:
    @pytest.mark.asyncio
    async def test_daemon_lifecycle(self):
        daemon = ThreatHuntingDaemon(chain="ethereum")
        assert not daemon.is_running

        status = await daemon.start()
        assert status.is_running
        assert daemon.is_running

        await asyncio.sleep(0.1)

        stop_status = await daemon.stop()
        assert not stop_status.is_running
        assert not daemon.is_running

    @pytest.mark.asyncio
    async def test_scan_single_block(self):
        daemon = ThreatHuntingDaemon(chain="arbitrum")
        findings = await daemon.scan_single_block(block_num=100)
        assert daemon.status().blocks_scanned == 1
        assert daemon.status().contracts_analyzed > 0
        # Block 100 is even -> triggers delegatecall proxy finding
        assert len(findings) >= 1
        detector_ids = [f.detector_id for f in findings]
        assert "HUNT-001" in detector_ids

    @pytest.mark.asyncio
    async def test_event_bus_integration(self):
        daemon = ThreatHuntingDaemon()
        mock_bus = MockEventBus()
        daemon.attach_event_bus(mock_bus)

        await daemon.scan_single_block(block_num=100)
        # Give asyncio tasks brief moment to publish
        await asyncio.sleep(0.05)
        assert len(mock_bus.published) >= 1
        assert mock_bus.published[0]["event_type"] == "THREAT_HUNTER_DETECTION"
