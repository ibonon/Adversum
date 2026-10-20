"""
Tests for JobQueueManager and ScanCheckpoint.
"""
import asyncio
import tempfile
import pytest
from orchestrator.services.job_queue import JobQueueManager, JobPriority
from orchestrator.services.checkpoint import ScanCheckpoint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _noop():
    """No-op coroutine for queue testing."""
    await asyncio.sleep(0)


async def _raise():
    """Failing coroutine for error path testing."""
    raise ValueError("intentional failure")


# ---------------------------------------------------------------------------
# Job Queue tests
# ---------------------------------------------------------------------------

def test_enqueue_returns_job_id():
    """Enqueue must return a non-empty string job ID."""
    async def _run():
        mgr = JobQueueManager(max_concurrent=1)
        jid = await mgr.enqueue(_noop, priority=JobPriority.NORMAL)
        assert isinstance(jid, str)
        assert len(jid) > 0

    asyncio.run(_run())


def test_priority_ordering():
    """CRITICAL jobs (priority=0) must be dequeued before NORMAL (priority=2)."""
    async def _run():
        mgr = JobQueueManager(max_concurrent=1)
        # Enqueue NORMAL first, then CRITICAL
        await mgr.enqueue(_noop, priority=JobPriority.NORMAL, job_id="normal-job")
        await mgr.enqueue(_noop, priority=JobPriority.CRITICAL, job_id="critical-job")

        # PriorityQueue: lowest value = highest priority
        first = await mgr._queue.get()
        second = await mgr._queue.get()
        assert first.priority < second.priority
        assert first.job_id == "critical-job"
        assert second.job_id == "normal-job"

    asyncio.run(_run())


def test_stats_structure():
    """Stats dict must contain all expected keys with integer values."""
    async def _run():
        mgr = JobQueueManager(max_concurrent=2)
        stats = mgr.stats
        assert set(stats.keys()) == {
            "queue_size", "active", "completed", "failed", "max_concurrent"
        }
        for v in stats.values():
            assert isinstance(v, int)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Checkpoint tests
# ---------------------------------------------------------------------------

def test_checkpoint_mark_and_check():
    """mark_file_done + is_file_done must work correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cp = ScanCheckpoint(job_id=42, checkpoint_dir=tmpdir)
        assert not cp.is_file_done("contracts/Token.sol")

        cp.mark_file_done("contracts/Token.sol", findings_count=3)
        assert cp.is_file_done("contracts/Token.sol")
        assert cp.total_findings_so_far() == 3

        done = cp.get_done_files()
        assert "contracts/Token.sol" in done


def test_checkpoint_cleanup():
    """cleanup() must remove the checkpoint file from disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cp = ScanCheckpoint(job_id=99, checkpoint_dir=tmpdir)
        cp.mark_file_done("src/Vault.sol", findings_count=1)
        assert cp._path.exists()

        cp.cleanup()
        assert not cp._path.exists()
