"""
Adversum Job Queue — Priority-based async job queue with concurrency control.
Priority: CRITICAL=0, HIGH=1, NORMAL=2, LOW=3
Max concurrent jobs: configurable via MAX_CONCURRENT_JOBS env var (default: 3)
"""
from __future__ import annotations
import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)

class JobPriority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3

@dataclass(order=True)
class QueuedJob:
    priority: int
    enqueued_at: float = field(compare=False)
    job_id: str = field(compare=False)
    coro_fn: Callable[..., Coroutine] = field(compare=False)
    args: tuple = field(compare=False, default_factory=tuple)
    kwargs: dict = field(compare=False, default_factory=dict)
    metadata: Dict[str, Any] = field(compare=False, default_factory=dict)

class JobQueueManager:
    def __init__(self, max_concurrent: int = 3):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._max_concurrent = int(os.getenv("MAX_CONCURRENT_JOBS", str(max_concurrent)))
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._active: Dict[str, QueuedJob] = {}
        self._completed: List[Dict] = []
        self._failed: List[Dict] = []
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None
        logger.info(f"[JobQueue] Initialized — max_concurrent={self._max_concurrent}")

    async def enqueue(
        self,
        coro_fn: Callable[..., Coroutine],
        *args,
        priority: JobPriority = JobPriority.NORMAL,
        job_id: Optional[str] = None,
        **kwargs,
    ) -> str:
        jid = job_id or str(uuid.uuid4())[:8]
        job = QueuedJob(
            priority=int(priority),
            enqueued_at=time.monotonic(),
            job_id=jid,
            coro_fn=coro_fn,
            args=args,
            kwargs=kwargs,
        )
        await self._queue.put(job)
        logger.info(f"[JobQueue] Enqueued job={jid} priority={priority.name} qsize={self._queue.qsize()}")
        return jid

    async def _run_job(self, job: QueuedJob) -> None:
        async with self._semaphore:
            self._active[job.job_id] = job
            start = time.monotonic()
            try:
                await job.coro_fn(*job.args, **job.kwargs)
                elapsed = round(time.monotonic() - start, 2)
                self._completed.append({"job_id": job.job_id, "elapsed_s": elapsed, "status": "ok"})
                logger.info(f"[JobQueue] Completed job={job.job_id} elapsed={elapsed}s")
            except Exception as exc:
                elapsed = round(time.monotonic() - start, 2)
                self._failed.append({"job_id": job.job_id, "error": str(exc), "elapsed_s": elapsed})
                logger.error(f"[JobQueue] Failed job={job.job_id} error={exc}")
            finally:
                self._active.pop(job.job_id, None)

    async def _worker(self) -> None:
        logger.info("[JobQueue] Worker started")
        while self._running:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                asyncio.create_task(self._run_job(job))
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.error(f"[JobQueue] Worker error: {exc}")
        logger.info("[JobQueue] Worker stopped")

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        self._running = False
        if self._worker_task:
            await asyncio.wait_for(self._worker_task, timeout=5.0)

    @property
    def stats(self) -> dict:
        return {
            "queue_size": self._queue.qsize(),
            "active": len(self._active),
            "completed": len(self._completed),
            "failed": len(self._failed),
            "max_concurrent": self._max_concurrent,
        }

# Global singleton
job_queue = JobQueueManager(max_concurrent=3)
