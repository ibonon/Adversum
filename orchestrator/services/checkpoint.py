"""
Adversum Scan Checkpoint — Persists incremental scan progress to SQLite.
Allows resuming interrupted scans from the last successfully processed file.
"""
from __future__ import annotations
import json
import logging
import time
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class ScanCheckpoint:
    """
    Lightweight file-based checkpoint for large repository scans.
    Stores processed file paths and partial findings count.
    """
    def __init__(self, job_id: int, checkpoint_dir: str = ".adversum_checkpoints"):
        self._dir = Path(checkpoint_dir)
        self._dir.mkdir(exist_ok=True)
        self._path = self._dir / f"job_{job_id}.json"
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save(self) -> None:
        self._path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def mark_file_done(self, file_path: str, findings_count: int = 0) -> None:
        """Record that a file was successfully scanned."""
        if "files" not in self._data:
            self._data["files"] = {}
        self._data["files"][file_path] = {
            "done": True,
            "findings": findings_count,
            "ts": time.time(),
        }
        self._data["updated_at"] = time.time()
        self._save()

    def is_file_done(self, file_path: str) -> bool:
        """Check if a file was already scanned (for resume)."""
        return self._data.get("files", {}).get(file_path, {}).get("done", False)

    def get_done_files(self) -> List[str]:
        return list(self._data.get("files", {}).keys())

    def total_findings_so_far(self) -> int:
        return sum(
            v.get("findings", 0)
            for v in self._data.get("files", {}).values()
        )

    def cleanup(self) -> None:
        """Remove checkpoint file after successful completion."""
        if self._path.exists():
            self._path.unlink()
            logger.info(f"[Checkpoint] Removed checkpoint for job at {self._path}")
